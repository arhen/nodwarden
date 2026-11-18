//! aac-core: headless Agent Access listener driven over stdin/stdout.
//!
//! Replaces `aac listen`'s TUI. The parent (the island app) is the only party
//! that can answer approvals, because the only channel is this process's own
//! stdin pipe — no tmux, no keystroke injection.
//!
//! Protocol, one JSON object per line.
//!   stdin  {"op":"unlock","session":"..."}
//!          {"op":"decide","id":N,"decision":"approve"|"deny"|"approve_for","minutes":M}
//!          {"op":"lock"}
//!   stdout {"ev":"status","state":"locked"|"unlocked"|"connecting"|"listening"|"offline","detail":...}
//!          {"ev":"request","id":N,"query":..,"domain":..,"username":..,"uri":..,"device":..}
//!          {"ev":"resolved","id":N,"outcome":"approved"|"denied"|"auto"|"expired"|"not_found"|"locked"}
//!          {"ev":"log","msg":...}
//! Secrets never go to stdout.

mod ssh_agent;
mod storage;

use std::collections::HashMap;
use std::process::Stdio;
use std::time::{Duration, Instant};

use ap_client::{
    ConnectionStore, CredentialData, CredentialQuery, CredentialRequestReply, DefaultProxyClient,
    FingerprintVerificationReply, IdentityFingerprint, PskStore, UserClient,
    UserClientNotification, UserClientRequest,
};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, oneshot};

use storage::{FileConnectionCache, FileIdentityStorage, FilePskStore};

const PROXY_URL: &str = "wss://ap.lesspassword.dev";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(110);

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Cmd {
    Unlock { session: String },
    Decide { id: u64, decision: String, minutes: Option<u32> },
    Lock,
}

struct Pending {
    identity: IdentityFingerprint,
    query_key: String,
    credential: CredentialData,
    reply: oneshot::Sender<CredentialRequestReply>,
    deadline: Instant,
}

fn emit(v: Value) {
    // stdout is a pipe to the parent; one line per event.
    println!("{v}");
}

async fn bw_status(bw: &str, session: Option<&SecretString>) -> Option<String> {
    let mut cmd = tokio::process::Command::new(bw);
    cmd.arg("status").stdin(Stdio::null()).stderr(Stdio::null());
    if let Some(s) = session {
        cmd.env("BW_SESSION", s.expose_secret());
    }
    let out = cmd.output().await.ok()?;
    let v: Value = serde_json::from_slice(&out.stdout).ok()?;
    v["status"].as_str().map(str::to_string)
}

enum Lookup {
    Found(CredentialData),
    NotFound(String),
    Locked,
}

async fn bw_lookup(bw: &str, session: &SecretString, search: &str) -> Lookup {
    let out = match tokio::process::Command::new(bw)
        .args(["get", "item", search])
        .env("BW_SESSION", session.expose_secret())
        .stdin(Stdio::null())
        .output()
        .await
    {
        Ok(o) => o,
        Err(e) => return Lookup::NotFound(format!("bw failed: {e}")),
    };
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        if err.contains("locked") || err.contains("Master password") {
            return Lookup::Locked;
        }
        let first = err.lines().next().unwrap_or("not found").to_string();
        return Lookup::NotFound(if first.starts_with("More than one result") {
            "More than one item matches; request by id".into()
        } else {
            first
        });
    }
    let item: Value = match serde_json::from_slice(&out.stdout) {
        Ok(v) => v,
        Err(_) => return Lookup::NotFound("unreadable item".into()),
    };
    let login = &item["login"];
    if login.is_null() {
        return Lookup::NotFound("item is not a login".into());
    }
    let uri = login["uris"][0]["uri"].as_str().map(str::to_string);
    let domain = uri.as_deref().and_then(host_of);
    Lookup::Found(CredentialData {
        username: login["username"].as_str().map(str::to_string),
        password: login["password"].as_str().map(|p| p.to_string().into()),
        totp: login["totp"].as_str().map(str::to_string),
        uri,
        notes: None,
        credential_id: item["id"].as_str().map(str::to_string),
        domain,
    })
}

fn host_of(uri: &str) -> Option<String> {
    let rest = uri.split_once("://").map_or(uri, |(_, r)| r);
    let rest = rest.split_once('@').map_or(rest, |(_, r)| r);
    let host = rest.split(['/', ':', '?', '#']).next()?;
    (!host.is_empty()).then(|| host.to_string())
}

fn device_label(conns: &[ap_client::ConnectionInfo], id: &IdentityFingerprint) -> String {
    conns
        .iter()
        .find(|c| &c.fingerprint == id)
        .and_then(|c| c.name.clone())
        .unwrap_or_else(|| hex::encode(id.0).chars().take(12).collect())
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    if let Err(e) = run().await {
        emit(json!({"ev":"status","state":"offline","detail":e}));
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    // Resolved through PATH, which the app sets for us.
    let bw = "bw".to_string();
    let mut session: Option<SecretString> = None;

    let (cmd_tx, mut cmd_rx) = mpsc::channel::<Cmd>(32);
    tokio::spawn(async move {
        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            match serde_json::from_str::<Cmd>(&line) {
                Ok(c) => {
                    if cmd_tx.send(c).await.is_err() {
                        break;
                    }
                }
                Err(e) => emit(json!({"ev":"log","msg":format!("bad command: {e}")})),
            }
        }
        // Parent went away: exit so no orphan listener holds the vault session.
        std::process::exit(0);
    });

    emit(json!({"ev":"status","state":"locked"}));
    emit(json!({"ev":"status","state":"connecting"}));

    let identity = FileIdentityStorage::load_or_generate("user_client").map_err(|e| e.to_string())?;
    let store = FileConnectionCache::load_or_create("user_client").map_err(|e| e.to_string())?;
    let psk_store = FilePskStore::load_or_create("user_client").map_err(|e| e.to_string())?;
    let existing = PskStore::list(&psk_store).await;

    let handle = UserClient::connect(
        Box::new(identity),
        Box::new(store),
        Box::new(DefaultProxyClient::from_url(PROXY_URL.to_string())),
        None,
        Some(Box::new(psk_store)),
    )
    .await
    .map_err(|e| format!("relay: {e}"))?;

    let client = handle.client;
    let mut notes = handle.notifications;
    let mut requests = handle.requests;

    if existing.is_empty() {
        // First run on this machine: mint the reusable PSK agents pair with.
        client.get_psk_token(None, true).await.map_err(|e| e.to_string())?;
    }
    emit(json!({"ev":"status","state":"listening"}));

    let mut pending: HashMap<u64, Pending> = HashMap::new();
    let mut approvals: HashMap<(IdentityFingerprint, String), Instant> = HashMap::new();
    let mut next_id: u64 = 1;
    let mut tick = tokio::time::interval(Duration::from_secs(1));

    // SSH agent: keys load on unlock, every signature waits for the island.
    let ssh_state: ssh_agent::Shared = Default::default();
    let (ssh_tx, mut ssh_rx) = mpsc::channel::<ssh_agent::SignAsk>(16);
    {
        let (st, tx) = (ssh_state.clone(), ssh_tx.clone());
        tokio::spawn(async move {
            if let Err(e) = ssh_agent::serve(st, tx).await {
                emit(json!({"ev":"log","msg":format!("ssh agent: {e}")}));
            }
        });
    }
    let mut ssh_pending: HashMap<u64, (ssh_agent::SignAsk, Instant)> = HashMap::new();

    loop {
        tokio::select! {
            Some(cmd) = cmd_rx.recv() => match cmd {
                Cmd::Unlock { session: s } => {
                    let s = SecretString::from(s);
                    if bw_status(&bw, Some(&s)).await.as_deref() == Some("unlocked") {
                        match ssh_agent::load_keys(&s).await {
                            Ok(keys) => {
                                emit(json!({"ev":"log","msg":format!("ssh agent: {} keys", keys.len())}));
                                ssh_state.lock().await.keys = keys;
                            }
                            Err(e) => emit(json!({"ev":"log","msg":format!("ssh agent: {e}")})),
                        }
                        session = Some(s);
                        emit(json!({"ev":"status","state":"unlocked"}));
                    } else {
                        emit(json!({"ev":"status","state":"locked","detail":"session rejected"}));
                    }
                }
                Cmd::Lock => {
                    session = None;
                    approvals.clear();
                    {
                        let mut st = ssh_state.lock().await;
                        st.keys.clear();
                        st.allowed.clear();
                    }
                    for (id, (ask, _)) in ssh_pending.drain() {
                        let _ = ask.reply.send(false);
                        emit(json!({"ev":"resolved","id":id,"outcome":"denied"}));
                    }
                    for (id, p) in pending.drain() {
                        let _ = p.reply.send(CredentialRequestReply { approved: false, credential: None, credential_id: None });
                        emit(json!({"ev":"resolved","id":id,"outcome":"denied"}));
                    }
                    emit(json!({"ev":"status","state":"locked"}));
                }
                Cmd::Decide { id, decision, minutes } => {
                    if let Some((ask, _)) = ssh_pending.remove(&id) {
                        let approve = decision == "approve" || decision == "approve_for";
                        if decision == "approve_for" {
                            let mins = u64::from(minutes.unwrap_or(10).clamp(1, 240));
                            ssh_agent::allow_for(&ssh_state, &ask.fingerprint, &ask.process, Instant::now() + Duration::from_secs(mins * 60)).await;
                        }
                        let _ = ask.reply.send(approve);
                        emit(json!({"ev":"resolved","id":id,"outcome": if approve {"approved"} else {"denied"}}));
                        continue;
                    }
                    let Some(p) = pending.remove(&id) else { continue };
                    let cred_id = p.credential.credential_id.clone();
                    let approve = decision == "approve" || decision == "approve_for";
                    if decision == "approve_for" {
                        let mins = minutes.unwrap_or(10).clamp(1, 240);
                        approvals.insert((p.identity, p.query_key), Instant::now() + Duration::from_secs(u64::from(mins) * 60));
                    }
                    let _ = p.reply.send(CredentialRequestReply {
                        approved: approve,
                        credential: approve.then_some(p.credential),
                        credential_id: cred_id,
                    });
                    emit(json!({"ev":"resolved","id":id,"outcome": if approve {"approved"} else {"denied"}}));
                }
            },

            Some(req) = requests.recv() => match req {
                UserClientRequest::VerifyFingerprint { reply, .. } => {
                    // Only rendezvous pairing asks this; we only accept PSK pairing.
                    let _ = reply.send(FingerprintVerificationReply { approved: false, name: None });
                    emit(json!({"ev":"log","msg":"rejected rendezvous pairing (PSK only)"}));
                }
                UserClientRequest::CredentialRequest { query, identity, reply } => {
                    let id = next_id;
                    next_id += 1;
                    let search = query.search_string().to_string();
                    let query_key = query.to_string();
                    let deny = |reply: oneshot::Sender<CredentialRequestReply>| {
                        let _ = reply.send(CredentialRequestReply { approved: false, credential: None, credential_id: None });
                    };

                    let Some(s) = session.as_ref() else {
                        deny(reply);
                        emit(json!({"ev":"resolved","id":id,"outcome":"locked","query":search}));
                        continue;
                    };

                    let cred = match bw_lookup(&bw, s, &search).await {
                        Lookup::Found(c) => c,
                        Lookup::Locked => {
                            session = None;
                            deny(reply);
                            emit(json!({"ev":"status","state":"locked","detail":"vault locked"}));
                            emit(json!({"ev":"resolved","id":id,"outcome":"locked","query":search}));
                            continue;
                        }
                        Lookup::NotFound(why) => {
                            deny(reply);
                            emit(json!({"ev":"resolved","id":id,"outcome":"not_found","query":search,"detail":why}));
                            continue;
                        }
                    };

                    let key = (identity, query_key.clone());
                    if approvals.get(&key).is_some_and(|t| *t > Instant::now()) {
                        let domain = cred.domain.clone();
                        let cid = cred.credential_id.clone();
                        let _ = reply.send(CredentialRequestReply { approved: true, credential: Some(cred), credential_id: cid });
                        emit(json!({"ev":"resolved","id":id,"outcome":"auto","query":search,"domain":domain}));
                        continue;
                    }

                    let conns = match FileConnectionCache::load_or_create("user_client") {
                        Ok(c) => c.list().await,
                        Err(_) => Vec::new(),
                    };

                    emit(json!({
                        "ev":"request","id":id,"query":search,
                        "kind": match query { CredentialQuery::Domain(_) => "domain", CredentialQuery::Id(_) => "id", CredentialQuery::Search(_) => "search" },
                        "domain":cred.domain,"username":cred.username,"uri":cred.uri,
                        "has_totp":cred.totp.is_some(),
                        "device":device_label(&conns, &identity),
                        "timeout":REQUEST_TIMEOUT.as_secs(),
                    }));
                    pending.insert(id, Pending { identity, query_key, credential: cred, reply, deadline: Instant::now() + REQUEST_TIMEOUT });
                }
            },

            Some(ask) = ssh_rx.recv() => {
                let id = next_id;
                next_id += 1;
                if session.is_none() {
                    let _ = ask.reply.send(false);
                    emit(json!({"ev":"resolved","id":id,"outcome":"locked","query":ask.key_name}));
                    continue;
                }
                emit(ssh_agent::ask_json(id, &ask));
                ssh_pending.insert(id, (ask, Instant::now() + REQUEST_TIMEOUT));
            },

            Some(n) = notes.recv() => match n {
                UserClientNotification::Reconnecting { attempt } =>
                    emit(json!({"ev":"status","state":"connecting","detail":format!("reconnecting ({attempt})")})),
                UserClientNotification::Reconnected {} =>
                    emit(json!({"ev":"status","state": if session.is_some() {"unlocked"} else {"locked"}})),
                UserClientNotification::ClientDisconnected {} =>
                    emit(json!({"ev":"status","state":"offline","detail":"relay disconnected"})),
                UserClientNotification::Error { message, .. } =>
                    emit(json!({"ev":"log","msg":message})),
                _ => {}
            },

            _ = tick.tick() => {
                let now = Instant::now();
                approvals.retain(|_, t| *t > now);
                let expired: Vec<u64> = pending.iter().filter(|(_, p)| p.deadline <= now).map(|(k, _)| *k).collect();
                for id in expired {
                    if let Some(p) = pending.remove(&id) {
                        let _ = p.reply.send(CredentialRequestReply { approved: false, credential: None, credential_id: None });
                        emit(json!({"ev":"resolved","id":id,"outcome":"expired"}));
                    }
                }
                let ssh_expired: Vec<u64> = ssh_pending.iter().filter(|(_, (_, d))| *d <= now).map(|(k, _)| *k).collect();
                for id in ssh_expired {
                    if let Some((ask, _)) = ssh_pending.remove(&id) {
                        let _ = ask.reply.send(false);
                        emit(json!({"ev":"resolved","id":id,"outcome":"expired"}));
                    }
                }
            }
        }
        let _ = tokio::io::stdout().flush().await;
    }
}
