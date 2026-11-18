//! aac-core: headless Agent Access listener and SSH agent, driven over stdin/stdout.
//!
//! The parent (NodWarden.app) is the only party that can answer approvals: the
//! only channel is this process's own stdin pipe.
//!
//! Protocol, one JSON object per line.
//!   stdin  {"op":"unlock","session":"..."}
//!          {"op":"decide","id":N,"decision":"approve"|"deny"|"approve_for","minutes":M}
//!          {"op":"lock"}
//!   stdout {"ev":"status","state":"locked"|"unlocked"|"connecting"|"listening"|"offline","detail":..}
//!          {"ev":"token","token":..}                      reusable PSK, once, when minted
//!          {"ev":"request","id":N,"name":..,"domain":..,"username":..,"device":..,"kind":..,"has_totp":..}
//!          {"ev":"ssh_request","id":N,...}                see ssh_agent::ask_json
//!          {"ev":"resolved","id":N,"outcome":"approved"|"denied"|"auto"|"expired"|"not_found"|"locked"|"cancelled"}
//!          {"ev":"log","msg":..}
//! Secrets never go to stdout. The vault session never goes into any child's argv or env.

mod bw;
mod ssh_agent;
#[allow(dead_code)] // copied unmodified from upstream; not every helper is used here
mod storage;

use std::collections::HashMap;
use std::time::{Duration, Instant};

use ap_client::{
    ConnectionStore, CredentialData, CredentialQuery, CredentialRequestReply, DefaultProxyClient,
    FingerprintVerificationReply, IdentityFingerprint, PskStore, UserClient, UserClientNotification,
    UserClientRequest,
};
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

use bw::Bw;
use storage::{FileConnectionCache, FileIdentityStorage, FilePskStore};

const PROXY_URL: &str = "wss://ap.lesspassword.dev";
/// How long a request may wait for a decision. The UI shows the same value from each event.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(110);
/// Upper bound for an "Allow N minutes" window; the UI offers 5–60.
const MAX_ALLOW_MINUTES: u32 = 60;
/// Requests a single device may have waiting at once (#14).
const MAX_PENDING_PER_DEVICE: usize = 3;

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Cmd {
    Unlock { session: bw::Secret },
    Decide { id: u64, decision: String, minutes: Option<u32> },
    Lock,
}

/// A credential request waiting for the user. The secret is not fetched yet (#1):
/// only metadata was read; the password is read after approval.
struct Pending {
    identity: IdentityFingerprint,
    item_id: String,
    reply: oneshot::Sender<CredentialRequestReply>,
    deadline: Instant,
}

/// Item metadata shown before approval. No secrets.
#[derive(Clone)]
struct ItemInfo {
    id: String,
    name: String,
    username: Option<String>,
    uri: Option<String>,
    domain: Option<String>,
    has_totp: bool,
}

fn emit(v: Value) {
    println!("{v}");
}

fn deny_reply() -> CredentialRequestReply {
    CredentialRequestReply { approved: false, credential: None, credential_id: None }
}

#[derive(Deserialize)]
struct BwUri {
    uri: Option<String>,
}
#[derive(Deserialize)]
struct BwLogin {
    username: Option<String>,
    password: Option<bw::Secret>,
    totp: Option<bw::Secret>,
    #[serde(default)]
    uris: Vec<BwUri>,
}
#[derive(Deserialize)]
struct BwItem {
    id: String,
    name: String,
    login: Option<BwLogin>,
}

enum Lookup {
    Found(ItemInfo),
    NotFound(String),
    Locked,
}

/// Reads an item's metadata. The password is parsed into a Zeroizing field and dropped here.
async fn bw_lookup(bw: &Bw, session: &SecretString, search: &str) -> Lookup {
    let out = match bw.run(Some(session), &["get", "item", "--", search]).await {
        Ok(o) => o,
        Err(e) => return Lookup::NotFound(e),
    };
    if !out.ok {
        if out.stderr.contains("locked") || out.stderr.contains("Master password") {
            return Lookup::Locked;
        }
        let first = out.stderr.lines().next().unwrap_or("not found").to_string();
        return Lookup::NotFound(if first.starts_with("More than one result") {
            "More than one item matches; request by id".into()
        } else {
            first
        });
    }
    let Ok(item) = serde_json::from_slice::<BwItem>(&out.stdout) else {
        return Lookup::NotFound("unreadable item".into());
    };
    let Some(login) = item.login else {
        return Lookup::NotFound("item is not a login".into());
    };
    let uri = login.uris.into_iter().find_map(|u| u.uri);
    Lookup::Found(ItemInfo {
        domain: uri.as_deref().and_then(host_of),
        id: item.id,
        name: item.name,
        username: login.username,
        uri,
        has_totp: login.totp.is_some(),
    })
}

/// Reads the secret of one item by id, after approval. TOTP is sent as a current code (#17).
async fn bw_secret(bw: &Bw, session: &SecretString, info: &ItemInfo) -> Option<CredentialData> {
    let out = bw.run(Some(session), &["get", "item", "--", &info.id]).await.ok()?;
    if !out.ok {
        return None;
    }
    let item: BwItem = serde_json::from_slice(&out.stdout).ok()?;
    let login = item.login?;
    let totp = if info.has_totp {
        let t = bw.run(Some(session), &["get", "totp", "--", &info.id]).await.ok()?;
        let code = String::from_utf8_lossy(&t.stdout).trim().to_string();
        (t.ok && code.chars().all(|c| c.is_ascii_digit()) && !code.is_empty()).then_some(code)
    } else {
        None
    };
    Some(CredentialData {
        username: login.username,
        password: login.password.map(|p| p.0),
        totp,
        uri: info.uri.clone(),
        notes: None,
        credential_id: Some(info.id.clone()),
        domain: info.domain.clone(),
    })
}

/// Host part of a URI; userinfo is only stripped before the first `/` (#30).
fn host_of(uri: &str) -> Option<String> {
    let rest = uri.split_once("://").map_or(uri, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next()?;
    let hostport = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = hostport.split(':').next()?;
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

fn device_label(conns: &[ap_client::ConnectionInfo], id: &IdentityFingerprint) -> String {
    conns
        .iter()
        .find(|c| &c.fingerprint == id)
        .and_then(|c| c.name.clone())
        .unwrap_or_else(|| hex::encode(id.0).chars().take(12).collect())
}

/// Makes the identity key and its directory private (#26: upstream writes them 0644).
fn tighten_access_protocol_perms() {
    use std::os::unix::fs::PermissionsExt;
    let Some(dir) = dirs::home_dir().map(|h| h.join(".access-protocol")) else { return };
    let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for e in entries.flatten() {
            let _ = std::fs::set_permissions(e.path(), std::fs::Permissions::from_mode(0o600));
        }
    }
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

/// Results of work that runs off the main loop (#13).
enum Done {
    Unlocked(SecretString, Vec<ssh_agent::Key>),
    UnlockFailed(String),
    Looked { id: u64, identity: IdentityFingerprint, query_key: String, kind: &'static str,
             reply: oneshot::Sender<CredentialRequestReply>, result: Lookup },
    Released { id: u64, reply: oneshot::Sender<CredentialRequestReply>, cred: Option<CredentialData>,
               auto: bool, domain: Option<String> },
}

struct Core {
    bw: Bw,
    session: Option<SecretString>,
    pending: HashMap<u64, (Pending, ItemInfo)>,
    /// (device, item id) -> allowed until. Keyed on the item, not the query (#22).
    approvals: HashMap<(IdentityFingerprint, String), Instant>,
    ssh_state: ssh_agent::Shared,
    ssh_pending: HashMap<u64, (ssh_agent::SignAsk, Instant)>,
    done_tx: mpsc::Sender<Done>,
}

impl Core {
    /// The one way to lock (#6): forget the session, keys and approvals, deny everything waiting,
    /// and lock bw so a session copied earlier stops working.
    async fn lock_all(&mut self, detail: &str) {
        self.session = None;
        self.approvals.clear();
        self.ssh_state.lock().await.clear();
        for (id, (p, _)) in self.pending.drain() {
            let _ = p.reply.send(deny_reply());
            emit(json!({"ev":"resolved","id":id,"outcome":"denied"}));
        }
        for (id, (ask, _)) in self.ssh_pending.drain() {
            let _ = ask.reply.send(false);
            emit(json!({"ev":"resolved","id":id,"outcome":"denied"}));
        }
        let bw = self.bw.clone();
        tokio::spawn(async move { bw.lock().await });
        emit(json!({"ev":"status","state":"locked","detail":detail}));
    }

    /// Fetches the secret and replies, off the main loop.
    fn release(&self, id: u64, info: ItemInfo, reply: oneshot::Sender<CredentialRequestReply>, auto: bool) {
        let (bw, session, tx) = (self.bw.clone(), self.session.clone(), self.done_tx.clone());
        tokio::spawn(async move {
            let cred = match session {
                Some(s) => bw_secret(&bw, &s, &info).await,
                None => None,
            };
            let _ = tx.send(Done::Released { id, reply, cred, auto, domain: info.domain }).await;
        });
    }
}

async fn run() -> Result<(), String> {
    let bw = Bw::resolve()?;
    emit(json!({"ev":"log","msg":format!("bw: {} {}", bw.node.display(), bw.script.display())}));

    let (cmd_tx, mut cmd_rx) = mpsc::channel::<Cmd>(32);
    tokio::spawn(async move {
        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let line = Zeroizing::new(line);
            match serde_json::from_str::<Cmd>(&line) {
                Ok(c) => {
                    if cmd_tx.send(c).await.is_err() {
                        break;
                    }
                }
                Err(_) => emit(json!({"ev":"log","msg":"bad command"})),
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
    tighten_access_protocol_perms();

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
        // First run: mint the reusable PSK agents pair with, and show it once (#19).
        let token = client.get_psk_token(None, true).await.map_err(|e| e.to_string())?;
        emit(json!({"ev":"token","token":token}));
        tighten_access_protocol_perms();
    }
    emit(json!({"ev":"status","state":"listening"}));

    let (done_tx, mut done_rx) = mpsc::channel::<Done>(32);
    let (ssh_tx, mut ssh_rx) = mpsc::channel::<ssh_agent::SignAsk>(16);
    let mut core = Core {
        bw: bw.clone(),
        session: None,
        pending: HashMap::new(),
        approvals: HashMap::new(),
        ssh_state: Default::default(),
        ssh_pending: HashMap::new(),
        done_tx: done_tx.clone(),
    };
    {
        let (st, tx) = (core.ssh_state.clone(), ssh_tx.clone());
        tokio::spawn(async move {
            if let Err(e) = ssh_agent::serve(st, tx).await {
                emit(json!({"ev":"log","msg":format!("ssh agent: {e}")}));
            }
        });
    }

    // Base request ids on the clock so ids from a restarted core never collide (#30).
    let mut next_id: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(1, |d| d.as_millis() as u64 * 1000);
    let mut tick = tokio::time::interval(Duration::from_secs(1));

    loop {
        tokio::select! {
            Some(cmd) = cmd_rx.recv() => match cmd {
                Cmd::Unlock { session } => {
                    let (bw, tx) = (core.bw.clone(), done_tx.clone());
                    let s = SecretString::from(session.as_str().to_owned());
                    tokio::spawn(async move {
                        if bw.status(Some(&s)).await.as_deref() != Some("unlocked") {
                            let _ = tx.send(Done::UnlockFailed("session rejected".into())).await;
                            return;
                        }
                        let keys = match ssh_agent::load_keys(&bw, &s).await {
                            Ok(k) => k,
                            Err(e) => { emit(json!({"ev":"log","msg":format!("ssh agent: {e}")})); Vec::new() }
                        };
                        let _ = tx.send(Done::Unlocked(s, keys)).await;
                    });
                }
                Cmd::Lock => core.lock_all("").await,
                Cmd::Decide { id, decision, minutes } => {
                    let approve = matches!(decision.as_str(), "approve" | "approve_for");
                    let window = (decision == "approve_for")
                        .then(|| Duration::from_secs(u64::from(minutes.unwrap_or(10).clamp(1, MAX_ALLOW_MINUTES)) * 60));
                    if let Some((ask, _)) = core.ssh_pending.remove(&id) {
                        if let Some(w) = window {
                            ssh_agent::allow_for(&core.ssh_state, &ask, Instant::now() + w).await;
                        }
                        let _ = ask.reply.send(approve);
                        emit(json!({"ev":"resolved","id":id,"outcome": if approve {"approved"} else {"denied"}}));
                        continue;
                    }
                    let Some((p, info)) = core.pending.remove(&id) else { continue };
                    if !approve || core.session.is_none() {
                        let _ = p.reply.send(deny_reply());
                        emit(json!({"ev":"resolved","id":id,"outcome":"denied"}));
                        continue;
                    }
                    if let Some(w) = window {
                        core.approvals.insert((p.identity, p.item_id.clone()), Instant::now() + w);
                    }
                    core.release(id, info, p.reply, false);
                }
            },

            Some(done) = done_rx.recv() => match done {
                Done::Unlocked(s, keys) => {
                    emit(json!({"ev":"log","msg":format!("ssh agent: {} keys", keys.len())}));
                    core.ssh_state.lock().await.keys = keys;
                    core.session = Some(s);
                    emit(json!({"ev":"status","state":"unlocked"}));
                }
                Done::UnlockFailed(why) => emit(json!({"ev":"status","state":"locked","detail":why})),
                Done::Looked { id, identity, query_key, kind, reply, result } => {
                    let search_label = query_key.clone();
                    let info = match result {
                        Lookup::Found(i) => i,
                        Lookup::Locked => {
                            let _ = reply.send(deny_reply());
                            emit(json!({"ev":"resolved","id":id,"outcome":"locked","query":search_label}));
                            core.lock_all("vault locked").await;
                            continue;
                        }
                        Lookup::NotFound(why) => {
                            let _ = reply.send(deny_reply());
                            emit(json!({"ev":"resolved","id":id,"outcome":"not_found","query":search_label,"detail":why}));
                            continue;
                        }
                    };
                    if core.session.is_none() {
                        let _ = reply.send(deny_reply());
                        emit(json!({"ev":"resolved","id":id,"outcome":"locked","query":search_label}));
                        continue;
                    }
                    if core.approvals.get(&(identity, info.id.clone())).is_some_and(|t| *t > Instant::now()) {
                        core.release(id, info, reply, true);
                        continue;
                    }
                    let conns = match FileConnectionCache::load_or_create("user_client") {
                        Ok(c) => c.list().await,
                        Err(_) => Vec::new(),
                    };
                    emit(json!({
                        "ev":"request","id":id,"kind":kind,
                        "name":info.name,"domain":info.domain,"username":info.username,
                        "has_totp":info.has_totp,
                        "device":device_label(&conns, &identity),
                        "timeout":REQUEST_TIMEOUT.as_secs(),
                    }));
                    let p = Pending { identity, item_id: info.id.clone(), reply, deadline: Instant::now() + REQUEST_TIMEOUT };
                    core.pending.insert(id, (p, info));
                }
                Done::Released { id, reply, cred, auto, domain } => {
                    let ok = cred.is_some();
                    let cid = cred.as_ref().and_then(|c| c.credential_id.clone());
                    let _ = reply.send(CredentialRequestReply { approved: ok, credential: cred, credential_id: cid });
                    let outcome = match (ok, auto) { (false, _) => "not_found", (true, true) => "auto", (true, false) => "approved" };
                    emit(json!({"ev":"resolved","id":id,"outcome":outcome,"domain":domain}));
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
                    let Some(session) = core.session.clone() else {
                        let _ = reply.send(deny_reply());
                        emit(json!({"ev":"resolved","id":id,"outcome":"locked","query":search}));
                        continue;
                    };
                    let waiting = core.pending.values().filter(|(p, _)| p.identity == identity).count();
                    if waiting >= MAX_PENDING_PER_DEVICE {
                        let _ = reply.send(deny_reply());
                        emit(json!({"ev":"log","msg":"too many waiting requests from one device; denied"}));
                        continue;
                    }
                    let kind = match query { CredentialQuery::Domain(_) => "domain", CredentialQuery::Id(_) => "id", CredentialQuery::Search(_) => "search" };
                    let (bw, tx) = (core.bw.clone(), done_tx.clone());
                    tokio::spawn(async move {
                        let result = bw_lookup(&bw, &session, &search).await;
                        let _ = tx.send(Done::Looked { id, identity, query_key: search, kind, reply, result }).await;
                    });
                }
            },

            Some(ask) = ssh_rx.recv() => {
                let id = next_id;
                next_id += 1;
                if core.session.is_none() {
                    let _ = ask.reply.send(false);
                    emit(json!({"ev":"resolved","id":id,"outcome":"locked","query":ask.key_name}));
                    continue;
                }
                if ask.auto {
                    // Already allowed: tell the UI it happened (#22), nothing to decide.
                    emit(json!({"ev":"resolved","id":id,"outcome":"auto","domain":ask.host.clone().unwrap_or_else(|| ask.key_name.clone())}));
                    let _ = ask.reply.send(true);
                    continue;
                }
                emit(ssh_agent::ask_json(id, &ask));
                core.ssh_pending.insert(id, (ask, Instant::now() + REQUEST_TIMEOUT));
            },

            Some(n) = notes.recv() => match n {
                UserClientNotification::Reconnecting { attempt } =>
                    emit(json!({"ev":"status","state":"connecting","detail":format!("reconnecting ({attempt})")})),
                UserClientNotification::Reconnected {} =>
                    emit(json!({"ev":"status","state": if core.session.is_some() {"unlocked"} else {"locked"}})),
                UserClientNotification::ClientDisconnected {} =>
                    emit(json!({"ev":"status","state":"offline","detail":"relay disconnected"})),
                UserClientNotification::Error { message, .. } =>
                    emit(json!({"ev":"log","msg":message})),
                _ => {}
            },

            _ = tick.tick() => {
                let now = Instant::now();
                core.approvals.retain(|_, t| *t > now);
                let expired: Vec<u64> = core.pending.iter().filter(|(_, (p, _))| p.deadline <= now).map(|(k, _)| *k).collect();
                for id in expired {
                    if let Some((p, _)) = core.pending.remove(&id) {
                        let _ = p.reply.send(deny_reply());
                        emit(json!({"ev":"resolved","id":id,"outcome":"expired"}));
                    }
                }
                let ssh_gone: Vec<(u64, &'static str)> = core.ssh_pending.iter()
                    .filter_map(|(k, (a, d))| {
                        if a.reply.is_closed() { Some((*k, "cancelled")) }
                        else if *d <= now { Some((*k, "expired")) }
                        else { None }
                    })
                    .collect();
                for (id, outcome) in ssh_gone {
                    if let Some((ask, _)) = core.ssh_pending.remove(&id) {
                        let _ = ask.reply.send(false);
                        emit(json!({"ev":"resolved","id":id,"outcome":outcome}));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::host_of;

    #[test]
    fn host_of_strips_userinfo_only_in_authority() {
        assert_eq!(host_of("https://github.com/login").as_deref(), Some("github.com"));
        assert_eq!(host_of("https://user:pw@Example.com:8443/x").as_deref(), Some("example.com"));
        assert_eq!(host_of("https://a.com/x@b").as_deref(), Some("a.com"));
        assert_eq!(host_of("a.com").as_deref(), Some("a.com"));
        assert_eq!(host_of("https://"), None);
    }
}
