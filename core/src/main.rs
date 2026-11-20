//! aac-core: headless Agent Access listener and SSH agent, driven over stdin/stdout.
//!
//! The parent (NodWarden.app) is the only party that can answer approvals: the
//! only channel is this process's own stdin pipe.
//!
//! Protocol, one JSON object per line.
//!   stdin  {"op":"unlock","session":"..."}
//!          {"op":"decide","id":N,"decision":"approve"|"deny"|"approve_for","minutes":M}
//!          {"op":"lock"}
//!          {"op":"new_token","name":..}                  mint a reusable PSK (needs the relay)
//!          {"op":"end_windows","ids":[..]?}              end these Allow windows, or all
//!          {"op":"agents"}                               list paired devices and tokens
//!          {"op":"remove_device","id":..} | {"op":"remove_token","id":..} | {"op":"revoke_all"}
//!          {"op":"rename_device","id":..,"name":..} | {"op":"rename_token","id":..,"name":..}
//!   stdout {"ev":"status","state":"locked"|"unlocked"|"connecting"|"listening"|"offline","detail":..}
//!            locked/unlocked: the vault. connecting/listening: the relay, which does not change
//!            the vault state. offline: fatal, the process exits.
//!          {"ev":"token","token":..}                      reusable PSK, once, when minted
//!          {"ev":"windows","items":[{"id","kind","title","sub","secs","total"}]}   open Allow windows (#5)
//!          {"ev":"agents","paired":[{"id","name","paired","seen"}],"tokens":[{"id","name","created"}]}
//!          {"ev":"keys","count":N,"problem":code?}        SSH keys loaded, or why none could be
//!          {"ev":"sync","ok":bool,"reason":code?}         vault sync result; codes: offline, login,
//!                                                         timeout, failed (the panel words them)
//!   stdin  {"op":"refresh"}                               sync now and reload the SSH keys
//!          {"op":"config","offline_ok":bool}              false: while the last sync failed,
//!                                                         refuse SSH and secrets ("offline")
//!          {"ev":"syncing"}                               a sync started (Retry, or the
//!                                                         automatic retry while offline)
//!          {"ev":"request","id":N,"name":..,"domain":..,"username":..,"device":..,"kind":..,"has_totp":..}
//!          {"ev":"ssh_request","id":N,...}                see ssh_agent::ask_json
//!          {"ev":"resolved","id":N,"outcome":"approved"|"denied"|"auto"|"expired"|"not_found"|"locked"|"cancelled"|"offline",
//!           "about":{"kind","title","sub"}?}   about: for requests that never showed a card
//!           (auto, locked, no match), so the history can name them. Never a secret.
//!          {"ev":"notice","code":..}                      something the user should know; the
//!                                                         panel words each code
//! Diagnostics go to stderr (the log file), never to the panel as raw text.
//! Vault secrets never go to stdout. The vault session never goes into any child's argv or env.

mod bw;
mod ssh_agent;
#[allow(dead_code)] // copied unmodified from upstream; not every helper is used here
mod storage;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ap_client::{
    ConnectionStore, CredentialData, CredentialQuery, CredentialRequestReply, DefaultProxyClient,
    FingerprintVerificationReply, IdentityFingerprint, ProxyClient, PskStore, UserClient,
    UserClientNotification, UserClientRequest,
};
use ap_proxy_client::IncomingMessage;
use ap_proxy_protocol::IdentityKeyPair;
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
/// Retrying the sync while the vault server can't be reached: first wait, and the most.
const SYNC_RETRY_FIRST: Duration = Duration::from_secs(30);
const SYNC_RETRY_MAX: Duration = Duration::from_secs(300);
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
    /// Mint a new reusable pairing token and show it once (#27). Needs the relay. An optional
    /// name labels the device that pairs with it (round-3 #21).
    NewToken { name: Option<String> },
    /// End these Allow windows, or every one (#5).
    EndWindows { ids: Option<Vec<String>> },
    /// List paired devices and pairing tokens (#3 on GitHub).
    Agents,
    /// Forget a paired device, and the token with its name. Restarts the relay client (#3).
    RemoveDevice { id: String },
    RemoveToken { id: String },
    /// Forget every paired device and token (#3).
    RevokeAll,
    /// Settings the core enforces. `offline_ok` false: refuse while working from a stale copy.
    Config { offline_ok: bool },
    /// Sync the vault and reload the SSH keys (the panel's Retry).
    Refresh,
    /// Rename a device (and the token it pairs with) or a token. Empty means unnamed.
    RenameDevice { id: String, name: String },
    RenameToken { id: String, name: String },
}

impl Cmd {
    /// Commands that edit the pairing files, which needs a fresh relay client (#3).
    fn edits_pairings(&self) -> bool {
        matches!(self, Cmd::RemoveDevice { .. } | Cmd::RemoveToken { .. } | Cmd::RevokeAll
            | Cmd::RenameDevice { .. } | Cmd::RenameToken { .. })
    }
}

/// A name from the user: trimmed, printable, at most 40 characters; empty means none.
fn clean_name(n: &str) -> Option<String> {
    let n: String = n.trim().chars().filter(|c| !c.is_control()).take(40).collect();
    (!n.is_empty()).then_some(n)
}

/// A credential request waiting for the user. Nothing secret is kept (#1): the lookup
/// kept only metadata, and the password is read again after approval.
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

/// A line for the log file (aac-core's stderr). Never shown in the panel as is.
fn log(level: &str, msg: impl Into<String>) {
    eprintln!("nodwarden {level}: {}", msg.into());
}

/// Tells the panel something happened; it shows its own wording for `code`.
fn notice(code: &str) {
    emit(json!({"ev":"notice","code":code}));
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

/// Reads an item's metadata. `bw` prints the whole item, so the password does pass through
/// this process: it is parsed into a Zeroizing field and dropped here, with the wiped output.
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
    let host = match hostport.strip_prefix('[') {
        // IPv6 literal: the colons inside the brackets are not the port separator.
        Some(v6) => v6.split(']').next()?,
        None => hostport.split(':').next()?,
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

fn device_label(conns: &[ap_client::ConnectionInfo], id: &IdentityFingerprint) -> String {
    conns.iter().find(|c| &c.fingerprint == id).and_then(|c| c.name.clone()).unwrap_or_else(|| short_id(id))
}

fn short_id(id: &IdentityFingerprint) -> String {
    hex::encode(id.0).chars().take(12).collect()
}

/// A secret request, for the history: item (or what was asked for), username, device.
fn secret_about(title: &str, username: Option<&str>, device: &str) -> Value {
    let sub = username.map_or_else(|| format!("→ {device}"), |u| format!("{u} · → {device}"));
    json!({"kind": "secret", "title": title, "sub": sub})
}

/// When each pairing token was last used, and by which device: ~/.nodwarden/token-usage.json.
/// Agent Access keeps neither, so NodWarden records them from the handshakes it sees (#3).
/// psk_id -> {"last": unix secs, "device": identity hex}. Holds no secret.
fn usage_path() -> Option<std::path::PathBuf> {
    dirs::home_dir().map(|h| h.join(".nodwarden/token-usage.json"))
}

fn read_usage() -> serde_json::Map<String, Value> {
    usage_path()
        .and_then(|p| std::fs::read(p).ok())
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default()
}

fn write_usage(m: &serde_json::Map<String, Value>) {
    use std::os::unix::fs::OpenOptionsExt;
    let Some(p) = usage_path() else { return };
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let tmp = p.with_extension("tmp");
    let ok = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)
        .and_then(|mut f| std::io::Write::write_all(&mut f, Value::Object(m.clone()).to_string().as_bytes()));
    if ok.is_ok() {
        let _ = std::fs::rename(&tmp, &p);
    }
}

/// The token a handshake names, if this relay message is one. Only the id: the message
/// carries no secret, and it is passed on unchanged.
fn handshake_token(payload: &[u8]) -> Option<String> {
    let v: Value = serde_json::from_slice(payload).ok()?;
    (v.get("type")?.as_str()? == "handshake-init").then_some(())?;
    v.get("psk_id")?.as_str().filter(|id| id.len() <= 128).map(str::to_owned)
}

fn record_use(psk_id: String, device: &IdentityFingerprint) {
    let mut m = read_usage();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    m.insert(psk_id, json!({"last": now, "device": hex::encode(device.0)}));
    write_usage(&m);
}

async fn load_keys_logged(bw: &Bw, session: &SecretString) -> Result<Vec<ssh_agent::Key>, &'static str> {
    match ssh_agent::load_keys(bw, session).await {
        Ok(k) => {
            log("info", format!("ssh agent: {} keys", k.len()));
            Ok(k)
        }
        Err((code, e)) => {
            log("info", format!("ssh agent: {e}"));
            Err(code)
        }
    }
}

/// Syncs the vault, then reads the SSH keys again: from the new data, or from the copy on this
/// Mac when the server can't be reached. Both results go to the panel (#30).
async fn sync_and_reload(bw: &Bw, session: &SecretString, epoch: u64, tx: &mpsc::Sender<Done>) {
    let sync = match tokio::time::timeout(Duration::from_secs(10), bw.run(Some(session), &["sync"])).await {
        Ok(Ok(o)) if o.ok => None,
        Ok(Ok(o)) => Some(bw::reason(&o.stderr)),
        Ok(Err(e)) if !e.contains("timed out") => Some("failed"),
        _ => Some("timeout"),
    };
    if let Some(r) = sync {
        log("info", format!("bw sync failed ({r}); using the copy on this Mac"));
    }
    let keys = load_keys_logged(bw, session).await;
    let _ = tx.send(Done::Synced { epoch, sync, keys }).await;
}

/// A credential window's id, stable while it is open.
fn approval_id(k: &(IdentityFingerprint, String)) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    k.hash(&mut h);
    format!("c{:016x}", h.finish())
}

/// Paired devices and pairing tokens, as stored on disk. Never the PSK itself.
async fn emit_agents() {
    let paired: Vec<Value> = match FileConnectionCache::load_or_create("user_client") {
        Ok(c) => c.list().await.iter().map(|c| json!({
            "id": hex::encode(c.fingerprint.0), "name": c.name,
            "paired": c.cached_at, "seen": c.last_connected_at,
        })).collect(),
        Err(_) => Vec::new(),
    };
    let usage = read_usage();
    let tokens: Vec<Value> = match FilePskStore::load_or_create("user_client") {
        Ok(p) => PskStore::list(&p).await.iter().map(|p| {
            let u = usage.get(&p.psk_id);
            json!({
                "id": p.psk_id, "name": p.name, "created": p.created_at,
                "last_used": u.and_then(|u| u.get("last")), "device": u.and_then(|u| u.get("device")),
            })
        }).collect(),
        Err(_) => Vec::new(),
    };
    emit(json!({"ev":"agents","paired":paired,"tokens":tokens}));
}

/// What a remove/revoke command keeps: (devices to keep, token ids to drop).
///
/// Removing a device also drops its token: a reusable token lets the device pair again. Its
/// token is the one recorded as used by it, or one with the same name.
fn plan_removal(cmd: &Cmd, conns: Vec<ap_client::ConnectionInfo>, tokens: &[ap_client::PskEntry],
                usage: &serde_json::Map<String, Value>) -> (Vec<ap_client::ConnectionInfo>, Vec<String>)
{
    let ids = |f: &dyn Fn(&ap_client::PskEntry) -> bool| tokens.iter().filter(|t| f(t)).map(|t| t.psk_id.clone()).collect();
    match cmd {
        Cmd::RevokeAll => (Vec::new(), ids(&|_| true)),
        Cmd::RemoveToken { id } => (conns, ids(&|t| t.psk_id == *id)),
        Cmd::RemoveDevice { id } => {
            let (gone, keep): (Vec<_>, Vec<_>) = conns.into_iter().partition(|c| hex::encode(c.fingerprint.0) == *id);
            let name = gone.first().and_then(|c| c.name.clone());
            let used_by = |t: &ap_client::PskEntry| usage.get(&t.psk_id).and_then(|u| u.get("device")).and_then(Value::as_str) == Some(id.as_str());
            (keep, ids(&|t| (name.is_some() && t.name == name) || used_by(t)))
        }
        _ => (conns, Vec::new()),
    }
}

/// Edits the pairing files for a remove/revoke command. Run only while no relay client is
/// alive: it keeps its own copy of both files and would write it back (#3).
async fn edit_pairings(cmd: &Cmd) -> Result<(), String> {
    let e = |e: ap_client::ClientError| e.to_string();
    let mut conns = FileConnectionCache::load_or_create("user_client").map_err(e)?;
    let mut psks = FilePskStore::load_or_create("user_client").map_err(e)?;
    let mut usage = read_usage();
    let tokens = PskStore::list(&psks).await;
    match cmd {
        Cmd::RenameToken { id, name } => {
            if let Some(mut t) = tokens.into_iter().find(|t| t.psk_id == *id) {
                t.name = clean_name(name);
                psks.save(t).await.map_err(e)?;
            }
            return Ok(());
        }
        Cmd::RenameDevice { id, name } => {
            let all = conns.list().await;
            let Some(mut c) = all.into_iter().find(|c| hex::encode(c.fingerprint.0) == *id) else { return Ok(()) };
            // Its token goes along, so the next pairing from it gets the same name.
            let ids: Vec<String> = plan_removal(&Cmd::RemoveDevice { id: id.clone() }, vec![c.clone()], &tokens, &usage).1;
            let old = c.name.clone();
            c.name = clean_name(name);
            for mut t in tokens.into_iter().filter(|t| ids.contains(&t.psk_id) && t.name == old) {
                t.name = c.name.clone();
                psks.save(t).await.map_err(e)?;
            }
            conns.save(c).await.map_err(e)?;
            return Ok(());
        }
        _ => {}
    }
    let (keep, drop) = plan_removal(cmd, conns.list().await, &tokens, &usage);
    for id in drop {
        psks.remove(&id).await.map_err(e)?;
        usage.remove(&id);
    }
    write_usage(&usage);
    // The cache has no remove: clear it and put the others back.
    conns.clear().await.map_err(e)?;
    for c in keep {
        conns.save(c).await.map_err(e)?;
    }
    tighten_access_protocol_perms();
    Ok(())
}

/// The relay transport, with a switch to retire it. A retired one never connects again, so a
/// replaced client can't come back with the pairings it had in memory, and dropping it closes
/// the websocket instead of leaving it to time out (#3).
struct Relay {
    inner: DefaultProxyClient,
    retired: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl ProxyClient for Relay {
    async fn connect(&mut self, id: IdentityKeyPair) -> Result<mpsc::UnboundedReceiver<IncomingMessage>, ap_client::ClientError> {
        if self.retired.load(Ordering::SeqCst) {
            return Err(ap_client::ClientError::ConnectionFailed("relay client replaced".into()));
        }
        // Pass every message on unchanged; note which token each handshake uses (#3).
        let mut from_relay = self.inner.connect(id).await?;
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(m) = from_relay.recv().await {
                if let IncomingMessage::Send { source, payload, .. } = &m
                    && let Some(psk_id) = handshake_token(payload)
                {
                    let source = *source;
                    let _ = tokio::task::spawn_blocking(move || record_use(psk_id, &source)).await;
                }
                if tx.send(m).is_err() {
                    break;
                }
            }
        });
        Ok(rx)
    }
    async fn request_rendezvous(&self) -> Result<(), ap_client::ClientError> {
        self.inner.request_rendezvous().await
    }
    async fn request_identity(&self, code: ap_client::RendezvousCode) -> Result<(), ap_client::ClientError> {
        self.inner.request_identity(code).await
    }
    async fn send_to(&self, to: IdentityFingerprint, data: Vec<u8>) -> Result<(), ap_client::ClientError> {
        self.inner.send_to(to, data).await
    }
    async fn disconnect(&mut self) -> Result<(), ap_client::ClientError> {
        self.inner.disconnect().await
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        let mut c = std::mem::replace(&mut self.inner, DefaultProxyClient::from_url(String::new()));
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                let _ = c.disconnect().await;
            });
        }
    }
}

/// Makes the identity key, the other pairing files and their directory private (#26: upstream
/// writes them 0644). Only files: 0600 on a directory would make it unusable.
fn tighten_perms(dir: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            if e.file_type().is_ok_and(|t| t.is_file()) {
                let _ = std::fs::set_permissions(e.path(), std::fs::Permissions::from_mode(0o600));
            }
        }
    }
}

fn tighten_access_protocol_perms() {
    if let Some(home) = dirs::home_dir() {
        tighten_perms(&home.join(".access-protocol"));
    }
}

#[tokio::main]
async fn main() {
    // `aac-core --tools`: the trusted paths of node, bw and bwbio, for the app (#23).
    if std::env::args().any(|a| a == "--tools") {
        println!("{}", bw::tools_report());
        return;
    }
    // Whatever this process and `bw` create (pairing files, the agent socket) is private from
    // the moment it exists, not only after a chmod.
    unsafe { libc::umask(0o077) };

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

/// Results of work that runs off the main loop (#13). `epoch` is `Core::epoch` when the work started.
enum Done {
    /// `keys`: the SSH keys, or a reason code when none could be read.
    Unlocked { epoch: u64, session: SecretString, keys: Result<Vec<ssh_agent::Key>, &'static str> },
    /// A notice code.
    UnlockFailed(&'static str),
    /// A vault sync finished (`sync`: None, or a reason code) and the keys were read again (#12).
    Synced { epoch: u64, sync: Option<&'static str>, keys: Result<Vec<ssh_agent::Key>, &'static str> },
    Looked { epoch: u64, id: u64, identity: IdentityFingerprint, query_key: String, kind: &'static str,
             reply: oneshot::Sender<CredentialRequestReply>, result: Lookup },
    Released { epoch: u64, id: u64, reply: oneshot::Sender<CredentialRequestReply>, cred: Option<CredentialData>,
               auto: bool, domain: Option<String>, about: Value },
}

struct Core {
    bw: Bw,
    session: Option<SecretString>,
    /// Counts locks. An unlock or a release that was started before a lock carries the old
    /// value and is thrown away when it finishes, so a lock always wins over work in flight.
    epoch: u64,
    pending: HashMap<u64, (Pending, ItemInfo)>,
    /// Lookups still running, per device. Counted with `pending` against
    /// MAX_PENDING_PER_DEVICE, or a burst would get past the limit before anything is waiting.
    looking: HashMap<IdentityFingerprint, usize>,
    /// (device, item id) -> (allowed until, window length in seconds, item name). Keyed on the
    /// item, not the query (#22).
    approvals: HashMap<(IdentityFingerprint, String), (Instant, u64, String)>,
    ssh_state: ssh_agent::Shared,
    ssh_pending: HashMap<u64, (ssh_agent::SignAsk, Instant)>,
    done_tx: mpsc::Sender<Done>,
    /// Asks the locker task for one more `bw lock`.
    locker: mpsc::Sender<()>,
    next_id: u64,
    labels: Option<Vec<ap_client::ConnectionInfo>>,
    labels_mtime: Option<std::time::SystemTime>,
    /// A credential window expired on the tick; report the list again (#5).
    windows_dirty: bool,
    /// While the vault server can't be reached: when to try the sync again, and the wait
    /// after that try. None when the last sync worked, or while locked.
    retry_sync: Option<(Instant, Duration)>,
    /// A sync is running; never start a second.
    syncing: bool,
    /// The last sync failed, so the keys and items come from the copy on this Mac.
    stale: bool,
    /// Setting: work from that copy. When false, requests are refused while `stale`.
    offline_ok: bool,
}


/// Runs `bw lock` one at a time. A request that arrives while one is running is kept, so a
/// lock always runs after the last request for one; a burst (sleep and screen lock arrive
/// together) collapses into at most two runs.
fn spawn_locker(bw: Bw) -> mpsc::Sender<()> {
    let (tx, mut rx) = mpsc::channel::<()>(1);
    tokio::spawn(async move {
        while rx.recv().await.is_some() {
            if !bw.lock().await {
                log("error", "bw lock failed: a copied vault session may still work");
                notice("lock_failed");
            }
        }
    });
    tx
}

impl Core {
    fn new(bw: Bw, done_tx: mpsc::Sender<Done>, locker: mpsc::Sender<()>) -> Self {
        Self {
            bw,
            session: None,
            epoch: 0,
            pending: HashMap::new(),
            looking: HashMap::new(),
            approvals: HashMap::new(),
            ssh_state: Default::default(),
            ssh_pending: HashMap::new(),
            done_tx,
            locker,
            labels: None,
            labels_mtime: None,
            windows_dirty: false,
            retry_sync: None,
            syncing: false,
            stale: false,
            offline_ok: true,
            // Base request ids on the clock so ids from a restarted core never collide (#30).
            next_id: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(1, |d| d.as_millis() as u64 * 1000),
        }
    }

    fn new_id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }

    /// The one way to lock (#6): forget the session, keys and approvals, deny everything waiting,
    /// and lock bw so a session copied earlier stops working.
    async fn lock_all(&mut self, why: Option<&str>) {
        self.epoch += 1;
        self.session = None;
        self.retry_sync = None;
        self.syncing = false;
        self.stale = false;
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
        let _ = self.locker.try_send(());
        emit(json!({"ev":"windows","items":[]}));
        emit(json!({"ev":"status","state":"locked"}));
        if let Some(code) = why {
            notice(code);
        }
    }

    /// Labels for paired devices, read once and reread only when the file changes (#13).
    async fn device_labels(&mut self) -> &[ap_client::ConnectionInfo] {
        let mtime = dirs::home_dir()
            .and_then(|h| std::fs::metadata(h.join(".access-protocol/connection_cache_user_client.json")).ok())
            .and_then(|m| m.modified().ok());
        if mtime != self.labels_mtime || self.labels.is_none() {
            self.labels = match FileConnectionCache::load_or_create("user_client") {
                Ok(c) => Some(c.list().await),
                Err(_) => None,
            };
            self.labels_mtime = mtime;
        }
        self.labels.as_deref().unwrap_or(&[])
    }

    /// Tells the UI which Allow windows are open (#5). Credential windows are per item.
    async fn report_windows(&mut self) {
        let now = Instant::now();
        let labels = self.device_labels().await.to_vec();
        let mut items: Vec<Value> = self
            .approvals
            .iter()
            .filter(|(_, (t, _, _))| *t > now)
            .map(|(k, (t, total, name))| json!({
                "id": approval_id(k), "kind": "secret", "title": name,
                "sub": format!("secret · {}", device_label(&labels, &k.0)),
                "secs": t.saturating_duration_since(now).as_secs(), "total": total,
            }))
            .collect();
        items.extend(self.ssh_state.lock().await.windows());
        emit(json!({"ev":"windows","items":items}));
    }

    /// Denies credential requests still waiting, and ends credential windows: they belong to
    /// relay connections that are being replaced (#3).
    fn drop_agent_requests(&mut self) {
        self.approvals.clear();
        for (id, (p, _)) in self.pending.drain() {
            let _ = p.reply.send(deny_reply());
            emit(json!({"ev":"resolved","id":id,"outcome":"cancelled"}));
        }
    }

    /// True while anything can expire, so the tick can stop otherwise (#13).
    fn has_deadlines(&self) -> bool {
        !self.approvals.is_empty() || !self.pending.is_empty() || !self.ssh_pending.is_empty()
            || self.retry_sync.is_some()
    }

    /// The setting says not to work from a stale copy, and the copy is stale.
    fn offline_blocked(&self) -> bool {
        self.stale && !self.offline_ok
    }

    /// Syncs the vault and reloads the SSH keys, off the loop. One at a time; nothing while
    /// locked. Keeps the retry wait, so a failure after this backs off further (#30).
    fn start_sync(&mut self) {
        let Some(session) = self.session.clone() else { return };
        if self.syncing {
            return;
        }
        self.syncing = true;
        emit(json!({"ev":"syncing"}));
        let (bw, tx, epoch) = (self.bw.clone(), self.done_tx.clone(), self.epoch);
        tokio::spawn(async move { sync_and_reload(&bw, &session, epoch, &tx).await });
    }

    /// Fetches the secret and replies, off the main loop.
    fn release(&self, id: u64, info: ItemInfo, reply: oneshot::Sender<CredentialRequestReply>, auto: bool, about: Value) {
        let (bw, session, tx, epoch) = (self.bw.clone(), self.session.clone(), self.done_tx.clone(), self.epoch);
        tokio::spawn(async move {
            let cred = match session {
                Some(s) => bw_secret(&bw, &s, &info).await,
                None => None,
            };
            let _ = tx.send(Done::Released { epoch, id, reply, cred, auto, domain: info.domain, about }).await;
        });
    }

    async fn on_cmd(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Unlock { session } => {
                let (bw, tx, epoch) = (self.bw.clone(), self.done_tx.clone(), self.epoch);
                let session = SecretString::from(session.as_str().to_owned());
                tokio::spawn(async move {
                    // One bw call: reading the items also proves the session (a bad one answers
                    // "Vault is locked"). A separate `bw status` cost another second or more.
                    let keys = load_keys_logged(&bw, &session).await;
                    if matches!(keys, Err("locked")) {
                        let _ = tx.send(Done::UnlockFailed("session_rejected")).await;
                        return;
                    }
                    // Unlocked even when the keys can't be read, so credential requests still work;
                    // the panel says why there are no keys. Read from the copy on this Mac first,
                    // so unlock doesn't wait on the network (#12).
                    let _ = tx.send(Done::Unlocked { epoch, session: session.clone(), keys }).await;
                });
            }
            Cmd::Refresh => self.start_sync(),
            Cmd::Config { offline_ok } => self.offline_ok = offline_ok,
            Cmd::Lock => self.lock_all(None).await,
            // Handled in run(): it needs the relay client.
            Cmd::NewToken { .. } => {}
            Cmd::EndWindows { ids } => {
                match &ids {
                    Some(ids) => self.approvals.retain(|k, _| !ids.contains(&approval_id(k))),
                    None => self.approvals.clear(),
                }
                self.ssh_state.lock().await.end_windows(ids.as_deref());
                self.report_windows().await;
            }
            Cmd::Agents => emit_agents().await,
            Cmd::Decide { id, decision, minutes } => {
                let approve = matches!(decision.as_str(), "approve" | "approve_for");
                let window = (decision == "approve_for")
                    .then(|| Duration::from_secs(u64::from(minutes.unwrap_or(10).clamp(1, MAX_ALLOW_MINUTES)) * 60));
                if let Some((ask, _)) = self.ssh_pending.remove(&id) {
                    if let Some(w) = window {
                        ssh_agent::allow_for(&self.ssh_state, &ask, Instant::now() + w).await;
                        self.report_windows().await;
                    }
                    let _ = ask.reply.send(approve);
                    emit(json!({"ev":"resolved","id":id,"outcome": if approve {"approved"} else {"denied"}}));
                    return;
                }
                let Some((p, info)) = self.pending.remove(&id) else { return };
                if !approve || self.session.is_none() {
                    let _ = p.reply.send(deny_reply());
                    emit(json!({"ev":"resolved","id":id,"outcome":"denied"}));
                    return;
                }
                if let Some(w) = window {
                    self.approvals.insert((p.identity, p.item_id.clone()), (Instant::now() + w, w.as_secs(), info.name.clone()));
                    self.report_windows().await;
                }
                self.release(id, info, p.reply, false, Value::Null);
            }
            // Handled in run(): they restart the relay client.
            _ => {}
        }
    }

    async fn on_done(&mut self, done: Done) {
        match done {
            Done::Unlocked { epoch, .. } if epoch != self.epoch => {
                // Locked (button, sleep, screen lock) while the unlock was still running.
                log("info", "unlock finished after a lock; ignored");
            }
            Done::Unlocked { session, keys, .. } => {
                let keys = keys.map_err(|c| emit(json!({"ev":"keys","count":0,"problem":c}))).unwrap_or_default();
                if !keys.is_empty() {
                    emit(json!({"ev":"keys","count":keys.len()}));
                }
                self.ssh_state.lock().await.keys = keys;
                self.session = Some(session);
                emit(json!({"ev":"status","state":"unlocked"}));
                self.start_sync();
            }
            Done::Synced { epoch, sync, keys } => {
                if epoch != self.epoch || self.session.is_none() {
                    return;
                }
                self.syncing = false;
                self.stale = sync.is_some();
                // Offline: try again by itself, 30 s doubling to 5 min. A login problem needs
                // you, so no retry for it.
                self.retry_sync = match sync {
                    Some("login") | None => None,
                    Some(_) => {
                        let wait = self.retry_sync.map_or(SYNC_RETRY_FIRST, |(_, w)| (w * 2).min(SYNC_RETRY_MAX));
                        Some((Instant::now() + wait, wait))
                    }
                };
                emit(json!({"ev":"sync","ok":sync.is_none(),"reason":sync}));
                let mut st = self.ssh_state.lock().await;
                match keys {
                    Ok(k) => {
                        emit(json!({"ev":"keys","count":k.len()}));
                        st.keys = k;
                    }
                    // Keep keys already loaded; report only when there are none.
                    Err(c) if st.keys.is_empty() => emit(json!({"ev":"keys","count":0,"problem":c})),
                    Err(_) => {}
                }
            }
            Done::UnlockFailed(code) => {
                if self.session.is_none() {
                    emit(json!({"ev":"status","state":"locked"}));
                    notice(code);
                }
            }
            Done::Looked { epoch, id, identity, query_key, kind, reply, result } => {
                if let std::collections::hash_map::Entry::Occupied(mut n) = self.looking.entry(identity) {
                    *n.get_mut() -= 1;
                    if *n.get() == 0 {
                        n.remove();
                    }
                }
                // Started before a lock: deny it, and don't let a stale "locked" lock again (#19).
                let device = device_label(self.device_labels().await, &identity);
                let asked = secret_about(&query_key, None, &device);
                if epoch != self.epoch {
                    let _ = reply.send(deny_reply());
                    emit(json!({"ev":"resolved","id":id,"outcome":"locked","query":query_key,"about":asked}));
                    return;
                }
                let info = match result {
                    Lookup::Found(i) => i,
                    Lookup::Locked => {
                        let _ = reply.send(deny_reply());
                        emit(json!({"ev":"resolved","id":id,"outcome":"locked","query":query_key,"about":asked}));
                        self.lock_all(Some("bw_locked")).await;
                        return;
                    }
                    Lookup::NotFound(why) => {
                        let _ = reply.send(deny_reply());
                        emit(json!({"ev":"resolved","id":id,"outcome":"not_found","query":query_key,"detail":why,"about":asked}));
                        return;
                    }
                };
                if self.session.is_none() {
                    let _ = reply.send(deny_reply());
                    emit(json!({"ev":"resolved","id":id,"outcome":"locked","query":query_key,"about":asked}));
                    return;
                }
                if self.approvals.get(&(identity, info.id.clone())).is_some_and(|(t, _, _)| *t > Instant::now()) {
                    let about = secret_about(&info.name, info.username.as_deref(), &device);
                    self.release(id, info, reply, true, about);
                    return;
                }
                emit(json!({
                    "ev":"request","id":id,"kind":kind,
                    "name":info.name,"domain":info.domain,"username":info.username,
                    "has_totp":info.has_totp,
                    "device":device,
                    "timeout":REQUEST_TIMEOUT.as_secs(),
                }));
                let p = Pending { identity, item_id: info.id.clone(), reply, deadline: Instant::now() + REQUEST_TIMEOUT };
                self.pending.insert(id, (p, info));
            }
            Done::Released { epoch, id, reply, domain, about, .. } if epoch != self.epoch => {
                // Locked while the secret was being read: it is dropped (and wiped), not sent.
                let _ = reply.send(deny_reply());
                emit(json!({"ev":"resolved","id":id,"outcome":"locked","domain":domain,"about":about}));
            }
            Done::Released { id, reply, cred, auto, domain, about, .. } => {
                let ok = cred.is_some();
                let cid = cred.as_ref().and_then(|c| c.credential_id.clone());
                let _ = reply.send(CredentialRequestReply { approved: ok, credential: cred, credential_id: cid });
                let outcome = match (ok, auto) {
                    (false, _) => "not_found",
                    (true, true) => "auto",
                    (true, false) => "approved",
                };
                emit(json!({"ev":"resolved","id":id,"outcome":outcome,"domain":domain,"about":about}));
            }
        }
    }

    fn on_credential_request(
        &mut self,
        query: CredentialQuery,
        identity: IdentityFingerprint,
        reply: oneshot::Sender<CredentialRequestReply>,
    ) {
        let id = self.new_id();
        let search = query.search_string().to_string();
        let Some(session) = self.session.clone() else {
            let _ = reply.send(deny_reply());
            let device = self.labels.as_deref().map_or_else(|| short_id(&identity), |l| device_label(l, &identity));
            emit(json!({"ev":"resolved","id":id,"outcome":"locked","query":search,"about":secret_about(&search, None, &device)}));
            return;
        };
        if self.offline_blocked() {
            let _ = reply.send(deny_reply());
            let device = self.labels.as_deref().map_or_else(|| short_id(&identity), |l| device_label(l, &identity));
            emit(json!({"ev":"resolved","id":id,"outcome":"offline","query":search,"about":secret_about(&search, None, &device)}));
            return;
        }
        let waiting = self.pending.values().filter(|(p, _)| p.identity == identity).count()
            + self.looking.get(&identity).copied().unwrap_or(0);
        if waiting >= MAX_PENDING_PER_DEVICE {
            let _ = reply.send(deny_reply());
            log("error", "too many waiting requests from one device; denied");
            notice("flood");
            return;
        }
        *self.looking.entry(identity).or_default() += 1;
        let kind = match query {
            CredentialQuery::Domain(_) => "domain",
            CredentialQuery::Id(_) => "id",
            CredentialQuery::Search(_) => "search",
        };
        let (bw, tx, epoch) = (self.bw.clone(), self.done_tx.clone(), self.epoch);
        tokio::spawn(async move {
            let result = bw_lookup(&bw, &session, &search).await;
            let _ = tx.send(Done::Looked { epoch, id, identity, query_key: search, kind, reply, result }).await;
        });
    }

    fn on_ssh_ask(&mut self, ask: ssh_agent::SignAsk) {
        let id = self.new_id();
        if self.session.is_none() {
            let about = ssh_agent::about(&ask);
            let _ = ask.reply.send(false);
            emit(json!({"ev":"resolved","id":id,"outcome":"locked","query":ask.key_name,"about":about}));
            return;
        }
        if self.offline_blocked() {
            let about = ssh_agent::about(&ask);
            let _ = ask.reply.send(false);
            emit(json!({"ev":"resolved","id":id,"outcome":"offline","query":ask.key_name,"about":about}));
            return;
        }
        if ask.auto {
            // Already allowed: tell the UI it happened (#22), nothing to decide.
            emit(json!({"ev":"resolved","id":id,"outcome":"auto","domain":ask.host.clone().unwrap_or_else(|| ask.key_name.clone()),
                        "about":ssh_agent::about(&ask)}));
            let _ = ask.reply.send(true);
            return;
        }
        emit(ssh_agent::ask_json(id, &ask));
        self.ssh_pending.insert(id, (ask, Instant::now() + REQUEST_TIMEOUT));
    }

    fn on_tick(&mut self) {
        let now = Instant::now();
        if self.retry_sync.is_some_and(|(at, _)| at <= now) {
            self.start_sync();
        }
        let before = self.approvals.len();
        self.approvals.retain(|_, (t, _, _)| *t > now);
        if self.approvals.len() != before {
            self.windows_dirty = true;
        }
        let expired: Vec<u64> = self.pending.iter().filter(|(_, (p, _))| p.deadline <= now).map(|(k, _)| *k).collect();
        for id in expired {
            if let Some((p, _)) = self.pending.remove(&id) {
                let _ = p.reply.send(deny_reply());
                emit(json!({"ev":"resolved","id":id,"outcome":"expired"}));
            }
        }
        let ssh_gone: Vec<(u64, &'static str)> = self.ssh_pending.iter()
            .filter_map(|(k, (a, d))| {
                if a.reply.is_closed() { Some((*k, "cancelled")) }
                else if *d <= now { Some((*k, "expired")) }
                else { None }
            })
            .collect();
        for (id, outcome) in ssh_gone {
            if let Some((ask, _)) = self.ssh_pending.remove(&id) {
                let _ = ask.reply.send(false);
                emit(json!({"ev":"resolved","id":id,"outcome":outcome}));
            }
        }
    }
}

async fn run() -> Result<(), String> {
    let bw = Bw::resolve()?;
    log("info", format!("bw: {} {}", bw.node.display(), bw.script.display()));

    let (cmd_tx, mut cmd_rx) = mpsc::channel::<Cmd>(32);
    {
        let bw = bw.clone();
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
                    Err(_) => log("info", "bad command"),
                }
            }
            // Parent went away (quit, crash, force quit): lock bw so a copied session stops
            // working (#8), then exit so no orphan listener holds the vault session.
            let _ = tokio::time::timeout(Duration::from_secs(5), bw.lock()).await;
            std::process::exit(0);
        });
    }

    // The SSH agent and unlock work without the relay (#24): start them first and connect
    // in the background. "locked" right away; relay state is reported on its own.
    let (done_tx, mut done_rx) = mpsc::channel::<Done>(32);
    let (ssh_tx, mut ssh_rx) = mpsc::channel::<ssh_agent::SignAsk>(16);
    let mut core = Core::new(bw.clone(), done_tx, spawn_locker(bw));
    {
        let st = core.ssh_state.clone();
        tokio::spawn(async move {
            if let Err(e) = ssh_agent::serve(st, ssh_tx).await {
                log("error", format!("ssh agent: {e}"));
                notice("agent_failed");
            }
        });
    }
    emit(json!({"ev":"status","state":"locked"}));
    emit(json!({"ev":"status","state":"connecting"}));

    FileIdentityStorage::load_or_generate("user_client").map_err(|e| e.to_string())?;
    FileConnectionCache::load_or_create("user_client").map_err(|e| e.to_string())?;
    let existing = PskStore::list(&FilePskStore::load_or_create("user_client").map_err(|e| e.to_string())?).await;
    tighten_access_protocol_perms();

    // Connect to the relay in the background, retrying with backoff; the agent keeps working.
    let mut retired = Arc::new(AtomicBool::new(false));
    let mut relay_rx = connect_relay(retired.clone());

    let mut client: Option<UserClient> = None;
    let mut notes: Option<mpsc::Receiver<UserClientNotification>> = None;
    let mut requests: Option<mpsc::Receiver<UserClientRequest>> = None;
    let mut minted_first = !existing.is_empty();
    let mut relay_up = false;
    // The tick only runs while something can expire; when idle it parks (#13).
    let mut tick = tokio::time::interval(Duration::from_secs(1));

    // ap-client answers commands from the same task that reconnects, so awaiting it here would
    // stall Lock, sleep lock and timeouts until the relay is back (#1). Mint off the loop.
    let mint = |c: UserClient, name: Option<String>| {
        // Names come from the user, but keep them short and printable anyway.
        let name = name.as_deref().and_then(clean_name);
        tokio::spawn(async move {
            match tokio::time::timeout(Duration::from_secs(10), c.get_psk_token(name, true)).await {
                Ok(Ok(token)) => {
                    emit(json!({"ev":"token","token":token}));
                    tighten_access_protocol_perms();
                    emit_agents().await;
                }
                Ok(Err(e)) => {
                    log("error", format!("new token failed: {e}"));
                    notice("token_failed");
                }
                Err(_) => {
                    log("error", "new token timed out");
                    notice("token_failed");
                }
            }
        });
    };

    loop {
        tokio::select! {
            // Commands first: a Lock is always handled before a waiting request (#1).
            biased;
            Some(cmd) = cmd_rx.recv() => match cmd {
                Cmd::NewToken { name } => match &client {
                    Some(c) if relay_up => mint(c.clone(), name),
                    _ => notice("token_relay"),
                },
                cmd if cmd.edits_pairings() => {
                    // ap-client keeps tokens and devices in memory and has no command to drop one,
                    // so retire this client, edit the files, and connect a new one that reads
                    // them. The vault, the keys and the SSH agent are not touched (#3).
                    retired.store(true, Ordering::SeqCst);
                    client = None;
                    requests = None;
                    relay_up = false;
                    // The old client's loop ends once its handles are gone; its notification
                    // channel closing says so. It must be gone before the files change.
                    if let Some(mut n) = notes.take() {
                        let _ = tokio::time::timeout(Duration::from_secs(1), async { while n.recv().await.is_some() {} }).await;
                    }
                    core.drop_agent_requests();
                    core.report_windows().await;
                    if let Err(e) = edit_pairings(&cmd).await {
                        log("error", format!("could not update pairings: {e}"));
                        notice("pairings_failed");
                    }
                    emit_agents().await;
                    retired = Arc::new(AtomicBool::new(false));
                    relay_rx = connect_relay(retired.clone());
                    emit(json!({"ev":"status","state":"connecting","detail":"reconnecting with the new list"}));
                }
                other => core.on_cmd(other).await,
            },
            Some(done) = done_rx.recv() => core.on_done(done).await,

            Some(r) = relay_rx.recv() => match r {
                Ok(h) => {
                    if !minted_first {
                        // First run: mint the reusable PSK agents pair with, and show it once (#19).
                        mint(h.client.clone(), Some("first agent".into()));
                        minted_first = true;
                    }
                    relay_up = true;
                    client = Some(h.client);
                    notes = Some(h.notifications);
                    requests = Some(h.requests);
                    emit(json!({"ev":"status","state":"listening"}));
                }
                Err(e) => {
                    log("error", format!("pairing files: {e}"));
                    notice("pairings_failed");
                }
            },

            Some(req) = async { requests.as_mut()?.recv().await }, if requests.is_some() => match req {
                UserClientRequest::VerifyFingerprint { reply, .. } => {
                    // Only rendezvous pairing asks this; we only accept PSK pairing.
                    let _ = reply.send(FingerprintVerificationReply { approved: false, name: None });
                    log("error", "rejected rendezvous pairing (PSK only)");
                    notice("rendezvous_refused");
                }
                UserClientRequest::CredentialRequest { query, identity, reply } =>
                    core.on_credential_request(query, identity, reply),
            },

            Some(ask) = ssh_rx.recv() => core.on_ssh_ask(ask),

            Some(n) = async { notes.as_mut()?.recv().await }, if notes.is_some() => match n {
                // The relay going away does not change the vault state: keys stay loaded and the
                // SSH agent keeps answering, so the UI must keep showing the lock state (and Lock).
                // ap-client reconnects by itself, for as long as it takes.
                UserClientNotification::ClientDisconnected {} => {
                    relay_up = false;
                    emit(json!({"ev":"status","state":"connecting","detail":"relay disconnected, reconnecting"}));
                }
                UserClientNotification::Reconnecting { attempt } => {
                    relay_up = false;
                    emit(json!({"ev":"status","state":"connecting","detail":format!("relay unreachable, retry {attempt}")}));
                }
                UserClientNotification::Reconnected {} => {
                    relay_up = true;
                    emit(json!({"ev":"status","state":"listening"}));
                }
                UserClientNotification::Error { message, .. } => log("info", format!("relay: {message}")),
                _ => {}
            },

            _ = tick.tick(), if core.has_deadlines() => {
                core.on_tick();
                if std::mem::take(&mut core.windows_dirty) {
                    core.report_windows().await;
                }
            }
        }
    }
}

/// Connects to the relay in the background, retrying with backoff (2 s doubling to 60 s), and
/// hands over the client once it's up. Reads the pairing files on each attempt. The SSH agent
/// and unlock never wait for this (#24). Gives up once `retired` is set.
fn connect_relay(retired: Arc<AtomicBool>) -> mpsc::Receiver<Result<ap_client::UserClientHandle, String>> {
    let (relay_tx, relay_rx) = mpsc::channel::<Result<ap_client::UserClientHandle, String>>(1);
    tokio::spawn(async move {
        let mut delay = Duration::from_secs(2);
        while !retired.load(Ordering::SeqCst) {
            let (identity, store, psk_store) = match (
                FileIdentityStorage::load_or_generate("user_client"),
                FileConnectionCache::load_or_create("user_client"),
                FilePskStore::load_or_create("user_client"),
            ) {
                (Ok(i), Ok(s), Ok(p)) => (i, s, p),
                _ => {
                    let _ = relay_tx.send(Err("cannot read ~/.access-protocol".into())).await;
                    return;
                }
            };
            let relay = Relay { inner: DefaultProxyClient::from_url(PROXY_URL.to_string()), retired: retired.clone() };
            match UserClient::connect(Box::new(identity), Box::new(store), Box::new(relay), None, Some(Box::new(psk_store))).await {
                Ok(h) => {
                    let _ = relay_tx.send(Ok(h)).await;
                    return;
                }
                Err(e) => {
                    emit(json!({"ev":"status","state":"connecting","detail":format!("relay unreachable: {e}")}));
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_secs(60));
                }
            }
        }
    });
    relay_rx
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A core whose `bw` is `/usr/bin/true`: every bw call ends at once with no output.
    fn test_core() -> (Core, mpsc::Receiver<Done>, mpsc::Receiver<()>) {
        let (done_tx, done_rx) = mpsc::channel(32);
        let (locker, locks) = mpsc::channel(1);
        let bw = Bw { node: "/usr/bin/true".into(), script: "/dev/null".into() };
        (Core::new(bw, done_tx, locker), done_rx, locks)
    }

    fn session() -> SecretString {
        SecretString::from("not-a-real-session".to_owned())
    }

    fn credential() -> CredentialData {
        CredentialData {
            username: Some("octocat".into()),
            password: Some(Zeroizing::new("hunter2".into())),
            totp: None,
            uri: None,
            notes: None,
            credential_id: Some("item-1".into()),
            domain: None,
        }
    }

    #[test]
    fn host_of_strips_userinfo_only_in_authority() {
        assert_eq!(host_of("https://github.com/login").as_deref(), Some("github.com"));
        assert_eq!(host_of("https://user:pw@Example.com:8443/x").as_deref(), Some("example.com"));
        assert_eq!(host_of("https://a.com/x@b").as_deref(), Some("a.com"));
        assert_eq!(host_of("a.com").as_deref(), Some("a.com"));
        assert_eq!(host_of("https://"), None);
        assert_eq!(host_of("https://[::1]:8443/x").as_deref(), Some("::1"));
        assert_eq!(host_of("http://[fe80::1]").as_deref(), Some("fe80::1"));
    }

    #[test]
    fn pairing_files_are_made_private_and_directories_stay_usable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("nw-perms-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("user_client.key"), "seed").unwrap();
        std::fs::write(dir.join("sub/file"), "x").unwrap();
        let chmod = |p: &std::path::Path, m| std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
        chmod(&dir, 0o755);
        chmod(&dir.join("sub"), 0o755);
        chmod(&dir.join("user_client.key"), 0o644);
        tighten_perms(&dir);
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join("user_client.key")), 0o600);
        assert_eq!(mode(&dir.join("sub")), 0o755);
        assert!(std::fs::read(dir.join("sub/file")).is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn unlock_that_finishes_after_a_lock_is_ignored() {
        let (mut core, _done, mut locks) = test_core();
        let started = core.epoch;
        // The screen locks while `bw status` / `bw list items` of the unlock are still running.
        core.on_cmd(Cmd::Lock).await;
        assert!(locks.try_recv().is_ok(), "bw lock was not requested");
        core.on_done(Done::Unlocked { epoch: started, session: session(), keys: Ok(Vec::new()) }).await;
        assert!(core.session.is_none(), "a lock must win over an unlock in flight");

        // An unlock started after the lock is accepted.
        core.on_done(Done::Unlocked { epoch: core.epoch, session: session(), keys: Ok(Vec::new()) }).await;
        assert!(core.session.is_some());
    }

    #[tokio::test]
    async fn secret_read_before_a_lock_is_not_sent_after_it() {
        let (mut core, _done, _locks) = test_core();
        core.session = Some(session());
        let started = core.epoch;
        let (tx, rx) = oneshot::channel();
        core.lock_all(None).await;
        core.on_done(Done::Released { epoch: started, id: 1, reply: tx, cred: Some(credential()), auto: false, domain: None, about: Value::Null }).await;
        let reply = rx.await.unwrap();
        assert!(!reply.approved && reply.credential.is_none());

        // Without a lock in between it goes out.
        let (tx, rx) = oneshot::channel();
        core.on_done(Done::Released { epoch: core.epoch, id: 2, reply: tx, cred: Some(credential()), auto: false, domain: None, about: Value::Null }).await;
        assert!(rx.await.unwrap().approved);
    }

    #[tokio::test]
    async fn a_burst_from_one_device_is_capped_while_lookups_are_still_running() {
        let (mut core, mut done, _locks) = test_core();
        core.session = Some(session());
        let (device, other) = (IdentityFingerprint([1; 32]), IdentityFingerprint([2; 32]));
        let mut replies = Vec::new();
        for _ in 0..MAX_PENDING_PER_DEVICE + 2 {
            let (tx, rx) = oneshot::channel();
            core.on_credential_request(CredentialQuery::Domain("github.com".into()), device, tx);
            replies.push(rx);
        }
        // Nothing has been looked up yet, and the two over the limit are already refused.
        let refused = replies.iter_mut().filter_map(|r| r.try_recv().ok()).filter(|r| !r.approved).count();
        assert_eq!(refused, 2);
        assert_eq!(core.looking.get(&device), Some(&MAX_PENDING_PER_DEVICE));

        // Another device is not affected.
        let (tx, mut rx) = oneshot::channel();
        core.on_credential_request(CredentialQuery::Domain("github.com".into()), other, tx);
        assert!(rx.try_recv().is_err(), "the other device was refused");

        // Each finished lookup frees its slot.
        for _ in 0..MAX_PENDING_PER_DEVICE + 1 {
            let d = done.recv().await.unwrap();
            core.on_done(d).await;
        }
        assert!(core.looking.is_empty() && core.pending.is_empty());
    }

    #[test]
    fn removing_a_device_drops_its_named_token_and_keeps_the_rest() {
        let conn = |b: u8, name: Option<&str>| ap_client::ConnectionInfo {
            fingerprint: IdentityFingerprint([b; 32]), name: name.map(Into::into),
            cached_at: 1, last_connected_at: 2, transport_state: None,
        };
        let token = |id: &str, name: Option<&str>| ap_client::PskEntry {
            psk_id: id.into(), psk: ap_client::Psk::generate(), name: name.map(Into::into), created_at: 1,
        };
        let conns = vec![conn(1, Some("laptop")), conn(2, None), conn(3, Some("ci"))];
        let tokens = [token("t1", Some("laptop")), token("t2", None), token("t3", Some("ci"))];
        let fps = |v: &[ap_client::ConnectionInfo]| v.iter().map(|c| c.fingerprint.0[0]).collect::<Vec<_>>();

        let none = serde_json::Map::new();
        let (keep, drop) = plan_removal(&Cmd::RemoveDevice { id: hex::encode([1u8; 32]) }, conns.clone(), &tokens, &none);
        assert_eq!((fps(&keep), drop), (vec![2, 3], vec!["t1".to_string()]), "named device takes its token");

        let (keep, drop) = plan_removal(&Cmd::RemoveDevice { id: hex::encode([2u8; 32]) }, conns.clone(), &tokens, &none);
        assert_eq!((fps(&keep), drop), (vec![1, 3], vec![]), "unnamed device, no record: no token can be matched");

        let mut usage = serde_json::Map::new();
        usage.insert("t2".into(), json!({"last": 5, "device": hex::encode([2u8; 32])}));
        let (_, drop) = plan_removal(&Cmd::RemoveDevice { id: hex::encode([2u8; 32]) }, conns.clone(), &tokens, &usage);
        assert_eq!(drop, vec!["t2".to_string()], "unnamed device takes the token it was seen using");

        let (keep, drop) = plan_removal(&Cmd::RemoveToken { id: "t2".into() }, conns.clone(), &tokens, &none);
        assert_eq!((fps(&keep), drop), (vec![1, 2, 3], vec!["t2".to_string()]), "a token alone keeps devices");

        let (keep, drop) = plan_removal(&Cmd::RevokeAll, conns, &tokens, &none);
        assert_eq!((keep.len(), drop.len()), (0, 3), "revoke all clears both");
    }

    #[test]
    fn only_a_handshake_names_a_token() {
        assert_eq!(handshake_token(br#"{"type":"handshake-init","data":"x","ciphersuite":"y","psk_id":"ab12"}"#), Some("ab12".into()));
        assert_eq!(handshake_token(br#"{"type":"handshake-init","data":"x","ciphersuite":"y"}"#), None, "rendezvous: no token");
        assert_eq!(handshake_token(br#"{"type":"credential-request","psk_id":"ab12"}"#), None);
        assert_eq!(handshake_token(b"not json"), None);
    }

    /// Every decision reaches its request: approve starts the release (and an Allow window
    /// opens), deny answers no. Guards the command match against a catch-all arm above it.
    #[tokio::test]
    async fn decisions_reach_their_requests() {
        let (mut core, mut done, _locks) = test_core();
        core.session = Some(session());
        let device = IdentityFingerprint([9; 32]);
        let info = || ItemInfo { id: "item-1".into(), name: "GitHub".into(), username: None, uri: None, domain: None, has_totp: false };
        let pending = |tx| Pending { identity: device, item_id: "item-1".into(), reply: tx, deadline: Instant::now() + REQUEST_TIMEOUT };

        let (tx, _rx) = oneshot::channel();
        core.pending.insert(1, (pending(tx), info()));
        core.on_cmd(Cmd::Decide { id: 1, decision: "approve_for".into(), minutes: Some(5) }).await;
        assert!(core.pending.is_empty(), "approve takes the request");
        assert_eq!(core.approvals.len(), 1, "approve_for opens a window");
        let released = tokio::time::timeout(Duration::from_secs(5), done.recv()).await.unwrap();
        assert!(matches!(released, Some(Done::Released { id: 1, .. })), "approve starts the release");

        let (tx, rx) = oneshot::channel();
        core.pending.insert(2, (pending(tx), info()));
        core.on_cmd(Cmd::Decide { id: 2, decision: "deny".into(), minutes: None }).await;
        assert!(!rx.await.unwrap().approved, "deny answers no");
    }

    /// Offline, the sync is tried again by itself with a growing wait; a sync that works, a
    /// login problem, or a lock stops the retries. Retry keeps its place in the backoff.
    #[tokio::test]
    async fn offline_sync_retries_by_itself_until_it_works() {
        let (mut core, _done, _locks) = test_core();
        core.session = Some(session());
        let synced = |sync| Done::Synced { epoch: 0, sync, keys: Ok(Vec::new()) };
        core.syncing = true;
        core.on_done(synced(Some("offline"))).await;
        assert_eq!(core.retry_sync.map(|(_, w)| w), Some(SYNC_RETRY_FIRST), "first failure: retry soon");
        assert!(!core.syncing && core.has_deadlines(), "the tick runs for the retry");
        core.on_done(synced(Some("timeout"))).await;
        assert_eq!(core.retry_sync.map(|(_, w)| w), Some(SYNC_RETRY_FIRST * 2), "then back off");
        for _ in 0..10 {
            core.on_done(synced(Some("offline"))).await;
        }
        assert_eq!(core.retry_sync.map(|(_, w)| w), Some(SYNC_RETRY_MAX), "capped");

        core.retry_sync = Some((Instant::now(), SYNC_RETRY_MAX));
        core.on_tick();
        assert!(core.syncing, "due: the tick starts the sync");
        core.start_sync();
        core.on_done(synced(None)).await;
        assert!(core.retry_sync.is_none() && !core.has_deadlines(), "back online: retries stop");

        core.on_done(synced(Some("login"))).await;
        assert!(core.retry_sync.is_none(), "a login problem needs you; no retry");

        core.on_done(synced(Some("offline"))).await;
        core.lock_all(None).await;
        assert!(core.retry_sync.is_none() && !core.syncing, "lock stops retries");
    }

    /// With "work from the offline copy" off, a failed sync refuses requests until one works.
    #[tokio::test]
    async fn offline_copy_off_refuses_while_stale() {
        let (mut core, _done, _locks) = test_core();
        core.session = Some(session());
        let synced = |sync| Done::Synced { epoch: 0, sync, keys: Ok(Vec::new()) };
        core.on_done(synced(Some("offline"))).await;
        assert!(!core.offline_blocked(), "default: the offline copy is used");
        core.on_cmd(Cmd::Config { offline_ok: false }).await;
        assert!(core.offline_blocked(), "off and stale: refused");
        core.on_done(synced(None)).await;
        assert!(!core.offline_blocked(), "a sync that works lifts it");
        core.on_done(synced(Some("offline"))).await;
        core.lock_all(None).await;
        assert!(!core.stale, "a lock forgets the state; the next unlock syncs again");
    }

    #[tokio::test]
    async fn lock_denies_everything_waiting_and_forgets_approvals() {
        let (mut core, _done, _locks) = test_core();
        core.session = Some(session());
        let device = IdentityFingerprint([7; 32]);
        let (tx, rx) = oneshot::channel();
        let info = ItemInfo { id: "item-1".into(), name: "GitHub".into(), username: None, uri: None, domain: None, has_totp: false };
        core.pending.insert(1, (Pending { identity: device, item_id: "item-1".into(), reply: tx, deadline: Instant::now() + REQUEST_TIMEOUT }, info));
        core.approvals.insert((device, "item-1".into()), (Instant::now() + Duration::from_secs(600), 600, "GitHub".into()));
        core.lock_all(None).await;
        assert!(!rx.await.unwrap().approved);
        assert!(core.session.is_none() && core.pending.is_empty() && core.approvals.is_empty());

        // A decision that arrives for a request the lock already denied does nothing.
        core.on_cmd(Cmd::Decide { id: 1, decision: "approve".into(), minutes: None }).await;
        assert!(core.session.is_none());
    }
}
