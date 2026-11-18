//! SSH agent that asks NodWarden (and so Touch ID) before every signature.
//!
//! Keys come from Bitwarden SSH key items, loaded with the vault session and held
//! in memory only while unlocked. Listing keys is free (like any agent); signing
//! waits for the user, unless an "Allow N minutes" window covers exactly the same
//! key, host, purpose and program.
//!
//! What the prompt shows is verified, not taken from the requester (#2):
//! - Host: from `session-bind@openssh.com`, accepted only if the host key's
//!   signature over the session id verifies. The SIGN_REQUEST payload must be a
//!   userauth request for that session id to be labelled a login.
//! - Purpose: parsed from the data. SSHSIG blobs show their namespace; anything
//!   else is "unverified data".
//! - Program: the peer's executable path from the kernel (`proc_pidpath` of the
//!   pid from `LOCAL_PEERPID`), not argv[0]. Shown as a hint.
//! - Forwarding: a connection that `ssh -A` forwarded from another host says so
//!   (a forwarding `session-bind`). The request then comes from that host, not
//!   from the local program, so the hop is shown and no Allow window applies.

use std::collections::HashMap;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rsa::pkcs1v15::SigningKey;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Sha256, Sha512};
use ssh_encoding::{Decode, Encode};
use ssh_key::private::KeypairData;
use ssh_key::{HashAlg, PrivateKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, mpsc, oneshot};

use crate::bw::Bw;

const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENT_SUCCESS: u8 = 6;
const SSH2_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH2_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH2_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH2_AGENT_SIGN_RESPONSE: u8 = 14;
const SSH_AGENTC_EXTENSION: u8 = 27;
const SSH_AGENT_RSA_SHA2_256: u32 = 2;
const SSH_AGENT_RSA_SHA2_512: u32 = 4;
const SSH2_MSG_USERAUTH_REQUEST: u8 = 50;
const MAX_MSG: usize = 256 * 1024;
/// Waiting sign requests per connecting program before new ones are refused (#14).
const MAX_WAITING_PER_PEER: usize = 2;

pub struct Key {
    pub name: String,
    pub key: PrivateKey,
    pub blob: Vec<u8>,
    pub fingerprint: String,
}

/// The verified identity of the connecting program (#2, #3).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Peer {
    pub pid: i32,
    /// Process start time; with `pid` it identifies one process instance.
    pub start: u64,
    /// Executable path from the kernel, not argv[0].
    pub path: String,
}

impl Peer {
    pub fn name(&self) -> String {
        self.path.rsplit('/').next().unwrap_or(&self.path).to_string()
    }
}

/// What the agent asks the main loop. `reply` gets true to sign.
pub struct SignAsk {
    pub key_name: String,
    pub fingerprint: String,
    /// Verified host for a login; None for anything else.
    pub host: Option<String>,
    pub user: Option<String>,
    /// "login", "git signing", "signing (namespace)", or "unverified data".
    pub purpose: String,
    /// The program that connected, and its ancestors (nearest first), as a hint.
    pub peer: Option<Peer>,
    pub chain: Vec<String>,
    /// Hosts the request was forwarded through (`ssh -A`), nearest to this Mac first.
    /// Not empty means the request was made on that host, not by `peer`.
    pub via: Vec<String>,
    /// True when an Allow window already covers this; the loop only reports it.
    pub auto: bool,
    pub reply: oneshot::Sender<bool>,
}

impl SignAsk {
    fn allow_key(&self) -> Option<AllowKey> {
        allow_key(&self.fingerprint, &self.host, &self.purpose, &self.peer, &self.via)
    }
}

/// What an Allow window covers: exactly what the user saw (#3).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct AllowKey {
    fingerprint: String,
    host: Option<String>,
    purpose: String,
    peer: Peer,
}

/// Only a login by an identified local program can be covered by an Allow window (#3).
/// A forwarded request is made by whoever controls the remote host, so it always asks.
fn allow_key(fingerprint: &str, host: &Option<String>, purpose: &str, peer: &Option<Peer>, via: &[String]) -> Option<AllowKey> {
    let peer = peer.as_ref()?;
    (purpose == "login" && via.is_empty()).then(|| AllowKey {
        fingerprint: fingerprint.to_owned(),
        host: host.clone(),
        purpose: purpose.to_owned(),
        peer: peer.clone(),
    })
}

#[derive(Default)]
pub struct State {
    pub keys: Vec<Key>,
    allowed: HashMap<AllowKey, Instant>,
    waiting: HashMap<i32, usize>,
}

impl State {
    pub fn clear(&mut self) {
        self.keys.clear();
        self.allowed.clear();
    }
}

pub type Shared = Arc<Mutex<State>>;

pub fn socket_path() -> Result<PathBuf, String> {
    Ok(dirs::home_dir().ok_or("no home directory")?.join(".nodwarden").join("ssh-agent.sock"))
}

#[derive(Deserialize)]
struct BwSshKey {
    #[serde(rename = "privateKey")]
    private_key: Option<crate::bw::Secret>,
}
#[derive(Deserialize)]
struct BwSshItem {
    name: String,
    #[serde(rename = "deletedDate")]
    deleted: Option<String>,
    #[serde(rename = "sshKey")]
    ssh_key: Option<BwSshKey>,
}

/// Loads SSH key items. Other fields of the vault are never deserialized (#9).
pub async fn load_keys(bw: &Bw, session: &secrecy::SecretString) -> Result<Vec<Key>, String> {
    let out = bw.run(Some(session), &["list", "items"]).await?;
    if !out.ok {
        return Err("bw list items failed".into());
    }
    let items: Vec<BwSshItem> = serde_json::from_slice(&out.stdout).map_err(|e| e.to_string())?;
    let mut keys = Vec::new();
    for it in items {
        let Some(pem) = it.ssh_key.and_then(|k| k.private_key) else { continue };
        if it.deleted.is_some() {
            continue;
        }
        let Ok(key) = PrivateKey::from_openssh(pem.as_str().as_bytes()) else { continue };
        if key.is_encrypted() {
            continue; // #27: would fail after the user already gave Touch ID.
        }
        let mut blob = Vec::new();
        if key.public_key().key_data().encode(&mut blob).is_err() {
            continue;
        }
        keys.push(Key { name: it.name, fingerprint: key.fingerprint(HashAlg::Sha256).to_string(), key, blob });
    }
    Ok(keys)
}

pub async fn serve(state: Shared, asks: mpsc::Sender<SignAsk>) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let path = socket_path()?;
    let dir = path.parent().ok_or("bad socket path")?;
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| format!("chmod {}: {e}", dir.display()))?;
    // Refuse to steal a live socket from another running instance (#25).
    if std::os::unix::net::UnixStream::connect(&path).is_ok() {
        return Err("another NodWarden SSH agent is already running".into());
    }
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).map_err(|e| format!("ssh agent socket: {e}"))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).map_err(|e| format!("chmod socket: {e}"))?;
    let uid = unsafe { libc::getuid() };
    loop {
        let Ok((stream, _)) = listener.accept().await else { continue };
        if peer_uid(&stream) != Some(uid) {
            continue;
        }
        let (state, asks) = (state.clone(), asks.clone());
        tokio::spawn(async move {
            let _ = handle(stream, state, asks).await;
        });
    }
}

/// Hops an agent connection may be forwarded through before binds are refused.
const MAX_HOPS: usize = 8;

/// One verified `session-bind@openssh.com`.
struct SessionBind {
    host: String,
    session_id: Vec<u8>,
    forwarding: bool,
}

/// What the verified binds on one connection say about it.
#[derive(Default)]
struct Bind {
    /// The host a login on this connection is for.
    host: Option<String>,
    session_id: Vec<u8>,
    /// Hosts this connection was forwarded through, nearest first.
    via: Vec<String>,
}

impl Bind {
    /// Same order as OpenSSH's own agent accepts: forwarding hops first, then at most one
    /// bind for authentication. Nothing may be bound after that one.
    fn add(&mut self, b: SessionBind) -> bool {
        if !self.session_id.is_empty() {
            return false;
        }
        if b.forwarding {
            if self.via.len() >= MAX_HOPS {
                return false;
            }
            self.via.push(b.host);
        } else {
            self.host = Some(b.host);
            self.session_id = b.session_id;
        }
        true
    }
}

async fn handle(mut s: UnixStream, state: Shared, asks: mpsc::Sender<SignAsk>) -> std::io::Result<()> {
    let pid = peer_pid(&s);
    let mut bind = Bind::default();
    loop {
        let mut len = [0u8; 4];
        if s.read_exact(&mut len).await.is_err() {
            return Ok(());
        }
        let n = u32::from_be_bytes(len) as usize;
        if n == 0 || n > MAX_MSG {
            return Ok(());
        }
        let mut msg = vec![0u8; n];
        s.read_exact(&mut msg).await?;
        let reply = match msg[0] {
            SSH2_AGENTC_REQUEST_IDENTITIES => identities(&state).await,
            SSH2_AGENTC_SIGN_REQUEST => sign(&mut s, &msg[1..], &state, &asks, pid, &bind).await,
            SSH_AGENTC_EXTENSION => {
                let bound = session_bind(&msg[1..]).is_some_and(|b| bind.add(b));
                vec![if bound { SSH_AGENT_SUCCESS } else { SSH_AGENT_FAILURE }]
            }
            _ => vec![SSH_AGENT_FAILURE],
        };
        let mut out = (reply.len() as u32).to_be_bytes().to_vec();
        out.extend(reply);
        s.write_all(&out).await?;
    }
}

async fn identities(state: &Shared) -> Vec<u8> {
    let st = state.lock().await;
    let mut r = vec![SSH2_AGENT_IDENTITIES_ANSWER];
    r.extend((st.keys.len() as u32).to_be_bytes());
    for k in &st.keys {
        put_string(&mut r, &k.blob);
        put_string(&mut r, k.name.as_bytes());
    }
    r
}

/// Labels the data to be signed from its own content (#2).
fn classify(data: &[u8], bind: &Bind) -> (String, Option<String>, Option<String>) {
    if let Some(ns) = sshsig_namespace(data) {
        let purpose = if ns == "git" { "git signing".to_string() } else { format!("signing ({ns})") };
        return (purpose, None, None);
    }
    if let (Some(host), Some(user)) = (&bind.host, userauth_user(data, &bind.session_id)) {
        return ("login".into(), Some(host.clone()), Some(user));
    }
    ("unverified data".into(), None, None)
}

/// SSHSIG namespace, if `data` is an OpenSSH signature blob (PROTOCOL.sshsig).
fn sshsig_namespace(data: &[u8]) -> Option<String> {
    let rest = data.strip_prefix(b"SSHSIG")?;
    let mut rd = Reader(rest);
    let ns = rd.string()?;
    String::from_utf8(ns).ok().filter(|s| !s.is_empty() && s.len() <= 64)
}

/// The user name, if `data` is a publickey userauth request for this bound session.
fn userauth_user(data: &[u8], session_id: &[u8]) -> Option<String> {
    if session_id.is_empty() {
        return None;
    }
    let mut rd = Reader(data);
    if rd.string()? != session_id || rd.byte()? != SSH2_MSG_USERAUTH_REQUEST {
        return None;
    }
    let user = rd.string()?;
    let _service = rd.string()?;
    // OpenSSH 8.9+ uses the host-bound variant whenever the server supports it.
    let method = rd.string()?;
    if method != b"publickey" && method != b"publickey-hostbound-v00@openssh.com" {
        return None;
    }
    String::from_utf8(user).ok()
}

async fn sign(
    sock: &mut UnixStream,
    body: &[u8],
    state: &Shared,
    asks: &mpsc::Sender<SignAsk>,
    pid: Option<i32>,
    bind: &Bind,
) -> Vec<u8> {
    let mut rd = Reader(body);
    let (Some(blob), Some(data), Some(flags)) = (rd.string(), rd.string(), rd.u32()) else {
        return vec![SSH_AGENT_FAILURE];
    };
    let (key_name, fingerprint) = {
        let st = state.lock().await;
        match st.keys.iter().find(|k| k.blob == blob) {
            Some(k) => (k.name.clone(), k.fingerprint.clone()),
            None => return vec![SSH_AGENT_FAILURE],
        }
    };
    let (purpose, host, user) = classify(&data, bind);
    let (peer, chain) = match pid {
        Some(p) => tokio::task::spawn_blocking(move || (anchor_of(p), chain_of(p))).await.unwrap_or((None, Vec::new())),
        None => (None, Vec::new()),
    };

    let allow_key = allow_key(&fingerprint, &host, &purpose, &peer, &bind.via);
    let auto = match &allow_key {
        Some(k) => {
            let mut st = state.lock().await;
            let now = Instant::now();
            st.allowed.retain(|_, t| *t > now);
            st.allowed.contains_key(k)
        }
        None => false,
    };

    let wait_key = pid.unwrap_or(0);
    {
        let mut st = state.lock().await;
        let w = st.waiting.entry(wait_key).or_default();
        if !auto && *w >= MAX_WAITING_PER_PEER {
            return vec![SSH_AGENT_FAILURE];
        }
        *w += 1;
    }
    let (tx, rx) = oneshot::channel();
    let ask = SignAsk { key_name, fingerprint, host, user, purpose, peer, chain, via: bind.via.clone(), auto, reply: tx };
    let approved = if asks.send(ask).await.is_err() {
        false
    } else {
        // Wait for the decision, or the client going away (#23).
        tokio::select! {
            r = tokio::time::timeout(crate::REQUEST_TIMEOUT + Duration::from_secs(5), rx) => matches!(r, Ok(Ok(true))),
            _ = peer_closed(sock) => false,
        }
    };
    {
        let mut st = state.lock().await;
        if let Some(w) = st.waiting.get_mut(&wait_key) {
            *w = w.saturating_sub(1);
        }
    }
    if !approved {
        return vec![SSH_AGENT_FAILURE];
    }

    let st = state.lock().await;
    let Some(k) = st.keys.iter().find(|k| k.blob == blob) else {
        return vec![SSH_AGENT_FAILURE];
    };
    let Some(sig) = make_signature(&k.key, &data, flags) else {
        return vec![SSH_AGENT_FAILURE];
    };
    let mut r = vec![SSH2_AGENT_SIGN_RESPONSE];
    put_string(&mut r, &sig);
    r
}

/// Resolves when the peer has closed its end. `readable()` alone also fires spuriously,
/// so confirm EOF with a non-consuming peek (MSG_PEEK) that returns 0 bytes.
async fn peer_closed(sock: &UnixStream) {
    loop {
        if sock.readable().await.is_err() {
            return;
        }
        let mut b = [0u8; 1];
        let n = unsafe { libc::recv(sock.as_raw_fd(), b.as_mut_ptr() as *mut libc::c_void, 1, libc::MSG_PEEK | libc::MSG_DONTWAIT) };
        match n {
            0 => return,
            n if n > 0 => {
                // The client sent something while waiting; not a close. Don't spin on it.
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            _ => {
                let e = std::io::Error::last_os_error();
                if e.kind() != std::io::ErrorKind::WouldBlock {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

/// Remembers an approval for exactly what was shown. Unidentified requests are never cached.
pub async fn allow_for(state: &Shared, ask: &SignAsk, until: Instant) {
    if let Some(key) = ask.allow_key() {
        state.lock().await.allowed.insert(key, until);
    }
}

/// SSH wire signature: string(algorithm) + string(signature bytes).
fn make_signature(key: &PrivateKey, data: &[u8], flags: u32) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    match key.key_data() {
        KeypairData::Rsa(kp) => {
            // ssh-key 0.6.7's TryFrom passes primes [p, p] instead of [p, q]; build it ourselves.
            let big = |m: &ssh_key::Mpint| rsa::BigUint::from_bytes_be(m.as_positive_bytes().unwrap_or(m.as_bytes()));
            let pk = rsa::RsaPrivateKey::from_components(
                big(&kp.public.n),
                big(&kp.public.e),
                big(&kp.private.d),
                vec![big(&kp.private.p), big(&kp.private.q)],
            )
            .ok()?;
            // Blinded signing (#20).
            let mut rng = rsa::rand_core::OsRng;
            let (alg, bytes) = if flags & SSH_AGENT_RSA_SHA2_512 != 0 {
                ("rsa-sha2-512", SigningKey::<Sha512>::new(pk).try_sign_with_rng(&mut rng, data).ok()?.to_vec())
            } else if flags & SSH_AGENT_RSA_SHA2_256 != 0 {
                ("rsa-sha2-256", SigningKey::<Sha256>::new(pk).try_sign_with_rng(&mut rng, data).ok()?.to_vec())
            } else {
                // Legacy ssh-rsa (SHA-1) is refused; every OpenSSH since 8.2 asks for SHA-2.
                return None;
            };
            put_string(&mut out, alg.as_bytes());
            put_string(&mut out, &bytes);
        }
        _ => {
            use signature::Signer;
            let sig: ssh_key::Signature = key.try_sign(data).ok()?;
            put_string(&mut out, sig.algorithm().to_string().as_bytes());
            put_string(&mut out, sig.as_bytes());
        }
    }
    Some(out)
}

/// `session-bind@openssh.com`: string hostkey, string session id, string signature, bool forwarding.
/// Accepted only if the host key's signature over the session id verifies (#2).
fn session_bind(body: &[u8]) -> Option<SessionBind> {
    let mut rd = Reader(body);
    if rd.string()? != b"session-bind@openssh.com" {
        return None;
    }
    let hostkey = rd.string()?;
    let session_id = rd.string()?;
    let sig = rd.string()?;
    let forwarding = rd.byte()? != 0;
    if session_id.is_empty() {
        return None;
    }
    let key = ssh_key::public::KeyData::decode(&mut hostkey.as_slice()).ok()?;
    let sig = ssh_key::Signature::decode(&mut sig.as_slice()).ok()?;
    {
        use signature::Verifier;
        key.verify(&session_id, &sig).ok()?;
    }
    let fp = key.fingerprint(HashAlg::Sha256).to_string();
    Some(SessionBind { host: known_host_for(&fp).unwrap_or(fp), session_id, forwarding })
}

/// Maps a verified host key fingerprint to a hostname via ~/.ssh/known_hosts (unhashed entries).
fn known_host_for(fp: &str) -> Option<String> {
    let text = std::fs::read_to_string(dirs::home_dir()?.join(".ssh/known_hosts")).ok()?;
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let (Some(hosts), Some(kt), Some(kb)) = (parts.next(), parts.next(), parts.next()) else { continue };
        if hosts.starts_with('|') || hosts.starts_with('@') {
            continue;
        }
        let Ok(pk) = ssh_key::PublicKey::from_openssh(&format!("{kt} {kb}")) else { continue };
        if pk.fingerprint(HashAlg::Sha256).to_string() == fp {
            let first = hosts.split(',').next()?;
            return Some(first.trim_start_matches('[').split(']').next().unwrap_or(first).to_string());
        }
    }
    None
}

fn peer_pid(s: &UnixStream) -> Option<i32> {
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    let ok = unsafe {
        libc::getsockopt(s.as_raw_fd(), libc::SOL_LOCAL, libc::LOCAL_PEERPID, &mut pid as *mut _ as *mut libc::c_void, &mut len)
    } == 0;
    (ok && pid > 0).then_some(pid)
}

fn peer_uid(s: &UnixStream) -> Option<u32> {
    let (mut uid, mut gid) = (0, 0);
    (unsafe { libc::getpeereid(s.as_raw_fd(), &mut uid, &mut gid) } == 0).then_some(uid)
}

/// pid, start time and parent pid from the kernel, without forking (#13).
fn bsdinfo(pid: i32) -> Option<libc::proc_bsdinfo> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
    let n = unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, &mut info as *mut _ as *mut libc::c_void, size) };
    (n == size).then_some(info)
}

fn exe_path(pid: i32) -> Option<String> {
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr() as *mut libc::c_void, buf.len() as u32) };
    (n > 0).then(|| String::from_utf8_lossy(&buf[..n as usize]).into_owned())
}

fn peer_of(pid: i32) -> Option<Peer> {
    let info = bsdinfo(pid)?;
    Some(Peer { pid, start: info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec, path: exe_path(pid)? })
}

fn exe_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Tools that run ssh on someone's behalf; the request belongs to whoever ran them.
fn is_helper(name: &str) -> bool {
    matches!(name, "ssh" | "ssh-keygen" | "git" | "env" | "sudo" | "xargs" | "timeout" | "nice" | "nohup")
        || name.starts_with("git-")
}

fn is_shell(name: &str) -> bool {
    matches!(name, "sh" | "bash" | "zsh" | "dash" | "fish" | "ksh" | "tcsh")
}

/// Hosts of interactive shells: an app bundle, a multiplexer, or a login.
fn is_terminal_host(path: &str) -> bool {
    path.contains(".app/") || matches!(exe_name(path), "tmux" | "screen" | "herdr-core" | "login" | "sshd" | "launchd")
}

/// The program instance a request really comes from, used both for display and as the
/// identity an Allow window is bound to (#3). Walks up from the connecting process past
/// helpers (ssh, git, sudo, ...) and non-interactive shells, and stops at:
/// - the first program that is neither (e.g. the `pi` or `claude` process), or
/// - an interactive shell, i.e. a shell whose parent is a terminal host.
///
/// It never climbs to the terminal itself, so one approval can't cover every tab.
fn anchor_of(pid: i32) -> Option<Peer> {
    let mut cur = pid;
    for _ in 0..16 {
        let info = bsdinfo(cur)?;
        let path = exe_path(cur)?;
        let name = exe_name(&path).to_string();
        let parent = info.pbi_ppid as i32;
        let parent_path = if parent > 1 { exe_path(parent) } else { None };
        let parent_is_host = parent_path.as_deref().is_none_or(is_terminal_host);
        let keep_walking = (is_helper(&name) || (is_shell(&name) && !parent_is_host)) && parent > 1;
        if !keep_walking {
            return peer_of(cur);
        }
        cur = parent;
    }
    None
}

/// Executable names of the peer and its ancestors, nearest first (a hint for the UI).
fn chain_of(mut pid: i32) -> Vec<String> {
    let mut chain = Vec::new();
    for _ in 0..8 {
        if pid <= 1 {
            break;
        }
        let Some(info) = bsdinfo(pid) else { break };
        if let Some(p) = exe_path(pid) {
            chain.push(p.rsplit('/').next().unwrap_or(&p).to_string());
        }
        pid = info.pbi_ppid as i32;
    }
    chain
}

pub fn ask_json(id: u64, a: &SignAsk) -> Value {
    json!({
        "ev": "ssh_request", "id": id,
        "key": a.key_name, "fingerprint": a.fingerprint,
        "host": a.host, "user": a.user, "purpose": a.purpose,
        "app": a.peer.as_ref().map(Peer::name), "app_path": a.peer.as_ref().map(|p| p.path.clone()),
        "process": a.chain,
        "via": a.via,
        // Whether "Allow N minutes" would be remembered; the UI offers it only then.
        "can_allow": a.allow_key().is_some(),
        "timeout": crate::REQUEST_TIMEOUT.as_secs(),
    })
}

struct Reader<'a>(&'a [u8]);
impl Reader<'_> {
    fn byte(&mut self) -> Option<u8> {
        let (b, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(*b)
    }
    fn u32(&mut self) -> Option<u32> {
        let b = self.0.get(..4)?;
        self.0 = &self.0[4..];
        Some(u32::from_be_bytes(b.try_into().ok()?))
    }
    fn string(&mut self) -> Option<Vec<u8>> {
        let n = self.u32()? as usize;
        let b = self.0.get(..n)?.to_vec();
        self.0 = &self.0[n..];
        Some(b)
    }
}

fn put_string(out: &mut Vec<u8>, b: &[u8]) {
    out.extend((b.len() as u32).to_be_bytes());
    out.extend(b);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(b: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        put_string(&mut v, b);
        v
    }

    #[test]
    fn sshsig_namespace_parsed() {
        let mut d = b"SSHSIG".to_vec();
        d.extend(s(b"git"));
        assert_eq!(sshsig_namespace(&d).as_deref(), Some("git"));
        assert_eq!(sshsig_namespace(b"not a sig"), None);
    }

    #[test]
    fn login_needs_bound_session_id() {
        let sid = b"session-123".to_vec();
        let mut d = s(&sid);
        d.push(SSH2_MSG_USERAUTH_REQUEST);
        d.extend(s(b"git"));
        d.extend(s(b"ssh-connection"));
        d.extend(s(b"publickey"));
        let bound = Bind { host: Some("github.com".into()), session_id: sid.clone(), via: Vec::new() };
        assert_eq!(classify(&d, &bound), ("login".into(), Some("github.com".into()), Some("git".into())));
        // The host-bound method modern OpenSSH actually sends.
        let mut hb = s(&sid);
        hb.push(SSH2_MSG_USERAUTH_REQUEST);
        hb.extend(s(b"git"));
        hb.extend(s(b"ssh-connection"));
        hb.extend(s(b"publickey-hostbound-v00@openssh.com"));
        assert_eq!(classify(&hb, &bound).0, "login");
        // Same data, but bound to another session: not a login for github.com.
        let other = Bind { host: Some("github.com".into()), session_id: b"other".to_vec(), via: Vec::new() };
        assert_eq!(classify(&d, &other).0, "unverified data");
        // No bind at all.
        assert_eq!(classify(&d, &Bind::default()).0, "unverified data");
    }

    fn host_key() -> ssh_key::PrivateKey {
        ssh_key::PrivateKey::random(&mut rsa::rand_core::OsRng, ssh_key::Algorithm::Ed25519).unwrap()
    }

    /// A `session-bind@openssh.com` body where host key `k` signs `signed` but claims `session_id`.
    fn bind_body(k: &ssh_key::PrivateKey, session_id: &[u8], signed: &[u8], forwarding: bool) -> Vec<u8> {
        use signature::Signer;
        let mut hostkey = Vec::new();
        k.public_key().key_data().encode(&mut hostkey).unwrap();
        let sig: ssh_key::Signature = k.try_sign(signed).unwrap();
        let mut sig_blob = Vec::new();
        sig.encode(&mut sig_blob).unwrap();
        let mut body = s(b"session-bind@openssh.com");
        body.extend(s(&hostkey));
        body.extend(s(session_id));
        body.extend(s(&sig_blob));
        body.push(forwarding as u8);
        body
    }

    #[test]
    fn forged_session_bind_rejected() {
        // A real ed25519 host key with a signature that does not cover the session id.
        let k = host_key();
        assert!(session_bind(&bind_body(&k, b"the real session", b"some other session", false)).is_none());
        // Signed correctly: accepted.
        let good = session_bind(&bind_body(&k, b"the real session", b"the real session", false)).unwrap();
        assert_eq!(good.session_id, b"the real session");
        assert!(!good.forwarding);
        assert!(session_bind(&bind_body(&k, b"", b"", false)).is_none(), "empty session id");
    }

    #[test]
    fn forwarded_connection_is_marked_and_never_remembered() {
        // `ssh -A jump`, then on jump: `ssh git@github.com`. The local ssh binds the jump host
        // as a forwarding hop; everything after that on the connection comes from the jump host.
        let (jump, github) = (host_key(), host_key());
        let mut bind = Bind::default();
        let hop = session_bind(&bind_body(&jump, b"sid-jump", b"sid-jump", true)).unwrap();
        assert!(hop.forwarding);
        let jump_name = hop.host.clone();
        assert!(bind.add(hop));
        assert!(bind.session_id.is_empty(), "a forwarding hop is not a login session");
        assert!(bind.add(session_bind(&bind_body(&github, b"sid-gh", b"sid-gh", false)).unwrap()));
        assert_eq!(bind.via, [jump_name]);
        assert_eq!(bind.session_id, b"sid-gh");
        // Nothing may be bound after the bind for authentication.
        assert!(!bind.add(session_bind(&bind_body(&jump, b"sid-3", b"sid-3", false)).unwrap()));
        assert!(!bind.add(session_bind(&bind_body(&jump, b"sid-3", b"sid-3", true)).unwrap()));

        let peer = Some(Peer { pid: 1, start: 1, path: "/usr/bin/ssh".into() });
        let host = Some("github.com".to_string());
        assert!(allow_key("SHA256:k", &host, "login", &peer, &[]).is_some());
        assert!(allow_key("SHA256:k", &host, "login", &peer, &bind.via).is_none(), "forwarded login was remembered");
        assert!(allow_key("SHA256:k", &None, "git signing", &peer, &[]).is_none());
        assert!(allow_key("SHA256:k", &host, "login", &None, &[]).is_none());
    }

    #[test]
    fn anchor_is_this_shell_not_the_terminal_or_ssh() {
        // The test runner is the real process here: its anchor must be itself or a
        // non-helper ancestor, never a terminal host, and never ssh/git.
        let me = std::process::id() as i32;
        let a = anchor_of(me).expect("anchor");
        let name = exe_name(&a.path);
        assert!(!is_helper(name), "anchor is a helper: {name}");
        assert!(!a.path.contains(".app/") || !is_shell(name), "anchor climbed to a terminal: {}", a.path);
        // Stable across calls: an Allow window keyed on it matches the next request.
        assert_eq!(anchor_of(me), Some(a));
    }

    #[test]
    fn helper_and_shell_names() {
        assert!(is_helper("ssh") && is_helper("git") && is_helper("git-remote-ssh"));
        assert!(!is_helper("pi") && !is_helper("claude"));
        assert!(is_shell("fish") && is_shell("bash") && !is_shell("pi"));
        assert!(is_terminal_host("/Applications/Ghostty.app/Contents/MacOS/ghostty"));
        assert!(is_terminal_host("/Users/x/.local/bin/herdr-core"));
        assert!(!is_terminal_host("/opt/homebrew/bin/fish"));
    }

    #[test]
    fn reader_never_panics_on_garbage() {
        for len in 0..64 {
            let junk: Vec<u8> = (0..len).map(|i| (i * 37 % 256) as u8).collect();
            let _ = session_bind(&junk);
            let _ = sshsig_namespace(&junk);
            let _ = userauth_user(&junk, b"x");
            let mut rd = Reader(&junk);
            let _ = (rd.string(), rd.u32(), rd.byte());
        }
    }
}
