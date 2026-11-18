//! SSH agent that asks NodWarden (and so Touch ID) before every signature.
//!
//! Keys come from Bitwarden SSH key items, loaded with the vault session and
//! held in memory only while unlocked. Listing keys is free (like any agent);
//! signing goes to the island as a request and waits for a decision.
//!
//! Implements the subset of draft-miller-ssh-agent that OpenSSH and git use:
//! REQUEST_IDENTITIES, SIGN_REQUEST, and the `session-bind@openssh.com`
//! extension (to show which host a login is for).

use std::collections::HashMap;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rsa::pkcs1v15::SigningKey;
use rsa::signature::{SignatureEncoding, Signer as _};
use serde_json::{Value, json};
use sha2::{Sha256, Sha512};
use ssh_key::private::KeypairData;
use ssh_key::{HashAlg, PrivateKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, mpsc, oneshot};

const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENT_SUCCESS: u8 = 6;
const SSH2_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH2_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH2_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH2_AGENT_SIGN_RESPONSE: u8 = 14;
const SSH_AGENTC_EXTENSION: u8 = 27;
const SSH_AGENT_RSA_SHA2_256: u32 = 2;
const SSH_AGENT_RSA_SHA2_512: u32 = 4;
const MAX_MSG: usize = 256 * 1024;

pub struct Key {
    pub name: String,
    pub key: PrivateKey,
    pub blob: Vec<u8>,
    pub fingerprint: String,
}

/// What the agent asks the island. `reply` gets true to sign.
pub struct SignAsk {
    pub key_name: String,
    pub fingerprint: String,
    pub host: Option<String>,
    pub purpose: &'static str,
    pub process: Vec<String>,
    pub reply: oneshot::Sender<bool>,
}

#[derive(Default)]
pub struct State {
    pub keys: Vec<Key>,
    /// (fingerprint, process root) -> allowed until.
    pub allowed: HashMap<(String, String), Instant>,
}

pub type Shared = Arc<Mutex<State>>;

pub fn socket_path() -> PathBuf {
    dirs::home_dir().unwrap_or_default().join(".nodwarden").join("ssh-agent.sock")
}

/// Loads every SSH key item from the unlocked vault.
pub async fn load_keys(session: &secrecy::SecretString) -> Result<Vec<Key>, String> {
    use secrecy::ExposeSecret;
    let out = tokio::process::Command::new("bw")
        .args(["list", "items"])
        .env("BW_SESSION", session.expose_secret())
        .stdin(std::process::Stdio::null())
        .output()
        .await
        .map_err(|e| format!("bw: {e}"))?;
    if !out.status.success() {
        return Err("bw list items failed".into());
    }
    let items: Vec<Value> = serde_json::from_slice(&out.stdout).map_err(|e| e.to_string())?;
    let mut keys = Vec::new();
    for it in items {
        let Some(pem) = it["sshKey"]["privateKey"].as_str() else { continue };
        if it["deletedDate"].is_string() {
            continue;
        }
        let Ok(key) = PrivateKey::from_openssh(pem) else { continue };
        let Ok(blob) = key.public_key().key_data().encode_vec() else { continue };
        keys.push(Key {
            name: it["name"].as_str().unwrap_or("ssh key").to_string(),
            fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
            key,
            blob,
        });
    }
    Ok(keys)
}

trait EncodeVec {
    fn encode_vec(&self) -> Result<Vec<u8>, ssh_key::Error>;
}
impl EncodeVec for ssh_key::public::KeyData {
    fn encode_vec(&self) -> Result<Vec<u8>, ssh_key::Error> {
        use ssh_encoding::Encode;
        let mut v = Vec::new();
        self.encode(&mut v)?;
        Ok(v)
    }
}

pub async fn serve(state: Shared, asks: mpsc::Sender<SignAsk>) -> Result<(), String> {
    let path = socket_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).map_err(|e| format!("ssh agent socket: {e}"))?;
    loop {
        let Ok((stream, _)) = listener.accept().await else { continue };
        let (state, asks) = (state.clone(), asks.clone());
        tokio::spawn(async move {
            let _ = handle(stream, state, asks).await;
        });
    }
}

async fn handle(mut s: UnixStream, state: Shared, asks: mpsc::Sender<SignAsk>) -> std::io::Result<()> {
    let process = peer_chain(&s);
    let mut host: Option<String> = None;
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
            SSH2_AGENTC_SIGN_REQUEST => sign(&msg[1..], &state, &asks, &process, host.as_deref()).await,
            SSH_AGENTC_EXTENSION => {
                if let Some(h) = session_bind_host(&msg[1..], &state).await {
                    host = Some(h);
                    vec![SSH_AGENT_SUCCESS]
                } else {
                    vec![SSH_AGENT_FAILURE]
                }
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

async fn sign(
    body: &[u8],
    state: &Shared,
    asks: &mpsc::Sender<SignAsk>,
    process: &[String],
    host: Option<&str>,
) -> Vec<u8> {
    let mut rd = Reader(body);
    let (Some(blob), Some(data), Some(flags)) = (rd.string(), rd.string(), rd.u32()) else {
        return vec![SSH_AGENT_FAILURE];
    };
    let (name, fingerprint) = {
        let st = state.lock().await;
        match st.keys.iter().find(|k| k.blob == blob) {
            Some(k) => (k.name.clone(), k.fingerprint.clone()),
            None => return vec![SSH_AGENT_FAILURE],
        }
    };
    let purpose = if data.starts_with(b"SSHSIG") { "git signing" } else if host.is_some() { "login" } else { "signing" };
    let root = process.last().cloned().unwrap_or_default();
    let key = (fingerprint.clone(), root);

    let pre_allowed = {
        let mut st = state.lock().await;
        let now = Instant::now();
        st.allowed.retain(|_, t| *t > now);
        st.allowed.contains_key(&key)
    };
    if !pre_allowed {
        let (tx, rx) = oneshot::channel();
        let ask = SignAsk {
            key_name: name,
            fingerprint: fingerprint.clone(),
            host: host.map(str::to_string),
            purpose,
            process: process.to_vec(),
            reply: tx,
        };
        if asks.send(ask).await.is_err() {
            return vec![SSH_AGENT_FAILURE];
        }
        match tokio::time::timeout(Duration::from_secs(120), rx).await {
            Ok(Ok(true)) => {}
            _ => return vec![SSH_AGENT_FAILURE],
        }
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

/// Remembers an approval for this key and calling program until `until`.
pub async fn allow_for(state: &Shared, fingerprint: &str, process: &[String], until: Instant) {
    let root = process.last().cloned().unwrap_or_default();
    state.lock().await.allowed.insert((fingerprint.to_string(), root), until);
}

/// SSH wire signature: string(algorithm) + string(signature bytes).
fn make_signature(key: &PrivateKey, data: &[u8], flags: u32) -> Option<Vec<u8>> {
    let (alg, bytes): (&str, Vec<u8>) = match key.key_data() {
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
            if flags & SSH_AGENT_RSA_SHA2_512 != 0 {
                ("rsa-sha2-512", SigningKey::<Sha512>::new(pk).try_sign(data).ok()?.to_vec())
            } else if flags & SSH_AGENT_RSA_SHA2_256 != 0 {
                ("rsa-sha2-256", SigningKey::<Sha256>::new(pk).try_sign(data).ok()?.to_vec())
            } else {
                // Legacy ssh-rsa (SHA-1) is refused; every OpenSSH since 8.2 asks for SHA-2.
                return None;
            }
        }
        _ => {
            use signature::Signer;
            let sig: ssh_key::Signature = key.try_sign(data).ok()?;
            let alg = sig.algorithm().to_string();
            let inner = sig.as_bytes().to_vec();
            let mut out = Vec::new();
            put_string(&mut out, alg.as_bytes());
            put_string(&mut out, &inner);
            return Some(out);
        }
    };
    let mut out = Vec::new();
    put_string(&mut out, alg.as_bytes());
    put_string(&mut out, &bytes);
    Some(out)
}

/// `session-bind@openssh.com`: string hostkey, string session id, string sig, bool forwarding.
/// We only use it to name the host; the binding signature is checked by OpenSSH itself.
async fn session_bind_host(body: &[u8], _state: &Shared) -> Option<String> {
    let mut rd = Reader(body);
    let ext = rd.string()?;
    if ext != b"session-bind@openssh.com" {
        return None;
    }
    let hostkey = rd.string()?;
    let fp = ssh_key::public::KeyData::decode_from(&hostkey)?.fingerprint(HashAlg::Sha256).to_string();
    Some(known_host_for(&fp).unwrap_or(fp))
}

trait DecodeFrom: Sized {
    fn decode_from(b: &[u8]) -> Option<Self>;
}
impl DecodeFrom for ssh_key::public::KeyData {
    fn decode_from(mut b: &[u8]) -> Option<Self> {
        use ssh_encoding::Decode;
        ssh_key::public::KeyData::decode(&mut b).ok()
    }
}

/// Maps a host key fingerprint back to a hostname via ~/.ssh/known_hosts (unhashed entries).
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
            return hosts.split(',').next().map(|h| h.trim_start_matches('[').split(']').next().unwrap_or(h).to_string());
        }
    }
    None
}

/// Names of the connecting process and its ancestors, nearest first, stopping at launchd.
fn peer_chain(s: &UnixStream) -> Vec<String> {
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    // SOL_LOCAL = 0, LOCAL_PEERPID = 2 (macOS)
    let ok = unsafe { libc::getsockopt(s.as_raw_fd(), 0, 2, &mut pid as *mut _ as *mut libc::c_void, &mut len) } == 0;
    let mut chain = Vec::new();
    if !ok {
        return chain;
    }
    for _ in 0..8 {
        if pid <= 1 {
            break;
        }
        let Some((name, ppid)) = proc_info(pid) else { break };
        chain.push(name);
        pid = ppid;
    }
    chain
}

fn proc_info(pid: libc::pid_t) -> Option<(String, libc::pid_t)> {
    let out = std::process::Command::new("/bin/ps")
        .args(["-o", "ppid=,comm=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    let line = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let (ppid, comm) = line.split_once(' ')?;
    let name = comm.trim().rsplit('/').next().unwrap_or(comm).to_string();
    Some((name, ppid.trim().parse().ok()?))
}

pub fn ask_json(id: u64, a: &SignAsk) -> Value {
    json!({
        "ev": "ssh_request", "id": id,
        "key": a.key_name, "fingerprint": a.fingerprint,
        "host": a.host, "purpose": a.purpose, "process": a.process,
        "timeout": 110,
    })
}

struct Reader<'a>(&'a [u8]);
impl Reader<'_> {
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
