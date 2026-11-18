//! Runs the Bitwarden CLI without exposing the vault session.
//!
//! `bw` is a Node script, and macOS lets same-user processes read the
//! environment of non-platform binaries (`ps eww`). So the session is never put
//! in `bw`'s environment or argv: `node` runs a tiny loader that reads the
//! session from its stdin, sets `process.env.BW_SESSION` inside the process,
//! and then loads `bw`. `ps` sees neither.
//!
//! `node` and `bw.js` are resolved once at start to absolute real paths. Every
//! directory walked through on the way, and the files themselves, must be ones
//! no other user can change (see `resolve_trusted`).

use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

const LOADER: &str = r#"
const fs = require('fs');
const buf = Buffer.alloc(512); let n = 0;
for (;;) { const r = fs.readSync(0, buf, n, 1, null); if (r === 0 || buf[n] === 10) break; n += r; if (n >= buf.length) break; }
process.env.BW_SESSION = buf.toString('utf8', 0, n); buf.fill(0);
const script = process.argv[1];
process.argv = [process.argv[0], script, ...process.argv.slice(2)];
require(script);
"#;

const TIMEOUT: Duration = Duration::from_secs(30);
/// macOS `admin` group. Its members can use sudo, so a directory they can write
/// (Homebrew's `/opt/homebrew/bin` is 775 user:admin) gives them nothing new.
const ADMIN_GID: u32 = 80;

#[derive(Clone, Debug)]
pub struct Bw {
    pub node: PathBuf,
    pub script: PathBuf,
}

impl Bw {
    /// Finds `node` and the real `bw.js`. NodWarden passes both as absolute paths in
    /// `NODWARDEN_NODE` / `NODWARDEN_BW`; PATH is the fallback when aac-core is run by hand.
    pub fn resolve() -> Result<Self, String> {
        let find = |var: &str, name: &str| match std::env::var_os(var).filter(|v| !v.is_empty()) {
            Some(p) => Ok(PathBuf::from(p)),
            None => which(name).ok_or(format!("{name} not found on PATH")),
        };
        Self::from_paths(&find("NODWARDEN_NODE", "node")?, &find("NODWARDEN_BW", "bw")?)
    }

    fn from_paths(node: &Path, bw: &Path) -> Result<Self, String> {
        let node = resolve_trusted(node)?;
        let script = resolve_trusted(bw)?;
        check_node_script(&script)?;
        Ok(Self { node, script })
    }

    /// Runs `bw <args>` with the session given through stdin. Output is zeroized on drop.
    pub async fn run(&self, session: Option<&SecretString>, args: &[&str]) -> Result<Output, String> {
        let mut cmd = tokio::process::Command::new(&self.node);
        cmd.arg("-e").arg(LOADER).arg(&self.script).args(args);
        cmd.env_remove("BW_SESSION")
            .env("BW_NOINTERACTION", "true")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = cmd.spawn().map_err(|e| format!("bw: {e}"))?;
        if let Some(mut stdin) = child.stdin.take() {
            let line = Zeroizing::new(format!("{}\n", session.map(|s| s.expose_secret()).unwrap_or("")));
            stdin.write_all(line.as_bytes()).await.map_err(|e| format!("bw stdin: {e}"))?;
        }
        let (Some(stdout), Some(mut stderr)) = (child.stdout.take(), child.stderr.take()) else {
            return Err("bw: no output pipes".into());
        };
        let work = async {
            let mut err = Vec::new();
            let (out, _, status) = tokio::join!(read_zeroizing(stdout), stderr.read_to_end(&mut err), child.wait());
            Ok::<_, std::io::Error>((out?, err, status?))
        };
        // On timeout `child` is dropped at the end of this function, which kills it.
        let (stdout, stderr, status) = tokio::time::timeout(TIMEOUT, work)
            .await
            .map_err(|_| "bw timed out".to_string())?
            .map_err(|e| format!("bw: {e}"))?;
        Ok(Output { ok: status.success(), stdout, stderr: String::from_utf8_lossy(&stderr).into_owned() })
    }

    pub async fn status(&self, session: Option<&SecretString>) -> Option<String> {
        #[derive(Deserialize)]
        struct S {
            status: String,
        }
        let out = self.run(session, &["status"]).await.ok()?;
        serde_json::from_slice::<S>(&out.stdout).ok().map(|s| s.status)
    }

    /// Locks bw so a session copied from anywhere stops working. Tries twice; the result is
    /// returned so a failure can be reported instead of silently claiming "locked" (#15).
    pub async fn lock(&self) -> bool {
        for _ in 0..2 {
            if matches!(self.run(None, &["lock"]).await, Ok(o) if o.ok) {
                return true;
            }
        }
        false
    }
}

/// Reads to the end without leaving plaintext behind: a plain `Vec` frees its old
/// buffer unwiped every time it grows, and `bw list items` is the whole decrypted vault.
async fn read_zeroizing<R: AsyncRead + Unpin>(mut r: R) -> std::io::Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(64 * 1024));
    let mut chunk = Zeroizing::new([0u8; 16 * 1024]);
    loop {
        let n = r.read(&mut chunk[..]).await?;
        if n == 0 {
            return Ok(out);
        }
        if out.len() + n > out.capacity() {
            let mut bigger = Zeroizing::new(Vec::with_capacity((out.capacity() * 2).max(out.len() + n)));
            bigger.extend_from_slice(&out);
            out = bigger; // the old buffer is wiped as it drops
        }
        out.extend_from_slice(&chunk[..n]);
    }
}

/// A string from JSON that is wiped from memory when dropped.
/// (`zeroize` has no serde support, so `Zeroizing<String>` can't be deserialized directly.)
pub struct Secret(pub Zeroizing<String>);

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Secret(Zeroizing::new(String::deserialize(d)?)))
    }
}

impl Secret {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub struct Output {
    pub ok: bool,
    pub stdout: Zeroizing<Vec<u8>>,
    pub stderr: String,
}

/// The one resolver for the tools both sides run (#23). `aac-core --tools` prints this as JSON
/// and the app uses it, so the trust check lives in one place. Each entry: where it was found on
/// PATH and the trusted real path, or why it was refused.
pub fn tools_report() -> serde_json::Value {
    let one = |name: &str| match which(name) {
        None => serde_json::json!({"error": format!("{name} not found on PATH")}),
        Some(found) => match resolve_trusted(&found) {
            Ok(real) => serde_json::json!({"found": found, "real": real}),
            Err(e) => serde_json::json!({"found": found, "error": e}),
        },
    };
    serde_json::json!({"node": one("node"), "bw": one("bw"), "bwbio": one("bwbio")})
}

fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

/// The loader `require()`s the script, so it must be the Node build of the CLI (npm,
/// Homebrew). The standalone download is a native binary: it can only take the session
/// through its environment, which other processes can read.
fn check_node_script(script: &Path) -> Result<(), String> {
    use std::io::Read;
    let mut head = [0u8; 128];
    let n = std::fs::File::open(script)
        .and_then(|mut f| f.read(&mut head))
        .map_err(|e| format!("{}: {e}", script.display()))?;
    let first = head[..n].split(|b| *b == b'\n').next().unwrap_or_default();
    if first.starts_with(b"#!") && first.windows(4).any(|w| w == b"node") {
        return Ok(());
    }
    Err(format!(
        "{} is not the Node.js build of the Bitwarden CLI; install it with npm or Homebrew",
        script.display()
    ))
}

/// Whether nobody but root, `me` and administrators can change this file or directory.
fn trusted(uid: u32, gid: u32, mode: u32, is_dir: bool, me: u32) -> Result<(), &'static str> {
    if uid != 0 && uid != me {
        return Err("is owned by another user");
    }
    // In a sticky directory (/tmp) others can add entries but not replace ours,
    // and every entry we go on to use is checked for its owner.
    let sticky = is_dir && mode & 0o1000 != 0;
    let group_writable = mode & 0o020 != 0 && gid != ADMIN_GID;
    if (group_writable || mode & 0o002 != 0) && !sticky {
        return Err("is writable by other users");
    }
    Ok(())
}

/// `realpath(3)` that also refuses the result if another user could redirect it: every
/// directory walked through (including the ones that hold a symlink on the way) and the
/// file itself must pass `trusted`. The owner's own directories (e.g. `~/.n/bin`) are
/// accepted: a same-user attacker is out of scope.
pub fn resolve_trusted(p: &Path) -> Result<PathBuf, String> {
    use std::os::unix::fs::MetadataExt;
    let me = unsafe { libc::getuid() };
    let check = |path: &Path, m: &std::fs::Metadata| {
        trusted(m.uid(), m.gid(), m.mode(), m.is_dir(), me)
            .map_err(|why| format!("{} {why}; refusing to run {}", path.display(), p.display()))
    };
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir().map_err(|e| e.to_string())?.join(p)
    };
    let push = |todo: &mut Vec<OsString>, path: &Path| {
        todo.extend(path.components().rev().filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_os_string()),
            Component::ParentDir => Some("..".into()),
            _ => None,
        }));
    };
    let mut todo = Vec::new();
    push(&mut todo, &abs);
    let mut cur = PathBuf::from("/");
    let mut meta = std::fs::symlink_metadata(&cur).map_err(|e| format!("/: {e}"))?;
    check(&cur, &meta)?;
    let mut links = 0;
    while let Some(name) = todo.pop() {
        if name == ".." {
            cur.pop();
            continue;
        }
        let next = cur.join(&name);
        let m = std::fs::symlink_metadata(&next).map_err(|e| format!("{}: {e}", next.display()))?;
        if m.file_type().is_symlink() {
            links += 1;
            if links > 40 {
                return Err(format!("{}: too many symlinks", p.display()));
            }
            let target = std::fs::read_link(&next).map_err(|e| format!("{}: {e}", next.display()))?;
            if target.is_absolute() {
                cur = PathBuf::from("/");
            }
            push(&mut todo, &target);
            continue;
        }
        check(&next, &m)?;
        cur = next;
        meta = m;
    }
    if !meta.is_file() {
        return Err(format!("{} is not a file", p.display()));
    }
    Ok(cur)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let d = std::env::temp_dir().join(format!("nw-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            Self(d)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn chmod(p: &Path, mode: u32) {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn rejects_world_writable_dir() {
        let d = TempDir::new("ww");
        let f = d.0.join("bw");
        std::fs::write(&f, "x").unwrap();
        chmod(&d.0, 0o777);
        assert!(resolve_trusted(&f).is_err());
        chmod(&d.0, 0o755);
        assert_eq!(resolve_trusted(&f).unwrap(), std::fs::canonicalize(&f).unwrap());
    }

    #[test]
    fn rejects_symlink_kept_in_a_writable_dir() {
        // The real file is fine, but anyone could repoint the link that leads to it.
        let d = TempDir::new("link");
        let (safe, open) = (d.0.join("safe"), d.0.join("open"));
        std::fs::create_dir_all(&safe).unwrap();
        std::fs::create_dir_all(&open).unwrap();
        std::fs::write(safe.join("bw.js"), "x").unwrap();
        std::os::unix::fs::symlink("../safe/bw.js", open.join("bw")).unwrap();
        assert!(resolve_trusted(&open.join("bw")).is_ok());
        chmod(&open, 0o777);
        assert!(resolve_trusted(&open.join("bw")).is_err());
        chmod(&open, 0o755);
    }

    #[test]
    fn trust_rules() {
        let me = 501;
        assert!(trusted(me, 20, 0o755, true, me).is_ok());
        assert!(trusted(0, 0, 0o755, true, me).is_ok());
        // Another user's file, even when not writable by anyone else.
        assert!(trusted(502, 20, 0o755, false, me).is_err());
        // Group staff is every user; group admin can already sudo (Homebrew dirs are 775 :admin).
        assert!(trusted(me, 20, 0o775, true, me).is_err());
        assert!(trusted(me, ADMIN_GID, 0o775, true, me).is_ok());
        assert!(trusted(me, ADMIN_GID, 0o777, true, me).is_err());
        // Sticky directories (/tmp) are fine to pass through; sticky means nothing on a file.
        assert!(trusted(0, 0, 0o1777, true, me).is_ok());
        assert!(trusted(me, 20, 0o1777, false, me).is_err());
    }

    #[test]
    fn finds_bw_behind_a_homebrew_style_symlink_chain() {
        // bin/bw -> ../libexec/bin/bw -> ../lib/build/bw.js. The real file is named bw.js and
        // sits in a directory that is not on PATH, so both tools must be taken by path.
        let d = TempDir::new("brew");
        for sub in ["bin", "libexec/bin", "libexec/lib/build"] {
            std::fs::create_dir_all(d.0.join(sub)).unwrap();
        }
        let js = d.0.join("libexec/lib/build/bw.js");
        std::fs::write(&js, "#!/usr/bin/env node\n").unwrap();
        std::os::unix::fs::symlink("../lib/build/bw.js", d.0.join("libexec/bin/bw")).unwrap();
        std::os::unix::fs::symlink("../libexec/bin/bw", d.0.join("bin/bw")).unwrap();
        let node = d.0.join("bin/node");
        std::fs::write(&node, "").unwrap();
        let bw = Bw::from_paths(&node, &d.0.join("bin/bw")).unwrap();
        assert_eq!(bw.script, std::fs::canonicalize(&js).unwrap());
        assert_eq!(bw.node, std::fs::canonicalize(&node).unwrap());
    }

    #[test]
    fn refuses_a_native_bw_binary() {
        let d = TempDir::new("native");
        let (node, bw) = (d.0.join("node"), d.0.join("bw"));
        std::fs::write(&node, "").unwrap();
        std::fs::write(&bw, [0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0x00, 0x00, 0x01]).unwrap();
        let err = Bw::from_paths(&node, &bw).unwrap_err();
        assert!(err.contains("not the Node.js build"), "{err}");
    }

    #[tokio::test]
    async fn output_is_read_whole_across_buffer_growth() {
        let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        let out = read_zeroizing(&data[..]).await.unwrap();
        assert_eq!(&out[..], &data[..]);
    }

    /// The point of the loader (#1): `bw` gets the session and its arguments, and `ps` shows neither
    /// the session in argv nor in the environment. Needs a real `node`; skipped without one.
    #[tokio::test]
    async fn loader_passes_the_session_out_of_sight_of_ps() {
        let Some(node) = which("node") else {
            eprintln!("node not on PATH; skipped");
            return;
        };
        let d = TempDir::new("loader");
        let script = d.0.join("fake-bw.js");
        std::fs::write(
            &script,
            r#"#!/usr/bin/env node
const { execFileSync } = require('child_process');
const ps = execFileSync('/bin/ps', ['eww', '-o', 'command=', '-p', String(process.pid)]).toString();
console.log(JSON.stringify({ session: process.env.BW_SESSION, args: process.argv.slice(2), ps }));
"#,
        )
        .unwrap();
        let bw = Bw { node, script };
        let marker = "c2Vzc2lvbi1tYXJrZXItbm90LWEtcmVhbC1rZXk=";
        let out = bw.run(Some(&SecretString::from(marker.to_owned())), &["get", "item", "--", "x y"]).await.unwrap();
        assert!(out.ok, "{}", out.stderr);
        #[derive(Deserialize)]
        struct Seen {
            session: String,
            args: Vec<String>,
            ps: String,
        }
        let seen: Seen = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(seen.session, marker);
        assert_eq!(seen.args, ["get", "item", "--", "x y"]);
        assert!(seen.ps.contains("fake-bw.js"), "ps did not show the process: {}", seen.ps);
        assert!(!seen.ps.contains(marker), "session visible to ps: {}", seen.ps);
    }
}
