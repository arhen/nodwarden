//! Runs the Bitwarden CLI without exposing the vault session.
//!
//! `bw` is a Node script, and macOS lets same-user processes read the
//! environment of non-platform binaries (`ps eww`). So the session is never put
//! in `bw`'s environment or argv: `node` runs a tiny loader that reads the
//! session from its stdin, sets `process.env.BW_SESSION` inside the process,
//! and then loads `bw`. `ps` sees neither.
//!
//! Paths to `node` and `bw.js` are resolved once at start, to absolute real
//! paths, and refused if any user-writable-by-others location is involved.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use tokio::io::AsyncWriteExt;
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

#[derive(Clone, Debug)]
pub struct Bw {
    pub node: PathBuf,
    pub script: PathBuf,
}

impl Bw {
    /// Resolves `node` and the real `bw.js` behind the `bw` on PATH.
    pub fn resolve() -> Result<Self, String> {
        let bw = which("bw").ok_or("bw not found on PATH")?;
        let script = std::fs::canonicalize(&bw).map_err(|e| format!("bw: {e}"))?;
        let node = std::fs::canonicalize(which("node").ok_or("node not found on PATH")?)
            .map_err(|e| format!("node: {e}"))?;
        for p in [&node, &script] {
            check_not_shared_writable(p)?;
        }
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
        let out = tokio::time::timeout(TIMEOUT, child.wait_with_output())
            .await
            .map_err(|_| "bw timed out".to_string())?
            .map_err(|e| format!("bw: {e}"))?;
        Ok(Output {
            ok: out.status.success(),
            stdout: Zeroizing::new(out.stdout),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }

    pub async fn status(&self, session: Option<&SecretString>) -> Option<String> {
        #[derive(Deserialize)]
        struct S {
            status: String,
        }
        let out = self.run(session, &["status"]).await.ok()?;
        serde_json::from_slice::<S>(&out.stdout).ok().map(|s| s.status)
    }

    pub async fn lock(&self) {
        let _ = self.run(None, &["lock"]).await;
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

fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

/// Refuses a file whose file or any parent directory is writable by group or others.
/// The owner's own dirs (e.g. ~/.n/bin) are accepted: a same-user attacker is out of scope.
pub fn check_not_shared_writable(p: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let mut cur = Some(p);
    while let Some(c) = cur {
        if let Ok(m) = std::fs::metadata(c) {
            let sticky = m.mode() & 0o1000 != 0;
            if m.mode() & 0o022 != 0 && !sticky {
                return Err(format!("{} is writable by other users; refusing to run it", c.display()));
            }
        }
        cur = c.parent();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_world_writable_dir() {
        let d = std::env::temp_dir().join(format!("nw-ww-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("bw");
        std::fs::write(&f, "x").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(check_not_shared_writable(&f).is_err());
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(check_not_shared_writable(&f).is_ok());
        std::fs::remove_dir_all(&d).unwrap();
    }
}
