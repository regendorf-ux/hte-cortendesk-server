//! The off-site copy of a backup (the previous console's `App\Services\Backups\RemoteTarget`): somewhere off the box a finished archive
//! is mirrored to. Blocking on purpose: the backup code runs in `spawn_blocking` / the scheduler's worker thread.
//! Every method returns an operator-readable message on failure; nothing retries, the next run does.

use crate::backup::{self, Env};
use std::path::Path;

pub trait Remote: Send {
    /// Upload a local file under the given name.
    fn put(&self, local: &Path, name: &str) -> Result<(), String>;
    /// The files present at the target (directory prefix stripped) with their size, None where the target does not say.
    fn list(&self) -> Result<Vec<(String, Option<u64>)>, String>;
    fn delete(&self, name: &str) -> Result<(), String>;
    /// Prove the credentials and location work; returns a one-line summary.
    fn test(&self) -> Result<String, String>;
    /// For log lines and the UI: "S3 bucket backups" / "FTP host:21".
    fn label(&self) -> String;
}

/// The configured target, or None when copies are off. Secrets are read from the settings table and decrypted with the app key.
pub fn target(env: &Env, c: &rusqlite::Connection) -> Result<Option<Box<dyn Remote>>, String> {
    let s = backup::settings(c)?;
    let get = |k: &str, d: &str| backup::setting_value(c, k, d);
    let plain = |k: &str| backup::setting_value(c, k, "").unwrap_or_default();
    let secret = |k: &str| -> String {
        let stored = plain(k);
        if stored.is_empty() {
            return String::new();
        }
        crate::laravel::Encrypter::from_app_key(&env.app_key).ok().and_then(|e| e.decrypt_string(stored.as_bytes()).ok()).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default()
    };
    Ok(match s.target.as_str() {
        "ftp" => Some(Box::new(crate::backup_ftp::Ftp {
            host: get("backup_ftp_host", "")?,
            port: get("backup_ftp_port", "21")?.parse().ok().filter(|p| *p > 0).unwrap_or(21),
            username: get("backup_ftp_username", "")?,
            password: secret("backup_ftp_password"),
            path: get("backup_ftp_path", "")?,
            tls: get("backup_ftp_tls", "0")? == "1",
        })),
        "s3" => Some(Box::new(crate::backup_s3::S3 {
            bucket: get("backup_s3_bucket", "")?,
            region: get("backup_s3_region", "")?,
            access_key: get("backup_s3_access_key", "")?,
            secret_key: secret("backup_s3_secret_key"),
            endpoint: get("backup_s3_endpoint", "")?,
            prefix: get("backup_s3_prefix", "")?,
            path_style: get("backup_s3_path_style", "0")? == "1",
        })),
        _ => None,
    })
}

/// Two runs copying at once can leave a copy that is full size but wrong, which no size check catches; the second leaves
/// the target alone. `flock`, as the previous console: the kernel lets go when a run dies.
struct CopyLock(Option<std::fs::File>);

impl CopyLock {
    fn take(env: &Env) -> Result<CopyLock, String> {
        use std::os::unix::io::AsRawFd;
        for path in [env.backups_dir.join(".backup-copy.lock"), std::env::temp_dir().join("hte-remote-backup-copy.lock")] {
            let f = std::fs::OpenOptions::new().create(true).write(true).open(&path).or_else(|_| std::fs::File::open(&path));
            if let Ok(f) = f {
                if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                    return Err("Another run is copying to the off-site target right now, so this one left it alone. Its backup goes up with the next run.".into());
                }
                return Ok(CopyLock(Some(f)));
            }
        }
        tracing::warn!("Backup off-site copy runs without its lock: no lock file could be opened.");
        Ok(CopyLock(None))
    }
}

impl Drop for CopyLock {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;
        if let Some(f) = &self.0 {
            unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_UN) };
        }
    }
}

#[derive(Debug, Default)]
pub struct Synced {
    pub uploaded: Vec<String>,
    pub deleted: Vec<String>,
}

/// `syncRemote()` / `mirror()`: the target is brought in line with the local list, oldest first so a run cut short
/// leaves the remote a prefix of the local list rather than holes in it.
pub fn sync(env: &Env, target: &dyn Remote) -> Result<Synced, String> {
    let _lock = CopyLock::take(env)?;
    let local = backup::list(env)?;
    let remote: std::collections::BTreeMap<String, Option<u64>> = target.list()?.into_iter().filter(|(n, _)| backup::is_backup_name(n)).collect();
    let mut out = Synced::default();
    for b in local.iter().rev() {
        let missing = match remote.get(&b.name) {
            None => true,
            // there at another size: a copy cut short by a run that died mid-upload would otherwise count as copied for good
            Some(Some(size)) => *size != b.size,
            Some(None) => false,
        };
        if missing {
            target.put(&b.path, &b.name)?;
            out.uploaded.push(b.name.clone());
        }
    }
    for name in remote.keys() {
        if !local.iter().any(|b| &b.name == name) {
            target.delete(name)?;
            out.deleted.push(name.clone());
        }
    }
    Ok(out)
}
