//! Everything HTE-specific comes from the environment, never from this repository.

use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct Config {
    /// `HTE_CONSOLE_UPSTREAM`: base URL of the previous console, e.g. `http://host:8080`.
    pub upstream: String,
    /// `HTE_CONSOLE_LISTEN`: address to listen on (default `0.0.0.0:8080`).
    pub listen: String,
    /// `HTE_CONSOLE_FIXTURES`: where fixtures are written. Unset = proxy only, record nothing.
    pub fixtures: Option<PathBuf>,
    /// `HTE_CONSOLE_CAPTURE_PREFIXES`: comma list of path prefixes that are recorded (default `/api/`).
    /// Everything else is forwarded and never recorded (console pages carry names, tokens, sessions).
    pub capture_prefixes: Vec<String>,
    /// `HTE_CONSOLE_CAPTURE_MAX_BYTES`: bodies larger than this are forwarded but not recorded (default 256 KiB).
    pub capture_max_bytes: usize,
    // Also from the environment, read by the sanitiser itself (see main.rs): `HTE_CONSOLE_SANITISE_SALT` (key of the
    // stable placeholders; random per run when unset) and `HTE_CONSOLE_SANITISE_LITERALS` (comma list of host names,
    // domains and other literals that are always replaced).
    /// `HTE_CONSOLE_CONNECT_TIMEOUT_SECS` (default 3) and `HTE_CONSOLE_REQUEST_TIMEOUT_SECS` (default 60).
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    /// `HTE_CONSOLE_MAX_BODY_BYTES`: largest request body accepted (default 600 MiB, as Caddy's).
    pub max_body: usize,
    /// Phase 1: set when `HTE_CONSOLE_DATABASE` is; the device endpoints are then answered here, not by the previous console.
    pub native: Option<NativeConfig>,
}

/// Phase 1 settings (the device endpoints served natively).
#[derive(Clone, Debug)]
pub struct NativeConfig {
    /// `HTE_CONSOLE_DATABASE`: the previous console's SQLite file (`/data/cortendesk.sqlite`), shared with the previous console.
    pub database: PathBuf,
    /// `HTE_CONSOLE_APP_KEY_FILE` (default `/data/.app_key`), or `APP_KEY` when set, as the CortenDesk image reads it.
    /// Holds a secret: never logged.
    pub app_key_file: PathBuf,
    /// `HTE_CONSOLE_HBBS_DB` (default `/data/rustdesk/db_v2.sqlite3`): hbbs's peers, read only.
    pub hbbs_db: PathBuf,
    /// `HTE_CONSOLE_TRUSTED_PROXIES` (else `TRUSTED_PROXIES`, else the previous console's default private ranges).
    pub trusted_proxies: String,
    /// `HTE_CONSOLE_API_VERSION` (else `HTE_REMOTE_API_VERSION`, else the previous console's release this phase ports).
    pub api_version: String,
    /// `HTE_CONSOLE_DEVICE_MAX_BODY_BYTES` (default 1 MiB): largest body on the device endpoints.
    pub device_max_body: usize,
    /// `HTE_CONSOLE_DB_BUSY_MS` (default 10000): how long a write waits for the previous console's lock.
    pub busy: Duration,
    /// `HTE_CONSOLE_DB_WAL` (default 1): switch the file to WAL (persistent; the previous console needs no change).
    pub wal: bool,
}

/// The previous console's release whose behaviour phase 1 reproduces (its `VERSION` file).
pub const PORTED_PHP_VERSION: &str = "1.15.0-hte.1";

fn list(name: &str) -> Vec<String> {
    crate::envvar::var(name)
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// A variable that is set and not empty (compose passes `${VAR:-}` as an empty string).
fn set(name: &str) -> Option<String> {
    crate::envvar::var(name).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

fn num(name: &str, default: u64) -> u64 {
    crate::envvar::var(name).ok().and_then(|v| v.trim().parse().ok()).unwrap_or(default)
}

impl Config {
    pub fn from_env() -> Result<Config, String> {
        let native = crate::envvar::var("HTE_CONSOLE_DATABASE").ok().filter(|s| !s.is_empty()).map(|db| NativeConfig {
            database: PathBuf::from(db),
            app_key_file: PathBuf::from(crate::envvar::var("HTE_CONSOLE_APP_KEY_FILE").unwrap_or_else(|_| "/data/.app_key".into())),
            hbbs_db: PathBuf::from(crate::envvar::var("HTE_CONSOLE_HBBS_DB").unwrap_or_else(|_| "/data/rustdesk/db_v2.sqlite3".into())),
            trusted_proxies: set("HTE_CONSOLE_TRUSTED_PROXIES")
                .or_else(|| set("TRUSTED_PROXIES"))
                .unwrap_or_else(|| crate::laravel::DEFAULT_TRUSTED.into()),
            api_version: set("HTE_CONSOLE_API_VERSION").or_else(|| set("HTE_REMOTE_API_VERSION")).unwrap_or_else(|| PORTED_PHP_VERSION.into()),
            device_max_body: num("HTE_CONSOLE_DEVICE_MAX_BODY_BYTES", 1024 * 1024) as usize,
            busy: Duration::from_millis(num("HTE_CONSOLE_DB_BUSY_MS", 10_000)),
            wal: num("HTE_CONSOLE_DB_WAL", 1) != 0,
        });
        // The upstream (the previous console) is what the shadow forwards to; with native routes it only answers the rest.
        let upstream = match crate::envvar::var("HTE_CONSOLE_UPSTREAM") {
            Ok(u) => u.trim_end_matches('/').to_string(),
            Err(_) if native.is_some() => String::new(),
            Err(_) => return Err("HTE_CONSOLE_UPSTREAM is not set (the previous console's base URL)".to_string()),
        };
        let mut prefixes = list("HTE_CONSOLE_CAPTURE_PREFIXES");
        if prefixes.is_empty() {
            prefixes.push("/api/".into());
        }
        Ok(Config {
            upstream,
            listen: crate::envvar::var("HTE_CONSOLE_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".into()),
            fixtures: crate::envvar::var("HTE_CONSOLE_FIXTURES").ok().filter(|s| !s.is_empty()).map(PathBuf::from),
            capture_prefixes: prefixes,
            capture_max_bytes: num("HTE_CONSOLE_CAPTURE_MAX_BYTES", 256 * 1024) as usize,
            connect_timeout: Duration::from_secs(num("HTE_CONSOLE_CONNECT_TIMEOUT_SECS", 3)),
            request_timeout: Duration::from_secs(num("HTE_CONSOLE_REQUEST_TIMEOUT_SECS", 60)),
            max_body: num("HTE_CONSOLE_MAX_BODY_BYTES", 600 * 1024 * 1024) as usize,
            native,
        })
    }
}
