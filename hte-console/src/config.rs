//! Everything HTE-specific comes from the environment, never from this repository.

use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct Config {
    /// `HTE_CONSOLE_UPSTREAM`: base URL of the PHP console, e.g. `http://host:8080`.
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
}

fn list(name: &str) -> Vec<String> {
    std::env::var(name)
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn num(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.trim().parse().ok()).unwrap_or(default)
}

impl Config {
    pub fn from_env() -> Result<Config, String> {
        let upstream = std::env::var("HTE_CONSOLE_UPSTREAM")
            .map_err(|_| "HTE_CONSOLE_UPSTREAM is not set (the PHP console's base URL)".to_string())?
            .trim_end_matches('/')
            .to_string();
        let mut prefixes = list("HTE_CONSOLE_CAPTURE_PREFIXES");
        if prefixes.is_empty() {
            prefixes.push("/api/".into());
        }
        Ok(Config {
            upstream,
            listen: std::env::var("HTE_CONSOLE_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".into()),
            fixtures: std::env::var("HTE_CONSOLE_FIXTURES").ok().filter(|s| !s.is_empty()).map(PathBuf::from),
            capture_prefixes: prefixes,
            capture_max_bytes: num("HTE_CONSOLE_CAPTURE_MAX_BYTES", 256 * 1024) as usize,
            connect_timeout: Duration::from_secs(num("HTE_CONSOLE_CONNECT_TIMEOUT_SECS", 3)),
            request_timeout: Duration::from_secs(num("HTE_CONSOLE_REQUEST_TIMEOUT_SECS", 60)),
            max_body: num("HTE_CONSOLE_MAX_BODY_BYTES", 600 * 1024 * 1024) as usize,
        })
    }
}
