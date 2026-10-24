//! Phase 1: the device-facing endpoints served natively (no PHP), each a port of the PHP console's handler:
//!
//!   POST /api/heartbeat, /api/sysinfo            SyncController       (sync.rs)
//!   POST /api/audit/conn, /api/audit/file, /alarm AuditController      (audit.rs)
//!   GET  /api/version                            routes/api.php
//!
//! This file is the HTTP side shared by all of them, written from Laravel's own behaviour: the global middleware
//! (TrustProxies, HandleCors, ValidatePostSize, TrimStrings, ConvertEmptyStringsToNull), the `device-sync`
//! rate limiter with its headers, and the JSON error bodies Laravel renders for `api/*` with APP_DEBUG off.
//! Everything else is forwarded to PHP by the phase 0 proxy (or answered 404 when no upstream is configured).

use crate::laravel::{self, Encrypter, Input, Trusted};
use crate::php::Fault;
use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use axum::routing::any;
use axum::Router;
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Everything a native handler needs.
pub struct Native {
    pub db: Mutex<Connection>,
    pub crypt: Encrypter,
    /// hbbs's database (`/data/rustdesk/db_v2.sqlite3`), read only, for the device keys.
    pub hbbs_db: PathBuf,
    pub trusted: Trusted,
    /// What `GET /api/version` answers (the PHP console's `VERSION`).
    pub api_version: String,
    /// Largest request body accepted on these endpoints.
    pub max_body: usize,
    pub limiter: Mutex<Limiter>,
    pub nonces: Mutex<Nonces>,
    /// Unix seconds; tests replace it.
    pub clock: Box<dyn Fn() -> i64 + Send + Sync>,
}

impl Native {
    pub fn now(&self) -> i64 {
        (self.clock)()
    }

    /// Open everything phase 1 needs, or say exactly what is missing. Nothing secret is logged.
    pub fn open(cfg: &crate::config::NativeConfig) -> Result<Native, String> {
        check_owner(&cfg.database)?;
        // As the PHP image's entrypoint: APP_KEY from the environment when set, else the file in /data.
        let key = match std::env::var("APP_KEY").ok().filter(|k| !k.trim().is_empty()) {
            Some(k) => k,
            None => std::fs::read_to_string(&cfg.app_key_file).map_err(|e| format!("cannot read the app key ({}): {e}", cfg.app_key_file.display()))?,
        };
        let crypt = Encrypter::from_app_key(&key)?;
        let conn = crate::sqlite::open(&cfg.database, cfg.busy, cfg.wal)?;
        warn_unported(&conn);
        sodiumoxide::init().map_err(|_| "libsodium did not initialise".to_string())?;
        let trusted = laravel::parse_trusted(&cfg.trusted_proxies);
        if !trusted.ignored.is_empty() {
            // as PHP: such an entry trusts nothing (names only, never a secret)
            tracing::warn!(entries = ?trusted.ignored, "trusted proxies: entries that are no address or range are ignored");
        }
        if trusted.is_empty() {
            tracing::warn!("no trusted proxies: every client address is the TCP peer");
        }
        Ok(Native {
            db: Mutex::new(conn),
            crypt,
            hbbs_db: cfg.hbbs_db.clone(),
            trusted,
            api_version: cfg.api_version.clone(),
            max_body: cfg.device_max_body,
            limiter: Mutex::new(Limiter::default()),
            nonces: Mutex::new(Nonces::default()),
            clock: Box::new(|| std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)),
        })
    }
}

/// SQLite creates the -wal/-shm/-journal files with the database's mode but the creating process's owner
/// (unless it runs as root, when it hands them to the database's owner). A different non-root user would leave
/// files PHP cannot write, so refuse to start rather than break PHP.
fn check_owner(db: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(db).map_err(|e| format!("cannot stat {}: {e}", db.display()))?;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let me = unsafe { libc::geteuid() };
    if me != 0 && me != meta.uid() {
        return Err(format!(
            "{} belongs to uid {}, this process runs as uid {}: run as that uid (compose `user:`) or as root",
            db.display(),
            meta.uid(),
            me
        ));
    }
    Ok(())
}

/// Say at start-up when a setting asks for behaviour phase 1 does not port.
fn warn_unported(c: &Connection) {
    if let Ok(v) = crate::sqlite::setting(c, "apprise_enabled", "0") {
        if v == b"1" {
            tracing::warn!("apprise_enabled is 1: hte-console does not send device/alarm notifications (phase 1 ports none)");
        }
    }
}

// ------------------------------------------------------------------------------------------- responses ---

/// An answer, as Laravel would build it.
#[derive(Debug, Clone, PartialEq)]
pub enum Reply {
    /// `response()->json(...)`: the encoded body.
    Json(u16, String),
    /// `response('...')`: text/html, as Laravel labels a plain string.
    Text(u16, Vec<u8>),
}

impl Reply {
    pub fn text(s: &str) -> Reply {
        Reply::Text(200, s.as_bytes().to_vec())
    }
    /// The audit endpoints' success: 200 with an empty body.
    pub fn stored() -> Reply {
        Reply::Text(200, vec![])
    }
    /// What Laravel renders for an uncaught exception on `api/*` with APP_DEBUG off.
    pub fn server_error() -> Reply {
        Reply::Json(500, r#"{"message":"Server Error"}"#.into())
    }
}

/// An uncaught exception in PHP: log it (never the request), answer like Laravel.
pub fn fail(where_: &str, f: &Fault) -> Reply {
    tracing::error!("{where_}: {}", match f {
        Fault::ArrayToString => "array where a string was expected (PHP: Array to string conversion)".to_string(),
        Fault::Other(m) => m.clone(),
    });
    Reply::server_error()
}

fn respond(r: Reply, extra: Vec<(&'static str, String)>, head: bool) -> Response<Body> {
    let (status, ct, body) = match r {
        Reply::Json(s, b) => (s, "application/json", b.into_bytes()),
        Reply::Text(s, b) => (s, "text/html; charset=UTF-8", b),
    };
    let mut b = Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
        .header(header::CONTENT_TYPE, ct)
        .header(header::CACHE_CONTROL, "no-cache, private")
        .header("access-control-allow-origin", "*");
    for (k, v) in extra {
        if let Ok(v) = HeaderValue::from_str(&v) {
            b = b.header(k, v);
        }
    }
    b.body(if head { Body::empty() } else { Body::from(body) }).unwrap_or_else(|_| Response::new(Body::empty()))
}

fn json_message(status: u16, msg: &str) -> Reply {
    let mut s = String::new();
    let _ = crate::php::enc_str(msg.as_bytes(), &mut s);
    Reply::Json(status, format!(r#"{{"message":{s}}}"#))
}

// ---------------------------------------------------------------------------------------- rate limiting ---

/// Entries that each expire at most `window` seconds after they are written, kept in two generations: the older
/// one is dropped whole once everything in it has expired, so nothing is ever scanned, whatever a flood sends.
/// A generation that reaches `cap` entries starts the next one early (memory stays at two generations; under such
/// a flood some live entries are forgotten early, never kept beyond their time).
struct Generations<V> {
    cur: HashMap<[u8; 32], (V, i64)>,
    prev: HashMap<[u8; 32], (V, i64)>,
    started: i64,
    window: i64,
    cap: usize,
}

impl<V: Copy> Generations<V> {
    fn new(window: i64, cap: usize) -> Self {
        Generations { cur: HashMap::new(), prev: HashMap::new(), started: i64::MIN, window, cap }
    }
    /// The unexpired value and its expiry.
    fn get(&self, k: &[u8; 32], now: i64) -> Option<(V, i64)> {
        self.cur.get(k).or_else(|| self.prev.get(k)).copied().filter(|(_, exp)| now < *exp)
    }
    /// `exp` is capped at `now + window`.
    fn put(&mut self, k: [u8; 32], v: V, exp: i64, now: i64) {
        if now >= self.started.saturating_add(self.window) || self.cur.len() >= self.cap {
            self.prev = std::mem::take(&mut self.cur);
            self.started = now;
        }
        self.cur.insert(k, (v, exp.min(now.saturating_add(self.window))));
    }
    fn remove(&mut self, k: &[u8; 32]) {
        self.cur.remove(k);
        self.prev.remove(k);
    }
    #[cfg(test)]
    fn len(&self) -> usize {
        self.cur.len() + self.prev.len()
    }
}

/// Laravel's RateLimiter over its cache: a fixed window opened by the first hit, `decay` seconds long.
pub struct Limiter {
    buckets: Generations<u64>,
}

/// The longest decay any limit here uses (`device-sync`: a minute).
const LIMITER_WINDOW: i64 = 60;
const LIMITER_CAP: usize = 100_000;

impl Default for Limiter {
    fn default() -> Self {
        Limiter { buckets: Generations::new(LIMITER_WINDOW, LIMITER_CAP) }
    }
}

impl Limiter {
    fn key(k: &[u8]) -> [u8; 32] {
        Sha256::digest(k).into()
    }
    fn live(&self, k: &[u8; 32], now: i64) -> Option<(u64, i64)> {
        self.buckets.get(k, now)
    }
    pub fn too_many(&self, k: &[u8], max: u64, now: i64) -> bool {
        self.live(&Self::key(k), now).map_or(false, |(n, _)| n >= max)
    }
    pub fn hit(&mut self, k: &[u8], decay: i64, now: i64) {
        let key = Self::key(k);
        let (n, exp) = self.live(&key, now).unwrap_or((0, now + decay));
        self.buckets.put(key, n + 1, exp, now);
    }
    pub fn remaining(&self, k: &[u8], max: u64, now: i64) -> u64 {
        max.saturating_sub(self.live(&Self::key(k), now).map_or(0, |(n, _)| n))
    }
    pub fn available_in(&self, k: &[u8], now: i64) -> i64 {
        self.live(&Self::key(k), now).map_or(0, |(_, exp)| (exp - now).max(0))
    }
}

/// AppServiceProvider's `device-sync`: 120 a minute per address and device id, 6000 a minute per address.
fn device_sync_limits(ip: &str, id: &[u8]) -> [(Vec<u8>, u64); 2] {
    let mut device = format!("device-sync|device|{ip}|").into_bytes();
    device.extend_from_slice(id);
    [(device, 120), (format!("device-sync|address|{ip}").into_bytes(), 6000)]
}

// ------------------------------------------------------------------------------------------------ nonces ---

/// The audit endpoints' "seen this nonce" memory (Laravel: `Cache::add(key, true, 300)` in the file cache).
pub struct Nonces {
    seen: Generations<()>,
}

const NONCE_CAP: usize = 250_000;

impl Default for Nonces {
    fn default() -> Self {
        Nonces { seen: Generations::new(crate::audit::NONCE_TTL_SECONDS, NONCE_CAP) }
    }
}

impl Nonces {
    /// `Cache::add`: false when the key is already there and unexpired.
    pub fn add(&mut self, key: [u8; 32], ttl: i64, now: i64) -> bool {
        if self.seen.get(&key, now).is_some() {
            return false;
        }
        self.seen.put(key, (), now + ttl, now);
        true
    }
    pub fn forget(&mut self, key: &[u8; 32]) {
        self.seen.remove(key);
    }
}

// ---------------------------------------------------------------------------------------------- routing ---

#[derive(Clone, Copy, Debug)]
pub enum Endpoint {
    Heartbeat,
    Sysinfo,
    AuditConn,
    AuditFile,
    AuditAlarm,
    Version,
}

impl Endpoint {
    fn route(self) -> &'static str {
        match self {
            Endpoint::Heartbeat => "api/heartbeat",
            Endpoint::Sysinfo => "api/sysinfo",
            Endpoint::AuditConn => "api/audit/conn",
            Endpoint::AuditFile => "api/audit/file",
            Endpoint::AuditAlarm => "api/audit/alarm",
            Endpoint::Version => "api/version",
        }
    }
    fn methods(self) -> &'static [&'static str] {
        match self {
            Endpoint::Version => &["GET", "HEAD"],
            _ => &["POST"],
        }
    }
}

/// The native routes; `fallback` (the shadow proxy) answers everything else.
pub fn router(native: Arc<Native>, fallback: Option<Router>) -> Router {
    let mut r = Router::new();
    for (path, ep) in [
        ("/api/heartbeat", Endpoint::Heartbeat),
        ("/api/sysinfo", Endpoint::Sysinfo),
        ("/api/audit/conn", Endpoint::AuditConn),
        ("/api/audit/file", Endpoint::AuditFile),
        ("/api/audit/alarm", Endpoint::AuditAlarm),
        ("/api/version", Endpoint::Version),
    ] {
        r = r.route(path, any(move |s, c, req| handle(s, c, req, ep)));
    }
    let r = r.route("/__hte-console/health", any(|| async { "ok" })).with_state(native);
    match fallback {
        Some(f) => r.fallback_service(f),
        None => r.fallback(|| async { respond(json_message(404, "Not Found"), vec![], false) }),
    }
}

fn header_str<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

async fn handle(State(n): State<Arc<Native>>, ConnectInfo(peer): ConnectInfo<SocketAddr>, req: Request<Body>, ep: Endpoint) -> Response<Body> {
    let (parts, body) = req.into_parts();
    let method = parts.method.clone();
    let head = method == Method::HEAD;

    // HandleCors: a preflight (OPTIONS with Access-Control-Request-Method; fruitcake does not ask for Origin)
    // never reaches the route.
    if method == Method::OPTIONS && parts.headers.contains_key("access-control-request-method") {
        let mut extra = vec![
            ("access-control-allow-methods", header_str(&parts.headers, "access-control-request-method").unwrap_or("").to_ascii_uppercase()),
            ("access-control-max-age", "0".to_string()),
            ("vary", "Access-Control-Request-Method, Access-Control-Request-Headers".to_string()),
        ];
        if let Some(h) = header_str(&parts.headers, "access-control-request-headers") {
            extra.push(("access-control-allow-headers", h.to_string()));
        }
        return respond(Reply::Text(204, vec![]), extra, false);
    }
    if !ep.methods().contains(&method.as_str()) {
        if method == Method::OPTIONS {
            // the router answers OPTIONS for a known path itself
            return respond(Reply::Text(200, vec![]), vec![("allow", ep.methods().join(",")), ("vary", "Access-Control-Request-Method".into())], false);
        }
        let msg = format!("The {} method is not supported for route {}. Supported methods: {}.", method, ep.route(), ep.methods().join(", "));
        return respond(json_message(405, &msg), vec![("allow", ep.methods().join(", "))], head);
    }
    if let Endpoint::Version = ep {
        return respond(Reply::Text(200, n.api_version.as_bytes().to_vec()), vec![], head);
    }

    // ValidatePostSize, bounded here far below PHP's limit: no device sends more than a few kilobytes.
    let declared = header_str(&parts.headers, "content-length").and_then(|v| v.trim().parse::<u64>().ok());
    if declared.map_or(false, |l| l > n.max_body as u64) {
        return respond(json_message(413, "The POST data is too large."), vec![], false);
    }
    let body = match axum::body::to_bytes(body, n.max_body).await {
        Ok(b) => b,
        Err(_) => return respond(json_message(413, "The POST data is too large."), vec![], false),
    };
    let xff: Vec<&str> = parts.headers.get_all("x-forwarded-for").iter().filter_map(|v| v.to_str().ok()).collect();
    let ip = laravel::client_ip(peer.ip(), &xff, &n.trusted);
    let input = Input::new(method.as_str(), header_str(&parts.headers, header::CONTENT_TYPE.as_str()), parts.uri.query(), &body);

    let n2 = n.clone();
    let out = tokio::task::spawn_blocking(move || throttled(&n2, ep, &input, &ip)).await;
    match out {
        Ok((reply, headers)) => respond(reply, headers, false),
        Err(_) => respond(Reply::server_error(), vec![], false),
    }
}

/// The `throttle:device-sync` middleware around a handler, then the handler itself.
fn throttled(n: &Native, ep: Endpoint, input: &Input, ip: &str) -> (Reply, Vec<(&'static str, String)>) {
    // The limiter reads `(string) $request->input('id')` first: an array id fails here, before any hit.
    let id = match input.string("id") {
        Ok(id) => id,
        Err(f) => return (fail("device-sync limiter", &f), vec![]),
    };
    let now = n.now();
    let limits = device_sync_limits(ip, &id);
    {
        let mut l = n.limiter.lock().unwrap_or_else(|e| e.into_inner());
        for (k, max) in &limits {
            if l.too_many(k, *max, now) {
                let retry = l.available_in(k, now);
                let headers = vec![
                    ("x-ratelimit-limit", max.to_string()),
                    ("x-ratelimit-remaining", "0".to_string()),
                    ("retry-after", retry.to_string()),
                    ("x-ratelimit-reset", (now + retry).to_string()),
                ];
                return (json_message(429, "Too Many Attempts."), headers);
            }
        }
        for (k, _) in &limits {
            l.hit(k, 60, now);
        }
    }
    let reply = {
        let conn = n.db.lock().unwrap_or_else(|e| e.into_inner());
        match ep {
            Endpoint::Heartbeat => crate::sync::heartbeat(n, &conn, input, ip, now),
            Endpoint::Sysinfo => crate::sync::sysinfo(n, &conn, input, ip, now),
            Endpoint::AuditConn => crate::audit::connection(n, &conn, input, ip, now),
            Endpoint::AuditFile => crate::audit::file(n, &conn, input, ip, now),
            Endpoint::AuditAlarm => crate::audit::alarm(n, &conn, input, now),
            Endpoint::Version => Reply::text(&n.api_version),
        }
    };
    // An uncaught exception skips the limiter's headers; any other answer gets them.
    if reply == Reply::server_error() {
        return (reply, vec![]);
    }
    let l = n.limiter.lock().unwrap_or_else(|e| e.into_inner());
    let mut shown: Option<(u64, u64)> = None;
    for (k, max) in &limits {
        let rem = l.remaining(k, *max, now);
        // addHeaders keeps the earlier pair unless this limit has fewer attempts left
        if shown.map_or(true, |(_, r)| r > rem) {
            shown = Some((*max, rem));
        }
    }
    let headers = shown.map_or(vec![], |(m, r)| vec![("x-ratelimit-limit", m.to_string()), ("x-ratelimit-remaining", r.to_string())]);
    (reply, headers)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(i: u32) -> [u8; 32] {
        Sha256::digest(i.to_be_bytes()).into()
    }

    #[test]
    fn generations_keep_live_entries_and_drop_expired_ones_whole() {
        let mut g: Generations<u32> = Generations::new(60, 1_000);
        g.put(k(1), 1, 60, 0);
        g.put(k(2), 2, 90, 30);
        g.put(k(3), 3, 120, 60); // starts the second generation: the first is still read
        assert_eq!(g.get(&k(2), 80), Some((2, 90)));
        assert_eq!(g.get(&k(1), 60), None);
        g.put(k(4), 4, 180, 120); // third generation: the first, all expired by now, is gone
        assert_eq!(g.len(), 2);
        assert_eq!(g.get(&k(3), 119), Some((3, 120)));
        g.remove(&k(3));
        assert_eq!(g.get(&k(3), 119), None);
        // an expiry past the window is cut to it
        g.put(k(5), 5, 1_000, 130);
        assert_eq!(g.get(&k(5), 130), Some((5, 190)));
    }

    #[test]
    fn a_flood_never_grows_past_two_generations() {
        let mut g: Generations<()> = Generations::new(300, 100);
        for i in 0..10_000 {
            g.put(k(i), (), 300, 0);
        }
        assert!(g.len() <= 200, "{}", g.len());
        assert!(g.get(&k(9_999), 0).is_some());
    }

    #[test]
    fn limiter_counts_across_a_generation_change() {
        let mut l = Limiter::default();
        for _ in 0..3 {
            l.hit(b"a", 60, 50);
        }
        l.hit(b"b", 60, 70); // new generation
        l.hit(b"a", 60, 80);
        assert_eq!(l.remaining(b"a", 5, 80), 1);
        assert_eq!(l.available_in(b"a", 80), 30);
        assert!(!l.too_many(b"a", 5, 109));
        assert_eq!(l.remaining(b"a", 5, 110), 5);
    }

    #[test]
    fn nonces_once_then_again_after_ttl_or_forget() {
        let mut n = Nonces::default();
        assert!(n.add(k(1), 300, 0));
        assert!(!n.add(k(1), 300, 299));
        assert!(n.add(k(1), 300, 300));
        n.forget(&k(1));
        assert!(n.add(k(1), 300, 301));
    }
}
