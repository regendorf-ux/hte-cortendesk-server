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
    /// Phase 2: the client sign-in's process memory and the identity provider side.
    pub signin: crate::signin::State,
    /// Unix seconds; tests replace it.
    pub clock: Box<dyn Fn() -> i64 + Send + Sync>,
}

impl Native {
    pub fn now(&self) -> i64 {
        (self.clock)()
    }

    /// Whether the clock was set with HTE_CONSOLE_CLOCK_START (the local page comparison), not the wall clock.
    pub fn clock_is_set(&self) -> bool {
        crate::envvar::var("HTE_CONSOLE_CLOCK_START").map_or(false, |v| !v.trim().is_empty())
    }

    /// Open everything phase 1 needs, or say exactly what is missing. Nothing secret is logged.
    pub fn open(cfg: &crate::config::NativeConfig) -> Result<Native, String> {
        check_owner(&cfg.database)?;
        // As the PHP image's entrypoint: APP_KEY from the environment when set, else the file in /data.
        let key = match crate::envvar::var("APP_KEY").ok().filter(|k| !k.trim().is_empty()) {
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
            signin: crate::signin::State::from_env(),
            clock: clock_from_env(),
        })
    }
}

fn real_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// The wall clock, or with `HTE_CONSOLE_CLOCK_START=<unix>` a clock that starts at that moment and runs on from there:
/// for the local page comparison against PHP answers captured earlier (`replay/compare-local.sh`), so "5 minutes ago"
/// and the dates read as they did when PHP answered. Never set in production.
fn clock_from_env() -> Box<dyn Fn() -> i64 + Send + Sync> {
    match crate::envvar::var("HTE_CONSOLE_CLOCK_START").ok().and_then(|v| v.trim().parse::<i64>().ok()) {
        Some(start) => {
            let offset = start - real_now();
            tracing::warn!("HTE_CONSOLE_CLOCK_START is set: the console's clock runs from {start}, not the wall clock");
            Box::new(move || real_now() + offset)
        }
        None => Box::new(real_now),
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
    if let Ok(v) = crate::sqlite::setting(c, "oidc_enabled", "0") {
        if v == b"1" && crate::envvar::var("HTE_CONSOLE_PUBLIC_URL").map_or(true, |u| u.trim().is_empty()) {
            tracing::warn!("SSO is on and HTE_CONSOLE_PUBLIC_URL is not set: the OIDC redirect URI is built from each request's Host header (as PHP does); set it to the console's https origin");
        }
    }
    if let Ok(v) = crate::sqlite::setting(c, "email_login_verification", "0") {
        if v == b"1" {
            tracing::warn!("email_login_verification is 1: hte-console sends no mail, so a password sign-in that would get an emailed code is refused (PHP's own answer when mail fails)");
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

pub(crate) fn respond(r: Reply, extra: Vec<(&'static str, String)>, head: bool) -> Response<Body> {
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

pub(crate) fn json_message(status: u16, msg: &str) -> Reply {
    let mut s = String::new();
    let _ = crate::php::enc_str(msg.as_bytes(), &mut s);
    Reply::Json(status, format!(r#"{{"message":{s}}}"#))
}

// ---------------------------------------------------------------------------------------- rate limiting ---

/// Entries that each expire at most `window` seconds after they are written, kept in two generations: the older
/// one is dropped whole once everything in it has expired, so nothing is ever scanned, whatever a flood sends.
/// A generation that reaches `cap` entries starts the next one early (memory stays at two generations; under such
/// a flood some live entries are forgotten early, never kept beyond their time).
pub struct Generations<V> {
    cur: HashMap<[u8; 32], (V, i64)>,
    prev: HashMap<[u8; 32], (V, i64)>,
    started: i64,
    window: i64,
    cap: usize,
}

impl<V: Clone> Generations<V> {
    pub fn new(window: i64, cap: usize) -> Self {
        Generations { cur: HashMap::new(), prev: HashMap::new(), started: i64::MIN, window, cap }
    }
    /// The unexpired value and its expiry.
    pub fn get(&self, k: &[u8; 32], now: i64) -> Option<(V, i64)> {
        self.cur.get(k).or_else(|| self.prev.get(k)).cloned().filter(|(_, exp)| now < *exp)
    }
    /// `exp` is capped at `now + window`.
    pub fn put(&mut self, k: [u8; 32], v: V, exp: i64, now: i64) {
        if now >= self.started.saturating_add(self.window) || self.cur.len() >= self.cap {
            self.prev = std::mem::take(&mut self.cur);
            self.started = now;
        }
        self.cur.insert(k, (v, exp.min(now.saturating_add(self.window))));
    }
    pub fn remove(&mut self, k: &[u8; 32]) {
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
    /// `RateLimiter::clear($key)`
    pub fn clear(&mut self, k: &[u8]) {
        self.buckets.remove(&Self::key(k));
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endpoint {
    Heartbeat,
    Sysinfo,
    AuditConn,
    AuditFile,
    AuditAlarm,
    Version,
    // phase 2
    LoginOptions,
    Login,
    Logout,
    CurrentUser,
    OidcAuth,
    OidcAuthQuery,
    ClientCallback,
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
            Endpoint::LoginOptions => "api/login-options",
            Endpoint::Login => "api/login",
            Endpoint::Logout => "api/logout",
            Endpoint::CurrentUser => "api/currentUser",
            Endpoint::OidcAuth => "api/oidc/auth",
            Endpoint::OidcAuthQuery => "api/oidc/auth-query",
            Endpoint::ClientCallback => "login/oidc/client-callback",
        }
    }
    fn methods(self) -> &'static [&'static str] {
        match self {
            Endpoint::Version | Endpoint::LoginOptions | Endpoint::OidcAuthQuery | Endpoint::ClientCallback => &["GET", "HEAD"],
            _ => &["POST"],
        }
    }
    /// Phase 2's routes: small bodies, their own limits.
    fn signin(self) -> bool {
        matches!(
            self,
            Endpoint::LoginOptions | Endpoint::Login | Endpoint::Logout | Endpoint::CurrentUser | Endpoint::OidcAuth | Endpoint::OidcAuthQuery | Endpoint::ClientCallback
        )
    }
    /// A web route (HTML answers, no CORS), not `api/*`.
    fn web(self) -> bool {
        self == Endpoint::ClientCallback
    }
}

/// Every path hte-console answers itself (phase 1 and phase 2), for the Caddy routes and the shadow's capture rule.
pub const NATIVE_PATHS: &[(&str, Endpoint)] = &[
    ("/api/heartbeat", Endpoint::Heartbeat),
    ("/api/sysinfo", Endpoint::Sysinfo),
    ("/api/audit/conn", Endpoint::AuditConn),
    ("/api/audit/file", Endpoint::AuditFile),
    ("/api/audit/alarm", Endpoint::AuditAlarm),
    ("/api/version", Endpoint::Version),
    ("/api/login-options", Endpoint::LoginOptions),
    ("/api/login", Endpoint::Login),
    ("/api/logout", Endpoint::Logout),
    ("/api/currentUser", Endpoint::CurrentUser),
    ("/api/oidc/auth", Endpoint::OidcAuth),
    ("/api/oidc/auth-query", Endpoint::OidcAuthQuery),
    ("/login/oidc/client-callback", Endpoint::ClientCallback),
];

/// The native routes; `fallback` (the shadow proxy) answers everything else.
pub fn router(native: Arc<Native>, fallback: Option<Router>) -> Router {
    let mut r = Router::new();
    for (path, ep) in NATIVE_PATHS.iter().copied() {
        r = r.route(path, any(move |s, c, req| handle(s, c, req, ep)));
    }
    let r = crate::client::mount(r); // phase 4: the bearer-token client endpoints
    let r = crate::admin::mount(r); // phase 5: the admin automation API and --assign
    let r = r.route("/__hte-console/health", any(|| async { "ok" })).with_state(native);
    match fallback {
        Some(f) => r.fallback_service(f),
        None => r.fallback(|| async { respond(json_message(404, "Not Found"), vec![], false) }),
    }
}

pub(crate) fn header_str<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

/// The largest body a sign-in route reads (`HTE_CONSOLE_SIGNIN_MAX_BODY_BYTES`, default 64 KiB): a sign-in is a few
/// hundred bytes.
fn signin_max_body() -> usize {
    crate::envvar::var("HTE_CONSOLE_SIGNIN_MAX_BODY_BYTES").ok().and_then(|v| v.trim().parse().ok()).unwrap_or(64 * 1024)
}

async fn handle(State(n): State<Arc<Native>>, ConnectInfo(peer): ConnectInfo<SocketAddr>, req: Request<Body>, ep: Endpoint) -> Response<Body> {
    let (parts, body) = req.into_parts();
    let method = parts.method.clone();
    let head = method == Method::HEAD;

    // HandleCors (api/* only): a preflight (OPTIONS with Access-Control-Request-Method; fruitcake does not ask for
    // Origin) never reaches the route.
    if !ep.web() && method == Method::OPTIONS && parts.headers.contains_key("access-control-request-method") {
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
            return respond_for(ep, Reply::Text(200, vec![]), vec![("allow", ep.methods().join(",")), ("vary", "Access-Control-Request-Method".into())], false);
        }
        if ep.web() {
            return page_response(405, crate::signin::error_page(405, "Method Not Allowed"), head);
        }
        let msg = format!("The {} method is not supported for route {}. Supported methods: {}.", method, ep.route(), ep.methods().join(", "));
        return respond(json_message(405, &msg), vec![("allow", ep.methods().join(", "))], head);
    }
    if let Endpoint::Version = ep {
        return respond(Reply::Text(200, n.api_version.as_bytes().to_vec()), vec![], head);
    }

    // ValidatePostSize, bounded here far below PHP's limit: no device sends more than a few kilobytes, no sign-in
    // more than a few hundred bytes.
    let max = if ep.signin() { signin_max_body() } else { n.max_body };
    let declared = header_str(&parts.headers, "content-length").and_then(|v| v.trim().parse::<u64>().ok());
    if declared.map_or(false, |l| l > max as u64) {
        return too_large(ep);
    }
    let body = match axum::body::to_bytes(body, max).await {
        Ok(b) => b,
        Err(_) => return too_large(ep),
    };
    let xff: Vec<&str> = parts.headers.get_all("x-forwarded-for").iter().filter_map(|v| v.to_str().ok()).collect();
    let ip = laravel::client_ip(peer.ip(), &xff, &n.trusted);
    let input = Input::new(method.as_str(), header_str(&parts.headers, header::CONTENT_TYPE.as_str()), parts.uri.query(), &body);

    if ep.signin() {
        let root = request_root(&n, &parts.headers, peer.ip());
        let bearer = laravel::bearer_token(parts.headers.get(header::AUTHORIZATION).map(|v| v.as_bytes()));
        return signin_route(n, ep, input, ip, root, bearer, head).await;
    }

    let n2 = n.clone();
    let out = tokio::task::spawn_blocking(move || throttled(&n2, ep, &input, &ip)).await;
    match out {
        Ok((reply, headers)) => respond(reply, headers, false),
        Err(_) => respond(Reply::server_error(), vec![], false),
    }
}

fn too_large(ep: Endpoint) -> Response<Body> {
    if ep.web() {
        return page_response(413, crate::signin::error_page(413, "Content Too Large"), false);
    }
    respond(json_message(413, "The POST data is too large."), vec![], false)
}

/// `respond`, without CORS for a web route.
fn respond_for(ep: Endpoint, r: Reply, extra: Vec<(&'static str, String)>, head: bool) -> Response<Body> {
    let mut resp = respond(r, extra, head);
    if ep.web() {
        resp.headers_mut().remove("access-control-allow-origin");
    }
    resp
}

/// An HTML page as Laravel sends a view (no session cookie: see the crate's notes).
fn page_response(status: u16, html: String, head: bool) -> Response<Body> {
    Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
        .header(header::CONTENT_TYPE, "text/html; charset=UTF-8")
        .header(header::CACHE_CONTROL, "no-cache, private")
        .header("x-content-type-options", "nosniff")
        .header("referrer-policy", "no-referrer")
        .body(if head { Body::empty() } else { Body::from(html) })
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

/// The console's origin for links and the OIDC redirect URI: `HTE_CONSOLE_PUBLIC_URL` when set (hardened: the
/// Host header then decides nothing); else as Laravel builds it (scheme from X-Forwarded-Proto, also untrusted as
/// the image's nginx passes `HTTPS=on`; Host and port; X-Forwarded-Port/-Prefix from a trusted proxy). None for a
/// Host Symfony would refuse.
pub(crate) fn request_root(n: &Native, h: &HeaderMap, peer: std::net::IpAddr) -> Option<String> {
    if let Some(u) = &n.signin.public_url {
        return Some(u.clone());
    }
    let trusted = n.trusted.trusts(&peer);
    let first = |name: &str| header_str(h, name).map(|v| v.split(',').next().unwrap_or("").trim().to_string());
    let proto = first("x-forwarded-proto").unwrap_or_default().to_ascii_lowercase();
    let secure = proto == "https" || (trusted && ["https", "on", "ssl", "1"].contains(&proto.as_str()));
    let scheme = if secure { "https" } else { "http" };
    let host_header = header_str(h, "host").unwrap_or("").trim().to_ascii_lowercase();
    let (host, host_port) = if let Some(rest) = host_header.strip_prefix('[') {
        let (h, tail) = rest.split_once(']')?;
        (format!("[{h}]"), tail.strip_prefix(':').and_then(|p| p.parse::<u16>().ok()))
    } else {
        match host_header.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse::<u16>().ok()),
            None => (host_header.clone(), None),
        }
    };
    // Symfony: preg_replace('/(?:^\[)?[a-zA-Z0-9-:\]_]+\.?/', '', $host) must leave nothing
    let ok = !host.is_empty() && host.chars().all(|c| c.is_ascii_alphanumeric() || "-.:[]_".contains(c));
    if !ok {
        return None;
    }
    let port = if trusted { first("x-forwarded-port").and_then(|p| p.parse::<u16>().ok()).or(host_port) } else { host_port };
    let default = if secure { 443 } else { 80 };
    let port = port.filter(|p| *p != default).map(|p| format!(":{p}")).unwrap_or_default();
    let prefix = if trusted { first("x-forwarded-prefix").map(|p| p.trim_end_matches('/').to_string()).unwrap_or_default() } else { String::new() };
    Some(format!("{scheme}://{host}{port}{prefix}"))
}

/// Laravel's `throttle:<max>,<minutes>,<prefix>` keys: the prefix and sha1 of `|<ip>` (no user on these routes).
fn throttle_key(prefix: &str, ip: &str) -> Vec<u8> {
    use sha1::Digest as _;
    format!("{prefix}{}", hex::encode(sha1::Sha1::digest(format!("|{ip}").as_bytes()))).into_bytes()
}

/// The throttles of a sign-in route, outermost first (routes/api.php: the `client-auth` group, then the route's own).
fn signin_limits(ep: Endpoint, ip: &str) -> Vec<(Vec<u8>, u64)> {
    let mut l = vec![];
    if matches!(ep, Endpoint::LoginOptions | Endpoint::Login | Endpoint::OidcAuth | Endpoint::OidcAuthQuery) {
        l.push((throttle_key("client-auth", ip), 240));
    }
    match ep {
        Endpoint::Login => l.push((throttle_key("client-login", ip), 20)),
        Endpoint::OidcAuth => l.push((throttle_key("client-oidc", ip), 20)),
        Endpoint::OidcAuthQuery => l.push((throttle_key("client-oidc-poll", ip), 400)),
        _ => {}
    }
    l
}

type Headers = Vec<(&'static str, String)>;

/// Nested ThrottleRequests middlewares on the way in: each checks, then hits, then passes on. The first that is
/// full answers 429 with its own headers (an outer one keeps them: they show fewer attempts left).
fn throttle_in(n: &Native, limits: &[(Vec<u8>, u64)], now: i64) -> Option<(Reply, Headers)> {
    let mut l = n.limiter.lock().unwrap_or_else(|e| e.into_inner());
    for (k, max) in limits {
        if l.too_many(k, *max, now) {
            let retry = l.available_in(k, now);
            return Some((
                json_message(429, "Too Many Attempts."),
                vec![
                    ("x-ratelimit-limit", max.to_string()),
                    ("x-ratelimit-remaining", "0".to_string()),
                    ("retry-after", retry.to_string()),
                    ("x-ratelimit-reset", (now + retry).to_string()),
                ],
            ));
        }
        l.hit(k, 60, now);
    }
    None
}

/// On the way out: the innermost sets its headers, an outer one replaces them only with fewer attempts left.
fn throttle_out(n: &Native, limits: &[(Vec<u8>, u64)], now: i64) -> Headers {
    let l = n.limiter.lock().unwrap_or_else(|e| e.into_inner());
    let mut shown: Option<(u64, u64)> = None;
    for (k, max) in limits.iter().rev() {
        let rem = l.remaining(k, *max, now);
        if shown.map_or(true, |(_, r)| rem < r) {
            shown = Some((*max, rem));
        }
    }
    shown.map_or(vec![], |(m, r)| vec![("x-ratelimit-limit", m.to_string()), ("x-ratelimit-remaining", r.to_string())])
}

pub(crate) async fn blocking<T: Send + 'static>(n: &Arc<Native>, f: impl FnOnce(&Native, &Connection) -> T + Send + 'static) -> Option<T> {
    let n2 = n.clone();
    tokio::task::spawn_blocking(move || {
        let conn = n2.db.lock().unwrap_or_else(|e| e.into_inner());
        f(&n2, &conn)
    })
    .await
    .ok()
}

/// Phase 2's routes: throttles, guard, handler.
async fn signin_route(n: Arc<Native>, ep: Endpoint, input: Input, ip: String, root: Option<String>, bearer: Option<Vec<u8>>, head: bool) -> Response<Body> {
    let now = n.now();
    let input = Arc::new(input);
    if ep == Endpoint::ClientCallback {
        return client_callback(n, input, ip, root, head, now).await;
    }
    let limits = signin_limits(ep, &ip);
    if let Some((r, h)) = throttle_in(&n, &limits, now) {
        return respond(r, h, head);
    }
    let reply = match ep {
        Endpoint::LoginOptions => blocking(&n, |n, c| crate::signin::login_options(n, c)).await,
        Endpoint::Login => {
            let (i, ip) = (input.clone(), ip.clone());
            blocking(&n, move |n, c| crate::signin::login(n, c, &i, &ip, now)).await
        }
        Endpoint::OidcAuthQuery => {
            let i = input.clone();
            blocking(&n, move |_, c| crate::signin::auth_query(c, &i, now)).await
        }
        Endpoint::Logout | Endpoint::CurrentUser => {
            let out = blocking(&n, move |_, c| -> Option<Reply> {
                match crate::signin::authenticate(c, bearer.as_deref(), now) {
                    Ok(None) => None,
                    Ok(Some((token, user))) => Some(if ep == Endpoint::Logout { crate::signin::logout(c, &token) } else { crate::signin::current_user(&user) }),
                    Err(f) => Some(fail("client-token guard", &f)),
                }
            })
            .await;
            match out {
                Some(None) => Some(json_message(401, "Unauthenticated.")),
                Some(Some(r)) => Some(r),
                None => None,
            }
        }
        Endpoint::OidcAuth => oidc_auth(&n, input.clone(), root, now).await,
        _ => None,
    };
    let reply = reply.unwrap_or_else(Reply::server_error);
    let headers = throttle_out(&n, &limits, now);
    respond(reply, headers, head)
}

/// POST /api/oidc/auth: the row first (database), then the provider's discovery (network, no lock held).
async fn oidc_auth(n: &Arc<Native>, input: Arc<Input>, root: Option<String>, now: i64) -> Option<Reply> {
    let i = input.clone();
    let started = blocking(n, move |n, c| crate::signin::oidc_start(n, c, &i, now)).await?;
    let st = match started {
        Err(f) => return Some(fail("oidc/auth", &f)),
        Ok(Err(reply)) => return Some(reply),
        Ok(Ok(st)) => st,
    };
    let Some(root) = root else {
        // Symfony refuses the Host header (SuspiciousOperationException -> 404)
        let _ = blocking(n, move |_, c| crate::sqlite::exec(c, r#"delete from "oidc_auth_requests" where "id" = ?"#, &[crate::sqlite::P(crate::php::Val::Int(st.id))])).await;
        return Some(json_message(404, "Bad hostname provided."));
    };
    let redirect = format!("{root}/login/oidc/client-callback");
    let url = n.signin.oidc.authorization_url(&st.settings, &redirect, &st.state, &st.nonce, &st.verifier).await;
    blocking(n, move |_, c| crate::signin::oidc_started(c, &st, url)).await
}

/// GET /login/oidc/client-callback: a page for the browser the client opened.
async fn client_callback(n: Arc<Native>, input: Arc<Input>, ip: String, root: Option<String>, head: bool, now: i64) -> Response<Body> {
    use crate::signin::{error_page, render_page, CallbackStart, Page};
    let Some(root) = root else { return page_response(404, error_page(404, "Not Found"), head) };
    let show = |p: Page| page_response(p.status, render_page(&p, &root, &n.signin.app_name, &n.api_version), head);
    let server_error = |w: &str, f: &crate::php::Fault| {
        let _ = fail(w, f);
        page_response(500, error_page(500, "Server Error"), head)
    };
    let i = input.clone();
    let start = match blocking(&n, move |n, c| crate::signin::callback_start(n, c, &i, now)).await {
        Some(Ok(s)) => s,
        Some(Err(f)) => return server_error("oidc client-callback", &f),
        None => return page_response(500, error_page(500, "Server Error"), head),
    };
    let (row, code, settings) = match start {
        CallbackStart::Page(p) => return show(p),
        CallbackStart::Exchange { row, code, settings } => (row, code, settings),
    };
    // one completion per state at a time; a second, concurrent use reads as expired
    let state = String::from_utf8_lossy(&row.val("state").to_php_string().unwrap_or_default()).into_owned();
    if !n.signin.inflight.lock().unwrap_or_else(|e| e.into_inner()).insert(state.clone()) {
        return show(Page { status: 400, ok: false, message: "This sign-in request has expired. Start again from HTE Remote.".into() });
    }
    // The exchange and the writes run in their own task: a browser that goes away mid-exchange (hyper then drops
    // this handler) neither leaves the state marked in flight nor stops the sign-in half way. The guard releases
    // the state however the task ends.
    struct Release(Arc<Native>, String);
    impl Drop for Release {
        fn drop(&mut self) {
            self.0.signin.inflight.lock().unwrap_or_else(|e| e.into_inner()).remove(&self.1);
        }
    }
    let release = Release(n.clone(), state);
    let redirect = format!("{root}/login/oidc/client-callback");
    let verifier = String::from_utf8_lossy(&row.val("verifier").to_php_string().unwrap_or_default()).into_owned();
    let nonce = String::from_utf8_lossy(&row.val("nonce").to_php_string().unwrap_or_default()).into_owned();
    let n2 = n.clone();
    let done = tokio::spawn(async move {
        let _release = release;
        let claims = n2.signin.oidc.exchange_code(&settings, &code, &redirect, &verifier, &nonce, now).await;
        blocking(&n2, move |_, c| crate::signin::callback_finish(c, &row, claims, &ip, now)).await
    })
    .await
    .ok()
    .flatten();
    match done {
        Some(Ok(p)) => show(p),
        Some(Err(f)) => server_error("oidc client-callback", &f),
        None => page_response(500, error_page(500, "Server Error"), head),
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
            _ => Reply::server_error(), // phase 2's routes never come here (signin_route)
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
