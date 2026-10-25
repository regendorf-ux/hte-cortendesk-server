//! Fleet diagnostics (`DiagnosticsController` + `FleetDiagnostics`, v1.15.0-hte.1): `GET /diagnostics`, the sanitised JSON
//! download `GET /diagnostics/export`, and the health routes that share its checks (`GET /health/live`, `/health/ready`, `/up`).
//!
//! What each check reads now that hte-console does the work behind it:
//! - Scheduler: the cache key `cortendesk:diagnostics:scheduler-heartbeat`, which hte-console's `diagnostics` sweep writes every
//!   minute (`HTE_CONSOLE_SWEEPS`) holding PHP's own lock, so a fresh heartbeat means hte-console's scheduler is alive.
//! - ID server link: the pull marker hte-console's `/api/server/policy` leaves (`link.rs`), read as Settings reads it.
//! - ID and relay server: a TCP connect with a one-second timeout, as `SocketTcpProbe`. Both probes run at the same time, so the
//!   page holds the database lock for at most about a second when a server does not answer (PHP: two seconds, one after the other).

use super::kit::*;
use super::{Ctx, Reply, Req};
use crate::php::{self, Fault, Val};
use crate::sqlite::{self as db, P};
use rusqlite::Connection;
use serde_json::{json, Value};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

const APPROVED: &str = r#""status" = ? and "devices"."deleted_at" is null"#;

/// One TCP probe: `SocketTcpProbe::check`.
#[derive(Clone, Debug)]
pub struct Probe {
    pub ok: bool,
    pub latency_ms: i64,
    pub error: Option<String>,
}

pub fn tcp_check(host: &str, port: u16, timeout: f64) -> Probe {
    let started = Instant::now();
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    let addr = (bare, port).to_socket_addrs().ok().and_then(|mut a| a.next());
    let ok = match addr {
        Some(a) => TcpStream::connect_timeout(&a, Duration::from_secs_f64(timeout)).is_ok(),
        None => false,
    };
    let latency_ms = (started.elapsed().as_secs_f64() * 1000.0).round() as i64;
    Probe { ok, latency_ms, error: if ok { None } else { Some("Connection failed.".into()) } }
}

/// `FleetDiagnostics::parseServer`: `parse_url('tcp://'.$value)`'s host and port.
pub fn parse_server(value: &str, default_port: u16) -> (String, u16) {
    let value = value.trim();
    if value.is_empty() {
        return (String::new(), default_port);
    }
    let rest = match value.split_once("://") {
        Some((_, r)) => r,
        None => value,
    };
    let auth = rest.split(['/', '?', '#']).next().unwrap_or("");
    let auth = auth.rsplit('@').next().unwrap_or("");
    let (host, port) = if auth.starts_with('[') {
        match auth.find(']') {
            Some(i) => (auth[..=i].to_string(), auth[i + 1..].strip_prefix(':').and_then(|p| p.parse::<u16>().ok())),
            None => (String::new(), None),
        }
    } else {
        match auth.rsplit_once(':') {
            Some((h, p)) if p.bytes().all(|b| b.is_ascii_digit()) => (h.to_string(), p.parse::<u16>().ok()),
            _ => (auth.to_string(), None),
        }
    };
    (host, port.filter(|p| *p != 0).unwrap_or(default_port))
}

fn host_label(host: &str) -> &'static str {
    if host.parse::<IpAddr>().is_ok() { "configured IP address" } else { "configured hostname" }
}

/// `FleetDiagnostics::serverProbe` as data.
struct Server {
    configured: bool,
    port: u16,
    host_label: &'static str,
    probe: Option<Probe>,
    host: String,
}

fn server(c: &Connection, key: &str, envs: &[&str], default_port: u16) -> Result<Server, Fault> {
    let (host, port) = parse_server(&super::settings::server_value(c, key, envs)?, default_port);
    Ok(Server { configured: !host.is_empty(), port, host_label: host_label(&host), probe: None, host })
}

/// Run the probes of every configured server at once.
fn probe_all(servers: &mut [&mut Server]) {
    std::thread::scope(|s| {
        let handles: Vec<_> = servers
            .iter()
            .map(|sv| {
                let (h, p, on) = (sv.host.clone(), sv.port, sv.configured);
                s.spawn(move || if on { Some(tcp_check(&h, p, 1.0)) } else { None })
            })
            .collect();
        for (sv, h) in servers.iter_mut().zip(handles) {
            sv.probe = h.join().ok().flatten();
        }
    });
}

impl Server {
    fn ok(&self) -> bool {
        self.probe.as_ref().map_or(false, |p| p.ok)
    }

    /// The report's `services.<name>` entry (`sanitized` keeps only configured, port, ok, latency_ms).
    fn report(&self, sanitized: bool) -> Val {
        let latency = self.probe.as_ref().map_or(Val::Null, |p| Val::Int(p.latency_ms));
        if !self.configured {
            let mut v = vec![("configured".to_string(), Val::Bool(false)), ("port".into(), Val::Int(self.port as i64)), ("ok".into(), Val::Bool(false)), ("latency_ms".into(), Val::Null)];
            if !sanitized {
                v.push(("error".into(), Val::str("Not configured.")));
            }
            return php::assoc(v);
        }
        if sanitized {
            return php::assoc([("configured".to_string(), Val::Bool(true)), ("port".into(), Val::Int(self.port as i64)), ("ok".into(), Val::Bool(self.ok())), ("latency_ms".into(), latency)]);
        }
        let error = self.probe.as_ref().and_then(|p| p.error.clone()).map_or(Val::Null, |e| Val::str(&e));
        php::assoc([
            ("configured".to_string(), Val::Bool(true)),
            ("port".into(), Val::Int(self.port as i64)),
            ("host_label".into(), Val::str(self.host_label)),
            ("ok".into(), Val::Bool(self.ok())),
            ("latency_ms".into(), latency),
            ("error".into(), error),
        ])
    }
}

fn database_ok(c: &Connection) -> bool {
    db::first(c, "select 1", &[]).is_ok()
}

fn setting_s(c: &Connection, key: &str) -> Result<String, Fault> {
    Ok(lossy(&db::setting(c, key, "")?).trim().to_string())
}

/// `config('app.url')` passes `FILTER_VALIDATE_URL` and has a host.
fn app_host_configured() -> bool {
    let url = crate::envvar::var("APP_URL").unwrap_or_else(|_| "http://localhost".into());
    let Some((scheme, rest)) = url.split_once("://") else { return false };
    let host = rest.split(['/', '?', '#']).next().unwrap_or("").rsplit('@').next().unwrap_or("");
    !scheme.is_empty() && scheme.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')) && !host.is_empty() && !url.contains(char::is_whitespace)
}

fn env_s(name: &str) -> String {
    crate::envvar::var(name).unwrap_or_default().trim().to_string()
}

/// `FleetDiagnostics::report()`: everything the page and the download show.
pub struct Report {
    generated_at: String,
    version: String,
    database: bool,
    id: Server,
    relay: Server,
    websocket_ok: bool,
    websocket_id: bool,
    websocket_relay: bool,
    scheduler_ok: bool,
    scheduler_at: Option<String>,
    link: super::settings::Link,
    mode: String,
    total: i64,
    online: i64,
    offline: i64,
    pending: i64,
    duplicates: i64,
    silent: i64,
    latest_heartbeat: Option<String>,
    versions: Vec<(String, i64, String)>,
    newest: Option<String>,
    smtp_configured: bool,
    smtp_enabled: bool,
    smtp_healthy: Option<bool>,
    smtp_note: &'static str,
}

pub fn report(ctx: &Ctx, c: &Connection) -> Result<Report, Fault> {
    let database = database_ok(c);
    let active = || P(Val::str("active"));
    let rows = db::rows(
        c,
        &format!(r#"select COALESCE(NULLIF(version, ''), 'unknown') as version, COUNT(*) as count from "devices" where {APPROVED} group by "version" order by "count" desc"#),
        &[active()],
    )?;
    let versions: Vec<(String, i64)> = rows.iter().map(|r| (s(r, "version"), r.val("count").to_int())).collect();
    let mut known: Vec<String> = versions.iter().map(|v| v.0.clone()).filter(|v| v != "unknown").collect();
    known.sort_by(|a, b| super::version_compare(a, b).cmp(&0));
    let newest = known.last().cloned();

    let scheduler_at = ctx.p.store.get_raw(c, crate::cache::SCHEDULER_HEARTBEAT_KEY, ctx.now)?.and_then(|b| super::unserialize_string(&b));
    let parsed = scheduler_at.as_deref().and_then(crate::backup::parse_when).map(|d| d.timestamp());
    let (scheduler_ok, scheduler_at) = match (&scheduler_at, parsed) {
        (Some(_), Some(t)) => ((ctx.now - t).abs() <= 180, scheduler_at),
        (Some(_), None) => (false, None),
        _ => (false, None),
    };

    let app_host = app_host_configured();
    let websocket_id = !env_s("HTE_REMOTE_WS_ID_URL").is_empty() || app_host;
    let websocket_relay = !env_s("HTE_REMOTE_WS_RELAY_URL").is_empty() || app_host;

    let smtp_configured = !setting_s(c, "smtp_host")?.is_empty() && !setting_s(c, "smtp_from_address")?.is_empty();
    let smtp_enabled = setting_s(c, "smtp_enabled")? == "1" && smtp_configured;
    let ok_at = lossy(&db::setting(c, "smtp_ok_at", "")?);
    let failed_at = lossy(&db::setting(c, "smtp_failed_at", "")?);
    let observed = !ok_at.trim().is_empty() || !failed_at.trim().is_empty();
    // MailSettings::isHealthy(): no failure recorded, or a success at or after the last failure
    let healthy = failed_at.is_empty() || (!ok_at.is_empty() && ok_at >= failed_at);
    let smtp_note = if !smtp_configured {
        "SMTP is not configured. No message is sent automatically."
    } else if !observed {
        "Configured, but no send result has been observed. No message is sent automatically."
    } else {
        "Health reflects the last observed send. No message is sent automatically."
    };

    let window = online_window(c)?;
    let cutoff = crate::laravel::ts(ctx.now - window);
    let total = count(c, &format!(r#"select count(*) as aggregate from "devices" where {APPROVED}"#), &[active()])?;
    let online = count(c, &format!(r#"select count(*) as aggregate from "devices" where {APPROVED} and "last_online_at" > ?"#), &[active(), P(Val::str(&cutoff))])?;
    let offline = count(c, &format!(r#"select count(*) as aggregate from "devices" where {APPROVED} and ("last_online_at" is null or "last_online_at" <= ?)"#), &[active(), P(Val::str(&cutoff))])?;
    let pending = count(c, r#"select count(*) as aggregate from "devices" where "status" = ? and "devices"."deleted_at" is null"#, &[P(Val::str("pending"))])?;
    let duplicates = crate::duplicates::Duplicates::all(c)?.count() as i64;
    let day = crate::laravel::ts(ctx.now - 86400);
    let silent = count(c, &format!(r#"select count(*) as aggregate from "devices" where {APPROVED} and ("last_online_at" is null or "last_online_at" < ?)"#), &[active(), P(Val::str(&day))])?;
    let latest_heartbeat = db::first(c, &format!(r#"select max("last_online_at") as aggregate from "devices" where {APPROVED}"#), &[active()])?
        .and_then(|r| if r.is_null("aggregate") { None } else { Some(s(&r, "aggregate")) });

    let mut id = server(c, "id_server", &["HTE_CONSOLE_ID_SERVER", "HTE_REMOTE_ID_SERVER"], 21116)?;
    let mut relay = server(c, "relay_server", &["HTE_CONSOLE_RELAY_SERVER", "HTE_REMOTE_RELAY_SERVER"], 21117)?;
    probe_all(&mut [&mut id, &mut relay]);

    let versions = versions
        .into_iter()
        .map(|(v, n)| {
            let behind = matches!(&newest, Some(top) if v != "unknown" && super::version_compare(&v, top) < 0);
            (v, n, if behind { "Behind newest fleet version" } else { "Newest or unknown" }.to_string())
        })
        .collect();

    Ok(Report {
        generated_at: chrono::DateTime::<chrono::Utc>::from_timestamp(ctx.now, 0).map(|d| d.format("%Y-%m-%dT%H:%M:%S+00:00").to_string()).unwrap_or_default(),
        version: ctx.p.n.api_version.clone(),
        database,
        id,
        relay,
        websocket_ok: ctx.p.config.native_webclient && websocket_id && websocket_relay,
        websocket_id,
        websocket_relay,
        scheduler_ok,
        scheduler_at,
        link: super::settings::link(ctx, c)?,
        mode: super::settings::server_mode(c)?,
        total,
        online,
        offline,
        pending,
        duplicates,
        silent,
        latest_heartbeat,
        versions,
        newest,
        smtp_configured,
        smtp_enabled,
        smtp_healthy: if smtp_configured && observed { Some(healthy) } else { None },
        smtp_note,
    })
}

const WS_NOTE: &str = "Readiness only; explicit endpoints or the APP_URL same-origin fallback are accepted. Remote endpoints are not contacted.";

fn opt_bool(b: Option<bool>) -> Val {
    b.map_or(Val::Null, Val::Bool)
}

fn opt_str(s: &Option<String>) -> Val {
    s.as_deref().map_or(Val::Null, Val::str)
}

impl Report {
    /// The report as PHP's array, for the download (`sanitized()`).
    fn to_val(&self, sanitized: bool) -> Val {
        let a = |pairs: Vec<(&str, Val)>| php::assoc(pairs.into_iter().map(|(k, v)| (k.to_string(), v)));
        let l = &self.link;
        let mut list = php::Arr::new();
        for (i, (v, n, st)) in self.versions.iter().enumerate() {
            list.set(php::Key::Int(i as i64), a(vec![("version", Val::str(v)), ("count", Val::Int(*n)), ("status", Val::str(st))]));
        }
        let versions = Val::Arr(list);
        a(vec![
            ("generated_at", Val::str(&self.generated_at)),
            ("application", a(vec![("ok", Val::Bool(true)), ("version", Val::str(&self.version))])),
            ("database", a(vec![("ok", Val::Bool(self.database))])),
            (
                "services",
                a(vec![
                    ("id_server", self.id.report(sanitized)),
                    ("relay_server", self.relay.report(sanitized)),
                    ("api", a(vec![("ok", Val::Bool(true)), ("mode", Val::str("local route")), ("version_route", Val::str("/api/version"))])),
                    (
                        "websocket_bridge",
                        a(vec![("ok", Val::Bool(self.websocket_ok)), ("id_configured", Val::Bool(self.websocket_id)), ("relay_configured", Val::Bool(self.websocket_relay)), ("note", Val::str(WS_NOTE))]),
                    ),
                ]),
            ),
            ("scheduler", a(vec![("ok", Val::Bool(self.scheduler_ok)), ("last_seen_at", opt_str(&self.scheduler_at))])),
            (
                "server_link",
                a(vec![
                    ("configured", Val::Bool(l.configured)),
                    ("last_pull_at", opt_str(&l.at_raw)),
                    ("agent", if l.has_pull { Val::str(&l.agent) } else { Val::Null }),
                    ("fresh", Val::Bool(l.fresh)),
                    ("needed", Val::Bool(l.needed)),
                    ("ok", opt_bool(l.ok)),
                    ("note", Val::str(&l.note)),
                    ("mode", Val::str(&self.mode)),
                ]),
            ),
            (
                "fleet",
                a(vec![
                    ("total", Val::Int(self.total)),
                    ("online", Val::Int(self.online)),
                    ("offline", Val::Int(self.offline)),
                    ("pending", Val::Int(self.pending)),
                    ("possible_duplicates", Val::Int(self.duplicates)),
                    ("silent_over_24h", Val::Int(self.silent)),
                    ("latest_heartbeat_at", opt_str(&self.latest_heartbeat)),
                    ("versions", versions),
                    ("newest_reported_version", opt_str(&self.newest)),
                ]),
            ),
            ("smtp", a(vec![("configured", Val::Bool(self.smtp_configured)), ("enabled", Val::Bool(self.smtp_enabled)), ("healthy", opt_bool(self.smtp_healthy)), ("note", Val::str(self.smtp_note))])),
        ])
    }

    fn checks(&self) -> Vec<Value> {
        let srv = |s: &Server| if s.configured { format!("{} on port {}", s.host_label, s.port) } else { "Not configured.".to_string() };
        let l = &self.link;
        let mut link_detail = l.note.clone();
        if l.has_pull && !l.agent.is_empty() {
            link_detail += &format!(" ({})", l.agent);
        }
        if self.mode == "approved" {
            link_detail += " Server access: approved devices only.";
        }
        let smtp_ok = if self.smtp_configured { self.smtp_healthy } else { None };
        let check = |label: &str, ok: Option<bool>, detail: String| {
            let status = match ok {
                None => "unknown",
                Some(true) => "ok",
                Some(false) => "failed",
            };
            let tone = match status {
                "ok" => "success",
                "failed" => "danger",
                _ => "secondary",
            };
            let mut st = status.to_string();
            st[..1].make_ascii_uppercase();
            json!({"label": label, "status": st, "tone": tone, "detail": detail})
        };
        vec![
            check("Application", Some(true), format!("HTE Remote v{}", crate::REMOTE_VERSION)),
            check("Database", Some(self.database), if self.database { "Query completed." } else { "Query failed." }.into()),
            check("ID server", Some(self.id.ok()), srv(&self.id)),
            check("Relay server", Some(self.relay.ok()), srv(&self.relay)),
            check("Public API", Some(true), "Local version route /api/version is registered.".into()),
            check("WebSocket bridge", Some(self.websocket_ok), WS_NOTE.into()),
            check("Scheduler", Some(self.scheduler_ok), if self.scheduler_ok { "Heartbeat is fresh." } else { "No fresh scheduler heartbeat." }.into()),
            check("ID server link", l.ok, link_detail),
            check("SMTP", smtp_ok, self.smtp_note.into()),
        ]
    }
}

/// `GET /diagnostics`
pub fn index(ctx: &Ctx, c: &Connection, _: &Req) -> Result<Reply, Fault> {
    let r = report(ctx, c)?;
    let fleet: Vec<Value> = [
        ("total", "Devices", r.total),
        ("online", "Online", r.online),
        ("offline", "Offline", r.offline),
        ("silent_over_24h", "Silent 24h+", r.silent),
        ("pending", "Pending", r.pending),
        ("possible_duplicates", "Possible duplicates", r.duplicates),
    ]
    .iter()
    .map(|(k, label, n)| json!({"key": k, "label": label, "value": n}))
    .collect();
    let versions: Vec<Value> = r.versions.iter().map(|(v, n, st)| json!({"version": v, "count": n, "status": st})).collect();
    let layout = ctx.layout(c, "diagnostics", "Fleet diagnostics", "")?;
    let page = json!({"checks": r.checks(), "fleet": fleet, "versions": versions});
    Ok(Reply::Html(200, ctx.render("diagnostics/index.html", layout, page)?))
}

/// `GET /diagnostics/export`: `json_encode($diagnostics->sanitized(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)`.
pub fn export(ctx: &Ctx, c: &Connection, _: &Req) -> Result<Reply, Fault> {
    let r = report(ctx, c)?;
    let body = json_pretty(&r.to_val(true)).ok_or_else(|| Fault::Other("json_encode of the diagnostics report failed".into()))?;
    Ok(Reply::Download { filename: "hte-remote-diagnostics.json".into(), content_type: "application/json", body: body.into_bytes() })
}

/// `json_encode($v, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)`: four spaces, `": "`, `[]`/`{}` for empty arrays.
pub fn json_pretty(v: &Val) -> Option<String> {
    fn go(v: &Val, depth: usize, out: &mut String) -> Option<()> {
        match v {
            Val::Arr(a) if a.len() == 0 => out.push_str("[]"),
            Val::Arr(a) => {
                let is_list = a.iter().enumerate().all(|(n, (k, _))| *k == php::Key::Int(n as i64));
                out.push(if is_list { '[' } else { '{' });
                for (n, (k, x)) in a.iter().enumerate() {
                    if n > 0 {
                        out.push(',');
                    }
                    out.push('\n');
                    out.push_str(&"    ".repeat(depth + 1));
                    if !is_list {
                        let mut key = String::new();
                        php::enc_str(&k.as_bytes(), &mut key)?;
                        out.push_str(&key.replace("\\/", "/"));
                        out.push_str(": ");
                    }
                    go(x, depth + 1, out)?;
                }
                out.push('\n');
                out.push_str(&"    ".repeat(depth));
                out.push(if is_list { ']' } else { '}' });
            }
            Val::Str(s) => {
                let mut t = String::new();
                php::enc_str(s, &mut t)?;
                out.push_str(&t.replace("\\/", "/"));
            }
            other => out.push_str(&php::json_encode(other)?),
        }
        Some(())
    }
    let mut out = String::new();
    go(v, 0, &mut out)?;
    Some(out)
}

// ----------------------------------------------------------------------------------------------------- health ---

/// What `FleetDiagnostics::readiness()` probes, read from the database: whether it answered, the ID server, every relay
/// of the active pool. Read under the database lock; the probes run after it is released (`readiness`).
pub fn readiness_targets(c: &Connection) -> (bool, (String, u16), Vec<(String, u16)>) {
    let database = database_ok(c);
    if !database {
        return (false, (String::new(), 21116), vec![]);
    }
    let id = super::settings::server_value(c, "id_server", &["HTE_CONSOLE_ID_SERVER", "HTE_REMOTE_ID_SERVER"]).map(|v| parse_server(&v, 21116)).unwrap_or_default();
    let relays = super::settings::relay_pool(c).unwrap_or_default().iter().map(|r| parse_server(r, 21117)).collect();
    (true, id, relays)
}

/// `FleetDiagnostics::readiness()`: (ready, database, id_server, relay_server). An unconfigured ID server and an empty
/// relay pool are not dependencies. No database lock is held here.
pub fn readiness((database, id, relays): (bool, (String, u16), Vec<(String, u16)>)) -> (bool, bool, bool, bool) {
    if !database {
        return (false, false, false, false);
    }
    let mut targets = vec![id];
    targets.extend(relays);
    let results: Vec<bool> = std::thread::scope(|s| {
        let hs: Vec<_> = targets.iter().map(|(h, p)| s.spawn(move || h.is_empty() || tcp_check(h, *p, 1.0).ok)).collect();
        hs.into_iter().map(|h| h.join().unwrap_or(false)).collect()
    });
    let (id_ok, relay_ok) = (results[0], results[1..].iter().all(|b| *b));
    (id_ok && relay_ok, true, id_ok, relay_ok)
}

/// `GET /health/ready`'s answer: 200 when ready, else 503.
pub fn ready_body(r: (bool, bool, bool, bool)) -> (u16, String) {
    let (ready, database, id, relay) = r;
    (if ready { 200 } else { 503 }, format!(r#"{{"ready":{ready},"database":{database},"id_server":{id},"relay_server":{relay}}}"#))
}

/// `ThrottleHealthProbe` with `config/health.php`: one global bucket per probe (live 120, ready 30 a minute; a forwarded
/// address is no identity behind proxies), Laravel's RateLimiter window: 60 s from the first hit.
pub fn probe_allowed(endpoint: &str, now: i64) -> bool {
    static BUCKETS: std::sync::Mutex<[(i64, u32); 2]> = std::sync::Mutex::new([(0, 0); 2]);
    let (i, max) = if endpoint == "live" { (0, 120) } else { (1, 30) };
    let mut b = BUCKETS.lock().unwrap_or_else(|e| e.into_inner());
    if now >= b[i].0 + 60 {
        b[i] = (now, 0);
    }
    if b[i].1 >= max {
        return false;
    }
    b[i].1 += 1;
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn servers_parse_as_parse_url_does() {
        assert_eq!(parse_server("rustdesk.example.test", 21116), ("rustdesk.example.test".into(), 21116));
        assert_eq!(parse_server(" 10.0.0.5:21200 ", 21116), ("10.0.0.5".into(), 21200));
        assert_eq!(parse_server("tcp://relay.example.test:21117/x", 21117), ("relay.example.test".into(), 21117));
        assert_eq!(parse_server("[2001:db8::1]:21116", 21116), ("[2001:db8::1]".into(), 21116));
        assert_eq!(parse_server("", 21117), (String::new(), 21117));
        assert_eq!(host_label("10.0.0.5"), "configured IP address");
        assert_eq!(host_label("[2001:db8::1]"), "configured hostname");
        assert_eq!(host_label("rustdesk.example.test"), "configured hostname");
    }

    #[test]
    fn pretty_json_is_phps() {
        let v = php::assoc([
            ("a".to_string(), Val::str("x/y")),
            ("b".into(), Val::Arr(php::Arr::new())),
            ("c".into(), {
                let mut l = php::Arr::new();
                l.set(php::Key::Int(0), Val::Int(1));
                l.set(php::Key::Int(1), Val::Null);
                Val::Arr(l)
            }),
            ("d".into(), Val::str("é")),
        ]);
        assert_eq!(json_pretty(&v).unwrap(), "{\n    \"a\": \"x/y\",\n    \"b\": [],\n    \"c\": [\n        1,\n        null\n    ],\n    \"d\": \"\\u00e9\"\n}");
    }

    #[test]
    fn a_closed_port_fails_fast() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        assert!(tcp_check("127.0.0.1", port, 1.0).ok);
        drop(l);
        let p = tcp_check("127.0.0.1", port, 1.0);
        assert!(!p.ok);
        assert_eq!(p.error.as_deref(), Some("Connection failed."));
    }
}
