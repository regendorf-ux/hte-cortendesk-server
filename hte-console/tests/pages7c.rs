//! Phase 7c end to end: Fleet diagnostics, Roles and the health routes on a real
//! socket, against a temporary database made from tests/schema_live.sql (the live schema) and a synthetic seed.
//! The session rows are minted here with the crate's own Encrypter, the way the previous console's `SESSION_DRIVER=database` writes
//! them. Expectations come from the previous console's source (v1.15.0-hte.1).

use hte_console::api::{Limiter, Native, Nonces};
use hte_console::laravel::{self, Encrypter};
use hte_console::oidc::Oidc;
use hte_console::pages::{self, session};
use rusqlite::Connection;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

const APP_KEY: &str = "base64:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
/// 2025-10-25 03:20:00 UTC.
const NOW: i64 = 1_761_362_400;
const TOKEN: &str = "TOKENtokenTOKENtokenTOKENtokenTOKENtoken";

struct H {
    url: String,
    db_path: PathBuf,
    client: reqwest::Client,
    crypt: Encrypter,
    cfg: session::SessionConfig,
    _dir: tempfile::TempDir,
}

struct Resp {
    status: u16,
    headers: reqwest::header::HeaderMap,
    body: String,
}

impl Resp {
    fn location(&self) -> String {
        self.headers.get("location").map(|v| v.to_str().unwrap().to_string()).unwrap_or_default()
    }
    /// The redirect's target without the host (Laravel redirects to absolute URLs).
    fn path(&self) -> String {
        let l = self.location();
        match l.find("://") {
            Some(i) => l[i + 3..].find('/').map(|j| l[i + 3 + j..].to_string()).unwrap_or_default(),
            None => l,
        }
    }
    fn set_cookie(&self) -> Option<String> {
        self.headers.get("set-cookie").map(|v| v.to_str().unwrap().to_string())
    }
}

fn ago(secs: i64) -> String {
    laravel::ts(NOW - secs)
}

const SEED: &str = "
insert into roles (id, name, permissions, require_two_factor) values (1, 'Auditor', '{\"audit\":\"rw\"}', 0);
insert into device_groups (id, name) values (1, 'Front desk'), (2, 'Back office');
insert into user_groups (id, name) values (1, 'Techs');
insert into devices (id, rustdesk_id, uuid, hostname, username, os, version, alias, user_id, device_group_id, status, last_online_at, last_online_ip, created_at, updated_at) values
 (1, '1001', 'u1', 'FRONT-PC', 'dana', 'windows / Windows 11', '1.4.0', 'Front PC', 2, 1, 'active', '2025-10-25 03:19:30', '10.0.0.1', '2025-09-01 10:00:00', '2025-10-25 03:19:30'),
 (2, '1002', 'u2', 'BACK-PC', 'erin', 'macos / macOS 14', '1.3.9', null, null, 2, 'active', '2025-10-20 08:00:00', '10.0.0.2', '2025-09-02 10:00:00', '2025-10-20 08:00:00'),
 (3, '1003', 'u3', 'OLD-PC', 'dana', 'linux / Ubuntu', '1.3.0', null, 2, null, 'active', null, null, '2025-09-03 10:00:00', '2025-09-03 10:00:00'),
 (4, '1004', 'u4', 'NEW-PC', 'dana', 'windows / Windows 10', '1.4.0', null, null, null, 'pending', '2025-10-25 03:00:00', '10.0.0.4', '2025-10-24 10:00:00', '2025-10-24 10:00:00');
update devices set deleted_at = '2025-10-01 00:00:00' where id = 3;
";

async fn harness() -> H {
    sodiumoxide::init().unwrap();
    std::env::set_var("BCRYPT_ROUNDS", "4");
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("cortendesk.sqlite");
    let crypt = Encrypter::from_app_key(APP_KEY).unwrap();
    let c = Connection::open(&db_path).unwrap();
    c.execute_batch(include_str!("schema_live.sql")).unwrap();
    c.execute_batch(SEED).unwrap();
    let hash = laravel::hash_make(b"oldpass123").unwrap();
    for (id, username, name, email, admin, active, role) in [
        (1, "jdoe", "Jane D", "o@example.test", 1, 1, None),
        (2, "dana", "", "dana@example.test", 0, 1, None),
        (3, "erin", "Erin", "erin@example.test", 0, 1, Some(1)),
        (4, "gone", "Gone", "gone@example.test", 0, 0, None),
    ] {
        c.execute(
            "insert into users (id, username, name, email, password, is_admin, is_active, role_id, created_at, updated_at) values (?, ?, ?, ?, ?, ?, ?, ?, '2025-01-01 00:00:00', '2025-01-01 00:00:00')",
            rusqlite::params![id, username, name, email, hash, admin, active, role],
        )
        .unwrap();
    }
    drop(c);
    let native = Arc::new(Native {
        db: Mutex::new(hte_console::sqlite::open(&db_path, std::time::Duration::from_secs(5), true).unwrap()),
        crypt: Encrypter::from_app_key(APP_KEY).unwrap(),
        hbbs_db: dir.path().join("none.sqlite3"),
        trusted: laravel::parse_trusted(laravel::DEFAULT_TRUSTED),
        api_version: "1.15.0-hte.1".into(),
        max_body: 1 << 20,
        limiter: Mutex::new(Limiter::default()),
        nonces: Mutex::new(Nonces::default()),
        signin: hte_console::signin::State::new(Oidc::new(true, false), None, "HTE Remote".into()),
        clock: Box::new(|| NOW),
    });
    let app = pages::routes(native, None).unwrap().into_make_service_with_connect_info::<std::net::SocketAddr>();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
    H { url, db_path, client, crypt, cfg: session::SessionConfig::from_env("HTE Remote"), _dir: dir }
}

impl H {
    fn db(&self) -> Connection {
        Connection::open(&self.db_path).unwrap()
    }
    fn sql(&self, s: &str) {
        self.db().execute_batch(s).unwrap();
    }
    fn count(&self, q: &str) -> i64 {
        self.db().query_row(&format!("select count(*) from {q}"), [], |r| r.get(0)).unwrap()
    }
    fn text(&self, q: &str) -> String {
        self.db().query_row(q, [], |r| r.get::<_, Option<String>>(0)).unwrap().unwrap_or_default()
    }

    /// A signed-in session row for `uid` (what the previous console's database driver writes) and its cookie.
    fn login(&self, id: &str, uid: i64, extra: Value) -> String {
        let mut data = json!({"_token": TOKEN, session::LOGIN_KEY: uid, "_flash": {"old": [], "new": []}});
        if let Value::Object(m) = extra {
            for (k, v) in m {
                data[k] = v;
            }
        }
        use base64::Engine;
        let payload = base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&data).unwrap());
        self.db()
            .execute("insert into sessions (id, user_id, ip_address, user_agent, payload, last_activity) values (?, ?, '198.18.9.1', 'test', ?, ?)", rusqlite::params![id, uid, payload, NOW - 5])
            .unwrap();
        self.cookie(id)
    }

    fn cookie(&self, id: &str) -> String {
        let set = session::set_cookie(&self.cfg, &self.crypt, id, false, NOW);
        set.split(';').next().unwrap().to_string()
    }

    fn payload(&self, id: &str) -> Value {
        use base64::Engine;
        let raw = self.text(&format!("select payload from sessions where id = '{id}'"));
        serde_json::from_slice(&base64::engine::general_purpose::STANDARD.decode(raw).unwrap()).unwrap()
    }

    async fn go(&self, method: &str, path: &str, cookie: Option<&str>, ct: Option<&str>, body: &str, headers: &[(&str, &str)]) -> Resp {
        let mut rq = self.client.request(method.parse().unwrap(), format!("{}{}", self.url, path)).header("x-forwarded-for", "198.18.9.1");
        if let Some(c) = cookie {
            rq = rq.header("cookie", c);
        }
        if let Some(ct) = ct {
            rq = rq.header("content-type", ct);
        }
        for (k, v) in headers {
            rq = rq.header(*k, *v);
        }
        let r = rq.body(body.to_string()).send().await.unwrap();
        let (status, headers) = (r.status().as_u16(), r.headers().clone());
        Resp { status, headers, body: r.text().await.unwrap() }
    }

    async fn theme_post(&self, cookie: &str, token: Option<&str>, header: Option<(&str, String)>, site: Option<&str>) -> Resp {
        let mut headers: Vec<(String, String)> = vec![];
        if let Some((k, v)) = header {
            headers.push((k.to_string(), v));
        }
        if let Some(s) = site {
            headers.push(("sec-fetch-site".into(), s.into()));
        }
        let hs: Vec<(&str, &str)> = headers.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
        match token {
            Some(t) => self.go("POST", "/account/theme", Some(cookie), Some("application/x-www-form-urlencoded"), &format!("theme=light&_token={t}"), &hs).await,
            None => self.go("POST", "/account/theme", Some(cookie), Some("application/json"), r#"{"theme":"light"}"#, &hs).await,
        }
    }

    async fn get(&self, path: &str, cookie: &str) -> Resp {
        self.go("GET", path, Some(cookie), None, "", &[]).await
    }

    async fn post_form(&self, path: &str, cookie: &str, form: &[(&str, &str)]) -> Resp {
        let body = laravel::http_build_query(&form.iter().map(|(k, v)| (*k, v.as_bytes())).collect::<Vec<_>>());
        self.go("POST", path, Some(cookie), Some("application/x-www-form-urlencoded"), &body, &[]).await
    }

    /// A multipart form with one file (the backup upload).
    async fn post_file(&self, path: &str, cookie: &str, field: &str, filename: &str, data: &[u8]) -> Resp {
        let mut body = format!("--XyZ\r\nContent-Disposition: form-data; name=\"_token\"\r\n\r\n{TOKEN}\r\n--XyZ\r\nContent-Disposition: form-data; name=\"{field}\"; filename=\"{filename}\"\r\nContent-Type: application/x-tar\r\n\r\n").into_bytes();
        body.extend_from_slice(data);
        body.extend_from_slice(b"\r\n--XyZ--\r\n");
        let r = self
            .client
            .post(format!("{}{}", self.url, path))
            .header("x-forwarded-for", "198.18.9.1")
            .header("cookie", cookie)
            .header("content-type", "multipart/form-data; boundary=XyZ")
            .body(body)
            .send()
            .await
            .unwrap();
        let (status, headers) = (r.status().as_u16(), r.headers().clone());
        Resp { status, headers, body: r.text().await.unwrap() }
    }

    fn alarms(&self, n: usize) {
        let c = self.db();
        for i in 0..n {
            c.execute(
                "insert into alarm_logs (rustdesk_id, typ, info, conn_id, created_at, updated_at) values ('1001', 2, ?, 7, ?, ?)",
                rusqlite::params![format!("{{\"ip\":\"10.0.0.{i}\"}}"), ago(330 + i as i64 * 60), ago(330)],
            )
            .unwrap();
        }
    }
}

/// A 40-character session id from a tag.
fn sid(tag: &str) -> String {
    let mut s = tag.repeat(40 / tag.len() + 1);
    s.truncate(40);
    s
}

fn squash(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

// ------------------------------------------------------------------------------------------------ devices ---

fn tok() -> (&'static str, &'static str) {
    ("_token", TOKEN)
}
/// The scheduler heartbeat as hte-console's `diagnostics` sweep writes it (`Cache::forever`), `secs` ago.
fn heartbeat(h: &H, secs: i64) {
    let at = chrono::DateTime::<chrono::Utc>::from_timestamp(NOW - secs, 0).unwrap().format("%Y-%m-%dT%H:%M:%S+00:00").to_string();
    let v = format!("s:{}:\"{at}\";", at.len());
    h.db()
        .execute("insert or replace into cache (key, value, expiration) values ('laravel-cache-cortendesk:diagnostics:scheduler-heartbeat', ?, ?)", rusqlite::params![v, NOW + 315_360_000])
        .unwrap();
}

fn card<'a>(body: &'a str, label: &str) -> String {
    let i = body.find(&format!("<strong>{label}</strong>")).unwrap_or_else(|| panic!("no card {label}"));
    squash(&body[i..(i + 600).min(body.len())])
}

// ------------------------------------------------------------------------------------------- diagnostics ---

#[tokio::test(flavor = "multi_thread")]
async fn fleet_diagnostics() {
    let h = harness().await;
    let admin = h.login(&sid("a"), 1, json!({}));
    let dana = h.login(&sid("d"), 2, json!({}));
    let erin = h.login(&sid("e"), 3, json!({}));
    // a listening ID server on this machine, a relay that does not answer
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let closed = {
        let x = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        x.local_addr().unwrap().port()
    };
    h.sql(&format!("insert into settings (key, value, created_at, updated_at) values ('id_server', '127.0.0.1:{port}', '2025-01-01 00:00:00', '2025-01-01 00:00:00'), ('relay_server', 'localhost:{closed}', '2025-01-01 00:00:00', '2025-01-01 00:00:00');"));
    heartbeat(&h, 50);

    let r = h.get("/diagnostics", &admin).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let b = &r.body;
    assert!(b.contains("<title>Fleet diagnostics | HTE Remote</title>"));
    assert!(b.contains("Bounded probes and fleet signals. No test email is sent automatically."));
    assert!(card(b, "Application").contains(concat!("text-success\">Ok</span> </div> <p class=\"text-muted fs-13 mb-0 mt-2\">HTE Remote v", env!("CARGO_PKG_VERSION"), "</p>")), "{}", card(b, "Application"));
    assert!(card(b, "ID server").contains(&format!(">Ok</span> </div> <p class=\"text-muted fs-13 mb-0 mt-2\">configured IP address on port {port}</p>")), "{}", card(b, "ID server"));
    assert!(card(b, "Relay server").contains(&format!("text-danger\">Failed</span> </div> <p class=\"text-muted fs-13 mb-0 mt-2\">configured hostname on port {closed}</p>")), "{}", card(b, "Relay server"));
    assert!(card(b, "Scheduler").contains(">Ok</span>") && card(b, "Scheduler").contains("Heartbeat is fresh."));
    // no secret configured: the link is not needed (open mode, no incoming-only device) => unknown
    assert!(card(b, "ID server link").contains("text-secondary\">Unknown</span>") && card(b, "ID server link").contains("Not configured. Approved-only mode and incoming-only devices are not enforced."), "{}", card(b, "ID server link"));
    assert!(card(b, "SMTP").contains(">Unknown</span>") && card(b, "SMTP").contains("SMTP is not configured. No message is sent automatically."));
    let s = squash(b);
    // two approved (one in the recycle bin is not), one online, one pending, the older client behind
    assert!(s.contains(r#"<div class="text-muted fs-13">Devices</div> <div class="fs-4 fw-semibold"> 2 </div>"#), "{s}");
    assert!(s.contains(r#"<div class="text-muted fs-13">Online</div> <div class="fs-4 fw-semibold"> 1 </div>"#));
    assert!(s.contains(r#"<div class="text-muted fs-13">Pending</div> <div class="fs-4 fw-semibold"> 1 </div>"#));
    assert!(s.contains(r#"<td class="rd-mono">1.3.9</td> <td>1</td> <td>Behind newest fleet version</td>"#));
    assert!(s.contains(r#"<td class="rd-mono">1.4.0</td> <td>1</td> <td>Newest or unknown</td>"#));

    // a stale heartbeat
    heartbeat(&h, 181);
    let r = h.get("/diagnostics", &admin).await;
    assert!(card(&r.body, "Scheduler").contains("text-danger\">Failed</span>") && card(&r.body, "Scheduler").contains("No fresh scheduler heartbeat."));

    // the download: sanitised, the previous console's pretty print, no host names
    let r = h.get("/diagnostics/export", &admin).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.headers["content-type"], "application/json");
    assert_eq!(r.headers["content-disposition"], "attachment; filename=hte-remote-diagnostics.json");
    assert_eq!(r.headers["cache-control"], "no-store, private");
    assert!(r.body.starts_with("{\n    \"generated_at\": \"2025-10-25T03:20:00+00:00\",\n    \"application\": {\n        \"ok\": true,"), "{}", r.body);
    assert!(!r.body.contains("localhost") && !r.body.contains("127.0.0.1") && !r.body.contains("host_label"));
    let j: Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(j["services"]["id_server"], json!({"configured": true, "port": port, "ok": true, "latency_ms": j["services"]["id_server"]["latency_ms"]}));
    assert_eq!(j["services"]["api"]["version_route"], "/api/version");
    assert_eq!(j["fleet"]["total"], 2);
    assert_eq!(j["fleet"]["newest_reported_version"], "1.4.0");
    assert_eq!(j["fleet"]["latest_heartbeat_at"], "2025-10-25 03:19:30");
    assert_eq!(j["server_link"]["mode"], "open");
    assert_eq!(j["smtp"]["healthy"], Value::Null);

    // console-can:setting,r: people without it are sent to the overview
    for c in [&dana, &erin] {
        let r = h.get("/diagnostics", c).await;
        assert_eq!((r.status, r.path()), (302, "/".to_string()));
        assert_eq!(h.get("/diagnostics/export", c).await.status, 302);
    }
    drop(l);
}

#[tokio::test(flavor = "multi_thread")]
async fn health_routes() {
    let h = harness().await;
    let r = h.go("GET", "/health/live", None, None, "", &[]).await;
    assert_eq!((r.status, r.body.as_str()), (200, r#"{"live":true}"#));
    // nothing configured: ready (an empty pool is not a dependency)
    let r = h.go("GET", "/health/ready", None, None, "", &[]).await;
    assert_eq!((r.status, r.body.as_str()), (200, r#"{"ready":true,"database":true,"id_server":true,"relay_server":true}"#));
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    h.sql(&format!("insert into settings (key, value, created_at, updated_at) values ('relay_servers', '[{{\"address\":\"127.0.0.1:{closed}\",\"geo\":\"\"}}]', '2025-01-01 00:00:00', '2025-01-01 00:00:00');"));
    let r = h.go("GET", "/health/ready", None, None, "", &[]).await;
    assert_eq!((r.status, r.body.as_str()), (503, r#"{"ready":false,"database":true,"id_server":true,"relay_server":false}"#));
    // The previous console's global limit: 30 readiness probes a minute (3 used above), then 429 with Retry-After
    let mut last = 0;
    for _ in 0..30 {
        last = h.go("GET", "/health/ready", None, None, "", &[]).await.status;
    }
    assert_eq!(last, 429);
    let r = h.go("GET", "/health/ready", None, None, "", &[]).await;
    assert_eq!((r.status, r.headers["retry-after"].to_str().unwrap()), (429, "60"));
    assert_eq!(r.body, r#"{"ready":false,"database":false,"id_server":false,"relay_server":false}"#);
    let r = h.go("GET", "/up", None, None, "", &[]).await;
    assert_eq!(r.status, 200);
    assert!(r.body.contains("Application up"));
    for p in ["/downloads", "/downloads/3", "/storage/downloads/x.exe"] {
        assert_eq!(h.go("GET", p, None, None, "", &[]).await.status, 404, "{p}");
    }
}

// ------------------------------------------------------------------------------------------------- roles ---

fn role_json(h: &H, name: &str) -> String {
    h.text(&format!("select permissions from roles where name = '{name}'"))
}

#[tokio::test(flavor = "multi_thread")]
async fn the_roles_page() {
    let h = harness().await;
    let admin = h.login(&sid("a"), 1, json!({}));
    let dana = h.login(&sid("d"), 2, json!({}));
    let erin = h.login(&sid("e"), 3, json!({}));

    // the list: the seeded Auditor, one holder
    let r = h.get("/roles", &admin).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let s = squash(&r.body);
    assert!(s.contains(r#"<span class="rd-cell-title">Auditor</span> <span class="rd-cell-sub">—</span>"#));
    assert!(s.contains(r#"<span class="badge bg-primary-subtle text-primary"> Logs: Manage </span>"#));
    assert!(s.contains(r#"<td> <span class="text-muted">—</span> </td> <td>1</td>"#));
    assert!(s.contains("Delete this role? 1 user(s) will revert to standard user access."));
    assert!(s.contains(r#"<span class="badge bg-secondary-subtle text-secondary flex-shrink-0"> 1 user </span>"#));

    // super-admin only: the page redirects with the previous console's flash, the writes are 403
    assert_eq!(h.get("/roles", &dana).await.status, 302);
    assert_eq!(h.payload(&sid("d"))["denied"], "That section is restricted to administrators.");
    for c in [&dana, &erin] {
        let r = h.get("/roles", c).await;
        assert_eq!((r.status, r.path()), (302, "/".to_string()));
        assert_eq!(h.post_form("/roles/save", c, &[tok(), ("name", "X")]).await.status, 403);
        assert_eq!(h.post_form("/roles/delete", c, &[tok(), ("id", "1")]).await.status, 403);
    }
    assert_eq!(h.count("roles"), 1);

    // the create dialog starts from the standard-user baseline
    let r = h.get("/roles?create=1", &admin).await;
    let s = squash(&r.body);
    assert!(s.contains(r#"<h5 class="modal-title">New Role</h5>"#));
    assert!(s.contains(r#"name="permissions[device]" value="rw" checked>"#) && s.contains(r#"name="permissions[address_book]" value="rw" checked>"#) && s.contains(r#"name="permissions[audit]" value="r" checked>"#));
    assert!(s.contains(r#"name="permissions[setting]" value="none" checked>"#));

    // validation: required, unique, a level that does not exist
    let r = h.post_form("/roles/save", &admin, &[tok(), ("id", "0"), ("name", "")]).await;
    assert_eq!(r.status, 422);
    assert!(r.body.contains("The name field is required."));
    let r = h.post_form("/roles/save", &admin, &[tok(), ("id", "0"), ("name", "Auditor")]).await;
    assert!(r.body.contains("The name has already been taken."), "{}", r.body);
    let r = h.post_form("/roles/save", &admin, &[tok(), ("id", "0"), ("name", "Helpdesk"), ("permissions[device]", "admin")]).await;
    assert_eq!(r.status, 422);
    assert!(r.body.contains(r#"<div class="text-danger fs-13 mb-1">The selected permissions.device is invalid.</div>"#), "{}", squash(&r.body));
    assert_eq!(h.count("roles"), 1);

    // create
    let form = [tok(), ("id", "0"), ("name", "Helpdesk"), ("description", ""), ("permissions[device]", "r"), ("permissions[setting]", "rw"), ("permissions[bogus]", "rw"), ("require_two_factor", "1")];
    let r = h.post_form("/roles/save", &admin, &form).await;
    assert_eq!((r.status, r.path()), (302, "/roles".to_string()));
    assert_eq!(role_json(&h, "Helpdesk"), r#"{"device":"r","user":"none","group":"none","address_book":"none","audit":"none","strategy":"none","setting":"rw","token":"none"}"#);
    assert_eq!(h.text("select coalesce(description, 'NULL') || '|' || require_two_factor || '|' || created_at || '|' || updated_at from roles where name = 'Helpdesk'"), "NULL|1|2025-10-25 03:20:00|2025-10-25 03:20:00");
    assert_eq!(
        h.text("select action || '|' || target_type || '|' || target_id || '|' || summary || '|' || username from console_audits order by id desc limit 1"),
        "role.create|role|Helpdesk|Created role Helpdesk [device:r, setting:rw]|jdoe"
    );
    let helpdesk: i64 = h.text("select cast(id as text) from roles where name = 'Helpdesk'").parse().unwrap();

    // a role that requires 2FA: its holder is sent to enrolment (RequireTwoFactor, answered by the previous console) before any page
    h.sql(&format!("update users set role_id = {helpdesk} where id = 2;"));
    assert_ne!(h.get("/diagnostics", &dana).await.status, 200);

    // edit: what the dialog shows, then a save that changes the description only
    let r = h.get(&format!("/roles?edit={helpdesk}"), &admin).await;
    let s = squash(&r.body);
    assert!(s.contains(r#"<h5 class="modal-title">Edit Role</h5>"#) && s.contains(r#"name="permissions[setting]" value="rw" checked>"#) && s.contains(r#"name="require_two_factor" value="1" checked>"#));
    assert_eq!(h.get("/roles?edit=999", &admin).await.status, 404);
    h.sql("update roles set updated_at = '2025-10-01 00:00:00' where name = 'Helpdesk';");
    let idv = helpdesk.to_string();
    let edit = [tok(), ("id", idv.as_str()), ("name", "Helpdesk"), ("description", "Front line"), ("permissions[device]", "r"), ("permissions[setting]", "rw"), ("require_two_factor", "1")];
    assert_eq!(h.post_form("/roles/save", &admin, &edit).await.status, 302);
    assert_eq!(h.text("select description || '|' || updated_at from roles where name = 'Helpdesk'"), "Front line|2025-10-25 03:20:00");
    assert!(h.text("select summary from console_audits order by id desc limit 1").starts_with("Updated role Helpdesk [device:r, setting:rw]"));
    // an unchanged save writes no new updated_at (Eloquent's dirty check), but still an audit row (the previous console records every save)
    h.sql("update roles set updated_at = '2025-10-01 00:00:00' where name = 'Helpdesk';");
    let audits = h.count("console_audits");
    assert_eq!(h.post_form("/roles/save", &admin, &edit).await.status, 302);
    assert_eq!(h.text("select updated_at from roles where name = 'Helpdesk'"), "2025-10-01 00:00:00");
    assert_eq!(h.count("console_audits"), audits + 1);
    // unticking the switch turns 2FA off; renaming to its own name is not "taken"
    let edit2 = [tok(), ("id", idv.as_str()), ("name", "Helpdesk"), ("description", "Front line"), ("permissions[device]", "r"), ("permissions[setting]", "rw")];
    assert_eq!(h.post_form("/roles/save", &admin, &edit2).await.status, 302);
    assert_eq!(h.text("select cast(require_two_factor as text) from roles where name = 'Helpdesk'"), "0");
    // the role takes effect on the next request: dana gets Settings and Diagnostics, loses address books
    assert_eq!(h.get("/diagnostics", &dana).await.status, 200);
    assert_eq!(h.get("/address-books", &dana).await.status, 302);
    assert_eq!(h.get("/devices", &dana).await.status, 200);

    // delete: holders revert to the standard-user baseline
    let r = h.post_form("/roles/delete", &admin, &[tok(), ("id", "1")]).await;
    assert_eq!((r.status, r.path()), (302, "/roles".to_string()));
    assert_eq!(h.count("roles where id = 1"), 0);
    assert_eq!(h.text("select coalesce(cast(role_id as text), 'NULL') from users where id = 3"), "NULL");
    assert_eq!(h.text("select summary from console_audits order by id desc limit 1"), "Deleted role Auditor (1 user(s) reverted to standard access)");
    assert_eq!(h.post_form("/roles/delete", &admin, &[tok(), ("id", "1")]).await.status, 404);
    // erin is a standard user again: no more login history
    assert_eq!(h.get("/logs/logins", &erin).await.status, 302);
    assert_eq!(h.get("/logs/connections", &erin).await.status, 200);
}
