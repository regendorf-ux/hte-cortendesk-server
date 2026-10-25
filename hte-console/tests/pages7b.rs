//! Phase 7b end to end: the devices, users, groups, address-book, strategy, dashboard and settings pages on a real
//! socket, against a temporary database made from tests/schema_live.sql (the live schema) and a synthetic seed.
//! The session rows are minted here with the crate's own Encrypter, the way PHP's `SESSION_DRIVER=database` writes
//! them. Expectations come from the PHP source (v1.15.0-hte.1) read for this phase: `phase7/NOTES.md`.

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
        (1, "owner", "owner D", "o@example.test", 1, 1, None),
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

    /// A signed-in session row for `uid` (what PHP's database driver writes) and its cookie.
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

#[tokio::test(flavor = "multi_thread")]
async fn the_device_list_and_its_filters() {
    let h = harness().await;
    let cookie = h.login(&sid("devlist"), 1, json!({}));
    let r = h.get("/devices", &cookie).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let body = squash(&r.body);
    assert!(body.contains("<title>Devices | HTE Remote</title>"));
    // chips: 3 live devices (1,2,4 is pending so not counted; 3 is trashed): total 2, online 1
    assert!(body.contains(r#"<span class="rd-chip-value">2</span> <span class="rd-chip-label">Devices</span>"#), "{body}");
    assert!(body.contains(r#"<span class="rd-chip-value">1</span> <span class="rd-chip-label">Online</span>"#));
    assert!(body.contains(r#"<span class="rd-chip-value">1</span> <span class="rd-chip-label">Pending</span>"#));
    assert!(body.contains("Recycle Bin (1)"));
    assert!(body.contains("FRONT-PC") && body.contains("BACK-PC") && !body.contains("OLD-PC"));
    // default order: last seen, newest first
    assert!(body.find("FRONT-PC").unwrap() < body.find("BACK-PC").unwrap());
    // search, status, group, owner
    let r = h.get("/devices?search=erin", &cookie).await;
    assert!(r.body.contains("BACK-PC") && !r.body.contains("FRONT-PC"));
    let r = h.get("/devices?status=offline", &cookie).await;
    assert!(r.body.contains("BACK-PC") && !r.body.contains("FRONT-PC"));
    let r = h.get("/devices?group=1", &cookie).await;
    assert!(r.body.contains("FRONT-PC") && !r.body.contains("BACK-PC"));
    let r = h.get("/devices?owner=-1", &cookie).await;
    assert!(r.body.contains("BACK-PC") && !r.body.contains("FRONT-PC"));
    let r = h.get("/devices?trashed=1", &cookie).await;
    assert!(r.body.contains("OLD-PC") && r.body.contains("Recycle bin"));
    let r = h.get("/devices?pending=1", &cookie).await;
    assert!(squash(&r.body).contains("Pending approval") && r.body.contains("1004") && r.body.contains("Approve"));
    // the person without admin sees only theirs
    let dana = h.login(&sid("devdana"), 2, json!({}));
    let r = h.get("/devices", &dana).await;
    assert!(r.body.contains("FRONT-PC") && !r.body.contains("BACK-PC"), "{}", r.body);
    assert!(!r.body.contains("All owners"));
    let r = h.get("/devices/2", &dana).await;
    assert_eq!(r.status, 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn sorting_and_columns_are_saved_on_the_person() {
    let h = harness().await;
    let cookie = h.login(&sid("devsort"), 1, json!({}));
    let r = h.post_form("/devices/sort", &cookie, &[tok(), ("field", "id"), ("back", "")]).await;
    assert_eq!(r.status, 302, "{}", r.body);
    assert_eq!(h.text("select devices_sort from users where id = 1"), "id");
    assert_eq!(h.text("select devices_sort_direction from users where id = 1"), "asc");
    let r = h.post_form("/devices/sort", &cookie, &[tok(), ("field", "id"), ("back", "")]).await;
    assert_eq!(r.status, 302);
    assert_eq!(h.text("select devices_sort_direction from users where id = 1"), "desc");
    let body = h.get("/devices", &cookie).await.body;
    assert!(body.find("BACK-PC").unwrap() < body.find("FRONT-PC").unwrap());
    // columns
    let r = h.post_form("/devices/columns", &cookie, &[tok(), ("columns[]", "device"), ("columns[]", "cpu"), ("back", ""), ("done", "1")]).await;
    assert_eq!(r.status, 302);
    assert_eq!(h.text("select devices_columns from users where id = 1"), r#"["device","cpu"]"#);
    let body = h.get("/devices", &cookie).await.body;
    assert!(body.contains(">CPU</th>") && !body.contains(">Version"));
    h.post_form("/devices/columns", &cookie, &[tok(), ("reset", "1"), ("back", "")]).await;
    assert_eq!(h.text("select coalesce(devices_columns, 'NULL') from users where id = 1"), "NULL");
}

#[tokio::test(flavor = "multi_thread")]
async fn device_writes() {
    let h = harness().await;
    let cookie = h.login(&sid("devwrite"), 1, json!({}));
    // bulk: incoming only, then a group move
    let r = h.post_form("/devices/bulk", &cookie, &[tok(), ("do", "incoming"), ("selected[]", "1"), ("selected[]", "2"), ("back", "")]).await;
    assert_eq!(r.status, 302, "{}", r.body);
    assert_eq!(h.count("devices where can_initiate = 0"), 2);
    assert_eq!(h.text("select summary from console_audits where action = 'device.initiate'"), "Set 2 devices incoming only");
    let body = h.get("/devices", &cookie).await.body;
    assert!(squash(&body).contains("2 devices set incoming only."));
    let r = h.post_form("/devices/bulk", &cookie, &[tok(), ("do", "move-group"), ("selected[]", "1"), ("selected[]", "2"), ("group_id", "2"), ("back", "")]).await;
    assert_eq!(r.status, 302);
    assert_eq!(h.text("select cast(device_group_id as text) from devices where id = 1"), "2");
    assert_eq!(h.text("select summary from console_audits where action = 'device.group-move'"), "Moved 1 device to Back office; 1 unchanged.");
    // a group move without a choice shows the picker with its message
    let r = h.post_form("/devices/bulk", &cookie, &[tok(), ("do", "move-group"), ("selected[]", "1"), ("back", "")]).await;
    assert_eq!(r.status, 200);
    assert!(r.body.contains("Pick a device group."));
    // edit
    let r = h.post_form("/devices/save", &cookie, &[tok(), ("id", "1"), ("alias", "Desk"), ("note", "n"), ("group_id", "1"), ("user_id", "0"), ("can_initiate", "1"), ("strategy_id", "0"), ("return", "/devices")]).await;
    assert_eq!(r.status, 302, "{}", r.body);
    assert_eq!(h.text("select alias from devices where id = 1"), "Desk");
    assert_eq!(h.text("select coalesce(cast(user_id as text), 'NULL') from devices where id = 1"), "NULL");
    assert_eq!(h.count("console_audits where action = 'device.update'"), 1);
    assert_eq!(h.count("console_audits where action = 'device.initiate' and summary like 'Device 1001%'"), 1);
    // create, with a duplicate id refused
    let r = h.post_form("/devices/save", &cookie, &[tok(), ("id", "0"), ("rustdesk_id", "2001"), ("alias", ""), ("note", ""), ("group_id", "0"), ("user_id", "0"), ("can_initiate", "1"), ("return", "/devices")]).await;
    assert_eq!(r.status, 302);
    assert_eq!(h.count("devices where rustdesk_id = '2001'"), 1);
    let r = h.post_form("/devices/save", &cookie, &[tok(), ("id", "0"), ("rustdesk_id", "2001"), ("return", "/devices")]).await;
    assert_eq!(r.status, 422);
    assert!(r.body.contains("The form rustdesk id has already been taken."), "{}", r.body);
    // delete, restore, destroy
    let r = h.post_form("/devices/bulk", &cookie, &[tok(), ("do", "delete"), ("selected[]", "2"), ("back", "")]).await;
    assert_eq!(r.status, 200);
    assert!(r.body.contains("Delete device 1002?"));
    let r = h.post_form("/devices/delete", &cookie, &[tok(), ("ids[]", "2"), ("return", "/devices")]).await;
    assert_eq!(r.status, 302);
    assert!(h.text("select deleted_at from devices where id = 2").starts_with("2025-10-25"));
    h.post_form("/devices/act", &cookie, &[tok(), ("do", "restore"), ("id", "2"), ("back", "trashed=1")]).await;
    assert_eq!(h.text("select coalesce(deleted_at, 'NULL') from devices where id = 2"), "NULL");
    h.post_form("/devices/act", &cookie, &[tok(), ("do", "destroy"), ("id", "3"), ("back", "trashed=1")]).await;
    assert_eq!(h.count("devices where id = 3"), 0);
    // approve
    h.post_form("/devices/act", &cookie, &[tok(), ("do", "approve"), ("id", "4"), ("back", "pending=1")]).await;
    assert_eq!(h.text("select status from devices where id = 4"), "active");
    assert_eq!(h.text("select summary from console_audits where action = 'device.approve'"), "Approved device 1004");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_device_page() {
    let h = harness().await;
    h.sql("insert into audit_connections (rustdesk_id, from_peer, from_name, ip, conn_type, created_at, closed_at) values ('1001', '555', 'Front PC', '10.1.1.1', 0, '2025-10-25 03:10:00', '2025-10-25 03:12:05')");
    let cookie = h.login(&sid("devpage"), 1, json!({}));
    let r = h.get("/devices/1", &cookie).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let body = squash(&r.body);
    assert!(body.contains("Front PC") && body.contains("Windows 11"));
    assert!(body.contains("Who can reach this device"));
    assert!(body.contains("Set on the computer itself") || body.contains("Not managed by the console"));
    assert!(body.contains("Recent connections") && body.contains("2m 5s"));
    // the note
    let r = h.post_form("/devices/1/do", &cookie, &[tok(), ("do", "note"), ("note", "  hello  ")]).await;
    assert_eq!(r.status, 302, "{}", r.body);
    assert_eq!(h.text("select note from devices where id = 1"), "hello");
    // the address book
    h.sql("insert into address_books (id, guid, name, is_personal, owner_user_id, created_at, updated_at) values (1, 'g1', 'Shared', 0, 1, '2025-01-01 00:00:00', '2025-01-01 00:00:00')");
    h.post_form("/devices/1/do", &cookie, &[tok(), ("do", "add-book"), ("book_id", "1")]).await;
    assert_eq!(h.count("address_book_entries where address_book_id = 1 and rustdesk_id = '1001'"), 1);
    h.post_form("/devices/1/do", &cookie, &[tok(), ("do", "remove-book"), ("book_id", "1")]).await;
    assert_eq!(h.count("address_book_entries"), 0);
    // the password: not enabled, so there is nothing to change; an administrator's request is accepted anyway
    let r = h.post_form("/devices/1/do", &cookie, &[tok(), ("do", "rotate-password")]).await;
    assert_eq!(r.status, 302);
    assert_eq!(h.count("hte_device_passwords where rustdesk_id = '1001'"), 1);
    // a person who may not write cannot
    let erin = h.login(&sid("deverin"), 3, json!({}));
    assert_eq!(h.get("/devices", &erin).await.status, 302);
}

#[tokio::test]
async fn the_users_pages() {
    let h = harness().await;
    let cookie = h.login(&sid("users1"), 1, json!({}));
    let r = h.get("/users", &cookie).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let body = squash(&r.body);
    assert!(body.contains("dana") && body.contains("Showing 1–4 of 4"), "{body}");
    let r = h.get("/users?search=gone&status=disabled", &cookie).await;
    assert!(squash(&r.body).contains("Showing 1–1 of 1"));
    // the editor opens, validates (422), then saves
    let r = h.get("/users?create=1", &cookie).await;
    assert!(squash(&r.body).contains("Add User"));
    let r = h.post_form("/users/save", &cookie, &[tok(), ("id", "0"), ("return", "/users"), ("username", "dana"), ("password", "short")]).await;
    assert_eq!(r.status, 422, "{}", r.body);
    assert!(r.body.contains("The username has already been taken.") && r.body.contains("The password field must be at least 8 characters."), "{}", r.body);
    let r = h.post_form("/users/save", &cookie, &[tok(), ("id", "0"), ("return", "/users"), ("username", "newbie"), ("name", "New B"), ("email", "n@example.test"), ("password", "longenough1"), ("is_active", "1"), ("user_group_ids[]", "1"), ("device_group_ids[]", "2")]).await;
    assert_eq!(r.status, 302, "{}", r.body);
    assert_eq!(h.count("users where username = 'newbie' and is_active = 1 and is_admin = 0"), 1);
    assert_eq!(h.count("user_group_user where user_id = 5"), 1);
    assert_eq!(h.count("device_group_user where user_id = 5 and device_group_id = 2"), 1);
    assert_eq!(h.count("console_audits where action = 'user.create'"), 1);
    // edit: role, blank password keeps the hash
    let before = h.text("select password from users where id = 5");
    h.post_form("/users/save", &cookie, &[tok(), ("id", "5"), ("return", "/users"), ("username", "newbie"), ("name", "New C"), ("password", ""), ("role_id", "1"), ("is_active", "1")]).await;
    assert_eq!(h.text("select password from users where id = 5"), before);
    assert_eq!(h.text("select cast(role_id as text) from users where id = 5"), "1");
    assert_eq!(h.count("device_group_user where user_id = 5"), 0);
    // actions
    h.post_form("/users/act", &cookie, &[tok(), ("id", "2"), ("do", "toggle"), ("back", "")]).await;
    assert_eq!(h.text("select cast(is_active as text) from users where id = 2"), "0");
    h.post_form("/users/act", &cookie, &[tok(), ("id", "1"), ("do", "toggle"), ("back", "")]).await;
    assert_eq!(h.text("select cast(is_active as text) from users where id = 1"), "1");
    h.sql("update users set totp_enabled = 1, totp_secret = 'x' where id = 4; insert into two_factor_recovery_codes (user_id, code_hash, created_at) values (4, 'c', '2025-01-01 00:00:00')");
    h.post_form("/users/act", &cookie, &[tok(), ("id", "4"), ("do", "reset2fa"), ("back", "")]).await;
    assert_eq!(h.count("users where id = 4 and totp_enabled = 0 and totp_secret is null"), 1);
    assert_eq!(h.count("two_factor_recovery_codes"), 0);
    // assign devices
    let r = h.get("/users?assign=2", &cookie).await;
    assert!(squash(&r.body).contains("Assign Devices"));
    h.post_form("/users/assign", &cookie, &[tok(), ("id", "2"), ("ids[]", "2"), ("back", "")]).await;
    assert_eq!(h.text("select cast(user_id as text) from devices where id = 2"), "2");
    assert_eq!(h.count("devices where id = 1 and user_id is null"), 1);
    // the person page
    let r = h.get("/users/2", &cookie).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(squash(&r.body).contains("Recent sign-ins") && squash(&r.body).contains("BACK-PC"));
    assert_eq!(h.get("/users/99", &cookie).await.status, 404);
    // delete
    h.post_form("/users/act", &cookie, &[tok(), ("id", "5"), ("do", "delete"), ("back", "")]).await;
    assert_eq!(h.count("users where id = 5"), 0);
    // the self guard and a person without the role
    h.post_form("/users/act", &cookie, &[tok(), ("id", "1"), ("do", "delete"), ("back", "")]).await;
    assert_eq!(h.count("users where id = 1"), 1);
    let erin = h.login(&sid("users-erin"), 3, json!({}));
    assert_eq!(h.get("/users", &erin).await.status, 302);
}

#[tokio::test]
async fn the_groups_page() {
    let h = harness().await;
    let cookie = h.login(&sid("groups1"), 1, json!({}));
    let r = h.get("/groups", &cookie).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(squash(&r.body).contains("Front desk") && squash(&r.body).contains("Back office"));
    assert!(squash(&h.get("/groups?tab=users", &cookie).await.body).contains("Techs"));
    assert!(squash(&h.get("/groups?tab=users&create=1", &cookie).await.body).contains("Add User Group"));
    assert!(squash(&h.get("/groups?edit=1", &cookie).await.body).contains("Edit Device Group"));
    let r = h.post_form("/groups/save", &cookie, &[tok(), ("type", "users"), ("id", "0"), ("name", "")]).await;
    assert_eq!(r.status, 422, "{}", r.body);
    assert!(r.body.contains("The name field is required."));
    let r = h.post_form("/groups/save", &cookie, &[tok(), ("type", "users"), ("id", "0"), ("name", "Ops"), ("note", "n"), ("device_group_ids[]", "1"), ("device_group_ids[]", "2"), ("accessor_group_ids[]", "1")]).await;
    assert_eq!(r.status, 302, "{}", r.body);
    assert_eq!(h.count("device_group_user_group where user_group_id = 2"), 2);
    assert_eq!(h.count("group_accesses where target_type = 'user_group' and target_id = 2 and accessor_id = 1"), 1);
    assert_eq!(h.count("console_audits where action = 'group.create'"), 1);
    h.post_form("/groups/save", &cookie, &[tok(), ("type", "devices"), ("id", "1"), ("name", "Front"), ("accessor_group_ids[]", "2")]).await;
    assert_eq!(h.text("select name from device_groups where id = 1"), "Front");
    assert_eq!(h.count("group_accesses where target_type = 'device_group' and target_id = 1 and accessor_id = 2"), 1);
    h.post_form("/groups/act", &cookie, &[tok(), ("type", "devices"), ("id", "1"), ("do", "delete")]).await;
    assert_eq!(h.count("device_groups"), 1);
    assert_eq!(h.count("devices where device_group_id = 1"), 0);
    assert_eq!(h.count("group_accesses where target_type = 'device_group'"), 0);
    h.post_form("/groups/act", &cookie, &[tok(), ("type", "users"), ("id", "2"), ("do", "delete")]).await;
    assert_eq!(h.count("user_groups"), 1);
    assert_eq!(h.count("group_accesses"), 0);
    assert_eq!(h.count("device_group_user_group where user_group_id = 2"), 0);
    let erin = h.login(&sid("groups-erin"), 3, json!({}));
    assert_eq!(h.get("/groups", &erin).await.status, 302);
}
