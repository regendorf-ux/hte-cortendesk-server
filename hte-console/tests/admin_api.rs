//! Phase 5 end to end: the admin automation API (/api/v1/*) and `--assign` (/api/devices/cli) on a real socket, against a
//! temporary database made from tests/schema.sql, schema_p4.sql, schema_p5.sql and the synthetic seed
//! (fixtures/adminapi/*.sql). Expectations come from the PHP source (v1.15.0-hte.1).

use hte_console::api::{router, Limiter, Native, Nonces};
use hte_console::laravel::{self, Encrypter};
use hte_console::oidc::Oidc;
use rusqlite::Connection;
use serde_json::{json, Value};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Once};

const APP_KEY: &str = "base64:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const SEED: &str = include_str!("../fixtures/adminapi/0000000000005-adminapi-seed.sql");
const FULL: &str = "tok-5eed000000005a01";
const READ: &str = "tok-5eed000000005a02";

/// Everything every test logs, to prove no secret ever reaches the log.
static LOG: Mutex<Vec<u8>> = Mutex::new(Vec::new());
static LOG_ONCE: Once = Once::new();

struct LogWriter;
impl Write for LogWriter {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        LOG.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn capture_logs() {
    LOG_ONCE.call_once(|| {
        let sub = tracing_subscriber::fmt().with_writer(|| LogWriter).with_ansi(false).with_max_level(tracing::Level::DEBUG).finish();
        let _ = tracing::subscriber::set_global_default(sub);
    });
}

struct H {
    url: String,
    db_path: PathBuf,
    client: reqwest::Client,
    _dir: tempfile::TempDir,
}

struct Resp {
    status: u16,
    ct: String,
    headers: reqwest::header::HeaderMap,
    body: String,
}

impl Resp {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_else(|_| panic!("not JSON: {:?}", self.body))
    }
}

async fn harness() -> H {
    capture_logs();
    sodiumoxide::init().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("cortendesk.sqlite");
    let crypt = Encrypter::from_app_key(APP_KEY).unwrap();
    let c = Connection::open(&db_path).unwrap();
    c.execute_batch(include_str!("schema.sql")).unwrap();
    c.execute_batch(include_str!("schema_p4.sql")).unwrap();
    c.execute_batch(include_str!("schema_p5.sql")).unwrap();
    c.execute_batch(SEED).unwrap();
    drop(c);
    let native = Arc::new(Native {
        db: Mutex::new(hte_console::sqlite::open(&db_path, std::time::Duration::from_secs(5), true).unwrap()),
        crypt,
        hbbs_db: dir.path().join("none.sqlite3"),
        trusted: laravel::parse_trusted(laravel::DEFAULT_TRUSTED),
        api_version: "1.15.0-hte.1".into(),
        max_body: 1 << 20,
        limiter: Mutex::new(Limiter::default()),
        nonces: Mutex::new(Nonces::default()),
        signin: hte_console::signin::State::new(Oidc::new(true, false), None, "HTE Remote".into()),
        clock: Box::new(|| chrono::Utc::now().timestamp()),
    });
    let app = router(native, None).into_make_service_with_connect_info::<std::net::SocketAddr>();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
    H { url, db_path, client, _dir: dir }
}

impl H {
    fn db(&self) -> Connection {
        Connection::open(&self.db_path).unwrap()
    }
    fn sql(&self, s: &str) {
        self.db().execute_batch(s).unwrap();
    }
    fn one<T: rusqlite::types::FromSql>(&self, q: &str) -> T {
        self.db().query_row(q, [], |r| r.get(0)).unwrap()
    }
    fn count(&self, q: &str) -> i64 {
        self.one(&format!("select count(*) from {q}"))
    }
    async fn raw(&self, method: &str, path: &str, token: Option<&str>, ct: Option<&str>, body: Vec<u8>, headers: &[(&str, &str)]) -> Resp {
        let mut rq = self.client.request(method.parse().unwrap(), format!("{}{}", self.url, path)).header("x-forwarded-for", "198.18.9.1");
        if let Some(t) = token {
            rq = rq.header("authorization", format!("Bearer {t}"));
        }
        for (k, v) in headers {
            rq = rq.header(*k, *v);
        }
        if let Some(ct) = ct {
            rq = rq.header("content-type", ct);
        }
        let r = rq.body(body).send().await.unwrap();
        let status = r.status().as_u16();
        let headers = r.headers().clone();
        let ct = headers.get("content-type").map(|v| v.to_str().unwrap().to_string()).unwrap_or_default();
        Resp { status, ct, headers, body: r.text().await.unwrap() }
    }
    async fn req(&self, method: &str, path: &str, token: &str, body: Option<Value>) -> Resp {
        match body {
            Some(b) => self.raw(method, path, Some(token), Some("application/json"), serde_json::to_vec(&b).unwrap(), &[]).await,
            None => self.raw(method, path, Some(token), None, vec![], &[]).await,
        }
    }
}

// ----------------------------------------------------------------------------------- the synthetic fixtures ---

#[tokio::test(flavor = "multi_thread")]
async fn synthetic_adminapi_fixtures_replay_with_no_differences() {
    let h = harness().await;
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/adminapi");
    let s = hte_console::sanitise::Sanitiser::new(Some("test"), &[]);
    let r = hte_console::replay::run(&dir, &h.url, &s).await.unwrap();
    assert!(r.total > 150, "{} fixtures", r.total);
    assert!(r.differences.is_empty(), "{} differences:\n{}", r.differences.len(), r.differences.join("\n"));

    // what PHP would have written
    assert_eq!(h.count("users where username = 'user-5eed0510' and is_active = 0 and is_admin = 0 and role_id is null"), 1, "store never takes admin or role");
    assert!(h.one::<String>("select password from users where username = 'user-5eed0510'").starts_with("$2y$"), "the hashed cast");
    assert_eq!(h.count("users where id = 950006"), 0, "deleted");
    assert_eq!(h.count("address_books where owner_user_id = 950006 and is_personal = 1"), 0, "personal books go with the user");
    assert_eq!(h.count("client_tokens where user_id in (950007, 950008)"), 0, "revoked");
    assert_eq!(h.count("sessions where user_id in (950007, 950008)"), 0);
    assert_eq!(h.count("trusted_devices where user_id = 950007"), 0);
    assert_eq!(h.one::<i64>("select is_active from users where id = 950007"), 0);
    assert_eq!(h.one::<i64>("select is_active from users where id = 950008"), 1);
    assert_ne!(h.one::<Option<String>>("select remember_token from users where id = 950008"), Some("tok-5eed00000000b002".into()));
    // the device written by --assign: ACTIVE, the named owner and the default folder, its policy resolved
    assert_eq!(h.one::<String>("select status from devices where rustdesk_id = '990000540'"), "active");
    assert_eq!(h.one::<i64>("select user_id from devices where rustdesk_id = '990000540'"), 950007);
    assert_eq!(h.one::<i64>("select device_group_id from devices where rustdesk_id = '990000540'"), 950502);
    assert_eq!(h.count("device_strategy where strategy_id = 950301"), 1);
    // the entry carries an encrypted password, never the plaintext
    let enc: String = h.one("select password_enc from address_book_entries where address_book_id = 950201 and rustdesk_id = '990000540'");
    assert!(enc.starts_with("eyJ"), "a Laravel payload: {enc}");
    // the soft-deleted device stays, the destroyed one does not
    assert_eq!(h.count("devices where rustdesk_id = '990000518' or rustdesk_id = '990000519'"), 0);
    assert_eq!(h.count("address_book_entries where rustdesk_id = '990000518'"), 0);
    // the token was stamped, the refused ones never
    assert!(h.one::<Option<String>>("select last_used_at from api_tokens where id = 950801").is_some());
    assert!(h.one::<Option<String>>("select last_used_at from api_tokens where id = 950804").is_none(), "an expired token is never stamped");
    assert!(h.one::<Option<String>>("select last_used_at from api_tokens where id = 950803").is_none(), "a none token is refused before it is stamped");
    // no secret reached the log
    let log = String::from_utf8_lossy(&LOG.lock().unwrap()).into_owned();
    for i in 1..=13 {
        let t = format!("tok-5eed000000005a{i:02x}");
        assert!(!log.contains(&t), "the log holds an API token: {t}");
    }
    assert!(!log.contains("tok-5eed00000000c0ff") && !log.contains("tok-5eed00000000c00"), "the log holds a password");
}

// ------------------------------------------------------------------------------------------------ the guard ---

#[tokio::test(flavor = "multi_thread")]
async fn nothing_under_api_v1_answers_without_a_token() {
    let h = harness().await;
    for (m, p) in [("GET", "/api/v1/users"), ("POST", "/api/v1/users"), ("GET", "/api/v1/audits/console"), ("DELETE", "/api/v1/devices/950711"), ("POST", "/api/devices/cli"), ("GET", "/api/v1/users/950001")] {
        let r = h.raw(m, p, None, None, vec![], &[]).await;
        assert_eq!(r.status, if m == "GET" && p.ends_with("/cli") { 405 } else { 401 }, "{m} {p}");
        assert_eq!(r.json(), json!({"message": "Unauthenticated."}));
    }
    // every route of the table refuses an unknown bearer
    for r in hte_console::admin::ROUTES {
        let path = r.pattern.replace("{}", "950001");
        let resp = h.raw(r.method, &path, Some("tok-5eed000000005aff"), None, vec![], &[]).await;
        assert_eq!(resp.status, 401, "{} {}", r.method, path);
    }
    assert_eq!(h.count("console_audits where id > 950632"), 0, "nothing was written");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_token_is_found_by_its_hash_and_only_whole() {
    let h = harness().await;
    for t in [FULL.to_string(), FULL.to_uppercase(), FULL[..12].to_string(), format!("{FULL}x")] {
        let r = h.req("GET", "/api/v1/user-groups", &t, None).await;
        assert_eq!(r.status, if t == FULL { 200 } else { 401 }, "{t:?}");
    }
    // the read-only token reads and cannot write
    assert_eq!(h.req("GET", "/api/v1/user-groups", READ, None).await.status, 200);
    let r = h.req("POST", "/api/v1/user-groups", READ, Some(json!({"name": "text-5eed0899"}))).await;
    assert_eq!(r.status, 403);
    assert_eq!(h.count("user_groups where name = 'text-5eed0899'"), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_owner_who_loses_the_right_stops_the_token_at_once() {
    let h = harness().await;
    assert_eq!(h.req("GET", "/api/v1/user-groups", FULL, None).await.status, 200);
    h.sql("update users set is_active = 0 where id = 950001");
    assert_eq!(h.req("GET", "/api/v1/user-groups", FULL, None).await.status, 401);
    h.sql("update users set is_active = 1 where id = 950001; update api_tokens set expires_at = datetime('now', '-1 second') where id = 950801");
    assert_eq!(h.req("GET", "/api/v1/user-groups", FULL, None).await.status, 401);
    h.sql("update api_tokens set expires_at = datetime('now', '+1 hour') where id = 950801");
    assert_eq!(h.req("GET", "/api/v1/user-groups", FULL, None).await.status, 200);
    h.sql("update api_tokens set is_active = 0 where id = 950801");
    assert_eq!(h.req("GET", "/api/v1/user-groups", FULL, None).await.status, 401);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_throttle_is_120_a_minute_per_owner_and_prefix() {
    let h = harness().await;
    let mut last = 0;
    for _ in 0..121 {
        last = h.req("GET", "/api/v1/user-groups", FULL, None).await.status;
    }
    assert_eq!(last, 429);
    let r = h.req("GET", "/api/v1/user-groups", FULL, None).await;
    assert_eq!(r.status, 429);
    assert!(r.headers.get("retry-after").is_some() && r.headers.get("x-ratelimit-limit").is_some());
    // the client prefix has its own counter
    let r = h.req("POST", "/api/devices/cli", FULL, Some(json!({"id": "x"}))).await;
    assert_eq!(r.status, 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_body_over_the_cap_is_413_and_nothing_is_written() {
    let h = harness().await;
    let big = vec![b'a'; (2 << 20) + 10];
    // the refusal comes from the declared length, before the body is read: the sender sees 413 or a closed socket
    let sent = h
        .client
        .post(format!("{}/api/v1/user-groups", h.url))
        .header("authorization", format!("Bearer {FULL}"))
        .header("content-type", "application/json")
        .body(big)
        .send()
        .await;
    if let Ok(r) = sent {
        assert_eq!(r.status().as_u16(), 413);
    }
    assert_eq!(h.count("user_groups"), 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_malformed_body_is_read_as_no_input() {
    let h = harness().await;
    let r = h.raw("POST", "/api/v1/user-groups", Some(FULL), Some("application/json"), b"{not json".to_vec(), &[]).await;
    assert_eq!(r.status, 422, "{}", r.body);
    assert_eq!(h.count("user_groups"), 3);
    // a form body is read as Laravel reads it
    let r = h.raw("POST", "/api/v1/user-groups", Some(FULL), Some("application/x-www-form-urlencoded"), b"name=text-5eed0897".to_vec(), &[]).await;
    assert_eq!(r.status, 201, "{}", r.body);
}

#[tokio::test(flavor = "multi_thread")]
async fn options_is_answered_without_a_token() {
    let h = harness().await;
    let r = h.raw("OPTIONS", "/api/v1/users", None, None, vec![], &[("origin", "https://example.invalid"), ("access-control-request-method", "GET")]).await;
    assert!(r.status == 204 || r.status == 200, "{}", r.status);
}
