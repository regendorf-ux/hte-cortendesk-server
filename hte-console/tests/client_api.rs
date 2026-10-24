//! Phase 4 end to end: the bearer-token client endpoints (address books, group tab, server-config, audit note and
//! active session, the web client's bootstrap script) on a real socket, against a temporary database made from
//! tests/schema.sql, tests/schema_p4.sql and the replay's synthetic seed (fixtures/clientapi/*.sql). Expectations come
//! from the PHP source (v1.15.0-hte.1); each test names the PHP behaviour it pins.

use hte_console::api::{router, Limiter, Native, Nonces};
use hte_console::laravel::{self, Encrypter};
use hte_console::oidc::Oidc;
use rusqlite::Connection;
use serde_json::{json, Value};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Once};

const APP_KEY: &str = "base64:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const SEED: &str = include_str!("../fixtures/clientapi/0000000000004-clientapi-seed.sql");
const ADMIN: &str = "tok-5eed000000004a01";
const ANNA: &str = "tok-5eed000000004a02";
const BEN: &str = "tok-5eed000000004a03";
const PERSONAL: &str = "00000000-0000-4000-8000-0000000004a1";
const C3: &str = "00000000-0000-4000-8000-0000000004c3";

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
    c.execute_batch(&hte_console::seed::expand(SEED, "http://127.0.0.1:1", &crypt).unwrap()).unwrap();
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
async fn synthetic_clientapi_fixtures_replay_with_no_differences() {
    let h = harness().await;
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/clientapi");
    let s = hte_console::sanitise::Sanitiser::new(Some("test"), &[]);
    let r = hte_console::replay::run(&dir, &h.url, &s).await.unwrap();
    assert!(r.total > 100, "{} fixtures", r.total);
    assert!(r.differences.is_empty(), "{} differences:\n{}", r.differences.len(), r.differences.join("\n"));

    // what PHP would have written
    assert_eq!(h.count("address_books where is_personal = 1 and owner_user_id = 940003"), 1, "firstOrCreate made one book for Ben");
    assert_eq!(h.count("address_books where is_personal = 1 and owner_user_id = 940001"), 1);
    assert_eq!(h.one::<String>("select name from address_books where owner_user_id = 940003 and is_personal = 1"), "My address book");
    // the audit note: trimmed, owner set, stamped; Ben's rewrite kept his id
    assert_eq!(h.one::<String>("select note from audit_connections where id = 940001"), "text-5eed0a01");
    assert_eq!(h.one::<i64>("select note_user_id from audit_connections where id = 940001"), 940002);
    assert!(h.one::<Option<String>>("select noted_at from audit_connections where id = 940001").is_some());
    assert_eq!(h.one::<String>("select note from audit_connections where id = 940003"), "text-5eed0a03");
    assert_eq!(h.one::<String>("select note from audit_connections where id = 940005"), "text-5eed04f5", "409: untouched");
    // the session without a guid got one, a uuid
    let g: String = h.one("select guid from audit_connections where id = 940002");
    assert_eq!(g.len(), 36);
    // shared-book password encrypted, personal-book hash plain
    let enc: String = h.one("select password_enc from address_book_entries where address_book_id = 940012 and rustdesk_id = '990000411'");
    assert!(enc.starts_with("eyJ"), "a Laravel payload, not the password: {enc}");
    assert!(h.one::<Option<String>>("select hash from address_book_entries where address_book_id = 940012 and rustdesk_id = '990000411'").is_none());
    assert_eq!(h.one::<Option<String>>("select password_enc from address_book_entries where address_book_id = 940001 and rustdesk_id = '990000425'"), None);
    // the legacy push rebuilt Anna's book, Ben's push emptied his
    assert_eq!(h.count("address_book_entries where address_book_id = 940001"), 2);
    assert_eq!(h.count("tags where address_book_id = 940001"), 2);
    // the tokens were stamped
    assert!(h.one::<Option<String>>("select last_used_at from client_tokens where token = 'tok-5eed000000004a02'").is_some());
    assert!(h.one::<Option<String>>("select last_used_at from client_tokens where token = 'tok-5eed000000004a06'").is_none(), "an expired token is never stamped");
    // no secret of the run reached the log
    let log = String::from_utf8_lossy(&LOG.lock().unwrap()).into_owned();
    for secret in ["tok-5eed000000000431", "tok-5eed000000000451", "tok-5eed000000000452", "tok-5eed0000000004a5"] {
        assert!(!log.contains(secret), "the log holds {secret}");
    }
    for t in ["tok-5eed000000004a01", "tok-5eed000000004a02", "tok-5eed000000004a03"] {
        assert!(!log.contains(t), "the log holds a client token");
    }
}

// -------------------------------------------------------------------------------------------- routing ---

#[tokio::test(flavor = "multi_thread")]
async fn options_and_preflight_are_answered_as_laravel_does() {
    let h = harness().await;
    // OPTIONS on a known path: 200, Allow joined by ","
    let r = h.raw("OPTIONS", "/api/ab", None, None, vec![], &[]).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.headers["allow"], "GET,HEAD,POST");
    // a CORS preflight never reaches the route
    let r = h
        .raw("OPTIONS", "/api/ab/peers", None, None, vec![], &[("origin", "http://web.invalid"), ("access-control-request-method", "post"), ("access-control-request-headers", "authorization")])
        .await;
    assert_eq!(r.status, 204);
    assert_eq!(r.headers["access-control-allow-methods"], "POST");
    assert_eq!(r.headers["access-control-allow-headers"], "authorization");
    // HEAD runs the GET route (and drops the body)
    let r = h.raw("HEAD", "/api/users", Some(ANNA), None, vec![], &[]).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body, "");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_body_over_the_cap_is_413_and_nothing_is_written() {
    let h = harness().await;
    // a valid push that would replace the book if it were read, over the 2 MiB default cap
    let peers: Vec<Value> = (0..30_000).map(|i| json!({"id": format!("97{i:07}"), "alias": "x".repeat(60)})).collect();
    let big = json!({"data": json!({"tags": [], "peers": peers, "tag_colors": ""}).to_string()}).to_string().into_bytes();
    assert!(big.len() > 2 * 1024 * 1024);
    // the refusal comes from the declared length, before the body is read: the sender sees 413 or a closed socket
    let sent = h
        .client
        .post(format!("{}/api/ab", h.url))
        .header("authorization", format!("Bearer {ANNA}"))
        .header("content-type", "application/json")
        .body(big)
        .send()
        .await;
    if let Ok(r) = sent {
        assert_eq!(r.status().as_u16(), 413);
    }
    assert_eq!(h.count("address_book_entries where address_book_id = 940001"), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_web_client_script_needs_no_login_and_names_the_origin() {
    let h = harness().await;
    let r = h.raw("GET", "/webclient-config/index.js", None, None, vec![], &[("host", "console.example.invalid"), ("x-forwarded-proto", "https")]).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.ct, "application/javascript");
    assert_eq!(
        r.body,
        "localStorage.setItem('api-server', 'https://console.example.invalid');\nconst ws2_prefix = 'wc-';\nlocalStorage.setItem(ws2_prefix + 'api-server', 'https://console.example.invalid');\nwindow.webclient_magic_queryonline = 0;\n"
    );
    // a host that is no host is a 404 (Symfony's SuspiciousOperationException)
    let r = h.raw("GET", "/webclient-config/index.js", None, None, vec![], &[("host", "bad host")]).await;
    assert_ne!(r.status, 200);
}

// ---------------------------------------------------------------------------------------------- reach ---

#[tokio::test(flavor = "multi_thread")]
async fn a_persons_peers_are_exactly_their_computers() {
    let h = harness().await;
    for (who, want) in [(ANNA, vec!["990000411", "990000412"]), (BEN, vec!["990000412", "990000413", "990000414"]), ("tok-5eed000000004a04", vec!["990000414"]), (ADMIN, vec!["990000411", "990000412", "990000413", "990000414", "990000417"])] {
        let v = h.req("GET", "/api/peers", who, None).await.json();
        let got: Vec<&str> = v["data"].as_array().unwrap().iter().map(|p| p["id"].as_str().unwrap()).collect();
        assert_eq!(got, want, "{who}");
        assert_eq!(v["total"], want.len());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_administrators_user_list_is_everyone() {
    let h = harness().await;
    let v = h.req("GET", "/api/users", ADMIN, None).await.json();
    assert_eq!(v["total"], 5);
    let v = h.req("GET", "/api/users?status=1", ADMIN, None).await.json();
    assert_eq!(v["total"], 4);
    assert_eq!(v["data"][0]["is_admin"], true);
}

#[tokio::test(flavor = "multi_thread")]
async fn paging_is_clamped_like_the_pagination_helper() {
    let h = harness().await;
    let mut s = String::new();
    for i in 0..600 {
        s += &format!("insert into address_book_entries (address_book_id, rustdesk_id, created_at, updated_at) values (940012, '98{i:07}', datetime('now'), datetime('now'));\n");
    }
    h.sql(&s);
    let q = |extra: &str| format!("/api/ab/peers?ab={C3}{extra}");
    let v = h.req("POST", &q(""), ANNA, None).await.json();
    assert_eq!(v["total"], 602);
    assert_eq!(v["data"].as_array().unwrap().len(), 100, "default page size");
    let v = h.req("POST", &q("&pageSize=1000"), ANNA, None).await.json();
    assert_eq!(v["data"].as_array().unwrap().len(), 500, "capped");
    let v = h.req("POST", &q("&pageSize=0&current=0"), ANNA, None).await.json();
    assert_eq!(v["data"].as_array().unwrap().len(), 1);
    let v = h.req("POST", &q("&pageSize=500&current=2"), ANNA, None).await.json();
    assert_eq!(v["data"].as_array().unwrap().len(), 102);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_online_window_defaults_to_sixty_seconds_without_the_setting() {
    let h = harness().await;
    h.sql("delete from settings where key = 'online_window'");
    h.sql("update devices set last_online_at = datetime('now', '-30 seconds') where rustdesk_id = '990000411'");
    h.sql("update devices set last_online_at = datetime('now', '-120 seconds') where rustdesk_id = '990000414'");
    let v = h.req("GET", "/api/peers", ADMIN, None).await.json();
    let status = |id: &str| v["data"].as_array().unwrap().iter().find(|p| p["id"] == id).unwrap()["status"].clone();
    assert_eq!(status("990000411"), 1);
    assert_eq!(status("990000414"), 0);
    // an empty or "0" setting is the default too
    h.sql("insert into settings (key, value) values ('online_window', '0')");
    let v = h.req("GET", "/api/peers", ADMIN, None).await.json();
    assert_eq!(v["data"].as_array().unwrap().iter().find(|p| p["id"] == "990000414").unwrap()["status"], 0);
}

// ---------------------------------------------------------------------------------------------- writes ---

#[tokio::test(flavor = "multi_thread")]
async fn a_form_encoded_put_is_read_like_laravel_reads_it() {
    let h = harness().await;
    let r = h
        .raw("PUT", &format!("/api/ab/peer/update/{PERSONAL}"), Some(ANNA), Some("application/x-www-form-urlencoded"), b"id=990000421&alias=text-5eed0481".to_vec(), &[])
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body, "");
    assert_eq!(h.one::<String>("select alias from address_book_entries where id = 940001"), "text-5eed0481");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_legacy_push_is_not_a_transaction_just_like_php() {
    let h = harness().await;
    // two tags of one name: the second insert hits the unique index after the old tags and entries are gone
    let data = json!({"tags": ["text-5eed04d5", "text-5eed04d5"], "peers": [{"id": "990000429"}], "tag_colors": ""}).to_string();
    let r = h.req("POST", "/api/ab", ANNA, Some(json!({"data": data}))).await;
    assert_eq!(r.status, 500);
    assert_eq!(r.json(), json!({"message": "Server Error"}));
    assert_eq!(h.count("tags where address_book_id = 940001"), 1, "the old tags were deleted, the first new one stayed");
    assert_eq!(h.count("address_book_entries where address_book_id = 940001"), 2, "the entries were not reached");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_long_note_is_cut_to_2000_characters() {
    let h = harness().await;
    let note = "é".repeat(2500);
    let r = h.req("PUT", "/api/audit", ANNA, Some(json!({"guid": "00000000-0000-4000-8000-0000000004f1", "note": note}))).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json(), json!({}));
    assert_eq!(h.one::<String>("select note from audit_connections where id = 940001").chars().count(), 2000);
}

#[tokio::test(flavor = "multi_thread")]
async fn deleting_a_tag_leaves_the_other_tags_of_an_entry_in_order() {
    let h = harness().await;
    let r = h.req("DELETE", &format!("/api/ab/tag/{PERSONAL}"), ANNA, Some(json!(["text-5eed04d1"]))).await;
    assert_eq!(r.status, 200);
    assert_eq!(h.one::<String>("select tag_ids from address_book_entries where id = 940002"), "[940002]");
    assert_eq!(h.one::<String>("select tag_ids from address_book_entries where id = 940001"), "[]");
}
