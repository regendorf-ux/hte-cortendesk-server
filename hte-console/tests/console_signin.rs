//! Phase 8 end to end: hte-console's own console sign-in (`/login`, `/login/oidc`, `/login/oidc/callback`,
//! `/logout`) and its session cookie, on a real socket, against a temporary database made from tests/schema_live.sql,
//! phase 2's sign-in seed (the SSO accounts and settings) and a break-glass account made here, with the fake
//! identity provider of src/fake_idp.rs on another socket. Expectations: the PHP source (v1.15.0-hte.1,
//! AuthController, OidcController, OidcUserResolver) and the design in `phase8/NOTES.md`.

use hte_console::api::{Limiter, Native, Nonces};
use hte_console::fake_idp::{Config as IdpConfig, FakeIdp, MODES};
use hte_console::laravel::{self, Encrypter};
use hte_console::oidc::Oidc;
use hte_console::pages::{self, session, websession::OwnConfig};
use rusqlite::Connection;
use serde_json::Value;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, Once};

const APP_KEY: &str = "base64:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const SEED: &str = include_str!("../fixtures/signin/0000000000002-signin-seed.sql");
const T0: i64 = 1_800_000_000;
/// The break-glass account made here (cost 4, so the tests stay quick).
const ADMIN: &str = "user-5eed0b01";
const ADMIN_PW: &str = "tok-5eed00000000b0b1";
/// phase 2's seed password (cost 12) for its accounts.
const SEED_PW: &str = "tok-5eed00000000b002";

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
    idp: String,
    db_path: PathBuf,
    clock: Arc<AtomicI64>,
    client: reqwest::Client,
    crypt: Encrypter,
    _dir: tempfile::TempDir,
}

#[derive(Debug)]
struct Resp {
    status: u16,
    headers: reqwest::header::HeaderMap,
    body: String,
}

impl Resp {
    fn location(&self) -> String {
        self.headers.get("location").map(|v| v.to_str().unwrap().to_string()).unwrap_or_default()
    }
    fn path(&self) -> String {
        let l = self.location();
        match l.find("://") {
            Some(i) => l[i + 3..].find('/').map(|j| l[i + 3 + j..].to_string()).unwrap_or_default(),
            None => l,
        }
    }
    fn cookies(&self) -> Vec<String> {
        self.headers.get_all("set-cookie").iter().map(|v| v.to_str().unwrap().to_string()).collect()
    }
    /// The value our cookie is set to (either name).
    fn own_cookie(&self) -> Option<String> {
        self.cookies().into_iter().find(|c| c.starts_with("hte-remote-console=") || c.starts_with("__Host-hte-remote=")).map(|c| c.split(';').next().unwrap().to_string())
    }
    fn php_cookie(&self) -> Option<String> {
        self.cookies().into_iter().find(|c| c.starts_with("hte-remote-session=")).map(|c| c.split(';').next().unwrap().to_string())
    }
    fn csrf(&self) -> String {
        let i = self.body.find("name=\"csrf-token\" content=\"").expect("csrf meta") + 27;
        self.body[i..i + 40].to_string()
    }
}

struct Opts {
    signin: bool,
    bridge: bool,
    laravel_read: bool,
}

impl Default for Opts {
    fn default() -> Self {
        Opts { signin: true, bridge: true, laravel_read: true }
    }
}

async fn harness() -> H {
    harness_with(Opts::default()).await
}

async fn harness_with(o: Opts) -> H {
    capture_logs();
    sodiumoxide::init().unwrap();
    std::env::set_var("BCRYPT_ROUNDS", "4");
    std::env::set_var("HTE_SIGNIN_DOMAIN", "example.invalid");
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("cortendesk.sqlite");
    let clock = Arc::new(AtomicI64::new(T0));
    let (ck1, ck2) = (clock.clone(), clock.clone());
    let idp_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let idp = format!("http://{}", idp_l.local_addr().unwrap());
    let fake = FakeIdp::new(IdpConfig {
        issuer: idp.clone(),
        client_id: "client-seed".into(),
        client_secret: "tok-5eed00000000c11e".into(),
        tenant: None,
        clock: Arc::new(move || ck1.load(Ordering::SeqCst)),
    });
    let idp_app = fake.router();
    tokio::spawn(async move { axum::serve(idp_l, idp_app).await.unwrap() });
    let crypt = Encrypter::from_app_key(APP_KEY).unwrap();
    let c = Connection::open(&db_path).unwrap();
    c.execute_batch(include_str!("schema_live.sql")).unwrap();
    c.execute_batch(&hte_console::seed::expand(SEED, &idp, &crypt).unwrap()).unwrap();
    c.execute(
        "insert into users (id, username, name, email, password, is_admin, is_active, remember_token, created_at, updated_at) values (920001, ?, 'text-5eed0b01', 'user-5eed000b01@example.invalid', ?, 1, 1, 'rt-1', '2026-01-01 00:00:00', '2026-01-01 00:00:00')",
        rusqlite::params![ADMIN, laravel::hash_make(ADMIN_PW.as_bytes()).unwrap()],
    )
    .unwrap();
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
        clock: Box::new(move || ck2.load(Ordering::SeqCst)),
    });
    let own = OwnConfig { signin: o.signin, idle_s: 3600, absolute_s: 12 * 3600, bridge: o.bridge, laravel_read: o.laravel_read };
    let app = pages::routes_with(native, None, own).unwrap().into_make_service_with_connect_info::<std::net::SocketAddr>();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
    H { url, idp, db_path, clock, client, crypt, _dir: dir }
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
    fn advance(&self, s: i64) {
        self.clock.fetch_add(s, Ordering::SeqCst);
    }
    async fn go(&self, method: &str, path: &str, cookie: Option<&str>, form: Option<&[(&str, &str)]>, headers: &[(&str, &str)]) -> Resp {
        let mut rq = self.client.request(method.parse().unwrap(), format!("{}{}", self.url, path)).header("x-forwarded-for", "198.18.9.1").header("user-agent", "test-agent");
        if let Some(c) = cookie {
            rq = rq.header("cookie", c);
        }
        for (k, v) in headers {
            rq = rq.header(*k, *v);
        }
        if let Some(f) = form {
            let body = laravel::http_build_query(&f.iter().map(|(k, v)| (*k, v.as_bytes())).collect::<Vec<_>>());
            rq = rq.header("content-type", "application/x-www-form-urlencoded").body(body);
        }
        let r = rq.send().await.unwrap();
        let (status, headers) = (r.status().as_u16(), r.headers().clone());
        Resp { status, headers, body: r.text().await.unwrap() }
    }
    async fn get(&self, path: &str, cookie: Option<&str>) -> Resp {
        self.go("GET", path, cookie, None, &[]).await
    }
    /// The sign-in page: (guest cookie, CSRF token).
    async fn guest(&self) -> (String, String) {
        let r = self.get("/login", None).await;
        assert_eq!(r.status, 200, "{}", r.body);
        (r.own_cookie().unwrap(), r.csrf())
    }
    async fn password(&self, cookie: &str, token: &str, user: &str, pw: &str) -> Resp {
        self.go("POST", "/login", Some(cookie), Some(&[("_token", token), ("username", user), ("password", pw), ("remember", "on")]), &[]).await
    }
    /// A whole break-glass sign-in: (our cookie, PHP's bridged cookie).
    async fn sign_in(&self) -> (String, Option<String>) {
        let (c, t) = self.guest().await;
        let r = self.password(&c, &t, ADMIN, ADMIN_PW).await;
        assert_eq!((r.status, r.path()), (302, "/".to_string()), "{}", r.body);
        (r.own_cookie().unwrap(), r.php_cookie())
    }
    /// The browser through the fake provider: start, authorize (with the mode and person), the callback.
    async fn sso(&self, mode: &str, user: &str) -> (Resp, String) {
        let (c, _) = self.guest().await;
        let r = self.get("/login/oidc", Some(&c)).await;
        assert_eq!(r.status, 302, "{}", r.body);
        let auth = r.location();
        assert!(auth.starts_with(&format!("{}/authorize?", self.idp)), "{auth}");
        let a = self.client.get(format!("{auth}&hte_fake={mode}&hte_user={user}")).send().await.unwrap();
        assert_eq!(a.status().as_u16(), 302);
        let back = url::Url::parse(a.headers()["location"].to_str().unwrap()).unwrap();
        let pq = format!("{}?{}", back.path(), back.query().unwrap_or(""));
        (self.get(&pq, Some(&c)).await, pq)
    }
    fn logins(&self) -> Vec<(Option<i64>, String, String, i64)> {
        let c = self.db();
        let mut st = c.prepare("select user_id, username, client, successful from login_logs order by id").unwrap();
        let v = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))).unwrap().map(Result::unwrap).collect();
        v
    }
    /// Flash on the next page: the error alert's text.
    async fn error_shown(&self, cookie: &str) -> String {
        let r = self.get("/login", Some(cookie)).await;
        match r.body.find("alert alert-danger w-100 mb-0\" role=\"alert\">") {
            Some(i) => {
                let rest = &r.body[i + 44..];
                rest[..rest.find("</div>").unwrap()].to_string()
            }
            None => String::new(),
        }
    }
}

// ------------------------------------------------------------------------------------------- the page ---

#[tokio::test(flavor = "multi_thread")]
async fn the_sign_in_page_is_hte_remote_s_and_opens_a_guest_session() {
    let h = harness().await;
    let r = h.get("/login", None).await;
    assert_eq!(r.status, 200);
    for want in [
        "<title>Sign In | HTE Remote</title>",
        "<h1>Welcome to HTE Remote</h1>",
        "Sign in with your <b>@example.invalid</b> account",
        "class=\"msbtn\"",
        "Sign in with Microsoft",
        "Use the console password instead",
        concat!("/assets/css/hte-auth.css?v=", env!("CARGO_PKG_VERSION")),
        "<input type=\"hidden\" name=\"_token\" value=\"",
    ] {
        assert!(r.body.contains(want), "missing {want}");
    }
    // the form is folded away while SSO is on and nothing went wrong
    assert!(r.body.contains("id=\"hteForm\" hidden"));
    assert!(!r.body.contains("Forgot password?"));
    let c = r.cookies().into_iter().find(|c| c.starts_with("hte-remote-console=")).unwrap();
    assert!(c.ends_with("; path=/; httponly; samesite=lax"), "{c}");
    assert_eq!(r.headers["cache-control"], "no-store, private");
    assert_eq!(r.headers["x-frame-options"], "DENY");
    // one guest row, keyed by the hash of the cookie, never the cookie itself
    let id = r.own_cookie().unwrap().split('=').nth(1).unwrap().to_string();
    assert_eq!(h.count("hte_console_sessions where user_id is null"), 1);
    assert_eq!(h.count(&format!("hte_console_sessions where id_hash = '{id}'")), 0);
    // the same browser keeps its session
    let again = h.get("/login", Some(&r.own_cookie().unwrap())).await;
    assert_eq!(again.own_cookie(), r.own_cookie());
    assert_eq!(h.count("hte_console_sessions"), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn over_https_the_cookie_is_host_prefixed_and_secure() {
    let h = harness().await;
    let r = h.go("GET", "/login", None, None, &[("x-forwarded-proto", "https")]).await;
    let c = r.cookies().into_iter().find(|c| c.starts_with("__Host-hte-remote=")).expect("__Host- cookie");
    assert!(c.ends_with("; path=/; httponly; samesite=lax; secure"), "{c}");
    assert!(!c.to_ascii_lowercase().contains("domain="));
    assert!(r.body.contains("action=\"https://"));
    // the plain-http name is not read over https (and the other way round)
    let plain = h.get("/login", None).await.own_cookie().unwrap();
    let r2 = h.go("GET", "/login", Some(&plain), None, &[("x-forwarded-proto", "https")]).await;
    assert_ne!(r2.own_cookie().unwrap().split('=').nth(1), plain.split('=').nth(1));
}

// ---------------------------------------------------------------------------------- break-glass password ---

#[tokio::test(flavor = "multi_thread")]
async fn the_break_glass_password_signs_in_with_a_new_session_and_php_s_rows() {
    let h = harness().await;
    let (guest, token) = h.guest().await;
    let r = h.password(&guest, &token, ADMIN, ADMIN_PW).await;
    assert_eq!((r.status, r.path()), (302, "/".into()));
    let own = r.own_cookie().unwrap();
    // fixation: a NEW id, the guest row gone
    assert_ne!(own, guest);
    assert_eq!(h.count("hte_console_sessions"), 1);
    assert_eq!(h.count("hte_console_sessions where user_id = 920001"), 1);
    // remember me: the cookie outlives the browser, up to the absolute lifetime
    let set = r.cookies().into_iter().find(|c| c.starts_with("hte-remote-console=")).unwrap();
    assert!(set.contains("Max-Age=43200"), "{set}");
    // login_logs as PHP writes it
    assert_eq!(h.logins(), vec![(Some(920001), ADMIN.to_string(), "web".to_string(), 1)]);
    // the bridge: PHP's own session row and cookie for the same person, marked
    let php = r.php_cookie().expect("PHP's cookie");
    assert_eq!(h.count("sessions where user_id = 920001"), 1);
    let lid = h.text("select laravel_session_id from hte_console_sessions");
    assert_eq!(h.text("select id from sessions"), lid);
    let cfg = session::SessionConfig { cookie: "hte-remote-session".into(), lifetime_min: 120, secure: None };
    let raw = session::cookie_value(&php, "hte-remote-session").unwrap();
    assert_eq!(session::id_from_cookie(&h.crypt, &cfg.cookie, &raw).as_deref(), Some(lid.as_str()));
    // a page hte-console serves opens with our cookie, and re-sends both
    let a = h.get("/account", Some(&own)).await;
    assert_eq!(a.status, 200, "{}", a.body);
    assert!(a.own_cookie().is_some() && a.php_cookie().is_some());
    // the old guest cookie is nobody
    let g = h.get("/account", Some(&guest)).await;
    assert_eq!((g.status, g.path()), (302, "/login".into()));
    // signed in, the sign-in page sends you home (RedirectIfAuthenticated)
    let l = h.get("/login", Some(&own)).await;
    assert_eq!((l.status, l.path()), (302, "/".into()));
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_unknown_and_disabled_accounts_get_the_same_answer() {
    let h = harness().await;
    let (c, t) = h.guest().await;
    for (user, pw) in [(ADMIN, "wrong"), ("user-5eed0999", "whatever"), ("user-5eed0003", SEED_PW)] {
        let r = h.password(&c, &t, user, pw).await;
        assert_eq!((r.status, r.path()), (302, "/login".into()));
        assert_eq!(h.error_shown(&c).await, "Invalid username or password.");
    }
    assert_eq!(
        h.logins(),
        vec![
            (None, ADMIN.into(), "web".into(), 0),
            (None, "user-5eed0999".into(), "web".into(), 0),
            (None, "user-5eed0003".into(), "web".into(), 0)
        ]
    );
    // the username comes back in the form, the password never
    let r = h.password(&c, &t, ADMIN, "wrong").await;
    assert_eq!(r.status, 302);
    let page = h.get("/login", Some(&c)).await;
    assert!(page.body.contains(&format!("value=\"{ADMIN}\"")));
    assert!(!page.body.contains("wrong"));
    assert!(page.body.contains("id=\"hteForm\" >") || !page.body.contains("id=\"hteForm\" hidden"));
    assert_eq!(h.count("hte_console_sessions where user_id is not null"), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn validation_and_accounts_the_password_may_not_open() {
    let h = harness().await;
    let (c, t) = h.guest().await;
    let r = h.go("POST", "/login", Some(&c), Some(&[("_token", &t), ("username", ""), ("password", "x")]), &[]).await;
    assert_eq!(r.status, 302);
    assert_eq!(h.error_shown(&c).await, "The username field is required.");
    let r = h.go("POST", "/login", Some(&c), Some(&[("_token", &t), ("username", "a")]), &[]).await;
    assert_eq!(r.status, 302);
    assert_eq!(h.error_shown(&c).await, "The password field is required.");
    let r = h.go("POST", "/login", Some(&c), Some(&[("_token", &t), ("username[]", "a"), ("password", "x")]), &[]).await;
    assert_eq!(r.status, 302);
    assert_eq!(h.error_shown(&c).await, "The username field must be a string.");
    assert_eq!(h.count("login_logs"), 0);
    for (user, msg) in [
        ("user-5eed0004", None), // provisioned by SSO: its password is unusable (wrong password)
        ("user-5eed0005", Some("Your account is waiting for administrator approval.")),
    ] {
        let pw = if user == "user-5eed0004" { "tok-5eed00000000b004" } else { SEED_PW };
        let r = h.password(&c, &t, user, pw).await;
        assert_eq!((r.status, r.path()), (302, "/login".into()), "{user}");
        let shown = h.error_shown(&c).await;
        match msg {
            Some(m) => assert_eq!(shown, m),
            None => assert_eq!(shown, "This account signs in through single sign-on."),
        }
    }
    assert_eq!(h.count("hte_console_sessions where user_id is not null"), 0);
    // TOTP enrolled: the second step, nothing signed in yet
    let r = h.password(&c, &t, "user-5eed0006", SEED_PW).await;
    assert_eq!(r.path(), "/login/2fa");
    assert_eq!(h.count("hte_console_sessions where user_id is not null"), 0);
    let (c, t) = h.guest().await;
    // two-factor required by the settings, not enrolled: signed in, and every page sends them to enrol (RequireTwoFactor)
    h.sql("insert into settings (key, value, created_at, updated_at) values ('two_factor_required', '1', datetime('now'), datetime('now'))");
    let r = h.password(&c, &t, ADMIN, ADMIN_PW).await;
    assert_eq!(r.path(), "/");
    assert_eq!(h.get("/devices", Some(&r.own_cookie().unwrap())).await.path(), "/account/two-factor");
    // the password form switched off by the settings
    h.sql("delete from settings where key = 'two_factor_required'; insert into settings (key, value, created_at, updated_at) values ('oidc_disable_local_login', '1', datetime('now'), datetime('now'))");
    let (c, t) = h.guest().await;
    let r = h.password(&c, &t, ADMIN, ADMIN_PW).await;
    assert_eq!(r.path(), "/login");
    let page = h.get("/login", Some(&c)).await;
    assert!(page.body.contains("Password sign-in is disabled on this console. Use single sign-on."));
    assert!(!page.body.contains("id=\"hteForm\""));
}

#[tokio::test(flavor = "multi_thread")]
async fn throttles_and_alarms_as_php() {
    let h = harness().await;
    let (c, t) = h.guest().await;
    for _ in 0..5 {
        h.password(&c, &t, ADMIN, "wrong").await;
    }
    // the sixth is refused before any password is checked, even the right one
    let r = h.password(&c, &t, ADMIN, ADMIN_PW).await;
    assert_eq!(r.path(), "/login");
    assert!(h.error_shown(&c).await.starts_with("Too many attempts. Try again in "));
    assert_eq!(h.count("login_logs"), 5);
    assert_eq!(h.count("alarm_logs where rustdesk_id = 'console' and typ = 100"), 1);
    let info: Value = serde_json::from_str(&h.text("select info from alarm_logs where typ = 100")).unwrap();
    assert_eq!(info["username"], ADMIN);
    assert_eq!(info["window"], "60s");
    // one alarm per cooldown, however often it trips
    h.password(&c, &t, ADMIN, ADMIN_PW).await;
    assert_eq!(h.count("alarm_logs where typ = 100"), 1);
    // the window passes
    h.advance(61);
    let r = h.password(&c, &t, ADMIN, ADMIN_PW).await;
    assert_eq!(r.path(), "/");
    // spraying: 20 failures from one address across names trips the address limit
    let h = harness().await;
    let (c, t) = h.guest().await;
    for i in 0..20 {
        h.password(&c, &t, &format!("user-5eed09{i:02}"), "x").await;
    }
    let r = h.password(&c, &t, ADMIN, ADMIN_PW).await;
    assert_eq!(r.path(), "/login");
    assert_eq!(h.count("alarm_logs where typ = 101"), 1);
    let info: Value = serde_json::from_str(&h.text("select info from alarm_logs where typ = 101")).unwrap();
    assert_eq!(info["attempts"], 20);
    assert_eq!(info["last_username"], ADMIN);
}

// ---------------------------------------------------------------------------------------- CSRF, fixation ---

#[tokio::test(flavor = "multi_thread")]
async fn csrf_and_session_fixation() {
    let h = harness().await;
    let (c, t) = h.guest().await;
    // no token, a wrong one, another session's
    let (_c2, t2) = h.guest().await;
    for tok in ["", "wrong", t2.as_str()] {
        let r = h.go("POST", "/login", Some(&c), Some(&[("_token", tok), ("username", ADMIN), ("password", ADMIN_PW)]), &[]).await;
        assert_eq!(r.status, 419, "{tok}");
    }
    // a cross-site post with no token, and a post with no session at all
    let r = h.go("POST", "/login", Some(&c), Some(&[("username", ADMIN), ("password", ADMIN_PW)]), &[("sec-fetch-site", "cross-site")]).await;
    assert_eq!(r.status, 419);
    let r = h.go("POST", "/login", None, Some(&[("_token", &t), ("username", ADMIN), ("password", ADMIN_PW)]), &[]).await;
    assert_eq!(r.status, 419);
    assert_eq!(h.count("login_logs"), 0);
    // an id the server never minted is never adopted
    let planted = format!("hte-remote-console={}", "P".repeat(40));
    let r = h.get("/login", Some(&planted)).await;
    let got = r.own_cookie().unwrap();
    assert_ne!(got, planted);
    let r = h.password(&planted, &t, ADMIN, ADMIN_PW).await;
    assert_eq!(r.status, 419);
    // and the id after a sign-in is never the one before it
    let r = h.password(&c, &t, ADMIN, ADMIN_PW).await;
    assert_eq!(r.status, 302);
    assert_ne!(r.own_cookie().unwrap(), c);
}

// ------------------------------------------------------------------------------- lifetimes and revocation ---

#[tokio::test(flavor = "multi_thread")]
async fn idle_absolute_and_revoked_sessions_go_back_to_sign_in_and_keep_the_target() {
    let h = harness().await;
    let (own, _) = h.sign_in().await;
    h.advance(3599);
    assert_eq!(h.get("/account", Some(&own)).await.status, 200);
    // idle for longer than an hour
    h.advance(3601);
    let r = h.get("/account?tab=x", Some(&own)).await;
    assert_eq!((r.status, r.path()), (302, "/login".into()));
    assert_eq!(h.count("hte_console_sessions where user_id is not null"), 0);
    assert_eq!(h.count("sessions"), 0, "the bridged PHP row goes with it");
    // the redirect opened a guest session that remembers where they were going
    let guest = r.own_cookie().unwrap();
    let page = h.get("/login", Some(&guest)).await;
    let r = h.password(&guest, &page.csrf(), ADMIN, ADMIN_PW).await;
    assert_eq!(r.path(), "/account?tab=x");
    // absolute: active all along, still ends after 12 hours
    let own = r.own_cookie().unwrap();
    for _ in 0..12 {
        h.advance(3500);
        assert_eq!(h.get("/account", Some(&own)).await.status, 200);
    }
    h.advance(1300);
    assert_eq!(h.get("/account", Some(&own)).await.path(), "/login");
    // revoked anywhere: revokeAllAccess rotates remember_token (PHP's force logout does it too)
    let (own, _) = h.sign_in().await;
    assert_eq!(h.get("/account", Some(&own)).await.status, 200);
    h.sql("update users set remember_token = 'rt-2' where id = 920001");
    assert_eq!(h.get("/account", Some(&own)).await.path(), "/login");
    // disabled
    h.sql("update users set remember_token = 'rt-2', is_active = 1 where id = 920001");
    let (own, _) = h.sign_in().await;
    h.sql("update users set is_active = 0 where id = 920001");
    assert_eq!(h.get("/account", Some(&own)).await.path(), "/login");
    assert_eq!(h.count("hte_console_sessions where user_id is not null"), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn open_redirects_are_never_followed() {
    let h = harness().await;
    for bad in ["https://evil.example/", "//evil.example/x", "/\\evil.example", "javascript:alert(1)"] {
        let (c, t) = h.guest().await;
        let id = c.split('=').nth(1).unwrap();
        let hash = hex_sha256(id);
        let payload = h.text(&format!("select payload from hte_console_sessions where id_hash = '{hash}'"));
        use base64::Engine;
        let mut data: Value = serde_json::from_slice(&base64::engine::general_purpose::STANDARD.decode(&payload).unwrap()).unwrap();
        data["url.intended"] = Value::String(bad.into());
        let enc = base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&data).unwrap());
        h.db().execute("update hte_console_sessions set payload = ? where id_hash = ?", rusqlite::params![enc, hash]).unwrap();
        let r = h.password(&c, &t, ADMIN, ADMIN_PW).await;
        assert_eq!(r.location(), format!("{}/", h.url), "{bad}");
    }
}

fn hex_sha256(s: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(s.as_bytes()))
}

// ------------------------------------------------------------------------------------------------ logout ---

#[tokio::test(flavor = "multi_thread")]
async fn logout_ends_both_sessions_and_needs_the_token() {
    let h = harness().await;
    let (own, php) = h.sign_in().await;
    let page = h.get("/account", Some(&own)).await;
    let token = page.body.split("name=\"csrf-token\" content=\"").nth(1).unwrap()[..40].to_string();
    // without the token: 419, still signed in
    let r = h.go("POST", "/logout", Some(&own), Some(&[("_token", "nope")]), &[]).await;
    assert_eq!(r.status, 419);
    assert_eq!(h.get("/account", Some(&own)).await.status, 200);
    // GET is not a logout
    assert_eq!(h.get("/logout", Some(&own)).await.status, 405);
    let r = h.go("POST", "/logout", Some(&format!("{own}; {}", php.unwrap())), Some(&[("_token", &token)]), &[]).await;
    assert_eq!((r.status, r.path()), (302, "/login".into()));
    let cleared = r.cookies();
    assert!(cleared.iter().any(|c| c.starts_with("hte-remote-console=deleted;") && c.contains("Max-Age=0")), "{cleared:?}");
    assert!(cleared.iter().any(|c| c.starts_with("hte-remote-session=deleted;") && c.contains("Max-Age=0")), "{cleared:?}");
    assert_eq!(h.count("hte_console_sessions"), 0);
    assert_eq!(h.count("sessions"), 0);
    assert_eq!(h.get("/account", Some(&own)).await.path(), "/login");
    // not signed in: to the sign-in page
    // not signed in and no token: PHP's CSRF check answers first (419); from our own page (same-origin) to the sign-in page
    assert_eq!(h.go("POST", "/logout", None, None, &[]).await.status, 419);
    assert_eq!(h.go("POST", "/logout", None, None, &[("sec-fetch-site", "same-origin")]).await.path(), "/login");
}

// ------------------------------------------------------------------------------- PHP's sessions meanwhile ---

#[tokio::test(flavor = "multi_thread")]
async fn php_s_own_sign_in_still_works_but_the_bridge_is_not_a_sign_in_by_itself() {
    let h = harness().await;
    // a session PHP signed in (its own /login) is read while HTE_CONSOLE_LARAVEL_SESSIONS allows it
    let cfg = session::SessionConfig { cookie: "hte-remote-session".into(), lifetime_min: 120, secure: None };
    use base64::Engine;
    let mk = |id: &str, extra: &str| {
        let payload = base64::engine::general_purpose::STANDARD.encode(format!("{{\"_token\":\"{}\",\"{}\":920001{extra}}}", "T".repeat(40), session::LOGIN_KEY));
        h.db().execute("insert into sessions values (?, 920001, 'ip', 'ua', ?, ?)", rusqlite::params![id, payload, T0]).unwrap();
        session::set_cookie(&cfg, &h.crypt, id, false, T0).split(';').next().unwrap().to_string()
    };
    let php = mk(&"a".repeat(40), "");
    assert_eq!(h.get("/account", Some(&php)).await.status, 200);
    // the bridged row alone (our session gone) opens nothing
    let bridged = mk(&"b".repeat(40), ",\"hte.bridged\":1");
    assert_eq!(h.get("/account", Some(&bridged)).await.path(), "/login");
    // logout of a PHP-signed-in session deletes PHP's row
    let r = h.go("POST", "/logout", Some(&php), Some(&[("_token", &"T".repeat(40))]), &[]).await;
    assert_eq!(r.path(), "/login");
    assert_eq!(h.count(&format!("sessions where id = '{}'", "a".repeat(40))), 0);
    // phase 9: PHP's sessions no longer read
    let h = harness_with(Opts { laravel_read: false, ..Default::default() }).await;
    let payload = base64::engine::general_purpose::STANDARD.encode(format!("{{\"_token\":\"t\",\"{}\":920001}}", session::LOGIN_KEY));
    h.db().execute("insert into sessions values (?, 920001, 'ip', 'ua', ?, ?)", rusqlite::params!["c".repeat(40), payload, T0]).unwrap();
    let c = session::set_cookie(&cfg, &h.crypt, &"c".repeat(40), false, T0).split(';').next().unwrap().to_string();
    assert_eq!(h.get("/account", Some(&c)).await.path(), "/login");
    // no bridge: no PHP row
    let h = harness_with(Opts { bridge: false, ..Default::default() }).await;
    let (_own, php) = h.sign_in().await;
    assert!(php.is_none());
    assert_eq!(h.count("sessions"), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_php_page_sends_the_person_back_and_the_bridge_is_repaired() {
    let h = harness().await;
    let (own, _) = h.sign_in().await;
    // PHP lost its row (say, a restart of the file driver); PHP's guest session remembers where it wanted them
    h.sql("delete from sessions");
    let cfg = session::SessionConfig { cookie: "hte-remote-session".into(), lifetime_min: 120, secure: None };
    use base64::Engine;
    let payload = base64::engine::general_purpose::STANDARD.encode(format!("{{\"_token\":\"{}\",\"url.intended\":\"{}/diagnostics\"}}", "G".repeat(40), h.url));
    h.db().execute("insert into sessions values (?, null, 'ip', 'ua', ?, ?)", rusqlite::params!["g".repeat(40), payload, T0]).unwrap();
    let php_guest = session::set_cookie(&cfg, &h.crypt, &"g".repeat(40), false, T0).split(';').next().unwrap().to_string();
    let r = h.get("/login", Some(&format!("{own}; {php_guest}"))).await;
    assert_eq!((r.status, r.path()), (302, "/diagnostics".into()));
    assert!(r.php_cookie().is_some());
    assert_eq!(h.count("sessions where user_id = 920001"), 1);
    assert_eq!(h.count("sessions where user_id is null"), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn with_the_switch_off_everything_stays_php_s() {
    let h = harness_with(Opts { signin: false, ..Default::default() }).await;
    // no PHP in the tests: forwarding answers with a redirect to /login and nothing is written
    let r = h.get("/login", None).await;
    assert_eq!((r.status, r.location()), (302, "/login".into()));
    assert!(r.own_cookie().is_none());
    let r = h.get("/account", None).await;
    assert_eq!(r.location(), "/login");
    assert_eq!(h.count("hte_console_sessions"), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn steps_without_a_pending_sign_in_or_a_valid_link() {
    let h = harness().await;
    // no challenge pending: back to the sign-in page (PHP's answer); the resend is a POST-only route
    for p in ["/login/2fa", "/login/email"] {
        assert_eq!(h.get(p, None).await.path(), "/login", "{p}");
    }
    assert_eq!(h.get("/login/email/resend", None).await.status, 405);
    // reset without mail: to the sign-in page; an unknown invitation: 404
    assert_eq!(h.get("/forgot-password", None).await.path(), "/login");
    assert_eq!(h.get("/reset-password/abc", None).await.path(), "/login");
    assert_eq!(h.get("/invite/abc", None).await.status, 404);
}

// --------------------------------------------------------------------------------------- single sign-on ---

#[tokio::test(flavor = "multi_thread")]
async fn microsoft_sign_in_links_by_email_once_then_by_subject() {
    let h = harness().await;
    let (r, _) = h.sso("ok", "linked").await;
    assert_eq!((r.status, r.path()), (302, "/".into()), "{}", r.body);
    let own = r.own_cookie().unwrap();
    assert_eq!(h.text("select oidc_sub from users where id = 910008"), "sub-5eed-linked");
    assert_eq!(h.text(&format!("select oidc_iss from users where id = 910008")), h.idp);
    assert_eq!(h.logins(), vec![(Some(910008), "user-5eed0008".into(), "sso".into(), 1)]);
    // the session is marked as single sign-on (RequireTwoFactor exempts it), PHP's bridged one too
    use base64::Engine;
    let p: Value = serde_json::from_slice(&base64::engine::general_purpose::STANDARD.decode(h.text("select payload from hte_console_sessions where user_id = 910008")).unwrap()).unwrap();
    assert_eq!(p["oidc.authenticated"], true);
    assert!(p.get("oidc.state").is_none() && p.get("oidc.verifier").is_none());
    let lp: Value = serde_json::from_slice(&base64::engine::general_purpose::STANDARD.decode(h.text("select payload from sessions where user_id = 910008")).unwrap()).unwrap();
    assert_eq!(lp["oidc.authenticated"], true);
    assert!(lp.get("oidc.id_token").is_none(), "no ID token is kept anywhere");
    assert_eq!(h.get("/account", Some(&own)).await.status, 200);
    // no remember-me for SSO: a browser-session cookie
    let set = r.cookies().into_iter().find(|c| c.starts_with("hte-remote-console=")).unwrap();
    assert!(!set.contains("Max-Age"));
    // a known identity, a new person under the `active` policy
    let (r, _) = h.sso("ok", "known").await;
    assert_eq!(r.path(), "/");
    let (r, _) = h.sso("ok", "anna").await;
    assert_eq!(r.path(), "/");
    assert_eq!(h.count("users where oidc_sub = 'sub-5eed-anna' and auth_provider = 'oidc'"), 1);
    // logout of an SSO session goes through the provider's end-session page when switched on, without the ID token
    h.sql("insert into settings (key, value, created_at, updated_at) values ('oidc_logout_enabled', '1', datetime('now'), datetime('now'))");
    let page = h.get("/account", Some(&own)).await;
    let token = page.body.split("name=\"csrf-token\" content=\"").nth(1).unwrap()[..40].to_string();
    let r = h.go("POST", "/logout", Some(&own), Some(&[("_token", &token)]), &[]).await;
    let loc = r.location();
    assert!(loc.starts_with(&format!("{}/logout?post_logout_redirect_uri=", h.idp)), "{loc}");
    assert!(loc.contains("client_id=client-seed") && !loc.contains("id_token_hint"));
}

#[tokio::test(flavor = "multi_thread")]
async fn microsoft_sign_in_refusals_and_every_broken_token() {
    let h = harness().await;
    for (user, msg, logged) in [
        ("outsider", "Your email domain is not permitted to sign in to this console.", "user-5eed00a0ff@elsewhere.invalid"),
        ("disabled", "This account is disabled. Contact your administrator.", "user-5eed00000a@example.invalid"),
    ] {
        let (r, _) = h.sso("ok", user).await;
        assert_eq!(r.path(), "/login", "{user}");
        let c = r.own_cookie().unwrap();
        assert_eq!(h.error_shown(&c).await, msg);
        assert_eq!(h.logins().last().unwrap(), &(None, logged.to_string(), "sso".to_string(), 0));
    }
    let before = h.count("login_logs");
    let mut n = 0;
    for mode in MODES.iter().filter(|m| !["ok", "slow-token", "wrong-tid", "multi-aud-azp"].contains(m)) {
        let (r, _) = h.sso(mode, "known").await;
        assert_eq!(r.path(), "/login", "{mode}: {}", r.body);
        let shown = h.error_shown(&r.own_cookie().unwrap()).await;
        assert!(!shown.is_empty(), "{mode}");
        n += 1;
    }
    assert_eq!(h.count("login_logs") - before, n);
    assert_eq!(h.count("login_logs where client = 'sso' and successful = 1"), 0);
    assert_eq!(h.count("hte_console_sessions where user_id is not null"), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_state_is_single_use_and_bound_to_the_browser() {
    let h = harness().await;
    // the callback replayed (same browser, same state): the state was pulled the first time
    let (r, pq) = h.sso("ok", "known").await;
    assert_eq!(r.path(), "/");
    let (c, _) = h.guest().await;
    let again = h.get(&pq, Some(&c)).await;
    assert_eq!(again.path(), "/login");
    assert_eq!(h.error_shown(&again.own_cookie().unwrap()).await, "The sign-in request expired or was tampered with. Please try again.");
    // a callback in another browser (no state in its session) and with a wrong state
    let (cb, _) = h.guest().await;
    let start = h.get("/login/oidc", Some(&cb)).await;
    let a = h.client.get(format!("{}&hte_fake=ok&hte_user=known", start.location())).send().await.unwrap();
    let back = url::Url::parse(a.headers()["location"].to_str().unwrap()).unwrap();
    let code = back.query_pairs().find(|(k, _)| k == "code").unwrap().1.to_string();
    let other = h.get(&format!("/login/oidc/callback?code={code}&state=x"), None).await;
    assert_eq!(other.path(), "/login");
    let wrong = h.get(&format!("/login/oidc/callback?code={code}&state=wrong"), Some(&cb)).await;
    assert_eq!(wrong.path(), "/login");
    // and that state is gone now, so the right one fails too
    let state = back.query_pairs().find(|(k, _)| k == "state").unwrap().1.to_string();
    let late = h.get(&format!("/login/oidc/callback?code={code}&state={state}"), Some(&cb)).await;
    assert_eq!(late.path(), "/login");
    assert_eq!(h.count("hte_console_sessions where user_id = 910009"), 1, "only the first sign-in");
    // the authorize request carries PKCE S256, a nonce, our callback
    let (cs, _) = h.guest().await;
    let s = h.get("/login/oidc", Some(&cs)).await.location();
    let u = url::Url::parse(&s).unwrap();
    let q: std::collections::HashMap<_, _> = u.query_pairs().into_owned().collect();
    assert_eq!(q["code_challenge_method"], "S256");
    assert_eq!(q["code_challenge"].len(), 43);
    assert_eq!(q["nonce"].len(), 40);
    assert_eq!(q["redirect_uri"], format!("{}/login/oidc/callback", h.url));
    // SSO switched off: a message, nothing started
    h.sql("update settings set value = '0' where key = 'oidc_enabled'");
    let r = h.get("/login/oidc", Some(&cs)).await;
    assert_eq!(r.path(), "/login");
    assert_eq!(h.error_shown(&cs).await, "Single sign-on is not enabled on this console.");
}

// ----------------------------------------------------------------------------------------------- the log ---

#[tokio::test(flavor = "multi_thread")]
async fn no_secret_reaches_the_log() {
    let h = harness().await;
    let (own, php) = h.sign_in().await;
    let (c, t) = h.guest().await;
    h.password(&c, &t, ADMIN, "tok-5eed0000wrongpw1").await;
    h.sso("ok", "known").await;
    h.sso("bad-signature", "known").await;
    let log = String::from_utf8_lossy(&LOG.lock().unwrap()).into_owned();
    for secret in [ADMIN_PW, "tok-5eed0000wrongpw1", "tok-5eed00000000c11e", own.split('=').nth(1).unwrap(), php.as_deref().unwrap().split('=').nth(1).unwrap(), &t] {
        assert!(!log.contains(secret), "a secret reached the log");
    }
    assert!(log.contains("console sign-in: password accepted"));
}

// ------------------------------------------------------------------------------------------- the replay ---

#[tokio::test(flavor = "multi_thread")]
async fn the_web_sign_in_replay_sees_no_difference_between_two_identical_consoles_and_sees_a_real_one() {
    let (a, b) = (harness().await, harness().await);
    // the replay computes the TOTP step from the wall clock, as it does against PHP
    let now = chrono::Utc::now().timestamp();
    a.clock.store(now, Ordering::SeqCst);
    b.clock.store(now, Ordering::SeqCst);
    let r = hte_console::webreplay::run(&a.url, &b.url).await.unwrap();
    assert!(r.total > 60, "{}", r.total);
    assert!(r.differences.is_empty(), "{:#?}", r.differences);
    // both consoles wrote the same login rows
    assert_eq!(a.logins(), b.logins());
    assert!(a.count("alarm_logs where typ = 100") == 1 && b.count("alarm_logs where typ = 100") == 1);
    let (c, d) = (harness().await, harness().await);
    c.clock.store(now, Ordering::SeqCst);
    d.clock.store(now, Ordering::SeqCst);
    std::env::set_var("HTE_WEBREPLAY_MUTATE", "1");
    let r = hte_console::webreplay::run(&c.url, &d.url).await.unwrap();
    std::env::remove_var("HTE_WEBREPLAY_MUTATE");
    assert_eq!(r.differences.len(), 1, "{:#?}", r.differences);
}

// ------------------------------------------------------------------------------------- after the review ---

#[tokio::test(flavor = "multi_thread")]
async fn review_fixes_hostile_queries_remember_and_writes_without_a_session() {
    let h = harness().await;
    // an array where a string belongs is a refusal, not a 500
    let (c, _) = h.guest().await;
    for q in ["code[]=1&state=x", "code=1&state[]=x", "error[]=x"] {
        let r = h.get(&format!("/login/oidc/callback?{q}"), Some(&c)).await;
        assert_eq!((r.status, r.path()), (302, "/login".into()), "{q}");
    }
    // a Microsoft session survives a later remembered password sign-in of the same account (its first remember token)
    h.sql("update users set password = (select password from users where id = 920001), auth_provider = 'local', remember_token = null where id = 910009");
    let (r, _) = h.sso("ok", "known").await;
    let sso = r.own_cookie().unwrap();
    let (g, t) = h.guest().await;
    let r = h.password(&g, &t, "user-5eed0009", ADMIN_PW).await;
    assert_eq!(r.path(), "/");
    assert_ne!(h.text("select remember_token from users where id = 910009"), "");
    assert_eq!(h.get("/account", Some(&sso)).await.status, 200);
    // but a real revoke still ends both
    h.sql("update users set remember_token = 'rt-x' where id = 910009");
    assert_eq!(h.get("/account", Some(&sso)).await.path(), "/login");
    // a write with no session: to the sign-in page, and no guest row for it
    let before = h.count("hte_console_sessions");
    let r = h.go("POST", "/devices/save", None, Some(&[("x", "1")]), &[]).await;
    assert_eq!(r.path(), "/login");
    assert_eq!(h.count("hte_console_sessions"), before);
}
