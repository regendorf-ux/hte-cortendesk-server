//! Phase 8: the console's sign-in pages without PHP, ported from v1.15.0-hte.1:
//!
//!   GET|POST /login               AuthController::showLogin / login (the HTE Remote welcome card, the break-glass password)
//!   GET      /login/oidc          OidcController::redirect (Microsoft sign-in: authorization code + PKCE S256 + nonce)
//!   GET      /login/oidc/callback OidcController::callback (+ OidcUserResolver, the same as the client flow's)
//!   POST     /logout              AuthController::logout (and the provider's end-session page when it is switched on)
//!
//! and, not used at HTE, a fixed answer: `/login/2fa`, `/login/email`, `/login/email/resend` redirect to `/login` (what
//! PHP does with no challenge pending, and none is ever started here); `/forgot-password`, `/reset-password/*`,
//! `/invite/*` show "not available". A password sign-in that PHP would send on to a second step (TOTP enrolled, TOTP
//! required but not enrolled, an emailed code) is refused with a message instead: none of that is switched on at HTE
//! and `phase8/deploy.sh` stops when it is.
//!
//! The session is hte-console's own (`websession`); the rows written are PHP's (`login_logs`, `alarm_logs`, `users`
//! when single sign-on links or provisions, `sessions` for the bridge). With `HTE_CONSOLE_SIGNIN` off every path here
//! is handed to PHP unchanged.

use super::session::{self, Session};
use super::websession as ws;
use super::{forward, html, Pages};
use crate::laravel::{self, Input};
use crate::oidc::{OidcError, Settings};
use crate::php::{self, Fault, Val};
use crate::sqlite::{self as db, Row, P};
use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use axum::routing::any;
use axum::Router;
use rusqlite::Connection;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;

/// AuthController's limits: per account and address, per address, the window, the alarm cooldown.
pub const MAX_PER_ACCOUNT: u64 = 5;
pub const MAX_PER_ADDRESS: u64 = 20;
pub const DECAY: i64 = 60;
pub const ALARM_COOLDOWN: i64 = 300;
/// `AlarmLog::TYP_BRUTE_FORCE`, `TYP_SPRAYING`
pub const TYP_BRUTE_FORCE: i64 = 100;
pub const TYP_SPRAYING: i64 = 101;
/// Guest sessions one address may open a minute (each is a row until it expires).
const GUEST_PER_MINUTE: u64 = 600;

const SSO_OFF: &str = "Single sign-on is not enabled on this console.";
const EXPIRED: &str = "The sign-in request expired or was tampered with. Please try again.";

#[derive(Clone, Copy, PartialEq, Debug)]
enum Which {
    Login,
    Oidc,
    Callback,
    Logout,
    /// A challenge step that is never started here: back to the sign-in page.
    Step,
    /// Password reset, invitations: not available.
    Unavailable,
}

pub fn routes(r: Router<Arc<Pages>>) -> Router<Arc<Pages>> {
    let mut r = r;
    for (path, w) in [
        ("/login", Which::Login),
        ("/login/oidc", Which::Oidc),
        ("/login/oidc/callback", Which::Callback),
        ("/logout", Which::Logout),
        ("/login/2fa", Which::Step),
        ("/login/email", Which::Step),
        ("/login/email/resend", Which::Step),
        ("/forgot-password", Which::Unavailable),
        ("/reset-password/:token", Which::Unavailable),
        ("/invite/:token", Which::Unavailable),
    ] {
        r = r.route(path, any(move |s: State<Arc<Pages>>, c: ConnectInfo<SocketAddr>, req: Request<Body>| entry(s, c, req, w)));
    }
    r
}

/// What a sign-in route knows about its request.
struct Web {
    root: String,
    secure: bool,
    ip: String,
    ua: String,
    cookie: String,
    now: i64,
    method: String,
    headers: HeaderMap,
    input: Input,
}

fn hstr<'a>(h: &'a HeaderMap, n: &str) -> Option<&'a str> {
    h.get(n).and_then(|v| v.to_str().ok())
}

fn web(p: &Pages, parts: &axum::http::request::Parts, body: &[u8], peer: SocketAddr) -> Option<Web> {
    let root = crate::api::request_root(&p.n, &parts.headers, peer.ip())?;
    let xff: Vec<&str> = parts.headers.get_all("x-forwarded-for").iter().filter_map(|v| v.to_str().ok()).collect();
    let method = if parts.method == Method::HEAD { "GET".to_string() } else { parts.method.as_str().to_string() };
    Some(Web {
        secure: root.starts_with("https://"),
        ip: laravel::client_ip(peer.ip(), &xff, &p.n.trusted),
        ua: hstr(&parts.headers, "user-agent").unwrap_or("").to_string(),
        cookie: parts.headers.get_all(header::COOKIE).iter().filter_map(|v| v.to_str().ok()).collect::<Vec<_>>().join("; "),
        now: p.n.now(),
        input: Input::new(&method, hstr(&parts.headers, "content-type"), parts.uri.query(), body),
        method,
        headers: parts.headers.clone(),
        root,
    })
}

// --------------------------------------------------------------------------------------------- responses ---

/// A response under construction: the status/body/location and the cookies to set.
struct Out {
    resp: Response<Body>,
    cookies: Vec<String>,
}

impl Out {
    fn new(resp: Response<Body>) -> Out {
        Out { resp, cookies: vec![] }
    }
    fn done(mut self) -> Response<Body> {
        let h = self.resp.headers_mut();
        h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
        h.insert("x-frame-options", HeaderValue::from_static("DENY"));
        h.insert("referrer-policy", HeaderValue::from_static("same-origin"));
        // a sign-in page is never cached (it carries a CSRF token, and the cookie it sets)
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store, private"));
        for c in self.cookies {
            if let Ok(v) = HeaderValue::from_str(&c) {
                h.append(header::SET_COOKIE, v);
            }
        }
        self.resp
    }
}

fn redirect(to: &str) -> Response<Body> {
    let body = format!("<!DOCTYPE html>\n<html>\n    <head>\n        <meta charset=\"UTF-8\" />\n        <meta http-equiv=\"refresh\" content=\"0;url='{u}'\" />\n\n        <title>Redirecting to {u}</title>\n    </head>\n    <body>\n        Redirecting to <a href=\"{u}\">{u}</a>.\n    </body>\n</html>", u = laravel::e(to));
    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, HeaderValue::from_str(to).unwrap_or(HeaderValue::from_static("/")))
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Body::from(body))
        .unwrap()
}

fn error(status: u16, text: &str, head: bool) -> Response<Body> {
    html(status, crate::signin::error_page(status, text), head)
}

// ------------------------------------------------------------------------------------- the guest session ---

/// The session a guest page works in: the browser's own (ours), else a new one. `stored` false: a transient session
/// (the address opened too many), whose writes go nowhere, so a form posted from it fails its CSRF check.
fn guest_session(p: &Pages, c: &Connection, w: &Web) -> Result<Session, Fault> {
    if let Some(s) = ws::load(c, &p.own, w.now, &w.cookie, w.secure)? {
        return Ok(s);
    }
    let data = ws::guest_data();
    let key = format!("hte-guest-session|{}", w.ip).into_bytes();
    let allowed = {
        let mut l = p.n.limiter.lock().unwrap_or_else(|e| e.into_inner());
        let ok = !l.too_many(&key, GUEST_PER_MINUTE, w.now);
        if ok {
            l.hit(&key, 60, w.now);
        }
        ok
    };
    let id = if allowed { ws::create(c, &data, &w.ip, &w.ua, w.now, w.now, None)? } else { laravel::str_random(40) };
    let stored = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, serde_json::to_vec(&data).unwrap_or_default());
    Ok(Session { id, stored, data, last_activity: w.now, own: true, created: w.now })
}

/// Is this a signed-in session of a person who may still use it?
fn signed_in(c: &Connection, s: &Session) -> Result<bool, Fault> {
    let Some(uid) = s.user_id() else { return Ok(false) };
    match db::first(c, r#"select * from "users" where "id" = ? limit 1"#, &[P(Val::Int(uid))])? {
        Some(u) => ws::still_valid(c, s, &u),
        None => {
            ws::destroy(c, s)?;
            Ok(false)
        }
    }
}

/// Save a guest session's changes the Laravel way (flash first, then age), and set its cookie on the response.
fn keep(p: &Pages, c: &Connection, w: &Web, s: &Session, mut data: Map<String, Value>, flashes: Vec<(&str, Value)>, out: &mut Out) -> Result<(), Fault> {
    for (k, v) in flashes {
        session::flash(&mut data, k, v);
    }
    if let Some(a) = session::aged(&data) {
        data = a;
    }
    if data != s.data {
        ws::save(c, s, &data, w.now)?;
    } else {
        ws::touch(c, s, w.now)?;
    }
    out.cookies.push(ws::cookie_for(&p.session, &p.own, &p.n.crypt, s, &s.id, w.secure, w.now));
    Ok(())
}

/// `back()->withErrors([$field => $message])` (and `->withInput($request->only('username'))`): to the sign-in page.
fn back_to_login(p: &Pages, c: &Connection, w: &Web, s: &Session, field: &str, message: &str, username: Option<&[u8]>) -> Result<Out, Fault> {
    let mut out = Out::new(redirect(&format!("{}/login", w.root)));
    let mut flashes = vec![("errors", json!({ field: [message] }))];
    if let Some(u) = username {
        flashes.push(("_old_input", json!({"username": String::from_utf8_lossy(u)})));
    }
    keep(p, c, w, s, s.data.clone(), flashes, &mut out)?;
    Ok(out)
}

// -------------------------------------------------------------------------------------------------- entry ---

async fn entry(State(p): State<Arc<Pages>>, ConnectInfo(peer): ConnectInfo<SocketAddr>, req: Request<Body>, which: Which) -> Response<Body> {
    if !p.own.signin {
        return forward(&p, req).await;
    }
    let (parts, body) = req.into_parts();
    let head = parts.method == Method::HEAD;
    let bytes = match axum::body::to_bytes(body, 64 * 1024).await {
        Ok(b) => b,
        Err(_) => return error(413, "Content Too Large", head),
    };
    let Some(w) = web(&p, &parts, &bytes, peer) else { return error(404, "Not Found", head) };
    let w = Arc::new(w);
    let out = match (which, w.method.as_str()) {
        (Which::Login, "GET") => sync(&p, &w, show_login).await,
        (Which::Login, "POST") => sync(&p, &w, password_login).await,
        (Which::Oidc, "GET") => oidc_start(&p, &w).await,
        (Which::Callback, "GET") => oidc_callback(&p, &w).await,
        (Which::Logout, "POST") => logout(&p, &w).await,
        (Which::Step, _) => Ok(Out::new(redirect(&format!("{}/login", w.root)))),
        (Which::Unavailable, "GET" | "POST") => sync(&p, &w, unavailable).await,
        _ => Ok(Out::new(error(405, "Method Not Allowed", false))),
    };
    let mut resp = match out {
        Ok(o) => o.done(),
        Err(f) => {
            tracing::error!("sign-in page: {}", match &f {
                Fault::Other(m) => m.as_str(),
                _ => "fault",
            });
            error(500, "Server Error", false)
        }
    };
    if head {
        *resp.body_mut() = Body::empty();
    }
    resp
}

/// Run a handler on the database connection, outside the async runtime.
async fn sync(p: &Arc<Pages>, w: &Arc<Web>, f: fn(&Pages, &Connection, &Web) -> Result<Out, Fault>) -> Result<Out, Fault> {
    let (p2, w2) = (p.clone(), w.clone());
    tokio::task::spawn_blocking(move || {
        let c = p2.n.db.lock().unwrap_or_else(|e| e.into_inner());
        let _ = ws::sweep(&c, &p2.own, w2.now);
        f(&p2, &c, &w2)
    })
    .await
    .map_err(|_| Fault::Other("sign-in task failed".into()))?
}

// --------------------------------------------------------------------------------------------- the page ---

fn flag(c: &Connection, key: &str, default: &str) -> Result<bool, Fault> {
    Ok(db::setting(c, key, default)? == b"1")
}

/// `RedirectIfAuthenticated` for a signed-in person, plus the bridge's repair: a person whose PHP session is gone
/// (PHP sent them here from one of its pages) gets a new one, and goes back where PHP wanted them.
fn already_signed_in(p: &Pages, c: &Connection, w: &Web, s: &Session) -> Result<Out, Fault> {
    let mut target = "/".to_string();
    let mut out_cookies = vec![];
    if p.own.bridge {
        let ok = match ws::bridged_id(c, s)? {
            Some(l) => ws::laravel_row_exists(c, &l)?,
            None => false,
        };
        if !ok {
            if let Some(u) = db::first(c, r#"select * from "users" where "id" = ? limit 1"#, &[P(Val::Int(s.user_id().unwrap_or(0)))])? {
                let lid = ws::mint_laravel(c, &u, s.via_oidc(), &w.root, &w.ip, &w.ua, w.now)?;
                ws::set_bridge(c, &s.id, &lid)?;
                out_cookies.push(session::set_cookie(&p.session, &p.n.crypt, &lid, w.secure, w.now));
                // where PHP's own guest session (the one it opened to send them here) wanted them
                if let Some(php) = session::load(c, &p.session, &p.n.crypt, w.now, &w.cookie)? {
                    if php.user_id().is_none() {
                        if let Some(t) = php.data.get(ws::INTENDED).and_then(|v| v.as_str()).and_then(|t| ws::safe_target(t, &w.root)) {
                            target = t;
                        }
                        db::exec(c, r#"delete from "sessions" where "id" = ?"#, &[P(Val::str(&php.id))])?;
                    }
                }
            }
        }
    }
    let mut out = Out::new(redirect(&format!("{}{target}", w.root)));
    keep(p, c, w, s, s.data.clone(), vec![], &mut out)?;
    out.cookies.extend(out_cookies);
    Ok(out)
}

fn show_login(p: &Pages, c: &Connection, w: &Web) -> Result<Out, Fault> {
    let s = guest_session(p, c, w)?;
    if signed_in(c, &s)? {
        return already_signed_in(p, c, w, &s);
    }
    let s = if s.user_id().is_some() { guest_session(p, c, w)? } else { s };
    let settings = Settings::load(c, &p.n.crypt)?;
    let env_off = p.n.signin.oidc.env_disabled;
    let flashed = s.flashed();
    let error = flashed.get("errors").and_then(|e| e.as_object()).and_then(|m| m.values().next()).and_then(|v| v.get(0)).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let old = flashed.get("_old_input").and_then(|o| o.get("username")).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let sso = settings.is_enabled(env_off);
    let downloads_default = std::env::var("CORTENDESK_DOWNLOADS_ON_LOGIN").map_or(true, |v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "on" | "yes"));
    let show_downloads = flag(c, "downloads_on_login", if downloads_default { "1" } else { "0" })?
        && db::first(c, r#"select 1 as "exists" from "client_downloads" where "is_published" = 1 limit 1"#, &[]).ok().flatten().is_some();
    let domain = std::env::var("HTE_SIGNIN_DOMAIN").unwrap_or_default().trim_matches(|ch| " \t@".contains(ch)).to_string();
    let page = p
        .view
        .render(
            "auth/login.html",
            json!({
                "app_name": p.n.signin.app_name,
                "version": p.n.api_version,
                "root": w.root,
                "csrf": s.token().unwrap_or(""),
                "title": "Sign In",
                "https_only": p.session.secure == Some(true) && !w.secure,
                "status": flashed.get("status").and_then(|v| v.as_str()).unwrap_or(""),
                "error": error,
                "sso_enabled": sso,
                "password_disabled": settings.local_login_disabled(env_off),
                "form_open": !sso || !error.is_empty() || !old.is_empty(),
                "old_username": old,
                "show_downloads": show_downloads,
                "signin_domain": domain,
            }),
        )
        .map_err(Fault::Other)?;
    let mut out = Out::new(html(200, page, false));
    keep(p, c, w, &s, s.data.clone(), vec![], &mut out)?;
    Ok(out)
}

fn unavailable(p: &Pages, c: &Connection, w: &Web) -> Result<Out, Fault> {
    if let Some(s) = ws::load(c, &p.own, w.now, &w.cookie, w.secure)? {
        if signed_in(c, &s)? {
            return already_signed_in(p, c, w, &s);
        }
    }
    let page = p
        .view
        .render("auth/unavailable.html", json!({"app_name": p.n.signin.app_name, "version": p.n.api_version, "root": w.root, "title": "Not available", "csrf": ""}))
        .map_err(Fault::Other)?;
    Ok(Out::new(html(404, page, false)))
}

// ------------------------------------------------------------------------------------- password sign-in ---

/// `PreventRequestForgery` for a sign-in form.
fn csrf(p: &Pages, s: &Session, w: &Web) -> bool {
    session::csrf_ok(
        &p.n.crypt,
        s,
        &w.method,
        hstr(&w.headers, "sec-fetch-site"),
        w.input.get("_token").and_then(|v| v.to_php_string().ok()).as_deref(),
        w.headers.get("x-csrf-token").map(|v| v.as_bytes()),
        w.headers.get("x-xsrf-token").map(|v| v.as_bytes()),
    )
}

fn page_expired() -> Out {
    Out::new(error(419, "Page Expired", false))
}

/// `ensureNotRateLimited($key, 'username', $max, $alarm)`: Some(message) when blocked (the alarm raised once per cooldown).
fn rate_limited(p: &Pages, c: &Connection, w: &Web, key: &[u8], max: u64, typ: i64, info: Vec<(&str, Val)>) -> Result<Option<String>, Fault> {
    let blocked = p.n.limiter.lock().unwrap_or_else(|e| e.into_inner()).too_many(key, max, w.now);
    if !blocked {
        return Ok(None);
    }
    let mut alarm_key = b"alarm-raised:".to_vec();
    alarm_key.extend_from_slice(hex::encode(<sha1::Sha1 as sha1::Digest>::digest(key)).as_bytes());
    let first = p.n.signin.alarms.lock().unwrap_or_else(|e| e.into_inner()).add(Sha256::digest(&alarm_key).into(), ALARM_COOLDOWN, w.now);
    if first {
        let info = php::assoc(info.into_iter().map(|(k, v)| (k.to_string(), v)));
        let info = php::json_encode(&info).ok_or_else(|| Fault::Other("json".into()))?;
        db::insert(c, "alarm_logs", vec![("rustdesk_id", Val::str("console")), ("typ", Val::Int(typ)), ("info", Val::Str(info.into_bytes()))], &laravel::ts(w.now))?;
        tracing::warn!(typ, "console sign-in: too many failed attempts (alarm raised)");
    }
    let wait = p.n.limiter.lock().unwrap_or_else(|e| e.into_inner()).available_in(key, w.now);
    Ok(Some(format!("Too many attempts. Try again in {wait} seconds.")))
}

fn login_log(c: &Connection, user_id: Val, username: Val, client: &str, ip: &str, ok: bool, now: i64) -> Result<(), Fault> {
    db::insert(
        c,
        "login_logs",
        vec![("user_id", user_id), ("username", username), ("client", Val::str(client)), ("ip", Val::str(ip)), ("successful", Val::Bool(ok))],
        &laravel::ts(now),
    )?;
    Ok(())
}

/// `$request->validate(['username' => ['required', 'string'], 'password' => ['required', 'string']])`: the first message.
fn validate(input: &Input) -> Option<(&'static str, String)> {
    let mut first = None;
    for f in ["username", "password"] {
        let m = match input.get(f) {
            None | Some(Val::Null) => format!("The {f} field is required."),
            Some(Val::Arr(_)) => format!("The {f} field must be a string."),
            Some(_) => continue,
        };
        first.get_or_insert((if f == "username" { "username" } else { "password" }, m));
    }
    first
}

fn boolean(v: Option<&Val>) -> bool {
    match v {
        Some(Val::Bool(b)) => *b,
        Some(Val::Int(i)) => *i == 1,
        Some(Val::Str(s)) => matches!(s.to_ascii_lowercase().as_slice(), b"1" | b"true" | b"on" | b"yes"),
        _ => false,
    }
}

/// `SESSION_SECURE_COOKIE=true` and a plain-http request: PHP's cookie would be dropped by the browser and the post fail
/// (419, then `/login` with the https note). No sign-in is completed over plain http then.
fn https_only(p: &Pages, w: &Web) -> bool {
    p.session.secure == Some(true) && !w.secure
}

/// `(string) $request->query($k, '')`, an array read as empty (a hostile `?code[]=` is a refusal, not a 500).
fn query_text(input: &Input, k: &str) -> Vec<u8> {
    match input.query(k) {
        None | Some(Val::Arr(_)) => vec![],
        Some(v) => v.to_php_string().unwrap_or_default(),
    }
}

fn password_login(p: &Pages, c: &Connection, w: &Web) -> Result<Out, Fault> {
    if https_only(p, w) {
        return Ok(Out::new(redirect(&format!("{}/login", w.root))));
    }
    let s = guest_session(p, c, w)?;
    if !csrf(p, &s, w) {
        return Ok(page_expired());
    }
    if signed_in(c, &s)? {
        return already_signed_in(p, c, w, &s);
    }
    let settings = Settings::load(c, &p.n.crypt)?;
    if settings.local_login_disabled(p.n.signin.oidc.env_disabled) {
        return back_to_login(p, c, w, &s, "username", "Password sign-in is disabled on this console. Use single sign-on.", None);
    }
    let username_in = w.input.get("username").and_then(|v| v.to_php_string().ok()).filter(|_| !matches!(w.input.get("username"), Some(Val::Arr(_))));
    if let Some((field, m)) = validate(&w.input) {
        return back_to_login(p, c, w, &s, field, &m, username_in.as_deref());
    }
    let username = w.input.string("username")?;
    let password = w.input.string("password")?;
    let ip = w.ip.clone();
    let lower = String::from_utf8_lossy(&username).to_lowercase();
    let account_key = format!("login:{lower}|{ip}").into_bytes();
    let address_key = format!("login-ip:{ip}").into_bytes();
    if let Some(m) = rate_limited(
        p,
        c,
        w,
        &address_key,
        MAX_PER_ADDRESS,
        TYP_SPRAYING,
        vec![("ip", Val::str(&ip)), ("attempts", Val::Int(MAX_PER_ADDRESS as i64)), ("window", Val::str(&format!("{DECAY}s"))), ("last_username", Val::Str(username.clone()))],
    )? {
        return back_to_login(p, c, w, &s, "username", &m, Some(&username));
    }
    if let Some(m) = rate_limited(
        p,
        c,
        w,
        &account_key,
        MAX_PER_ACCOUNT,
        TYP_BRUTE_FORCE,
        vec![("ip", Val::str(&ip)), ("username", Val::Str(username.clone())), ("attempts", Val::Int(MAX_PER_ACCOUNT as i64)), ("window", Val::str(&format!("{DECAY}s")))],
    )? {
        return back_to_login(p, c, w, &s, "username", &m, Some(&username));
    }
    let remember = boolean(w.input.get("remember"));
    // Auth::validate($credentials + ['is_active' => true]): the account must exist AND be active; otherwise no hash is
    // checked in PHP (hardened here: as long as a wrong password, so the timing does not tell which names exist)
    let user = db::first(c, r#"select * from "users" where "username" = ? and "is_active" = ? limit 1"#, &[P(Val::Str(username.clone())), P(Val::Bool(true))])?;
    let ok = match &user {
        Some(u) => laravel::hash_check(&password, &u.val("password"))?,
        None => {
            laravel::hash_check_dummy(&password);
            false
        }
    };
    let user = user.filter(|_| ok);
    login_log(c, user.as_ref().map_or(Val::Null, |u| u.val("id")), Val::Str(username.clone()), "web", &ip, ok, w.now)?;
    let Some(user) = user else {
        {
            let mut l = p.n.limiter.lock().unwrap_or_else(|e| e.into_inner());
            l.hit(&account_key, DECAY, w.now);
            l.hit(&address_key, DECAY, w.now);
        }
        tracing::info!("console sign-in: wrong credentials");
        return back_to_login(p, c, w, &s, "username", "Invalid username or password.", Some(&username));
    };
    p.n.limiter.lock().unwrap_or_else(|e| e.into_inner()).clear(&account_key);
    if user.val("auth_provider") == Val::str("oidc") {
        return back_to_login(p, c, w, &s, "username", "This account signs in through single sign-on.", Some(&username));
    }
    if user.val("oidc_status") == Val::str("pending") {
        return back_to_login(p, c, w, &s, "username", "Your account is waiting for administrator approval.", Some(&username));
    }
    // The second steps PHP would start next. None is used at HTE (deploy.sh checks), so none is ported: refused here.
    if user.val("totp_enabled").to_bool() {
        tracing::warn!("console sign-in refused: the account has two-factor sign-in, which hte-console does not offer");
        return back_to_login(p, c, w, &s, "username", "Two-factor sign-in is not available on this console yet. Contact an administrator.", Some(&username));
    }
    if crate::signin::email_verification_active(c)? && !php::trim(&user.val("email").to_php_string()?).is_empty() {
        tracing::warn!("console sign-in refused: emailed sign-in codes are on and hte-console does not send mail");
        return back_to_login(p, c, w, &s, "username", "Sign-in is temporarily unavailable: this console cannot send verification codes. Contact an administrator.", Some(&username));
    }
    if crate::signin::two_factor_required(c, &user)? {
        tracing::warn!("console sign-in refused: two-factor enrolment is required and hte-console does not offer it");
        return back_to_login(p, c, w, &s, "username", "Two-factor authentication is required for this account, and this console cannot set it up yet. Contact an administrator.", Some(&username));
    }
    tracing::info!("console sign-in: password accepted");
    complete(p, c, w, &s, &user, false, remember)
}

/// `Auth::login($user)` + `$request->session()->regenerate()` + `redirect()->intended(route('overview'))`: a NEW
/// session id and CSRF token (the guest row is deleted: fixation-proof), PHP's session minted beside it (the bridge).
fn complete(p: &Pages, c: &Connection, w: &Web, guest: &Session, user: &Row, via_oidc: bool, remember: bool) -> Result<Out, Fault> {
    // `Auth::login($user, $remember)`: a remembered sign-in gives the account a remember token when it has none
    // (`ensureRememberTokenIsSet`, no `updated_at`). No remember-me cookie is issued here; the token matters because
    // it is what revocation rotates (`websession::still_valid`).
    let mut user = user.clone();
    if remember && user.val("remember_token").to_php_string()?.is_empty() {
        let before = ws::fingerprint(&user);
        cycle_remember_token(c, &user)?;
        user = db::first(c, r#"select * from "users" where "id" = ? limit 1"#, &[P(user.val("id"))])?.ok_or_else(|| Fault::Other("user vanished".into()))?;
        // giving a token to an account that had none is not a revocation: its other sessions follow the new token
        ws::refingerprint(c, user.id(), &before, &ws::fingerprint(&user))?;
    }
    let user = &user;
    let target = guest.data.get(ws::INTENDED).and_then(|v| v.as_str()).and_then(|t| ws::safe_target(t, &w.root)).unwrap_or_else(|| "/".into());
    let data = ws::signed_in_data(user, via_oidc, remember);
    let laravel_id = if p.own.bridge { Some(ws::mint_laravel(c, user, via_oidc, &w.root, &w.ip, &w.ua, w.now)?) } else { None };
    let id = ws::create(c, &data, &w.ip, &w.ua, w.now, w.now, laravel_id.as_deref())?;
    ws::destroy(c, guest)?;
    let mut out = Out::new(redirect(&format!("{}{target}", w.root)));
    out.cookies.push(ws::set_cookie(&id, w.secure, remember.then_some(p.own.absolute_s), w.now));
    if let Some(l) = laravel_id {
        out.cookies.push(session::set_cookie(&p.session, &p.n.crypt, &l, w.secure, w.now));
    }
    Ok(out)
}

// ------------------------------------------------------------------------------------------ single sign-on ---

fn callback_url(w: &Web) -> String {
    format!("{}/login/oidc/callback", w.root)
}

fn oidc_message(e: &OidcError) -> Option<String> {
    match e {
        OidcError::Msg(m) => Some(m.clone()),
        OidcError::Fault(_) => None,
    }
}

async fn oidc_start(p: &Arc<Pages>, w: &Arc<Web>) -> Result<Out, Fault> {
    // the session first: state, nonce and verifier stored before the browser leaves
    let (p2, w2) = (p.clone(), w.clone());
    let started = tokio::task::spawn_blocking(move || -> Result<Result<(Settings, String, String, String, String), Out>, Fault> {
        if https_only(&p2, &w2) {
            return Ok(Err(Out::new(redirect(&format!("{}/login", w2.root)))));
        }
        let c = p2.n.db.lock().unwrap_or_else(|e| e.into_inner());
        let s = guest_session(&p2, &c, &w2)?;
        if signed_in(&c, &s)? {
            return Ok(Err(already_signed_in(&p2, &c, &w2, &s)?));
        }
        let settings = Settings::load(&c, &p2.n.crypt)?;
        if !settings.is_enabled(p2.n.signin.oidc.env_disabled) {
            return Ok(Err(back_to_login(&p2, &c, &w2, &s, "username", SSO_OFF, None)?));
        }
        let (state, nonce, verifier) = (laravel::str_random(40), laravel::str_random(40), laravel::str_random(96));
        let mut data = s.data.clone();
        data.insert("oidc.state".into(), json!(state));
        data.insert("oidc.nonce".into(), json!(nonce));
        data.insert("oidc.verifier".into(), json!(verifier));
        // saved now; the cookie is set on the final answer, whichever it is
        keep(&p2, &c, &w2, &s, data, vec![], &mut Out::new(redirect("/")))?;
        Ok(Ok((settings, state, nonce, verifier, s.id.clone())))
    })
    .await
    .map_err(|_| Fault::Other("sign-in task failed".into()))??;
    let (settings, state, nonce, verifier, sid) = match started {
        Err(out) => return Ok(out),
        Ok(t) => t,
    };
    let url = p.n.signin.oidc.authorization_url(&settings, &callback_url(w), &state, &nonce, &verifier).await;
    let (p2, w2) = (p.clone(), w.clone());
    tokio::task::spawn_blocking(move || -> Result<Out, Fault> {
        let c = p2.n.db.lock().unwrap_or_else(|e| e.into_inner());
        let s = match ws::load_id(&c, &p2.own, w2.now, &sid)? {
            Some(s) => s,
            None => guest_session(&p2, &c, &w2)?,
        };
        match url {
            Ok(u) => {
                let mut out = Out::new(redirect(&u));
                out.cookies.push(ws::cookie_for(&p2.session, &p2.own, &p2.n.crypt, &s, &s.id, w2.secure, w2.now));
                Ok(out)
            }
            Err(e) => {
                let Some(m) = oidc_message(&e) else { return Err(Fault::Other("OIDC: could not start sign-in".into())) };
                tracing::warn!("OIDC: could not start sign-in");
                back_to_login(&p2, &c, &w2, &s, "username", &m, None)
            }
        }
    })
    .await
    .map_err(|_| Fault::Other("sign-in task failed".into()))?
}

/// What the callback learned before the network part.
struct Pending {
    settings: Settings,
    code: String,
    verifier: String,
    nonce: String,
}

async fn oidc_callback(p: &Arc<Pages>, w: &Arc<Web>) -> Result<Out, Fault> {
    let (p2, w2) = (p.clone(), w.clone());
    let first = tokio::task::spawn_blocking(move || -> Result<Result<Pending, Out>, Fault> {
        if https_only(&p2, &w2) {
            return Ok(Err(Out::new(redirect(&format!("{}/login", w2.root)))));
        }
        let c = p2.n.db.lock().unwrap_or_else(|e| e.into_inner());
        let s = guest_session(&p2, &c, &w2)?;
        if signed_in(&c, &s)? {
            return Ok(Err(already_signed_in(&p2, &c, &w2, &s)?));
        }
        let settings = Settings::load(&c, &p2.n.crypt)?;
        if !settings.is_enabled(p2.n.signin.oidc.env_disabled) {
            return Ok(Err(back_to_login(&p2, &c, &w2, &s, "username", SSO_OFF, None)?));
        }
        // `session()->pull()` of state, nonce and verifier: single use, written before anything else happens (a
        // compare-and-swap: of two requests carrying the same state, only the first finds it)
        let take = |k: &str| s.data.get(k).and_then(|v| v.as_str()).map(str::to_string);
        let (expected, nonce, verifier) = (take("oidc.state"), take("oidc.nonce"), take("oidc.verifier"));
        let mut data = s.data.clone();
        for k in ["oidc.state", "oidc.nonce", "oidc.verifier"] {
            data.remove(k);
        }
        let pulled = expected.is_none() || ws::save(&c, &s, &data, w2.now)?;
        let s = Session { stored: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, serde_json::to_vec(&data).unwrap_or_default()), data, ..s };
        let fail = |m: &str| -> Result<Result<Pending, Out>, Fault> {
            tracing::warn!("OIDC: sign-in failed");
            login_log(&c, Val::Null, Val::str("sso"), "sso", &w2.ip, false, w2.now)?;
            Ok(Err(back_to_login(&p2, &c, &w2, &s, "username", m, None)?))
        };
        if w2.input.query("error").map_or(false, |v| v.to_bool()) {
            let desc = match w2.input.query("error_description") {
                Some(_) => query_text(&w2.input, "error_description"),
                None => query_text(&w2.input, "error"),
            };
            return fail(&format!("The identity provider rejected the sign-in: {}", String::from_utf8_lossy(&desc)));
        }
        let code = String::from_utf8_lossy(&query_text(&w2.input, "code")).into_owned();
        let state = query_text(&w2.input, "state");
        if code.is_empty() {
            return fail("The identity provider did not return an authorization code.");
        }
        let Some(expected) = expected.filter(|e| !e.is_empty() && pulled) else { return fail(EXPIRED) };
        if !php::hash_equals(expected.as_bytes(), &state) {
            return fail(EXPIRED);
        }
        Ok(Ok(Pending { settings, code, verifier: verifier.unwrap_or_default(), nonce: nonce.unwrap_or_default() }))
    })
    .await
    .map_err(|_| Fault::Other("sign-in task failed".into()))??;
    let pending = match first {
        Err(out) => return Ok(out),
        Ok(x) => x,
    };
    let claims = p.n.signin.oidc.exchange_code(&pending.settings, &pending.code, &callback_url(w), &pending.verifier, &pending.nonce, w.now).await;
    let (p2, w2) = (p.clone(), w.clone());
    tokio::task::spawn_blocking(move || -> Result<Out, Fault> {
        let c = p2.n.db.lock().unwrap_or_else(|e| e.into_inner());
        let s = guest_session(&p2, &c, &w2)?;
        let claims = match claims {
            Ok(cl) => cl,
            Err(e) => {
                let Some(m) = oidc_message(&e) else { return Err(Fault::Other("OIDC: the exchange failed".into())) };
                tracing::warn!("OIDC: sign-in failed");
                login_log(&c, Val::Null, Val::str("sso"), "sso", &w2.ip, false, w2.now)?;
                return back_to_login(&p2, &c, &w2, &s, "username", &m, None);
            }
        };
        match crate::resolver::resolve(&c, &claims, w2.now)? {
            crate::resolver::Outcome::Refused(m) => {
                // (string) ($claims['preferred_username'] ?? $claims['email'] ?? 'sso'), then `?: 'sso'`
                let get = |k: &str| match &claims {
                    Val::Arr(a) => a.get_str(k).cloned().filter(|v| !matches!(v, Val::Null)),
                    _ => None,
                };
                let name = get("preferred_username").or_else(|| get("email")).map_or(Ok(b"sso".to_vec()), |v| v.to_php_string())?;
                let name = if name.is_empty() || name == b"0" { b"sso".to_vec() } else { name };
                tracing::info!("OIDC: sign-in refused by the account rules");
                login_log(&c, Val::Null, Val::Str(name), "sso", &w2.ip, false, w2.now)?;
                back_to_login(&p2, &c, &w2, &s, "username", &m, None)
            }
            crate::resolver::Outcome::Ok(user) => {
                let out = complete(&p2, &c, &w2, &s, &user, true, false)?;
                login_log(&c, user.val("id"), user.val("username"), "sso", &w2.ip, true, w2.now)?;
                tracing::info!("OIDC: console sign-in");
                Ok(out)
            }
        }
    })
    .await
    .map_err(|_| Fault::Other("sign-in task failed".into()))?
}

// ------------------------------------------------------------------------------------------------- logout ---

/// `EloquentUserProvider::updateRememberToken($user, Str::random(60))` (timestamps off).
fn cycle_remember_token(c: &Connection, user: &Row) -> Result<(), Fault> {
    db::exec(c, r#"update "users" set "remember_token" = ? where "id" = ?"#, &[P(Val::str(&laravel::str_random(60))), P(user.val("id"))])?;
    Ok(())
}

async fn logout(p: &Arc<Pages>, w: &Arc<Web>) -> Result<Out, Fault> {
    let (p2, w2) = (p.clone(), w.clone());
    let first = tokio::task::spawn_blocking(move || -> Result<Result<(bool, Settings, bool, Out), Out>, Fault> {
        let c = p2.n.db.lock().unwrap_or_else(|e| e.into_inner());
        let Some(s) = session::load_any(&c, &p2.session, &p2.own, &p2.n.crypt, w2.now, &w2.cookie, w2.secure)?.filter(|s| s.user_id().is_some()) else {
            // the `auth` middleware: not signed in, to the sign-in page
            return Ok(Err(Out::new(redirect(&format!("{}/login", w2.root)))));
        };
        if !csrf(&p2, &s, &w2) {
            return Ok(Err(page_expired()));
        }
        let was_sso = s.via_oidc();
        // `Auth::logout()` cycles a remember token the account has. That also ends this person's other hte-console
        // sessions (they carry the old token's fingerprint): signing out signs out everywhere.
        if let Some(u) = db::first(&c, r#"select * from "users" where "id" = ? limit 1"#, &[P(Val::Int(s.user_id().unwrap_or(0)))])? {
            if !u.val("remember_token").to_php_string()?.is_empty() {
                cycle_remember_token(&c, &u)?;
            }
        }
        let mut out = Out::new(redirect(&format!("{}/login", w2.root)));
        if s.own {
            ws::destroy(&c, &s)?;
            out.cookies.push(ws::clear_cookie(ws::cookie_name(w2.secure), w2.secure));
        } else {
            db::exec(&c, r#"delete from "sessions" where "id" = ?"#, &[P(Val::str(&s.id))])?;
        }
        // PHP's cookie goes too (bridged or PHP's own sign-in): this browser is signed out of both
        out.cookies.push(ws::clear_cookie(&p2.session.cookie, w2.secure));
        let settings = Settings::load(&c, &p2.n.crypt)?;
        let provider_logout = was_sso && settings.is_enabled(p2.n.signin.oidc.env_disabled) && flag(&c, "oidc_logout_enabled", "")?;
        tracing::info!("console sign-out");
        Ok(Ok((provider_logout, settings, was_sso, out)))
    })
    .await
    .map_err(|_| Fault::Other("sign-in task failed".into()))??;
    let (provider_logout, settings, _was_sso, mut out) = match first {
        Err(o) => return Ok(o),
        Ok(t) => t,
    };
    if provider_logout {
        // `logoutUrl()`: the provider's end-session page, then back to our sign-in page. Deliberately without the ID
        // token as a hint (it would sit in a URL and the browser's history): `client_id` names the application instead.
        if let Ok(d) = p.n.signin.oidc.discovery(&settings).await {
            let end = match &d {
                Val::Arr(a) => a.get_str("end_session_endpoint").and_then(|v| v.to_php_string().ok()).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default(),
                _ => String::new(),
            };
            let end = crate::oidc::browser_facing(&settings.public_base_url, &end);
            if !end.is_empty() && p.n.signin.oidc.url_allowed(&end) {
                let q = laravel::http_build_query(&[("post_logout_redirect_uri", format!("{}/login", w.root).as_bytes()), ("client_id", settings.client_id.as_bytes())]);
                let cookies = std::mem::take(&mut out.cookies);
                out = Out::new(redirect(&format!("{end}{}{q}", if end.contains('?') { '&' } else { '?' })));
                out.cookies = cookies;
            }
        }
    }
    Ok(out)
}

/// The page gate's answer when a page needs a session and there is none: hte-console's own sign-in page, remembering
/// where the person wanted to go (`redirect()->guest()` keeps `url.intended`).
pub fn to_login(p: &Pages, c: &Connection, cookie: &str, root: &str, secure: bool, ip: &str, ua: &str, method: &str, path_query: &str, now: i64, message: Option<&str>) -> Response<Body> {
    let w = Web {
        root: root.to_string(),
        secure,
        ip: ip.to_string(),
        ua: ua.to_string(),
        cookie: cookie.to_string(),
        now,
        method: method.to_string(),
        headers: HeaderMap::new(),
        input: Input::new("GET", None, None, b""),
    };
    let built = (|| -> Result<Out, Fault> {
        let _ = ws::sweep(c, &p.own, now);
        // a write without a session has no page to come back to: no guest row for it (crawlers and scripts make none)
        if method != "GET" {
            if let Some(old) = ws::load(c, &p.own, now, cookie, secure)?.filter(|s| s.user_id().is_some()) {
                ws::destroy(c, &old)?;
            }
            return Ok(Out::new(redirect(&format!("{root}/login"))));
        }
        let mut s = guest_session(p, c, &w)?;
        if s.user_id().is_some() {
            // a signed-in session the gate refused (revoked, or a step this console cannot offer): it ends here
            ws::destroy(c, &s)?;
            s = guest_session(p, c, &Web { cookie: String::new(), ..w.clone_basic() })?;
        }
        let mut data = s.data.clone();
        if method == "GET" {
            if let Some(t) = ws::safe_target(path_query, root) {
                data.insert(ws::INTENDED.into(), json!(t));
            }
        }
        let mut out = Out::new(redirect(&format!("{root}/login")));
        let flashes = message.map_or(vec![], |m| vec![("errors", json!({"username": [m]}))]);
        keep(p, c, &w, &s, data, flashes, &mut out)?;
        Ok(out)
    })();
    match built {
        Ok(o) => o.done(),
        Err(_) => error(500, "Server Error", false),
    }
}

impl Web {
    fn clone_basic(&self) -> Web {
        Web {
            root: self.root.clone(),
            secure: self.secure,
            ip: self.ip.clone(),
            ua: self.ua.clone(),
            cookie: self.cookie.clone(),
            now: self.now,
            method: self.method.clone(),
            headers: HeaderMap::new(),
            input: Input::new("GET", None, None, b""),
        }
    }
}
