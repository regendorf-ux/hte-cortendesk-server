//! The Laravel session, read from the `sessions` table (PHP runs with `SESSION_DRIVER=database`), and CSRF.
//!
//! A browser carries one cookie (`<slug of APP_NAME>-session`, `SESSION_COOKIE` when set) whose value is
//! `Crypt::encryptString(hmac_sha1(name . "v2", key) . "|" . session_id)` (EncryptCookies + CookieValuePrefix).
//! The row's `payload` is `base64(json)` (`'serialization' => 'json'` in the console's config/session.php; a payload
//! that is not JSON is never served here, the request goes to PHP). Expiry is `DatabaseSessionHandler::read`'s:
//! `last_activity < now - lifetime*60` reads as no session.
//!
//! Writing is kept to the minimum, and never replaces a payload blindly: PHP and this service share rows, so every
//! write is a compare-and-swap on the payload text read (`update ... where id = ? and payload = ?`), and a lost race is
//! simply retried by the next request. This module writes: `last_activity` (sliding expiry, at most once a minute),
//! the aged flash data (what Laravel's `ageFlashData` does at the start of every request), a flash message for the
//! next page, and a regenerated session id after a password change.
//!
//! CSRF is `PreventRequestForgery` of Laravel 13: a read passes; `Sec-Fetch-Site: same-origin` passes; else the
//! `_token` input, `X-CSRF-TOKEN` or the decrypted `X-XSRF-TOKEN` must equal the session's `_token` (`hash_equals`).

use crate::laravel::Encrypter;
use crate::php::{self, Fault, Val};
use crate::sqlite::{self as db, P};
use base64::Engine;
use hmac::{Hmac, Mac};
use rusqlite::Connection;
use serde_json::{json, Map, Value};
use sha1::Sha1;

/// `Auth::guard('web')`'s session key: `login_web_` . sha1(`Illuminate\Auth\SessionGuard`).
pub const LOGIN_KEY: &str = "login_web_59ba36addc2b2f9401580f014c7f58ea4e30989d";
/// `OidcService::SESSION_PROVIDER`: set while a session was signed in through single sign-on.
pub const OIDC_KEY: &str = "oidc.authenticated";

#[derive(Clone, Debug)]
pub struct SessionConfig {
    /// The cookie's name.
    pub cookie: String,
    /// `SESSION_LIFETIME` in minutes (default 120).
    pub lifetime_min: i64,
    /// `SESSION_SECURE_COOKIE`: `Some(b)` forces the flag, None follows the request's scheme.
    pub secure: Option<bool>,
}

impl SessionConfig {
    /// From the environment as the PHP image has it: `SESSION_COOKIE`, else the slug of `APP_NAME` + `-session`.
    pub fn from_env(app_name: &str) -> SessionConfig {
        let set = |n: &str| crate::envvar::var(n).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
        let cookie = set("HTE_CONSOLE_SESSION_COOKIE")
            .or_else(|| set("SESSION_COOKIE"))
            .unwrap_or_else(|| format!("{}-session", crate::cache::slug(app_name)));
        let lifetime_min = set("SESSION_LIFETIME").and_then(|v| v.parse().ok()).filter(|n: &i64| *n > 0).unwrap_or(120);
        let secure = set("SESSION_SECURE_COOKIE").map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "on" | "yes"));
        SessionConfig { cookie, lifetime_min, secure }
    }
}

#[derive(Clone, Debug)]
pub struct Session {
    pub id: String,
    /// The `payload` column as stored (base64), the compare-and-swap's expected value.
    pub stored: String,
    pub data: Map<String, Value>,
    pub last_activity: i64,
    /// Phase 8: hte-console's own session (`websession`), not a row PHP wrote.
    pub own: bool,
    /// When an own session was signed in (its absolute lifetime counts from here); `last_activity` for PHP's.
    pub created: i64,
}

impl Session {
    /// The signed-in user's id (the web guard's key), if any.
    pub fn user_id(&self) -> Option<i64> {
        match self.data.get(LOGIN_KEY)? {
            Value::Number(n) => n.as_i64(),
            Value::String(s) => s.parse().ok(),
            _ => None,
        }
    }

    pub fn token(&self) -> Option<&str> {
        self.data.get("_token").and_then(|v| v.as_str())
    }

    pub fn via_oidc(&self) -> bool {
        match self.data.get(OIDC_KEY) {
            None | Some(Value::Null) | Some(Value::Bool(false)) => false,
            Some(Value::String(s)) => !s.is_empty() && s != "0",
            Some(Value::Number(n)) => n.as_f64() != Some(0.0),
            Some(_) => true,
        }
    }

    /// The flash values that were set by the previous request: what `session('key')` returns on this one.
    pub fn flashed(&self) -> Map<String, Value> {
        let mut out = Map::new();
        if let Some(Value::Array(old)) = self.data.get("_flash").and_then(|f| f.get("old")) {
            for k in old.iter().filter_map(|k| k.as_str()) {
                if let Some(v) = self.data.get(k) {
                    out.insert(k.to_string(), v.clone());
                }
            }
        }
        out
    }
}

type HmacSha1 = Hmac<Sha1>;

/// `CookieValuePrefix::create($name, $key)`.
fn prefix(name: &str, key: &[u8]) -> String {
    let mut m = <HmacSha1 as Mac>::new_from_slice(key).expect("hmac takes any key length");
    m.update(format!("{name}v2").as_bytes());
    format!("{}|", hex::encode(m.finalize().into_bytes()))
}

/// The value of cookie `name` in a `Cookie` header, url-decoded as PHP does.
pub fn cookie_value(header: &str, name: &str) -> Option<Vec<u8>> {
    for part in header.split(';') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            if k.trim() == name {
                return Some(php::urldecode(v.trim().as_bytes()));
            }
        }
    }
    None
}

/// The session id inside an encrypted cookie value, if the value is ours (decrypts, prefix of this cookie's name).
pub fn id_from_cookie(crypt: &Encrypter, name: &str, raw: &[u8]) -> Option<String> {
    let plain = crypt.decrypt_string(raw).ok()?;
    let want = prefix(name, crypt.key_bytes());
    let rest = plain.strip_prefix(want.as_bytes())?;
    let id = std::str::from_utf8(rest).ok()?;
    valid_id(id).then(|| id.to_string())
}

/// `Store::isValidId`: 40 alphanumeric characters.
pub fn valid_id(id: &str) -> bool {
    id.len() == 40 && id.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// The `Set-Cookie` value for a session id (`StartSession::addCookieToResponse`): encrypted with the prefix,
/// percent-encoded as Symfony does, `HttpOnly`, `SameSite=Lax` (or `SESSION_SAME_SITE`), `Secure` as asked.
pub fn set_cookie(cfg: &SessionConfig, crypt: &Encrypter, id: &str, secure: bool, now: i64) -> String {
    let value = crypt.encrypt_string(format!("{}{id}", prefix(&cfg.cookie, crypt.key_bytes())).as_bytes());
    let same_site = crate::envvar::var("SESSION_SAME_SITE").ok().filter(|v| !v.trim().is_empty()).unwrap_or_else(|| "lax".into());
    let max = cfg.lifetime_min * 60;
    let expires = chrono::DateTime::<chrono::Utc>::from_timestamp(now + max, 0).unwrap_or_default().format("%a, %d-%b-%Y %H:%M:%S GMT");
    let mut c = format!(
        "{}={}; expires={expires}; Max-Age={max}; path=/; httponly; samesite={}",
        cfg.cookie,
        crate::laravel::urlencode(value.as_bytes()),
        same_site.to_ascii_lowercase()
    );
    if cfg.secure.unwrap_or(secure) {
        c.push_str("; secure");
    }
    c
}

/// Read the session a request's `Cookie` header names: None when there is no cookie, it is not ours, the row is
/// missing or expired, or its payload is not JSON.
pub fn load(c: &Connection, cfg: &SessionConfig, crypt: &Encrypter, now: i64, cookie_header: &str) -> Result<Option<Session>, Fault> {
    let Some(raw) = cookie_value(cookie_header, &cfg.cookie) else { return Ok(None) };
    let Some(id) = id_from_cookie(crypt, &cfg.cookie, &raw) else { return Ok(None) };
    load_id(c, cfg, now, &id)
}

/// Phase 8: the session a request carries. hte-console's own when it is signed in; else (while
/// `HTE_CONSOLE_LARAVEL_SESSIONS` allows) one PHP signed in, never a PHP row the bridge minted (that one exists only for
/// PHP's pages and lives and dies with ours); else our guest session, if any.
pub fn load_any(c: &Connection, cfg: &SessionConfig, own: &super::websession::OwnConfig, crypt: &Encrypter, now: i64, cookie_header: &str, secure: bool) -> Result<Option<Session>, Fault> {
    let mine = super::websession::load(c, own, now, cookie_header, secure)?;
    if mine.as_ref().map_or(false, |s| s.user_id().is_some()) {
        return Ok(mine);
    }
    if own.laravel_read {
        if let Some(s) = load(c, cfg, crypt, now, cookie_header)? {
            if s.user_id().is_some() && !s.data.contains_key(super::websession::BRIDGED) {
                return Ok(Some(s));
            }
        }
    }
    Ok(mine)
}

/// Reload a session after its id changed (`regenerate`), from the right table.
pub fn reload(c: &Connection, cfg: &SessionConfig, own: &super::websession::OwnConfig, now: i64, s: &Session, id: &str) -> Result<Option<Session>, Fault> {
    if s.own {
        super::websession::load_id(c, own, now, id)
    } else {
        load_id(c, cfg, now, id)
    }
}

pub fn load_id(c: &Connection, cfg: &SessionConfig, now: i64, id: &str) -> Result<Option<Session>, Fault> {
    let Some(row) = db::first(c, r#"select * from "sessions" where "id" = ? limit 1"#, &[P(Val::str(id))])? else { return Ok(None) };
    let last = row.val("last_activity").to_int();
    if last < now - cfg.lifetime_min * 60 {
        return Ok(None);
    }
    let stored = String::from_utf8_lossy(&row.val("payload").to_php_string()?).into_owned();
    let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(stored.trim()) else { return Ok(None) };
    let Ok(Value::Object(data)) = serde_json::from_slice::<Value>(&raw) else { return Ok(None) };
    Ok(Some(Session { id: id.to_string(), stored, data, last_activity: last, own: false, created: last }))
}

fn encode(data: &Map<String, Value>) -> String {
    base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(data).unwrap_or_default())
}

/// `Store::ageFlashData`: the old flash keys go, the new become old. None when there is nothing to age.
pub fn aged(data: &Map<String, Value>) -> Option<Map<String, Value>> {
    let flash = data.get("_flash")?;
    let list = |k: &str| -> Vec<String> {
        match flash.get(k) {
            Some(Value::Array(a)) => a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect(),
            _ => vec![],
        }
    };
    let (old, new) = (list("old"), list("new"));
    if old.is_empty() && new.is_empty() {
        return None;
    }
    let mut out = data.clone();
    for k in &old {
        out.remove(k);
    }
    out.insert("_flash".into(), json!({"old": new, "new": []}));
    Some(out)
}

/// `session()->flash($key, $value)` on a payload (as Laravel: put + push the key onto `_flash.new`, off `_flash.old`).
pub fn flash(data: &mut Map<String, Value>, key: &str, value: Value) {
    data.insert(key.to_string(), value);
    let mut old: Vec<Value> = vec![];
    let mut new: Vec<Value> = vec![];
    if let Some(f) = data.get("_flash") {
        if let Some(Value::Array(a)) = f.get("old") {
            old = a.clone();
        }
        if let Some(Value::Array(a)) = f.get("new") {
            new = a.clone();
        }
    }
    if !new.iter().any(|v| v.as_str() == Some(key)) {
        new.push(json!(key));
    }
    old.retain(|v| v.as_str() != Some(key));
    data.insert("_flash".into(), json!({"old": old, "new": new}));
}

/// Compare-and-swap the payload (and `last_activity`); false when another writer got there first.
pub fn save(c: &Connection, s: &Session, data: &Map<String, Value>, now: i64) -> Result<bool, Fault> {
    if s.own {
        return super::websession::save(c, s, data, now);
    }
    let n = db::exec(
        c,
        r#"update "sessions" set "payload" = ?, "last_activity" = ? where "id" = ? and "payload" = ?"#,
        &[P(Val::str(&encode(data))), P(Val::Int(now)), P(Val::str(&s.id)), P(Val::str(&s.stored))],
    )?;
    Ok(n == 1)
}

/// Slide the expiry like the next PHP request would, but at most once a minute.
pub fn touch(c: &Connection, s: &Session, now: i64) -> Result<(), Fault> {
    if s.own {
        return super::websession::touch(c, s, now);
    }
    if now - s.last_activity >= 60 {
        db::exec(c, r#"update "sessions" set "last_activity" = ? where "id" = ? and "last_activity" < ?"#, &[P(Val::Int(now)), P(Val::str(&s.id)), P(Val::Int(now))])?;
    }
    Ok(())
}

/// `session()->regenerate()` with a fresh `_token` (`regenerateToken()`), and the old row deleted: the person gets the
/// new cookie in this same response, and a copy of the old cookie must stop working: the new id.
pub fn regenerate(c: &Connection, s: &Session, now: i64) -> Result<String, Fault> {
    if s.own {
        return super::websession::regenerate(c, s, now);
    }
    let id = crate::laravel::str_random(40);
    let old = db::first(c, r#"select * from "sessions" where "id" = ? limit 1"#, &[P(Val::str(&s.id))])?;
    let (ip, ua, uid) = match &old {
        Some(r) => (r.val("ip_address"), r.val("user_agent"), r.val("user_id")),
        None => (Val::Null, Val::Null, Val::Null),
    };
    let mut data = s.data.clone();
    data.insert("_token".into(), Value::String(crate::laravel::str_random(40)));
    db::exec(
        c,
        r#"insert into "sessions" ("id", "user_id", "ip_address", "user_agent", "payload", "last_activity") values (?, ?, ?, ?, ?, ?)"#,
        &[P(Val::str(&id)), P(uid), P(ip), P(ua), P(Val::str(&encode(&data))), P(Val::Int(now))],
    )?;
    db::exec(c, r#"delete from "sessions" where "id" = ?"#, &[P(Val::str(&s.id))])?;
    Ok(id)
}

/// `PreventRequestForgery`: may this request change something? `site` is `Sec-Fetch-Site`, `input_token` the `_token`
/// input, `header_token` `X-CSRF-TOKEN`, `xsrf` the raw `X-XSRF-TOKEN` header.
pub fn csrf_ok(crypt: &Encrypter, s: &Session, method: &str, site: Option<&str>, input_token: Option<&[u8]>, header_token: Option<&[u8]>, xsrf: Option<&[u8]>) -> bool {
    if matches!(method, "GET" | "HEAD" | "OPTIONS") {
        return true;
    }
    if site == Some("same-origin") {
        return true;
    }
    let Some(want) = s.token() else { return false };
    // `$request->input('_token') ?: $request->header('X-CSRF-TOKEN')`, then the XSRF cookie's header
    let mut got: Option<Vec<u8>> = input_token.filter(|t| !t.is_empty()).or(header_token.filter(|t| !t.is_empty())).map(|t| t.to_vec());
    if got.is_none() {
        if let Some(h) = xsrf.filter(|h| !h.is_empty()) {
            got = Some(match crypt.decrypt_string(h) {
                Ok(p) if p.len() >= 41 => p[41..].to_vec(),
                _ => vec![],
            });
        }
    }
    match got {
        Some(t) => php::hash_equals(want.as_bytes(), &t),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha1::Digest;

    const KEY: &str = "base64:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

    #[test]
    fn the_login_key_is_the_sha1_of_the_guard_class() {
        assert_eq!(LOGIN_KEY, format!("login_web_{}", hex::encode(Sha1::digest(b"Illuminate\\Auth\\SessionGuard"))));
    }

    #[test]
    fn a_cookie_round_trips_and_a_foreign_one_is_refused() {
        let crypt = Encrypter::from_app_key(KEY).unwrap();
        let cfg = SessionConfig { cookie: "hte-remote-session".into(), lifetime_min: 120, secure: None };
        let id = "a".repeat(40);
        let sc = set_cookie(&cfg, &crypt, &id, true, 1_700_000_000);
        assert!(sc.contains("httponly") && sc.contains("samesite=lax") && sc.contains("secure") && sc.contains("Max-Age=7200"));
        let header = sc.split(';').next().unwrap().to_string();
        let raw = cookie_value(&header, "hte-remote-session").unwrap();
        assert_eq!(id_from_cookie(&crypt, "hte-remote-session", &raw), Some(id.clone()));
        // the same value under another cookie's name has another prefix
        assert_eq!(id_from_cookie(&crypt, "other-session", &raw), None);
        // another key does not decrypt
        let other = Encrypter::from_app_key("base64:ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=").unwrap();
        assert_eq!(id_from_cookie(&other, "hte-remote-session", &raw), None);
        // an id of the wrong shape is no session id
        let bad = crypt.encrypt_string(format!("{}short", prefix("hte-remote-session", crypt.key_bytes())).as_bytes());
        assert_eq!(id_from_cookie(&crypt, "hte-remote-session", bad.as_bytes()), None);
    }

    fn sess(data: Value) -> Session {
        let Value::Object(m) = data else { panic!() };
        Session { id: "x".repeat(40), stored: String::new(), data: m, last_activity: 0, own: false, created: 0 }
    }

    #[test]
    fn user_and_flash() {
        let s = sess(json!({"_token": "t0k", LOGIN_KEY: 7, "denied": "no", "_flash": {"old": ["denied"], "new": []}}));
        assert_eq!(s.user_id(), Some(7));
        assert_eq!(s.flashed().get("denied").and_then(|v| v.as_str()), Some("no"));
        let a = aged(&s.data).unwrap();
        assert!(!a.contains_key("denied"));
        assert_eq!(a["_flash"], json!({"old": [], "new": []}));
        // nothing flashed, nothing to write
        assert!(aged(&sess(json!({"_flash": {"old": [], "new": []}})).data).is_none());
    }

    #[test]
    fn flashing_for_the_next_page() {
        let mut d = Map::new();
        flash(&mut d, "status", json!("saved"));
        assert_eq!(d["_flash"], json!({"old": [], "new": ["status"]}));
        let aged_once = aged(&d).unwrap();
        // the next request sees it as old
        assert_eq!(sess(Value::Object(aged_once)).flashed().get("status"), Some(&json!("saved")));
    }

    #[test]
    fn csrf_rules() {
        let crypt = Encrypter::from_app_key(KEY).unwrap();
        let s = sess(json!({"_token": "abcDEF123"}));
        let ok = |m: &str, site: Option<&str>, i: Option<&[u8]>, h: Option<&[u8]>, x: Option<&[u8]>| csrf_ok(&crypt, &s, m, site, i, h, x);
        assert!(ok("GET", None, None, None, None));
        assert!(ok("POST", Some("same-origin"), None, None, None));
        assert!(!ok("POST", Some("cross-site"), None, None, None));
        assert!(!ok("POST", None, None, None, None));
        assert!(ok("POST", None, Some(b"abcDEF123"), None, None));
        assert!(!ok("POST", None, Some(b"abcDEF124"), None, None));
        assert!(ok("POST", None, None, Some(b"abcDEF123"), None));
        // the input wins over the header, as `input() ?: header()`
        assert!(!ok("POST", None, Some(b"wrong"), Some(b"abcDEF123"), None));
        // the XSRF cookie travels encrypted with the cookie prefix
        let cookie = crypt.encrypt_string(format!("{}abcDEF123", prefix("XSRF-TOKEN", crypt.key_bytes())).as_bytes());
        assert!(ok("POST", None, None, None, Some(cookie.as_bytes())));
        assert!(!ok("POST", None, None, None, Some(b"garbage")));
        // a session without a token never passes a write without same-origin
        let none = sess(json!({}));
        assert!(!csrf_ok(&crypt, &none, "POST", Some("same-site"), Some(b"x"), None, None));
    }

    #[test]
    fn an_expired_or_foreign_payload_is_no_session() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(r#"create table "sessions" ("id" varchar not null, "user_id" integer, "ip_address" varchar, "user_agent" text, "payload" text not null, "last_activity" integer not null, primary key ("id"));"#).unwrap();
        let cfg = SessionConfig { cookie: "s".into(), lifetime_min: 120, secure: None };
        let id = "b".repeat(40);
        let payload = base64::engine::general_purpose::STANDARD.encode(r#"{"_token":"t","login_web_x":1}"#);
        c.execute("insert into sessions values (?, 1, null, null, ?, ?)", rusqlite::params![id, payload, 1_000_000]).unwrap();
        assert!(load_id(&c, &cfg, 1_000_000 + 7200, &id).unwrap().is_some());
        assert!(load_id(&c, &cfg, 1_000_000 + 7201, &id).unwrap().is_none());
        // a PHP-serialized payload (another SESSION_SERIALIZATION) is not read here
        c.execute("update sessions set payload = ?", [base64::engine::general_purpose::STANDARD.encode(r#"a:1:{s:6:"_token";s:1:"t";}"#)]).unwrap();
        assert!(load_id(&c, &cfg, 1_000_001, &id).unwrap().is_none());
    }
}
