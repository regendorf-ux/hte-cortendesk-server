//! Phase 8: hte-console's OWN console session, so that signing in needs no previous console.
//!
//! - Cookie `__Host-hte-remote` over https (`hte-remote-console` over plain http, where the `__Host-` prefix is not
//!   allowed): 40 random letters and digits (`Str::random`, the OS CSPRNG), `HttpOnly`, `SameSite=Lax`, `Path=/`, no
//!   `Domain`, `Secure` over https. Nothing else is in it: it is not encrypted because there is nothing to hide, and
//!   a value this server did not mint never matches a row (`load` never adopts an id a browser offers).
//! - Row in `hte_console_sessions` (created here with `create table if not exists`: additive, the previous console never reads or
//!   migrates it, its backups skip it as hte-console's do). The row's key is sha256(cookie), so the database (or a
//!   backup, or a copy of the file) holds nothing a browser could present. The payload is Laravel's shape (base64 of
//!   JSON: `_token`, the guard's `login_web_...` key, `_flash`, `oidc.authenticated`), so the page layer reads both
//!   kinds of session the same way (`session::Session` with `own = true`).
//! - Lifetimes: idle `HTE_CONSOLE_SESSION_IDLE_MIN` (default 60) and absolute `HTE_CONSOLE_SESSION_ABSOLUTE_HOURS`
//!   (default 12) from the moment of sign-in; a rotation (sign-in) restarts both, a regeneration (password change)
//!   keeps the absolute one. "Remember me" only makes the cookie outlive the browser (Max-Age = what is left of the
//!   absolute lifetime); there is no long-lived remember-me cookie.
//! - Revocation: the payload keeps sha256 of the user's `remember_token` at sign-in. Every revoke the previous console or hte-console
//!   does (`User::revokeAllAccess`: force logout, disable, API) rotates that column, so the session dies at its next
//!   request, whoever revoked it. A disabled account (`is_active` false) also ends it.
//! - The bridge (`HTE_CONSOLE_PHP_SESSION_BRIDGE`, on until phase 9): at sign-in a Laravel session row for the same
//!   person is minted in `sessions` (the row the previous console writes at its own sign-in) and the previous console's cookie is set, so the pages the previous console
//!   still serves keep working. It is tied to this session: touched with it, re-sent with it, deleted with it (logout,
//!   expiry sweep), and marked `hte.bridged` so the page gate never accepts it as a sign-in of its own.

use super::session::{self, Session, SessionConfig, LOGIN_KEY, OIDC_KEY};
use crate::laravel::{self, Encrypter};
use crate::php::{Fault, Val};
use crate::sqlite::{self as db, Row, P};
use base64::Engine;
use rusqlite::Connection;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

pub const TABLE: &str = "hte_console_sessions";
pub const COOKIE_SECURE: &str = "__Host-hte-remote";
pub const COOKIE_PLAIN: &str = "hte-remote-console";
/// Payload keys of our own (never the previous console's).
pub const REMEMBER: &str = "hte.remember";
pub const FINGERPRINT: &str = "hte.fp";
pub const BRIDGED: &str = "hte.bridged";
pub const INTENDED: &str = "url.intended";

pub(crate) const SCHEMA: &str = r#"create table if not exists "hte_console_sessions" (
    "id_hash" varchar not null primary key,
    "user_id" integer,
    "ip_address" varchar,
    "user_agent" text,
    "payload" text not null,
    "created_at" integer not null,
    "last_activity" integer not null,
    "laravel_session_id" varchar
);
create index if not exists "hte_console_sessions_user_id_index" on "hte_console_sessions" ("user_id");
create index if not exists "hte_console_sessions_last_activity_index" on "hte_console_sessions" ("last_activity");"#;

/// The phase 8 switches, from the environment.
#[derive(Clone, Debug)]
pub struct OwnConfig {
    /// `HTE_CONSOLE_SIGNIN=1`: hte-console answers `/login`, `/login/oidc*`, `/logout` and sends a request without a
    /// session to its own sign-in page. Off (the default): those paths and such requests go to the previous console, as before.
    pub signin: bool,
    pub idle_s: i64,
    pub absolute_s: i64,
    /// Mint the previous console's session too at sign-in (default on).
    pub bridge: bool,
    /// Accept a session the previous console signed in (default on; phase 9 turns it off).
    pub laravel_read: bool,
}

impl OwnConfig {
    pub fn from_env() -> OwnConfig {
        let get = |n: &str| crate::envvar::var(n).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
        let flag = |n: &str, d: bool| get(n).map_or(d, |v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "on" | "yes"));
        let num = |n: &str, d: i64, max: i64| get(n).and_then(|v| v.parse::<i64>().ok()).filter(|v| *v > 0 && *v <= max).unwrap_or(d);
        OwnConfig {
            signin: flag("HTE_CONSOLE_SIGNIN", false),
            idle_s: num("HTE_CONSOLE_SESSION_IDLE_MIN", 60, 24 * 60) * 60,
            absolute_s: num("HTE_CONSOLE_SESSION_ABSOLUTE_HOURS", 12, 7 * 24) * 3600,
            bridge: flag("HTE_CONSOLE_PHP_SESSION_BRIDGE", true),
            laravel_read: flag("HTE_CONSOLE_LARAVEL_SESSIONS", true),
        }
    }

    pub fn test(signin: bool) -> OwnConfig {
        OwnConfig { signin, idle_s: 3600, absolute_s: 12 * 3600, bridge: true, laravel_read: true }
    }
}

/// The additive migration (idempotent).
pub fn migrate(c: &Connection) -> Result<(), String> {
    c.execute_batch(SCHEMA).map_err(|e| format!("cannot create {TABLE}: {e}"))
}

pub fn cookie_name(secure: bool) -> &'static str {
    if secure { COOKIE_SECURE } else { COOKIE_PLAIN }
}

fn hash(id: &str) -> String {
    hex::encode(Sha256::digest(id.as_bytes()))
}

fn encode(data: &Map<String, Value>) -> String {
    base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(data).unwrap_or_default())
}

/// sha256 of the user's `remember_token` (hex), what revocation is checked against.
pub fn fingerprint(user: &Row) -> String {
    let t = user.val("remember_token").to_php_string().unwrap_or_default();
    hex::encode(Sha256::digest(&t))
}

/// The value of our cookie in a `Cookie` header (the one for this scheme), when it has the shape we mint.
pub fn cookie_id(header: &str, secure: bool) -> Option<String> {
    let raw = session::cookie_value(header, cookie_name(secure))?;
    let id = String::from_utf8(raw).ok()?;
    session::valid_id(&id).then_some(id)
}

/// The session a request's cookie names: None when absent, unknown, idle or past its absolute lifetime.
pub fn load(c: &Connection, cfg: &OwnConfig, now: i64, cookie_header: &str, secure: bool) -> Result<Option<Session>, Fault> {
    let Some(id) = cookie_id(cookie_header, secure) else { return Ok(None) };
    load_id(c, cfg, now, &id)
}

pub fn load_id(c: &Connection, cfg: &OwnConfig, now: i64, id: &str) -> Result<Option<Session>, Fault> {
    let Some(row) = db::first(c, r#"select * from "hte_console_sessions" where "id_hash" = ? limit 1"#, &[P(Val::str(&hash(id)))])? else { return Ok(None) };
    let last = row.val("last_activity").to_int();
    let created = row.val("created_at").to_int();
    if last < now - cfg.idle_s || created < now - cfg.absolute_s {
        destroy_row(c, &row)?;
        return Ok(None);
    }
    let stored = String::from_utf8_lossy(&row.val("payload").to_php_string()?).into_owned();
    let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(stored.trim()) else { return Ok(None) };
    let Ok(Value::Object(data)) = serde_json::from_slice::<Value>(&raw) else { return Ok(None) };
    Ok(Some(Session { id: id.to_string(), stored, data, last_activity: last, own: true, created }))
}

/// Is this signed-in session still valid for this user (not revoked, account active)? Ends it when not.
pub fn still_valid(c: &Connection, s: &Session, user: &Row) -> Result<bool, Fault> {
    let fp_ok = s.data.get(FINGERPRINT).and_then(|v| v.as_str()).map_or(false, |fp| crate::php::hash_equals(fingerprint(user).as_bytes(), fp.as_bytes()));
    if fp_ok && user.val("is_active").to_bool() {
        return Ok(true);
    }
    destroy(c, s)?;
    Ok(false)
}

/// Move this account's sessions that carry fingerprint `from` to `to` (a remember token given where there was none).
pub fn refingerprint(c: &Connection, user_id: i64, from: &str, to: &str) -> Result<(), Fault> {
    let rows = db::rows(c, r#"select "id_hash", "payload" from "hte_console_sessions" where "user_id" = ?"#, &[P(Val::Int(user_id))])?;
    for r in rows {
        let stored = String::from_utf8_lossy(&r.val("payload").to_php_string()?).into_owned();
        let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(stored.trim()) else { continue };
        let Ok(Value::Object(mut data)) = serde_json::from_slice::<Value>(&raw) else { continue };
        if data.get(FINGERPRINT).and_then(|v| v.as_str()) != Some(from) {
            continue;
        }
        data.insert(FINGERPRINT.into(), json!(to));
        db::exec(c, r#"update "hte_console_sessions" set "payload" = ? where "id_hash" = ? and "payload" = ?"#, &[P(Val::str(&encode(&data))), P(r.val("id_hash")), P(Val::str(&stored))])?;
    }
    Ok(())
}

/// A new session row (a guest's, before sign-in, or the signed-in one after a rotation). Returns the cookie id.
pub fn create(c: &Connection, data: &Map<String, Value>, ip: &str, ua: &str, now: i64, created: i64, laravel_id: Option<&str>) -> Result<String, Fault> {
    let id = laravel::str_random(40);
    let uid = data.get(LOGIN_KEY).and_then(|v| v.as_i64()).map_or(Val::Null, Val::Int);
    // a user agent longer than this is not worth keeping (Laravel keeps 500 characters)
    let ua: String = ua.chars().take(500).collect();
    db::exec(
        c,
        r#"insert into "hte_console_sessions" ("id_hash", "user_id", "ip_address", "user_agent", "payload", "created_at", "last_activity", "laravel_session_id") values (?, ?, ?, ?, ?, ?, ?, ?)"#,
        &[
            P(Val::str(&hash(&id))),
            P(uid),
            P(Val::str(ip)),
            P(Val::str(&ua)),
            P(Val::str(&encode(data))),
            P(Val::Int(created)),
            P(Val::Int(now)),
            P(laravel_id.map_or(Val::Null, Val::str)),
        ],
    )?;
    Ok(id)
}

/// A fresh guest payload: a CSRF token and nothing else.
pub fn guest_data() -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("_token".into(), json!(laravel::str_random(40)));
    m.insert("_flash".into(), json!({"old": [], "new": []}));
    m
}

/// Compare-and-swap the payload, as `session::save` does for the previous console's rows.
pub fn save(c: &Connection, s: &Session, data: &Map<String, Value>, now: i64) -> Result<bool, Fault> {
    let n = db::exec(
        c,
        r#"update "hte_console_sessions" set "payload" = ?, "last_activity" = ? where "id_hash" = ? and "payload" = ?"#,
        &[P(Val::str(&encode(data))), P(Val::Int(now)), P(Val::str(&hash(&s.id))), P(Val::str(&s.stored))],
    )?;
    Ok(n == 1)
}

/// Slide the idle expiry (at most once a minute), the bridged the previous console row with it.
pub fn touch(c: &Connection, s: &Session, now: i64) -> Result<(), Fault> {
    if now - s.last_activity < 60 {
        return Ok(());
    }
    let h = hash(&s.id);
    db::exec(c, r#"update "hte_console_sessions" set "last_activity" = ? where "id_hash" = ? and "last_activity" < ?"#, &[P(Val::Int(now)), P(Val::str(&h)), P(Val::Int(now))])?;
    db::exec(
        c,
        r#"update "sessions" set "last_activity" = ? where "id" = (select "laravel_session_id" from "hte_console_sessions" where "id_hash" = ?) and "last_activity" < ?"#,
        &[P(Val::Int(now)), P(Val::str(&h)), P(Val::Int(now))],
    )?;
    Ok(())
}

/// The bridged the previous console session id of a session, if any.
pub fn bridged_id(c: &Connection, s: &Session) -> Result<Option<String>, Fault> {
    let row = db::first(c, r#"select "laravel_session_id" from "hte_console_sessions" where "id_hash" = ? limit 1"#, &[P(Val::str(&hash(&s.id)))])?;
    Ok(row.and_then(|r| match r.val("laravel_session_id") {
        Val::Null => None,
        v => v.to_php_string().ok().map(|b| String::from_utf8_lossy(&b).into_owned()),
    }))
}

/// `session()->regenerate()` with a fresh `_token`: new id, old row gone, same absolute lifetime and bridge.
pub fn regenerate(c: &Connection, s: &Session, now: i64) -> Result<String, Fault> {
    let old = db::first(c, r#"select * from "hte_console_sessions" where "id_hash" = ? limit 1"#, &[P(Val::str(&hash(&s.id)))])?;
    let text = |k: &str| old.as_ref().and_then(|r| r.val(k).to_php_string().ok()).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
    let (ip, ua) = (text("ip_address"), text("user_agent"));
    let bridged = bridged_id(c, s)?;
    let mut data = s.data.clone();
    data.insert("_token".into(), json!(laravel::str_random(40)));
    let id = create(c, &data, &ip, &ua, now, s.created, bridged.as_deref())?;
    db::exec(c, r#"delete from "hte_console_sessions" where "id_hash" = ?"#, &[P(Val::str(&hash(&s.id)))])?;
    Ok(id)
}

fn destroy_row(c: &Connection, row: &Row) -> Result<(), Fault> {
    if let Val::Str(l) = row.val("laravel_session_id") {
        db::exec(c, r#"delete from "sessions" where "id" = ?"#, &[P(Val::Str(l))])?;
    }
    db::exec(c, r#"delete from "hte_console_sessions" where "id_hash" = ?"#, &[P(row.val("id_hash"))])?;
    Ok(())
}

/// End a session: its row and the previous console session bridged to it.
pub fn destroy(c: &Connection, s: &Session) -> Result<(), Fault> {
    if let Some(row) = db::first(c, r#"select * from "hte_console_sessions" where "id_hash" = ? limit 1"#, &[P(Val::str(&hash(&s.id)))])? {
        destroy_row(c, &row)?;
    }
    Ok(())
}

/// Delete expired rows (and their bridged the previous console rows). Called at most once a minute by the sign-in pages and the gate.
pub fn sweep(c: &Connection, cfg: &OwnConfig, now: i64) -> Result<usize, Fault> {
    static LAST: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
    let last = LAST.load(std::sync::atomic::Ordering::Relaxed);
    if now - last < 60 && now >= last {
        return Ok(0);
    }
    LAST.store(now, std::sync::atomic::Ordering::Relaxed);
    let (idle, abs) = (Val::Int(now - cfg.idle_s), Val::Int(now - cfg.absolute_s));
    db::exec(
        c,
        r#"delete from "sessions" where "id" in (select "laravel_session_id" from "hte_console_sessions" where ("last_activity" < ? or "created_at" < ?) and "laravel_session_id" is not null)"#,
        &[P(idle.clone()), P(abs.clone())],
    )?;
    db::exec(c, r#"delete from "hte_console_sessions" where "last_activity" < ? or "created_at" < ?"#, &[P(idle), P(abs)])
}

/// `Set-Cookie` for our session. `remember_left`: the cookie outlives the browser for that many seconds.
pub fn set_cookie(id: &str, secure: bool, remember_left: Option<i64>, now: i64) -> String {
    let mut c = format!("{}={id}; path=/; httponly; samesite=lax", cookie_name(secure));
    if let Some(left) = remember_left.filter(|l| *l > 0) {
        let expires = chrono::DateTime::<chrono::Utc>::from_timestamp(now + left, 0).unwrap_or_default().format("%a, %d-%b-%Y %H:%M:%S GMT");
        c = format!("{}={id}; expires={expires}; Max-Age={left}; path=/; httponly; samesite=lax", cookie_name(secure));
    }
    if secure {
        c.push_str("; secure");
    }
    c
}

/// A `Set-Cookie` that removes a cookie.
pub fn clear_cookie(name: &str, secure: bool) -> String {
    let mut c = format!("{name}=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; Max-Age=0; path=/; httponly; samesite=lax");
    if secure {
        c.push_str("; secure");
    }
    c
}

/// The cookie a response re-sends for a session (ours or the previous console's).
pub fn cookie_for(scfg: &SessionConfig, own: &OwnConfig, crypt: &Encrypter, s: &Session, id: &str, secure: bool, now: i64) -> String {
    if s.own {
        let remember = s.data.get(REMEMBER).map_or(false, |v| v.as_bool() == Some(true));
        set_cookie(id, secure, remember.then(|| s.created + own.absolute_s - now), now)
    } else {
        session::set_cookie(scfg, crypt, id, secure, now)
    }
}

/// The signed-in payload after a sign-in: a new `_token`, the guard key, the revocation fingerprint, and what the
/// guest session carried that a sign-in keeps (the intended URL is consumed by the caller).
pub fn signed_in_data(user: &Row, via_oidc: bool, remember: bool) -> Map<String, Value> {
    let mut m = guest_data();
    m.insert(LOGIN_KEY.into(), json!(user.id()));
    m.insert(FINGERPRINT.into(), json!(fingerprint(user)));
    if via_oidc {
        m.insert(OIDC_KEY.into(), json!(true));
    }
    if remember {
        m.insert(REMEMBER.into(), json!(true));
    }
    m
}

/// Mint the previous console's session for the same person (the row `Auth::login` + `regenerate()` leaves). Returns its id.
pub fn mint_laravel(c: &Connection, user: &Row, via_oidc: bool, root: &str, ip: &str, ua: &str, now: i64) -> Result<String, Fault> {
    let id = laravel::str_random(40);
    let mut m = Map::new();
    m.insert("_token".into(), json!(laravel::str_random(40)));
    m.insert("_previous".into(), json!({"url": format!("{root}/")}));
    m.insert("_flash".into(), json!({"old": [], "new": []}));
    m.insert(LOGIN_KEY.into(), json!(user.id()));
    if via_oidc {
        m.insert(OIDC_KEY.into(), json!(true));
    }
    m.insert(BRIDGED.into(), json!(1));
    let ua: String = ua.chars().take(500).collect();
    db::exec(
        c,
        r#"insert into "sessions" ("id", "user_id", "ip_address", "user_agent", "payload", "last_activity") values (?, ?, ?, ?, ?, ?)"#,
        &[P(Val::str(&id)), P(Val::Int(user.id())), P(Val::str(ip)), P(Val::str(&ua)), P(Val::str(&encode(&m))), P(Val::Int(now))],
    )?;
    Ok(id)
}

/// Point a session at a (new) bridged the previous console row.
pub fn set_bridge(c: &Connection, id: &str, laravel_id: &str) -> Result<(), Fault> {
    db::exec(c, r#"update "hte_console_sessions" set "laravel_session_id" = ? where "id_hash" = ?"#, &[P(Val::str(laravel_id)), P(Val::str(&hash(id)))])?;
    Ok(())
}

/// Does the previous console's bridged row still exist?
pub fn laravel_row_exists(c: &Connection, laravel_id: &str) -> Result<bool, Fault> {
    Ok(db::first(c, r#"select "id" from "sessions" where "id" = ? limit 1"#, &[P(Val::str(laravel_id))])?.is_some())
}

/// A post-login target that cannot leave this console: a path on this origin, nothing else. Accepts an absolute URL
/// only when it starts with `root/`. Everything else (`//host`, `/\host`, `https://other`, control characters,
/// `javascript:`) is refused.
pub fn safe_target(t: &str, root: &str) -> Option<String> {
    let path = if let Some(rest) = t.strip_prefix(root) {
        if !rest.starts_with('/') {
            return None;
        }
        rest
    } else {
        t
    };
    let ok = path.starts_with('/')
        && !path.starts_with("//")
        && !path.starts_with("/\\")
        && path.len() <= 2048
        && path.bytes().all(|b| (0x21..0x7f).contains(&b) && b != b'\\');
    ok.then(|| path.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(r#"create table "sessions" ("id" varchar not null, "user_id" integer, "ip_address" varchar, "user_agent" text, "payload" text not null, "last_activity" integer not null, primary key ("id"));
            create table "users" ("id" integer primary key, "remember_token" varchar, "is_active" tinyint(1) not null default 1);
            insert into users values (7, 'r1', 1);"#).unwrap();
        migrate(&c).unwrap();
        migrate(&c).unwrap(); // idempotent
        c
    }

    fn user(c: &Connection) -> Row {
        db::first(c, "select * from users where id = 7", &[]).unwrap().unwrap()
    }

    #[test]
    fn the_row_holds_only_the_hash_and_lifetimes_are_enforced() {
        let c = db();
        let cfg = OwnConfig::test(true);
        let u = user(&c);
        let id = create(&c, &signed_in_data(&u, false, false), "198.18.0.1", "ua", 1000, 1000, None).unwrap();
        assert!(session::valid_id(&id));
        let stored: String = c.query_row("select id_hash from hte_console_sessions", [], |r| r.get(0)).unwrap();
        assert_ne!(stored, id);
        assert_eq!(stored, hash(&id));
        let s = load_id(&c, &cfg, 1000 + 3600, &id).unwrap().unwrap();
        assert_eq!(s.user_id(), Some(7));
        assert!(s.own);
        // idle
        assert!(load_id(&c, &cfg, 1000 + 3601, &id).unwrap().is_none());
        assert_eq!(c.query_row("select count(*) from hte_console_sessions", [], |r| r.get::<_, i64>(0)).unwrap(), 0);
        // absolute, even while active
        let id = create(&c, &signed_in_data(&u, false, false), "ip", "ua", 1000, 1000, None).unwrap();
        let mut t = 1000;
        while t < 1000 + 12 * 3600 {
            t += 3000;
            let s = load_id(&c, &cfg, t, &id).unwrap();
            if t <= 1000 + 12 * 3600 {
                touch(&c, &s.unwrap(), t).unwrap();
            }
        }
        assert!(load_id(&c, &cfg, 1000 + 12 * 3600 + 1, &id).unwrap().is_none());
    }

    #[test]
    fn a_revoke_anywhere_ends_the_session() {
        let c = db();
        let cfg = OwnConfig::test(true);
        let u = user(&c);
        let lid = mint_laravel(&c, &u, false, "https://x", "ip", "ua", 1000).unwrap();
        let id = create(&c, &signed_in_data(&u, false, false), "ip", "ua", 1000, 1000, Some(&lid)).unwrap();
        let s = load_id(&c, &cfg, 1001, &id).unwrap().unwrap();
        assert!(still_valid(&c, &s, &user(&c)).unwrap());
        // revokeAllAccess (the previous console or Rust) rotates remember_token
        c.execute("update users set remember_token = 'r2'", []).unwrap();
        assert!(!still_valid(&c, &s, &user(&c)).unwrap());
        assert!(load_id(&c, &cfg, 1002, &id).unwrap().is_none());
        assert!(!laravel_row_exists(&c, &lid).unwrap());
    }

    #[test]
    fn the_bridge_is_marked_touched_and_swept_with_its_session() {
        let c = db();
        let cfg = OwnConfig::test(true);
        let u = user(&c);
        let lid = mint_laravel(&c, &u, true, "https://x", "ip", "ua", 1000).unwrap();
        let ls = session::load_id(&c, &SessionConfig { cookie: "s".into(), lifetime_min: 120, secure: None }, 1000, &lid).unwrap().unwrap();
        assert_eq!(ls.user_id(), Some(7));
        assert!(ls.via_oidc());
        assert!(ls.data.contains_key(BRIDGED));
        let id = create(&c, &signed_in_data(&u, true, false), "ip", "ua", 1000, 1000, Some(&lid)).unwrap();
        let s = load_id(&c, &cfg, 1100, &id).unwrap().unwrap();
        touch(&c, &s, 1100).unwrap();
        let last: i64 = c.query_row("select last_activity from sessions", [], |r| r.get(0)).unwrap();
        assert_eq!(last, 1100);
        // regenerate keeps the bridge and the absolute start
        let id2 = regenerate(&c, &s, 1200).unwrap();
        let s2 = load_id(&c, &cfg, 1200, &id2).unwrap().unwrap();
        assert_eq!(s2.created, 1000);
        assert_eq!(bridged_id(&c, &s2).unwrap().as_deref(), Some(lid.as_str()));
        assert!(load_id(&c, &cfg, 1200, &id).unwrap().is_none());
        assert_ne!(s2.token(), s.token());
        // the sweep takes both when the session expires
        assert_eq!(sweep(&c, &cfg, 1200 + 3601).unwrap(), 1);
        assert!(!laravel_row_exists(&c, &lid).unwrap());
    }

    #[test]
    fn cookie_flags() {
        let s = set_cookie(&"a".repeat(40), true, None, 0);
        assert!(s.starts_with("__Host-hte-remote=aaaa"));
        assert!(s.contains("; path=/; httponly; samesite=lax") && s.ends_with("; secure"));
        assert!(!s.contains("Max-Age") && !s.to_ascii_lowercase().contains("domain"));
        let p = set_cookie(&"a".repeat(40), false, Some(600), 0);
        assert!(p.starts_with("hte-remote-console=") && p.contains("Max-Age=600") && !p.contains("secure"));
        // a cookie of the wrong shape is not even looked up
        assert_eq!(cookie_id("__Host-hte-remote=short", true), None);
        assert_eq!(cookie_id(&format!("hte-remote-console={}", "b".repeat(40)), true), None);
        assert_eq!(cookie_id(&format!("x=1; __Host-hte-remote={}", "b".repeat(40)), true), Some("b".repeat(40)));
    }

    #[test]
    fn open_redirects_are_refused() {
        let root = "https://console.example.invalid";
        assert_eq!(safe_target("/devices?x=1", root).as_deref(), Some("/devices?x=1"));
        assert_eq!(safe_target(&format!("{root}/users/3"), root).as_deref(), Some("/users/3"));
        for bad in [
            "//evil.example",
            "/\\evil.example",
            "https://evil.example/",
            "https://console.example.invalid.evil.example/",
            "https://console.example.invalid@evil.example/",
            "javascript:alert(1)",
            "/ok\r\nSet-Cookie: x=1",
            "/a b",
            "",
            "devices",
        ] {
            assert_eq!(safe_target(bad, root), None, "{bad:?}");
        }
    }
}
