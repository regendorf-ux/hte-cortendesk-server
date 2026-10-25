//! Phase 8 (0.8.2): invitations, ported from v1.15.0-hte.1 `InvitationManager` (the card at the end of Users),
//! `InvitationController` (the accept page) and the `Invitation` model.
//!
//!   POST /users/invitations          do=save (the Invite dialog), resend, revoke     (`user: rw`)
//!   GET  /users?invite=1             the Invite dialog
//!   GET|POST /invite/{token}         the invitee sets a password; the account is created and signed in
//!   GET  /invitations                hte-console's old "not available" link: to Users
//!
//! The token is 'inv_' + 48 random characters, only its sha256 stored; the accept URL is shown once, in the answer to the
//! create or resend post (never in a session or a log), and mailed when mail is on. Privileges come from the row, never
//! the request; a delegated user-manager is clamped as `UserList::save` is; an inviter who lost the authority voids it.

use super::kit::*;
use super::login::{self, already_signed_in, csrf, guest_session, keep, login_log_note, page_expired, redirect, signed_in, Out, Web};
use super::users::Modal;
use super::{html, Ctx, Pages, Reply, Req};
use crate::laravel::{self, Cast};
use crate::php::{Fault, Val};
use crate::sqlite::{self as db, Row, P};
use rusqlite::Connection;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

/// `Invitation::DEFAULT_EXPIRY_HOURS`
const DEFAULT_EXPIRY_HOURS: i64 = 48;

/// `Invitation::expiryHours()`
fn expiry_hours(c: &Connection) -> Result<i64, Fault> {
    let v = String::from_utf8_lossy(&db::setting(c, "invite_expiry_hours", "48")?).trim().parse::<i64>().unwrap_or(0);
    Ok(if v == 0 { DEFAULT_EXPIRY_HOURS } else { v.clamp(1, 720) })
}

fn ids_of(r: &Row, col: &str) -> Vec<i64> {
    let raw = r.val(col).to_php_string().unwrap_or_default();
    serde_json::from_slice::<Vec<Value>>(&raw).unwrap_or_default().iter().filter_map(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))).collect()
}

fn json_ids(ids: &[i64]) -> String {
    serde_json::to_string(ids).unwrap_or_else(|_| "[]".into())
}

/// `mayManage($invitation)`: could this actor have created it themselves?
fn may_manage(ctx: &Ctx, c: &Connection, inv: &Row) -> Result<bool, Fault> {
    if ctx.is_admin() {
        return Ok(true);
    }
    if inv.val("is_admin").to_bool() {
        return Ok(false);
    }
    let d = ids_of(inv, "device_group_ids");
    if d.iter().any(|i| !grantable_device_group_ids(ctx, c, &d).map(|g| g.contains(i)).unwrap_or(false)) {
        return Ok(false);
    }
    let u = ids_of(inv, "user_group_ids");
    let ok = grantable_user_group_ids(ctx, c, &u)?;
    Ok(u.iter().all(|i| ok.contains(i)))
}

// ------------------------------------------------------------------------------------------------- the card ---

/// The card's variables. `notice`: the accept URL just made (shown once), or null.
pub(super) fn card(ctx: &Ctx, c: &Connection, notice: Value) -> Result<Value, Fault> {
    if !ctx.allows("user", "rw") {
        return Ok(Value::Null);
    }
    let rows = db::rows(c, r#"select * from "invitations" where "accepted_at" is null order by "created_at" desc"#, &[])?;
    let inviters = find_in(c, "users", &rows.iter().filter(|r| !r.is_null("invited_by")).map(|r| r.val("invited_by").to_int()).collect::<Vec<_>>())?;
    let mut items = vec![];
    for r in &rows {
        let expires = ts_of(r, "expires_at").unwrap_or(0);
        items.push(json!({
            "id": r.id(), "email": s(r, "email"), "username": s(r, "username"), "admin": r.val("is_admin").to_bool(),
            "inviter": by_id(&inviters, &r.val("invited_by")).map(|u| s(u, "username")),
            "expired": expires <= ctx.now, "expires_human": super::time::ago(expires, ctx.now, false), "expires_at": laravel::ts(expires),
            "manage": may_manage(ctx, c, r)?,
        }));
    }
    Ok(json!({"rows": items, "mail_enabled": crate::mail::enabled(c)?, "notice": notice, "hours": expiry_hours(c)?}))
}

pub(super) fn blank() -> Map<String, Value> {
    let Value::Object(m) = json!({"email": "", "username": "", "name": "", "is_admin": false, "user_group_ids": [], "device_group_ids": []}) else { unreachable!() };
    m
}

/// The Invite dialog's variables.
pub(super) fn modal_json(ctx: &Ctx, c: &Connection, values: &Map<String, Value>, errors: &Map<String, Value>, url: &str) -> Result<Value, Fault> {
    let mut filled = errors.clone();
    for k in ["email", "username", "name"] {
        filled.entry(k.to_string()).or_insert(Value::Null);
    }
    let ug: Vec<Value> = grantable_user_groups(ctx, c)?.iter().map(|g| json!({"id": g.id(), "name": s(g, "name")})).collect();
    let dg: Vec<Value> = grantable_device_groups(ctx, c)?.iter().map(|g| json!({"id": g.id(), "name": s(g, "name")})).collect();
    Ok(json!({"kind": "invite", "values": values, "errors": filled, "user_groups": ug, "device_groups": dg, "return": url, "hours": expiry_hours(c)?}))
}

/// Mail the link when mail is on; the notice that shows it either way.
fn deliver(ctx: &Ctx, c: &Connection, inv: &Row, plain: &str) -> Result<Value, Fault> {
    let url = format!("{}/invite/{plain}", ctx.root);
    let expires = ts_of(inv, "expires_at").unwrap_or(ctx.now);
    let p = ctx.p;
    let html = p
        .view
        .render(
            "mail/invitation.html",
            json!({
                "app_name": p.n.signin.app_name, "root": ctx.root, "invited_by": ctx.display_name(), "username": s(inv, "username"), "url": url,
                "expires_human": super::time::ago(expires, ctx.now, false), "expires_at": laravel::ts(expires)[..16].to_string(),
            }),
        )
        .map_err(Fault::Other)?;
    let msg = crate::mail::Message { to: s(inv, "email"), subject: format!("You have been invited to {}", p.n.signin.app_name), html };
    let domain = url::Url::parse(&ctx.root).ok().and_then(|u| u.host_str().map(str::to_string)).unwrap_or_default();
    let sent = crate::mail::send(c, &p.n.crypt, &p.n.signin.app_name, &domain, &msg, ctx.now)?;
    Ok(json!({"url": url, "for": s(inv, "email"), "sent": sent}))
}

/// `POST /users/invitations`
pub fn post(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    if !ctx.allows("user", "rw") {
        return Ok(abort(403));
    }
    let body = Body::of(req);
    let back = body.get("back");
    match body.get("do").as_str() {
        "save" => save(ctx, c, &body, &back),
        "resend" | "revoke" => {
            let id = body.int("id");
            let Some(mut inv) = db::first(c, r#"select * from "invitations" where "invitations"."id" = ? and "accepted_at" is null limit 1"#, &[P(Val::Int(id))])? else {
                return super::users::page(ctx, c, &back, 200, Modal::None, Value::Null);
            };
            if !may_manage(ctx, c, &inv)? {
                return Ok(abort(403));
            }
            let email = s(&inv, "email");
            if body.get("do") == "revoke" {
                db::exec(c, r#"delete from "invitations" where "id" = ?"#, &[P(Val::Int(id))])?;
                audit(ctx, c, "user.invite-revoke", &format!("Revoked the invitation for {email}"), Some("invitation"), Some(&id.to_string()))?;
                return Ok(Reply::Redirect(format!("/users{}", if back.is_empty() { String::new() } else { format!("?{back}") })));
            }
            // `rotate()`: a new token (the old link stops working) and a new expiry
            let plain = format!("inv_{}", laravel::str_random(48));
            let hours = expiry_hours(c)?;
            update(
                c,
                "invitations",
                &mut inv,
                vec![("token_hash", Val::str(&hex::encode(Sha256::digest(plain.as_bytes()))), Cast::Plain), ("expires_at", Val::str(&laravel::ts(ctx.now + hours * 3600)), Cast::Date)],
                ctx.now,
            )?;
            let notice = deliver(ctx, c, &inv, &plain)?;
            audit(ctx, c, "user.invite-resend", &format!("Re-sent the invitation for {email}"), Some("invitation"), Some(&id.to_string()))?;
            super::users::page(ctx, c, &back, 200, Modal::None, notice)
        }
        _ => Ok(abort(400)),
    }
}

fn unique_taken(c: &Connection, table: &str, col: &str, v: &str, now: i64) -> Result<bool, Fault> {
    let live = if table == "invitations" { r#" and "accepted_at" is null and "expires_at" > ?"# } else { "" };
    let sql = format!(r#"select count(*) as aggregate from "{table}" where "{col}" = ?{live}"#);
    let mut params = vec![P(Val::str(v))];
    if table == "invitations" {
        params.push(P(Val::str(&laravel::ts(now))));
    }
    Ok(count(c, &sql, &params)? > 0)
}

fn save(ctx: &Ctx, c: &Connection, body: &Body, back: &str) -> Result<Reply, Fault> {
    let email = body.get("email").trim().to_string();
    let username = body.get("username").trim().to_string();
    let name = body.get("name").trim().to_string();
    let mut is_admin = body.checked("is_admin");
    let mut ug = body.ints("user_group_ids");
    let mut dg = body.ints("device_group_ids");
    let mut errors = Map::new();
    let mut err = |k: &str, m: String| {
        errors.entry(k.to_string()).or_insert(json!(m));
    };
    if email.is_empty() {
        err("email", "The email field is required.".into());
    } else if !crate::email::is_valid(email.as_bytes()) {
        err("email", "The email field must be a valid email address.".into());
    } else if email.chars().count() > 255 {
        err("email", "The email field must not be greater than 255 characters.".into());
    } else if unique_taken(c, "users", "email", &email, ctx.now)? || unique_taken(c, "invitations", "email", &email, ctx.now)? {
        err("email", "That address already has an account or a pending invitation.".into());
    }
    if username.is_empty() {
        err("username", "The username field is required.".into());
    } else if username.chars().count() > 255 {
        err("username", "The username field must not be greater than 255 characters.".into());
    } else if unique_taken(c, "users", "username", &username, ctx.now)? || unique_taken(c, "invitations", "username", &username, ctx.now)? {
        err("username", "That username is already taken or reserved by a pending invitation.".into());
    }
    if name.chars().count() > 255 {
        err("name", "The name field must not be greater than 255 characters.".into());
    }
    for (i, id) in ug.iter().enumerate() {
        if find(c, "user_groups", *id)?.is_none() {
            err(&format!("user_group_ids.{i}"), format!("The selected user_group_ids.{i} is invalid."));
        }
    }
    for (i, id) in dg.iter().enumerate() {
        if find(c, "device_groups", *id)?.is_none() {
            err(&format!("device_group_ids.{i}"), format!("The selected device_group_ids.{i} is invalid."));
        }
    }
    if !errors.is_empty() {
        let values = json!({"email": email, "username": username, "name": name, "is_admin": is_admin, "user_group_ids": ug, "device_group_ids": dg});
        let Value::Object(v) = values else { unreachable!() };
        return super::users::page(ctx, c, back, 422, Modal::Invite { values: v, errors }, Value::Null);
    }
    if !ctx.is_admin() {
        is_admin = false;
        dg = grantable_device_group_ids(ctx, c, &dg)?;
        ug = grantable_user_group_ids(ctx, c, &ug)?;
    }
    // `Invitation::issue()`
    let plain = format!("inv_{}", laravel::str_random(48));
    let hours = expiry_hours(c)?;
    let id = db::insert(
        c,
        "invitations",
        vec![
            ("email", Val::str(&email)),
            ("username", Val::str(&username)),
            ("name", if name.is_empty() { Val::Null } else { Val::str(&name) }),
            ("token_hash", Val::str(&hex::encode(Sha256::digest(plain.as_bytes())))),
            ("is_admin", Val::Bool(is_admin)),
            ("user_group_ids", Val::str(&json_ids(&ug))),
            ("device_group_ids", Val::str(&json_ids(if is_admin { &[] } else { &dg }))),
            ("invited_by", ctx.user.val("id")),
            ("expires_at", Val::str(&laravel::ts(ctx.now + hours * 3600))),
        ],
        &laravel::ts(ctx.now),
    )?;
    let inv = find(c, "invitations", id)?.ok_or_else(|| Fault::Other("invitation vanished".into()))?;
    let notice = deliver(ctx, c, &inv, &plain)?;
    audit(ctx, c, "user.invite", &format!("Invited {email} as {username}{}", if is_admin { " (administrator)" } else { "" }), Some("invitation"), Some(&id.to_string()))?;
    super::users::page(ctx, c, back, 200, Modal::None, notice)
}

/// `GET /invitations`: hte-console's own old link target; the card lives on Users, as in PHP.
pub fn to_users(_ctx: &Ctx, _c: &Connection, _req: &Req) -> Result<Reply, Fault> {
    Ok(Reply::Redirect("/users".into()))
}

// ------------------------------------------------------------------------------------------ the accept page ---

fn token_of(w: &Web) -> String {
    let last = w.path.rsplit('/').next().unwrap_or("");
    String::from_utf8_lossy(&crate::php::urldecode(last.as_bytes())).into_owned()
}

enum Resolved {
    Ok(Row),
    Missing,
    Void,
}

/// `resolve($token)`: a live invitation whose inviter still holds the authority it needs.
fn resolve(c: &Connection, token: &str, now: i64) -> Result<Resolved, Fault> {
    let Some(inv) = db::first(
        c,
        r#"select * from "invitations" where "token_hash" = ? and "accepted_at" is null and "expires_at" > ? limit 1"#,
        &[P(Val::str(&hex::encode(Sha256::digest(token.as_bytes())))), P(Val::str(&laravel::ts(now)))],
    )?
    else {
        return Ok(Resolved::Missing);
    };
    let inviter = if inv.is_null("invited_by") { None } else { find(c, "users", inv.val("invited_by").to_int())? };
    let ok = match &inviter {
        Some(u) => u.val("is_active").to_bool() && user_allows(c, u, "user", "rw")? && (!inv.val("is_admin").to_bool() || u.val("is_admin").to_bool()),
        None => false,
    };
    Ok(if ok { Resolved::Ok(inv) } else { Resolved::Void })
}

/// `User::consoleAllows($resource, $level)` for a user who is not the request's.
fn user_allows(c: &Connection, u: &Row, resource: &str, level: &str) -> Result<bool, Fault> {
    if u.val("is_admin").to_bool() {
        return Ok(true);
    }
    let rank = |l: &str| match l {
        "rw" => 2,
        "r" => 1,
        _ => 0,
    };
    let have = if u.is_null("role_id") {
        super::legacy_level(resource).to_string()
    } else {
        let role = find(c, "roles", u.val("role_id").to_int())?;
        let perms: Value = role.and_then(|r| r.val("permissions").to_php_string().ok()).and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(Value::Null);
        perms.get(resource).and_then(|v| v.as_str()).filter(|l| ["none", "r", "rw"].contains(l)).unwrap_or("none").to_string()
    };
    Ok(rank(&have) >= rank(level))
}

fn refusal(r: &Resolved) -> Option<Out> {
    match r {
        Resolved::Ok(_) => None,
        Resolved::Missing => Some(Out::new(login::error(404, "Not Found", false))),
        Resolved::Void => Some(Out::new(login::error(403, "This invitation is no longer valid. Ask an administrator for a new one.", false))),
    }
}

pub(super) fn accept_show(p: &Pages, c: &Connection, w: &Web) -> Result<Out, Fault> {
    let s = guest_session(p, c, w)?;
    if signed_in(c, &s)? {
        return already_signed_in(p, c, w, &s);
    }
    let token = token_of(w);
    let r = resolve(c, &token, w.now)?;
    if let Some(o) = refusal(&r) {
        return Ok(o);
    }
    let Resolved::Ok(inv) = r else { unreachable!() };
    let flashed = s.flashed();
    let error = flashed.get("errors").and_then(|e| e.as_object()).and_then(|m| m.values().next()).and_then(|v| v.get(0)).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let old_name = flashed.get("_old_input").and_then(|o| o.get("name")).and_then(|v| v.as_str()).map(str::to_string).unwrap_or_else(|| s_of(&inv, "name"));
    let expires = ts_of(&inv, "expires_at").unwrap_or(w.now);
    let page = p
        .view
        .render(
            "auth/invite.html",
            json!({
                "app_name": p.n.signin.app_name, "version": p.n.api_version, "root": w.root, "csrf": s.token().unwrap_or(""), "title": "Accept Invitation",
                "error": error, "token": laravel::urlencode(token.as_bytes()), "username": s_of(&inv, "username"), "email": s_of(&inv, "email"), "name": old_name,
                "expires_human": super::time::ago(expires, w.now, false),
            }),
        )
        .map_err(Fault::Other)?;
    let mut out = Out::new(html(200, page, false));
    keep(p, c, w, &s, s.data.clone(), vec![], &mut out)?;
    Ok(out)
}

fn s_of(r: &Row, col: &str) -> String {
    s(r, col)
}

pub(super) fn accept_post(p: &Pages, c: &Connection, w: &Web) -> Result<Out, Fault> {
    let s = guest_session(p, c, w)?;
    if !csrf(p, &s, w) {
        return Ok(page_expired());
    }
    if signed_in(c, &s)? {
        return already_signed_in(p, c, w, &s);
    }
    let token = token_of(w);
    let r = resolve(c, &token, w.now)?;
    if let Some(o) = refusal(&r) {
        return Ok(o);
    }
    let Resolved::Ok(inv) = r else { unreachable!() };
    let here = format!("/invite/{}", laravel::urlencode(token.as_bytes()));
    let name_in = w.input.get("name").and_then(|v| v.to_php_string().ok()).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
    let back = |field: &str, m: &str| -> Result<Out, Fault> {
        let mut out = Out::new(redirect(&format!("{}{here}", w.root)));
        keep(p, c, w, &s, s.data.clone(), vec![("errors", json!({ field: [m] })), ("_old_input", json!({"name": name_in}))], &mut out)?;
        Ok(out)
    };
    if matches!(w.input.get("name"), Some(Val::Arr(_))) {
        return back("name", "The name field must be a string.");
    }
    if name_in.chars().count() > 255 {
        return back("name", "The name field must not be greater than 255 characters.");
    }
    if let Some((field, m)) = super::challenge::new_password_error(w, "The passwords do not match.", Some("Please confirm your password.")) {
        return back(field, &m);
    }
    let (username, email) = (s_of(&inv, "username"), s_of(&inv, "email"));
    if count(c, r#"select count(*) as aggregate from "users" where "username" = ?"#, &[P(Val::str(&username))])? > 0
        || count(c, r#"select count(*) as aggregate from "users" where "email" = ?"#, &[P(Val::str(&email))])? > 0
    {
        return back("password", "An account already uses this username or email. Contact your administrator.");
    }
    let ts = laravel::ts(w.now);
    let hash = laravel::hash_make(&w.input.string("password")?)?;
    // one transaction: claim first (a double submit cannot make two accounts), then the account and its groups
    let created = super::strategies_tx(c, || {
        let claimed = db::exec(
            c,
            r#"update "invitations" set "accepted_at" = ?, "updated_at" = ? where "invitations"."id" = ? and "accepted_at" is null and "expires_at" > ?"#,
            &[P(Val::str(&ts)), P(Val::str(&ts)), P(inv.val("id")), P(Val::str(&ts))],
        )?;
        if claimed == 0 {
            return Ok(None);
        }
        let name = if name_in.trim().is_empty() { inv.val("name") } else { Val::str(name_in.trim()) };
        let uid = db::insert(
            c,
            "users",
            vec![
                ("username", Val::str(&username)),
                ("name", name),
                ("email", Val::str(&email)),
                ("password", Val::str(&hash)),
                ("is_admin", Val::Bool(inv.val("is_admin").to_bool())),
                ("is_active", Val::Bool(true)),
            ],
            &ts,
        )?;
        let keep_ids = |table: &str, ids: Vec<i64>| -> Result<Vec<i64>, Fault> { Ok(find_in(c, table, &ids)?.iter().map(|r| r.id()).collect()) };
        let ug = keep_ids("user_groups", ids_of(&inv, "user_group_ids"))?;
        let dg = if inv.val("is_admin").to_bool() { vec![] } else { keep_ids("device_groups", ids_of(&inv, "device_group_ids"))? };
        sync_pivot(c, "user_group_user", "user_id", uid, "user_group_id", &ug)?;
        sync_pivot(c, "device_group_user", "user_id", uid, "device_group_id", &dg)?;
        db::exec(c, r#"update "invitations" set "accepted_user_id" = ?, "updated_at" = ? where "invitations"."id" = ?"#, &[P(Val::Int(uid)), P(Val::str(&ts)), P(inv.val("id"))])?;
        Ok(Some(uid))
    })?;
    let Some(uid) = created else { return Ok(Out::new(login::error(410, "This invitation has already been used.", false))) };
    let user = find(c, "users", uid)?.ok_or_else(|| Fault::Other("user vanished".into()))?;
    let mut out = login::complete(p, c, w, &s, &user, false, false)?;
    // the overview, not the intended page
    out.resp = redirect(&format!("{}/", w.root));
    login_log_note(c, user.val("id"), user.val("username"), "web", &w.ip, true, Some("invitation"), w.now)?;
    db::exec(
        c,
        r#"insert into "console_audits" ("user_id", "username", "action", "target_type", "target_id", "summary", "ip", "created_at") values (?, ?, ?, ?, ?, ?, ?, ?)"#,
        &[P(Val::Int(uid)), P(Val::str(&username)), P(Val::str("user.invite-accept")), P(Val::str("user")), P(Val::str(&username)), P(Val::str(&format!("Accepted invitation and created user {username}"))), P(Val::str(&w.ip)), P(Val::str(&ts))],
    )?;
    tracing::info!("invitation accepted");
    Ok(out)
}
