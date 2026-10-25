//! Users (Livewire `UserList` and `UserDetail`): the list with its filters, the add / edit dialog, the device
//! assignment dialog, enable / disable, force logout, reset 2FA and delete; and the read-only person page.
//!
//! State is the URL (`?search=`, `?role=`, `?status=`, `?create=1`, `?edit=<id>`, `?assign=<id>`); every action is a
//! form post that redirects back. A role-holder may only touch plain users and may only hand out what they hold
//! themselves (`guardTarget`, the `grantable*` clamps): the same checks as PHP, applied before any write.

use super::kit::*;
use super::{logs, paginate, time, Ctx, Reply, Req};
use crate::laravel::Cast;
use crate::php::{Fault, Val};
use crate::sqlite::{self as db, Row, P};
use crate::validate::{self, Rule};
use rusqlite::Connection;
use serde_json::{json, Map, Value};

const PER_PAGE: i64 = 20;

#[derive(Clone, Default)]
struct St {
    search: String,
    role: String,
    status: String,
    page: i64,
}

impl St {
    fn from(req: &Req) -> St {
        let pick = |k: &str, ok: &[&str]| {
            let v = q(req, k);
            if ok.contains(&v.as_str()) { v } else { "all".into() }
        };
        St { search: q(req, "search"), role: pick("role", &["admin", "user"]), status: pick("status", &["active", "disabled"]), page: q(req, "page").parse::<i64>().ok().filter(|n| *n >= 1).unwrap_or(1) }
    }

    fn query(&self) -> String {
        let mut pairs: Vec<(&str, Vec<u8>)> = vec![];
        if !self.search.is_empty() {
            pairs.push(("search", self.search.clone().into_bytes()));
        }
        if self.role != "all" {
            pairs.push(("role", self.role.clone().into_bytes()));
        }
        if self.status != "all" {
            pairs.push(("status", self.status.clone().into_bytes()));
        }
        crate::laravel::http_build_query(&pairs.iter().map(|(k, v)| (*k, v.as_slice())).collect::<Vec<_>>())
    }

    fn url(&self) -> String {
        let q = self.query();
        if q.is_empty() { "/users".into() } else { format!("/users?{q}") }
    }

    fn from_back(back: &str) -> St {
        let input = crate::laravel::Input::new("GET", None, Some(back), b"");
        let req = Req { method: "GET".into(), path: "/users".into(), htmx: false, headers: Default::default(), input };
        St::from(&req)
    }
}

fn join(url: &str, extra: &str) -> String {
    if url.contains('?') { format!("{url}&{extra}") } else { format!("{url}?{extra}") }
}

fn flag(ctx: &Ctx, key: &str) -> String {
    ctx.flashed.get(key).and_then(|v| v.as_str()).unwrap_or("").to_string()
}

pub enum Modal {
    None,
    Edit { id: i64, values: Map<String, Value>, errors: Map<String, Value> },
    Assign { id: i64, search: String, picked: Vec<i64> },
}

/// `guardTarget`: a role-holder may only touch plain users, never themselves.
fn guard(ctx: &Ctx, target: &Row) -> bool {
    ctx.is_admin() || !(target.id() == ctx.uid() || target.val("is_admin").to_bool() || !target.is_null("role_id"))
}

fn can_touch(ctx: &Ctx, u: &Row) -> bool {
    ctx.allows("user", "rw") && (ctx.is_admin() || (!u.val("is_admin").to_bool() && u.is_null("role_id") && u.id() != ctx.uid()))
}

pub fn index(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    let st = St::from(req);
    let modal = if q(req, "create") == "1" && ctx.allows("user", "rw") {
        Modal::Edit { id: 0, values: editor_values(ctx, c, None)?, errors: Map::new() }
    } else if let Some(id) = Some(qint(req, "edit")).filter(|i| *i > 0) {
        if !ctx.allows("user", "rw") {
            return Ok(abort(403));
        }
        let Some(u) = find(c, "users", id)? else { return Ok(abort(404)) };
        if !guard(ctx, &u) {
            return Ok(abort(403));
        }
        Modal::Edit { id, values: editor_values(ctx, c, Some(&u))?, errors: Map::new() }
    } else if let Some(id) = Some(qint(req, "assign")).filter(|i| *i > 0) {
        if !ctx.allows("user", "rw") {
            return Ok(abort(403));
        }
        let Some(u) = find(c, "users", id)? else { return Ok(abort(404)) };
        if !guard(ctx, &u) {
            return Ok(abort(403));
        }
        let picked = if q(req, "picked") == "1" {
            let b = Body::of(req);
            b.ints("ids")
        } else {
            let mut w = assignable(ctx, c)?;
            w.add(r#""devices"."user_id" = ?"#, vec![P(Val::Int(id))]);
            db::rows(c, &format!(r#"select "id" from "devices"{} order by "id" asc"#, w.sql()), &w.params)?.iter().map(|r| r.id()).collect()
        };
        Modal::Assign { id, search: q(req, "assign_search"), picked }
    } else {
        Modal::None
    };
    render(ctx, c, &st, 200, modal)
}

fn editor_values(ctx: &Ctx, c: &Connection, u: Option<&Row>) -> Result<Map<String, Value>, Fault> {
    let _ = ctx;
    let mut m = Map::new();
    match u {
        None => {
            for (k, v) in [("username", json!("")), ("name", json!("")), ("email", json!("")), ("password", json!("")), ("user_group_ids", json!([])), ("is_admin", json!(false)), ("role_id", json!(0)), ("is_active", json!(true)), ("device_group_ids", json!([]))] {
                m.insert(k.into(), v);
            }
        }
        Some(u) => {
            m.insert("username".into(), json!(s(u, "username")));
            m.insert("name".into(), json!(s(u, "name")));
            m.insert("email".into(), json!(s(u, "email")));
            m.insert("password".into(), json!(""));
            m.insert("user_group_ids".into(), json!(pivot_ids(c, "user_group_user", "user_id", "user_group_id", u.id())?));
            m.insert("is_admin".into(), json!(u.val("is_admin").to_bool()));
            m.insert("role_id".into(), json!(if u.is_null("role_id") { 0 } else { u.val("role_id").to_int() }));
            m.insert("is_active".into(), json!(u.val("is_active").to_bool()));
            m.insert("device_group_ids".into(), json!(pivot_ids(c, "device_group_user", "user_id", "device_group_id", u.id())?));
        }
    }
    Ok(m)
}

/// `assignableDevices()` as a where clause: an administrator re-owns any device, anyone else only what they can see.
fn assignable(ctx: &Ctx, c: &Connection) -> Result<Where, Fault> {
    if ctx.is_admin() {
        let mut w = Where::default();
        w.add(r#""devices"."deleted_at" is null"#, vec![]);
        Ok(w)
    } else {
        visible(c, &ctx.user, false)
    }
}

fn render(ctx: &Ctx, c: &Connection, st: &St, status: u16, modal: Modal) -> Result<Reply, Fault> {
    let mut w = Where::default();
    if !st.search.is_empty() {
        let like = format!("%{}%", st.search);
        w.add(r#"("username" like ? or "name" like ? or "email" like ?)"#, (0..3).map(|_| P(Val::str(&like))).collect());
    }
    match st.role.as_str() {
        "admin" => w.add(r#""is_admin" = ?"#, vec![P(Val::Bool(true))]),
        "user" => w.add(r#""is_admin" = ?"#, vec![P(Val::Bool(false))]),
        _ => {}
    }
    match st.status.as_str() {
        "active" => w.add(r#""is_active" = ?"#, vec![P(Val::Bool(true))]),
        "disabled" => w.add(r#""is_active" = ?"#, vec![P(Val::Bool(false))]),
        _ => {}
    }
    let total = count(c, &format!(r#"select count(*) as aggregate from "users"{}"#, w.sql()), &w.params)?;
    let rows = db::rows(
        c,
        &format!(
            r#"select "users".*, (select count(*) from "devices" where "users"."id" = "devices"."user_id" and "devices"."deleted_at" is null) as "devices_count" from "users"{} order by "username" asc limit {PER_PAGE} offset {}"#,
            w.sql(),
            (st.page - 1) * PER_PAGE
        ),
        &w.params,
    )?;
    let ids: Vec<i64> = rows.iter().map(|r| r.id()).collect();
    let groups = if ids.is_empty() {
        vec![]
    } else {
        db::rows(
            c,
            &format!(r#"select "user_groups"."name", "user_group_user"."user_id" as "pivot_user_id" from "user_groups" inner join "user_group_user" on "user_groups"."id" = "user_group_user"."user_group_id" where "user_group_user"."user_id" in ({}) order by "user_group_user"."user_id", "user_groups"."id""#, marks(ids.len())),
            &ints_val(&ids),
        )?
    };
    let roles = db::rows(c, r#"select * from "roles" order by "name" asc"#, &[])?;
    let items: Vec<Value> = rows
        .iter()
        .map(|u| {
            let role = if u.is_null("role_id") { None } else { roles.iter().find(|r| r.id() == u.val("role_id").to_int()) };
            let names: Vec<String> = groups.iter().filter(|g| g.val("pivot_user_id").to_int() == u.id()).map(|g| s(g, "name")).collect();
            let username = s(u, "username");
            json!({
                "id": u.id(), "username": username, "initial": username.chars().next().map(|c| c.to_uppercase().collect::<String>()).unwrap_or_default(),
                "name": s(u, "name"), "email": s(u, "email"), "groups": names, "groups_line": names.join(", "),
                "admin": u.val("is_admin").to_bool(), "role": role.map(|r| s(r, "name")), "active": u.val("is_active").to_bool(), "totp": u.val("totp_enabled").to_bool(),
                "devices": u.val("devices_count").to_int(), "devices_word": plural("device", u.val("devices_count").to_int()),
                "created": ymd(u, "created_at").unwrap_or_default(), "created_at": ts_of(u, "created_at").map(crate::laravel::ts).unwrap_or_default(),
                "touch": can_touch(ctx, u), "self": u.id() == ctx.uid(),
            })
        })
        .collect();
    let back = st.query();
    let url = st.url();
    let page = paginate::page(st.page, PER_PAGE, total, rows.len() as i64);
    let layout = ctx.layout(c, "users", "Users", "Manage")?;
    let page_json = json!({
        "st": {"search": st.search, "role": st.role, "status": st.status}, "rows": items, "pager": page, "path": "/users",
        "query": if back.is_empty() { String::new() } else { format!("{back}&") }, "back": back, "url": url, "create_url": join(&url, "create=1"),
        "edit_prefix": join(&url, "edit="), "assign_prefix": join(&url, "assign="),
        "can_manage": ctx.allows("user", "rw"), "super": ctx.is_admin(), "me": ctx.uid(),
        "modal": modal_json(ctx, c, &modal, &roles, &url)?,
        "result": flag(ctx, "users_result"),
    });
    Ok(Reply::Html(status, ctx.render("users/index.html", layout, page_json)?))
}

fn modal_json(ctx: &Ctx, c: &Connection, modal: &Modal, roles: &[Row], url: &str) -> Result<Value, Fault> {
    Ok(match modal {
        Modal::None => json!({"kind": ""}),
        Modal::Edit { id, values, errors } => {
            let mut filled = errors.clone();
            for k in ["username", "name", "email", "password", "role_id", "user_group_ids", "device_group_ids"] {
                filled.entry(k.to_string()).or_insert(Value::Null);
            }
            let ug: Vec<Value> = grantable_user_groups(ctx, c)?.iter().map(|g| json!({"id": g.id(), "name": s(g, "name")})).collect();
            let dg: Vec<Value> = grantable_device_groups(ctx, c)?.iter().map(|g| json!({"id": g.id(), "name": s(g, "name")})).collect();
            json!({
                "kind": "edit", "id": id, "editing": *id != 0, "title": if *id == 0 { "Add User" } else { "Edit User" }, "values": values, "errors": filled,
                "user_groups": ug, "device_groups": dg, "roles": roles.iter().map(|r| json!({"id": r.id(), "name": s(r, "name")})).collect::<Vec<_>>(),
                "self": *id == ctx.uid(), "return": url,
            })
        }
        Modal::Assign { id, search, picked } => {
            let target = find(c, "users", *id)?;
            let mut w = assignable(ctx, c)?;
            if !search.is_empty() {
                let like = format!("%{search}%");
                w.add(r#"("rustdesk_id" like ? or "alias" like ? or "hostname" like ?)"#, (0..3).map(|_| P(Val::str(&like))).collect());
            }
            let devices = db::rows(c, &format!(r#"select "id", "rustdesk_id", "alias", "hostname", "user_id" from "devices"{} order by "rustdesk_id" asc limit 200"#, w.sql()), &w.params)?;
            let owners = find_in(c, "users", &devices.iter().filter(|d| !d.is_null("user_id")).map(|d| d.val("user_id").to_int()).collect::<Vec<_>>())?;
            json!({
                "kind": "assign", "id": id, "username": target.map(|t| s(&t, "username")).unwrap_or_default(), "search": search, "return": url,
                "count": picked.len(), "capped": devices.len() >= 200,
                "devices": devices.iter().map(|d| {
                    let alias = s(d, "alias");
                    let label = if truthy(&alias) { alias.clone() } else { s(d, "hostname") };
                    let other = !d.is_null("user_id") && d.val("user_id").to_int() != *id;
                    json!({"id": d.id(), "rustdesk_id": s(d, "rustdesk_id"), "label": label, "checked": picked.contains(&d.id()),
                           "owned_by": if other { Some(by_id(&owners, &d.val("user_id")).map(|o| s(o, "username")).unwrap_or_else(|| "—".into())) } else { None }})
                }).collect::<Vec<_>>(),
            })
        }
    })
}

// ---------------------------------------------------------------------------------------------------- writes ---

fn back_to(body: &Body) -> Reply {
    Reply::Redirect(St::from_back(&body.get("back")).url())
}

/// `POST /users/save`: the Add / Edit dialog.
pub fn save(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    if !ctx.allows("user", "rw") {
        return Ok(abort(403));
    }
    let body = Body::of(req);
    let id = body.int("id");
    let ret = body.get("return");
    let editing = if id != 0 { find(c, "users", id)? } else { None };
    if id != 0 && editing.is_none() {
        return Ok(abort(404));
    }
    let username = body.get("username");
    let name = body.get("name");
    let email = body.get("email");
    let password = body.get("password");
    let mut user_group_ids = body.ints("user_group_ids");
    let mut device_group_ids = body.ints("device_group_ids");
    let is_admin = body.checked("is_admin");
    let role_id = body.get("role_id");
    let is_active = if id != 0 && id == ctx.uid() { body.checked("is_active") || editing.as_ref().map_or(false, |u| u.val("is_active").to_bool()) } else { body.checked("is_active") };

    let mut data = crate::php::Arr::new();
    let mut set = |k: &str, v: Val| data.set(crate::php::Key::Str(k.as_bytes().to_vec()), v);
    set("username", Val::str(&username));
    set("name", Val::str(&name));
    set("email", Val::str(&email));
    set("user_group_ids", int_array(&user_group_ids));
    set("is_admin", Val::Bool(is_admin));
    set("role_id", if role_id.is_empty() || role_id == "0" { Val::Null } else { Val::str(&role_id) });
    set("is_active", Val::Bool(is_active));
    set("password", Val::str(&password));
    set("device_group_ids", int_array(&device_group_ids));
    let rules: [(&str, &[Rule]); 11] = [
        ("username", &[Rule::Required, Rule::String, Rule::Max(255), Rule::Unique("users", "username", editing.as_ref().map(|u| u.id()))]),
        ("name", &[Rule::Nullable, Rule::String, Rule::Max(255)]),
        ("email", &[Rule::Nullable, Rule::Email, Rule::Max(255), Rule::Unique("users", "email", editing.as_ref().map(|u| u.id()))]),
        ("user_group_ids", &[Rule::Array]),
        ("user_group_ids.*", &[Rule::Exists("user_groups", "id")]),
        ("is_admin", &[Rule::Boolean]),
        ("role_id", &[Rule::Nullable, Rule::Integer, Rule::Exists("roles", "id")]),
        ("is_active", &[Rule::Boolean]),
        ("password", if editing.is_some() { &[Rule::Nullable, Rule::String, Rule::Min(8)] } else { &[Rule::Required, Rule::String, Rule::Min(8)] }),
        ("device_group_ids", &[Rule::Array]),
        ("device_group_ids.*", &[Rule::Exists("device_groups", "id")]),
    ];
    let probe_fn = |rule: &Rule, v: &Val| probe(c, rule, v);
    if let Err(b) = validate::validate_db(&data, &rules, &probe_fn)? {
        let errors = first_messages(&b);
        let mut values = Map::new();
        for (k, v) in [
            ("username", json!(username)), ("name", json!(name)), ("email", json!(email)), ("password", json!("")), ("user_group_ids", json!(user_group_ids)),
            ("is_admin", json!(is_admin)), ("role_id", json!(role_id.parse::<i64>().unwrap_or(0))), ("is_active", json!(is_active)), ("device_group_ids", json!(device_group_ids)),
        ] {
            values.insert(k.into(), v);
        }
        let st = St::from_back(ret.strip_prefix("/users?").unwrap_or(""));
        return render(ctx, c, &st, 422, Modal::Edit { id, values, errors });
    }

    // ---- privilege-escalation guards for a delegated user-manager: the authority, not the form
    let mut role_set = !role_id.is_empty() && role_id != "0";
    let mut is_admin = is_admin;
    let mut role_value: Option<i64> = if role_set { role_id.parse().ok() } else { None };
    if !ctx.is_admin() {
        is_admin = false;
        role_set = false;
        let (mut existing_dg, mut existing_ug) = (vec![], vec![]);
        if let Some(t) = &editing {
            if !guard(ctx, t) {
                return Ok(abort(403));
            }
            existing_dg = pivot_ids(c, "device_group_user", "user_id", "device_group_id", t.id())?;
            existing_ug = user_group_ids_of(c, t.id())?;
        }
        let merge = |allowed: Vec<i64>, existing: &[i64], reachable: &[i64]| -> Vec<i64> {
            let mut out = allowed;
            for e in existing {
                if !reachable.contains(e) && !out.contains(e) {
                    out.push(*e);
                }
            }
            out
        };
        let g_new = grantable_device_group_ids(ctx, c, &device_group_ids)?;
        let g_reach = grantable_device_group_ids(ctx, c, &existing_dg)?;
        device_group_ids = merge(g_new, &existing_dg, &g_reach);
        let u_new = grantable_user_group_ids(ctx, c, &user_group_ids)?;
        let u_reach = grantable_user_group_ids(ctx, c, &existing_ug)?;
        user_group_ids = merge(u_new, &existing_ug, &u_reach);
    } else {
        let dedupe = |l: &mut Vec<i64>| { let mut seen = vec![]; l.retain(|i| { if seen.contains(i) { false } else { seen.push(*i); true } }); };
        dedupe(&mut device_group_ids);
        dedupe(&mut user_group_ids);
    }
    if is_admin {
        role_set = false;
        role_value = None;
    }
    let now_s = crate::laravel::ts(ctx.now);
    let email_v = if email.is_empty() { Val::Null } else { Val::str(&email) };
    let mut previous_role: Option<i64> = None;
    let user_id;
    let user_row;
    if let Some(mut u) = editing {
        previous_role = if u.is_null("role_id") { None } else { Some(u.val("role_id").to_int()) };
        let mut changes: Vec<(&str, Val, Cast)> = vec![
            ("username", Val::str(&username), Cast::Plain),
            ("name", Val::str(&name), Cast::Plain),
            ("email", email_v, Cast::Plain),
            ("is_admin", Val::Bool(is_admin), Cast::Bool),
        ];
        // role_id is in the payload for a super-admin (null when an administrator), and absent for a delegate
        if ctx.is_admin() {
            changes.push(("role_id", if is_admin { Val::Null } else { role_value.map_or(Val::Null, Val::Int) }, Cast::Plain));
        } else if is_admin {
            changes.push(("role_id", Val::Null, Cast::Plain));
        }
        changes.push(("is_active", Val::Bool(is_active), Cast::Bool));
        if !password.is_empty() {
            changes.push(("password", Val::str(&crate::laravel::hash_make(password.as_bytes())?), Cast::Plain));
        }
        update(c, "users", &mut u, changes, ctx.now)?;
        user_id = u.id();
        user_row = u;
    } else {
        let mut cols: Vec<(&str, Val)> = vec![("username", Val::str(&username)), ("name", Val::str(&name)), ("email", email_v), ("is_admin", Val::Bool(is_admin))];
        if ctx.is_admin() {
            cols.push(("role_id", if is_admin { Val::Null } else { role_value.map_or(Val::Null, Val::Int) }));
        }
        cols.push(("is_active", Val::Bool(is_active)));
        cols.push(("password", Val::str(&crate::laravel::hash_make(password.as_bytes())?)));
        let _ = role_set;
        user_id = db::insert(c, "users", cols, &now_s)?;
        user_row = find(c, "users", user_id)?.ok_or_else(|| Fault::Other("inserted user vanished".into()))?;
    }
    sync_pivot(c, "device_group_user", "user_id", user_id, "device_group_id", &if is_admin { vec![] } else { device_group_ids })?;
    sync_pivot(c, "user_group_user", "user_id", user_id, "user_group_id", &user_group_ids)?;
    let now_role = if user_row.is_null("role_id") { None } else { Some(user_row.val("role_id").to_int()) };
    let mut note = String::new();
    if previous_role != now_role {
        let n = match now_role {
            Some(r) => find(c, "roles", r)?.map(|r| s(&r, "name")).unwrap_or_default(),
            None => "standard user".to_string(),
        };
        note = format!(" (role: {n})");
    }
    let uname = s(&user_row, "username");
    audit(ctx, c, if id != 0 { "user.update" } else { "user.create" }, &format!("{} user {uname}{note}", if id != 0 { "Updated" } else { "Created" }), Some("user"), Some(&uname))?;
    Ok(Reply::Redirect(if ret.starts_with("/users") { ret } else { "/users".into() }))
}

fn user_group_ids_of(c: &Connection, id: i64) -> Result<Vec<i64>, Fault> {
    pivot_ids(c, "user_group_user", "user_id", "user_group_id", id)
}

/// `POST /users/act`: enable / disable, force logout, reset 2FA, delete.
pub fn act(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    if !ctx.allows("user", "rw") {
        return Ok(abort(403));
    }
    let body = Body::of(req);
    let id = body.int("id");
    let back = back_to(&body);
    let Some(mut user) = find(c, "users", id)? else { return Ok(abort(404)) };
    let name = s(&user, "username");
    match body.get("do").as_str() {
        "toggle" => {
            if id == ctx.uid() {
                return Ok(back);
            }
            if !guard(ctx, &user) {
                return Ok(abort(403));
            }
            let active = !user.val("is_active").to_bool();
            update(c, "users", &mut user, vec![("is_active", Val::Bool(active), Cast::Bool)], ctx.now)?;
            if !active {
                revoke_all_access(c, &mut user, ctx.now)?;
            }
            audit(ctx, c, if active { "user.enable" } else { "user.disable" }, &format!("{} user {name}", if active { "Enabled" } else { "Disabled" }), Some("user"), Some(&name))?;
        }
        "logout" => {
            if id == ctx.uid() {
                return Ok(back);
            }
            if !guard(ctx, &user) {
                return Ok(abort(403));
            }
            revoke_all_access(c, &mut user, ctx.now)?;
            audit(ctx, c, "user.force-logout", &format!("Forced logout of {name}"), Some("user"), Some(&name))?;
        }
        "reset2fa" => {
            if !guard(ctx, &user) {
                return Ok(abort(403));
            }
            let codes = count(c, r#"select count(*) as aggregate from "two_factor_recovery_codes" where "user_id" = ?"#, &[P(Val::Int(id))])?;
            if !user.val("totp_enabled").to_bool() && codes == 0 && user.is_null("totp_secret") {
                return Ok(back);
            }
            db::exec(c, r#"delete from "two_factor_recovery_codes" where "two_factor_recovery_codes"."user_id" = ? and "two_factor_recovery_codes"."user_id" is not null"#, &[P(Val::Int(id))])?;
            update(
                c,
                "users",
                &mut user,
                vec![("totp_secret", Val::Null, Cast::Plain), ("totp_enabled", Val::Bool(false), Cast::Bool), ("totp_confirmed_at", Val::Null, Cast::Date), ("totp_last_timestep", Val::Null, Cast::Plain)],
                ctx.now,
            )?;
            audit(ctx, c, "user.2fa-reset", &format!("Reset two-factor authentication for {name}"), Some("user"), Some(&name))?;
        }
        "delete" => {
            if id == ctx.uid() {
                return Ok(back);
            }
            if !guard(ctx, &user) {
                return Ok(abort(403));
            }
            let ts = crate::laravel::ts(ctx.now);
            db::exec(c, r#"update "devices" set "user_id" = ?, "updated_at" = ? where "devices"."user_id" = ? and "devices"."deleted_at" is null"#, &[P(Val::Null), P(Val::str(&ts)), P(Val::Int(id))])?;
            for b in db::rows(c, r#"select * from "address_books" where "owner_user_id" = ? and "is_personal" = ?"#, &[P(Val::Int(id)), P(Val::Bool(true))])? {
                delete_book_rows(c, b.id())?;
            }
            db::exec(c, r#"delete from "users" where "id" = ?"#, &[P(Val::Int(id))])?;
            recompute_all(c, ctx.now)?;
            audit(ctx, c, "user.delete", &format!("Deleted user {name}"), Some("user"), Some(&name))?;
        }
        _ => {}
    }
    Ok(back)
}

/// `POST /users/assign`: the Assign Devices dialog's Save.
pub fn assign(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    if !ctx.allows("user", "rw") {
        return Ok(abort(403));
    }
    let body = Body::of(req);
    let id = body.int("id");
    let Some(user) = find(c, "users", id)? else { return Ok(abort(404)) };
    if !guard(ctx, &user) {
        return Ok(abort(403));
    }
    let posted = body.ints("ids");
    let mut w = assignable(ctx, c)?;
    w.in_ints(r#""devices"."id""#, &posted);
    let ids: Vec<i64> = db::rows(c, &format!(r#"select "id" from "devices"{} order by "id" asc"#, w.sql()), &w.params)?.iter().map(|r| r.id()).collect();
    let ts = crate::laravel::ts(ctx.now);
    if !ids.is_empty() {
        let mut params = vec![P(Val::Int(id)), P(Val::str(&ts))];
        params.extend(ints_val(&ids));
        db::exec(c, &format!(r#"update "devices" set "user_id" = ?, "updated_at" = ? where "id" in ({}) and "devices"."deleted_at" is null"#, marks(ids.len())), &params)?;
    }
    let mut r = assignable(ctx, c)?;
    r.add(r#""devices"."user_id" = ?"#, vec![P(Val::Int(id))]);
    let keep: Vec<i64> = if ids.is_empty() { vec![0] } else { ids.clone() };
    r.add(&format!(r#""devices"."id" not in ({})"#, marks(keep.len())), ints_val(&keep));
    let mut params = vec![P(Val::Null), P(Val::str(&ts))];
    params.extend(r.params.clone());
    db::exec(c, &format!(r#"update "devices" set "user_id" = ?, "updated_at" = ?{}"#, r.sql()), &params)?;
    recompute_all(c, ctx.now)?;
    let uname = s(&user, "username");
    audit(ctx, c, "user.assign-devices", &format!("Assigned {} device(s) to {uname}", ids.len()), Some("user"), Some(&uname))?;
    Ok(back_to(&body))
}

// ----------------------------------------------------------------------------------------------- user page ---

const RECENT: i64 = 25;

fn conn_item(r: &Row, now: i64, incoming: bool) -> Value {
    let t = r.val("conn_type").to_int();
    let created = ts_of(r, "created_at");
    let closed = ts_of(r, "closed_at");
    let from = { let a = s(r, "from_name"); if truthy(&a) { a } else { let b = s(r, "from_peer"); if truthy(&b) { b } else { "unknown".into() } } };
    let from = if incoming { from } else { s(r, "from_peer") };
    json!({
        "icon": logs::conn_icon(t), "label": logs::conn_label(t), "from": from, "to": s(r, "rustdesk_id"),
        "ago": created.map(|t| time::ago(t, now, false)).unwrap_or_default(),
        "duration": match (closed, created) { (Some(a), Some(b)) => Some(time::short_full(a, b)), _ => None },
    })
}

/// `GET /users/:id`
pub fn show(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    let id = path_id(&req.path, 1);
    let Some(user) = find(c, "users", id)? else { return Ok(abort(404)) };
    let now = ctx.now;
    let window = online_window(c)?;
    let (can_devices, can_conn, can_sign, can_books) = (ctx.allows("device", "r"), ctx.allows("audit", "r"), ctx.allows("audit", "rw"), ctx.allows("address_book", "r"));
    let role = if user.is_null("role_id") { None } else { find(c, "roles", user.val("role_id").to_int())? };
    let groups: Vec<String> = db::rows(c, r#"select "user_groups"."name" from "user_groups" inner join "user_group_user" on "user_groups"."id" = "user_group_user"."user_group_id" where "user_group_user"."user_id" = ? order by "user_groups"."id""#, &[P(Val::Int(id))])?.iter().map(|g| s(g, "name")).collect();

    let mut owned = visible(c, &ctx.user, false)?;
    owned.add(r#""devices"."user_id" = ?"#, vec![P(Val::Int(id))]);
    let device_count = if can_devices { count(c, &format!(r#"select count(*) as aggregate from "devices"{}"#, owned.sql()), &owned.params)? } else { 0 };
    let devices: Vec<Row> = if can_devices { db::rows(c, &format!(r#"select * from "devices"{} order by "rustdesk_id" asc limit {RECENT}"#, owned.sql()), &owned.params)? } else { vec![] };
    let device_items: Vec<Value> = devices
        .iter()
        .map(|d| {
            let name = { let a = s(d, "alias"); if truthy(&a) { a } else { let h = s(d, "hostname"); if truthy(&h) { h } else { s(d, "rustdesk_id") } } };
            json!({"id": d.id(), "name": name, "rustdesk_id": s(d, "rustdesk_id"), "platform": platform_ui(&crate::duplicates::platform(&d.val("os"))), "online": is_online(d, now, window),
                   "last_seen": human(d, "last_online_at", now, false).unwrap_or_else(|| "never".into())})
        })
        .collect();

    let last_sign_in = if can_sign {
        db::first(c, r#"select * from "login_logs" where "user_id" = ? and "successful" = ? order by "created_at" desc, "id" desc limit 1"#, &[P(Val::Int(id)), P(Val::Bool(true))])?
    } else {
        None
    };
    let sign_ins: Vec<Value> = if can_sign {
        db::rows(
            c,
            &format!(r#"select * from "login_logs" where ("user_id" = ? or ("user_id" is null and "username" = ?)) order by "created_at" desc, "id" desc limit {RECENT}"#),
            &[P(Val::Int(id)), P(Val::str(&s(&user, "username")))],
        )?
        .iter()
        .map(|l| {
            let client = s(l, "client");
            let label = if client == "web" { "Console".to_string() } else if client == "sso" { "Console (SSO)".to_string() } else { format!("RustDesk {client}{}", { let d = s(l, "device_id"); if truthy(&d) { format!(" · {d}") } else { String::new() } }) };
            let ip = { let i = s(l, "ip"); if truthy(&i) { i } else { "—".to_string() } };
            json!({"label": label, "ip": ip, "when": ts_of(l, "created_at").map(crate::laravel::ts).unwrap_or_default(),
                   "ago": human(l, "created_at", now, false).unwrap_or_default(), "ok": l.val("successful").to_bool()})
        })
        .collect()
    } else {
        vec![]
    };
    let actions: Vec<Value> = if can_sign {
        db::rows(c, &format!(r#"select * from "console_audits" where "user_id" = ? order by "created_at" desc, "id" desc limit {RECENT}"#), &[P(Val::Int(id))])?
            .iter()
            .map(|a| json!({"action": s(a, "action"), "summary": s(a, "summary"), "when": ts_of(a, "created_at").map(crate::laravel::ts).unwrap_or_default(), "ago": human(a, "created_at", now, false).unwrap_or_default()}))
            .collect()
    } else {
        vec![]
    };

    // devices this person has signed in on with the RustDesk client
    let client_ids: Vec<String> = if can_conn {
        let mut ids: Vec<String> = db::rows(c, r#"select "device_id" from "login_logs" where "user_id" = ? and "successful" = ? and "device_id" is not null and "device_id" != '' order by "created_at" desc limit 200"#, &[P(Val::Int(id)), P(Val::Bool(true))])?.iter().map(|r| s(r, "device_id")).collect();
        for r in db::rows(c, r#"select "device_id" from "client_tokens" where "user_id" = ? and "device_id" is not null and "device_id" != '' order by "id" asc"#, &[P(Val::Int(id))])? {
            ids.push(s(&r, "device_id"));
        }
        let mut seen: Vec<String> = vec![];
        ids.retain(|i| { if seen.contains(i) { false } else { seen.push(i.clone()); true } });
        ids.truncate(50);
        ids
    } else {
        vec![]
    };
    let incoming: Vec<Value> = if can_conn && can_devices {
        let rids: Vec<String> = db::rows(c, &format!(r#"select "rustdesk_id" from "devices"{} order by "devices"."id" asc"#, owned.sql()), &owned.params)?.iter().map(|d| s(d, "rustdesk_id")).collect();
        if rids.is_empty() {
            vec![]
        } else {
            let params: Vec<P> = rids.iter().map(|r| P(Val::str(r))).collect();
            db::rows(c, &format!(r#"select * from "audit_connections" where "rustdesk_id" in ({}) order by "created_at" desc, "id" desc limit {RECENT}"#, marks(rids.len())), &params)?.iter().map(|r| conn_item(r, now, true)).collect()
        }
    } else {
        vec![]
    };
    let outgoing: Vec<Value> = if can_conn && !client_ids.is_empty() {
        let mut sql = format!(r#"select * from "audit_connections" where "from_peer" in ({})"#, marks(client_ids.len()));
        let mut params: Vec<P> = client_ids.iter().map(|r| P(Val::str(r))).collect();
        if !ctx.is_admin() {
            let w = visible(c, &ctx.user, false)?;
            sql.push_str(&format!(r#" and "rustdesk_id" in (select "rustdesk_id" from "devices"{})"#, w.sql()));
            params.extend(w.params);
        }
        sql.push_str(&format!(r#" order by "created_at" desc, "id" desc limit {RECENT}"#));
        db::rows(c, &sql, &params)?.iter().map(|r| conn_item(r, now, false)).collect()
    } else {
        vec![]
    };

    let books: Vec<Value> = if can_books {
        let vgroups: Vec<i64> = if ctx.is_admin() { vec![] } else { user_group_ids(c, ctx.uid())? };
        let mut out = vec![];
        for b in db::rows(c, r#"select "address_books".*, (select count(*) from "address_book_entries" where "address_books"."id" = "address_book_entries"."address_book_id") as "entries_count" from "address_books" where "owner_user_id" = ? order by "is_personal" desc, "name" asc"#, &[P(Val::Int(id))])? {
            let n = b.val("entries_count").to_int();
            out.push(json!({"id": b.id(), "name": s(&b, "name"), "personal": b.val("is_personal").to_bool(), "entries": n, "word": plural("entry", n), "open": book_permission(c, &ctx.user, &b, Some(&vgroups))? > 0}));
        }
        out
    } else {
        vec![]
    };

    let sso = if user.val("oidc_status").to_php_string().ok().as_deref() == Some(b"pending") {
        "pending"
    } else if s(&user, "auth_provider") == "oidc" {
        "provisioned"
    } else if truthy(&s(&user, "oidc_sub")) {
        "linked"
    } else {
        "password"
    };
    let username = s(&user, "username");
    let layout = ctx.layout(c, "users", "User", "Manage")?;
    let page = json!({
        "u": {
            "id": id, "username": username, "initial": username.chars().next().map(|c| c.to_uppercase().collect::<String>()).unwrap_or_default(), "display": display_name(&user), "name": s(&user, "name"), "email": s(&user, "email"),
            "admin": user.val("is_admin").to_bool(), "role": role.as_ref().map(|r| s(r, "name")), "active": user.val("is_active").to_bool(), "totp": user.val("totp_enabled").to_bool(), "sso": sso,
            "created": ymd(&user, "created_at").unwrap_or_else(|| "—".into()), "created_at": ts_of(&user, "created_at").map(crate::laravel::ts).unwrap_or_default(), "groups": groups,
        },
        "can_devices": can_devices, "can_conn": can_conn, "can_sign": can_sign, "can_books": can_books, "is_admin": ctx.is_admin(),
        "last_sign_in": last_sign_in.as_ref().map(|l| json!({"when": ts_of(l, "created_at").map(crate::laravel::ts).unwrap_or_default(), "ago": human(l, "created_at", now, false).unwrap_or_default()})),
        "device_count": device_count, "devices": device_items, "more_devices": device_count > devices.len() as i64,
        "books": books, "sign_ins": sign_ins, "actions": actions, "incoming": incoming, "outgoing": outgoing, "no_client": client_ids.is_empty(),
        "urlencoded_username": crate::laravel::urlencode(username.as_bytes()),
    });
    Ok(Reply::Html(200, ctx.render("users/detail.html", layout, page)?))
}
