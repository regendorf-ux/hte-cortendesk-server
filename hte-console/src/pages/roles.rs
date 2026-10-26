//! Roles (the previous console's `RoleList`, v1.15.0-hte.1): named permission matrices over the console areas, assigned to people from
//! the Users editor. Super-admin only, at the route (`admin` middleware: a redirect to the overview with the flash) and in
//! every write (the previous console's `abort_unless(is_admin, 403)`), because a delegated admin who could edit roles could grant
//! themselves anything.
//!
//! What a role grants is read by `Ctx::allows` (every page) and `admin.rs` (the API token clamp); both read the same
//! `roles.permissions` JSON this page writes, with unknown or missing areas as "none" (`Role::levelFor`).
//!
//! State is the URL (`?create=1`, `?edit=<id>`); the dialog's save and the delete are form posts.

use super::kit::*;
use super::{Ctx, Reply, Req};
use crate::laravel::Cast;
use crate::php::{self, Fault, Key, Val};
use crate::sqlite::{self as db, Row, P};
use crate::validate::{self, Rule};
use rusqlite::Connection;
use serde_json::{json, Map, Value};

/// `Permissions::LEVELS`
pub const LEVELS: [&str; 3] = ["none", "r", "rw"];

/// `Permissions::CONSOLE_RESOURCES`, `RESOURCE_LABELS`, `RESOURCE_HINTS`
pub const RESOURCES: [(&str, &str, &str); 8] = [
    ("device", "Devices", "View grants the Devices screen; Manage adds edit, approve, delete and restore. Which devices are listed is still decided by device-group access, never by the role."),
    ("user", "Users", "Manage covers creating, editing, disabling and deleting users, and inviting new ones. Only a full administrator can grant administrator or assign roles."),
    ("group", "Groups", "Covers both device groups and user groups, matching the API token matrix."),
    ("address_book", "Address books", "View grants the Address Books screen; Manage adds books, tags, entries and sharing rules. Per-book sharing rules still apply on top."),
    ("audit", "Logs", "View grants Connections, File Transfers and Alarms. Manage also grants Login history and the Console audit trail."),
    ("strategy", "Strategies", "Client strategies pushed to devices over the heartbeat."),
    ("setting", "Settings", "Server settings, SSO, SMTP, retention and the sidebar version banner."),
    ("token", "API tokens", "Tokens for the automation REST API. A new token can never be granted more than its creator already has."),
];

fn level_label(l: &str) -> &'static str {
    match l {
        "r" => "View",
        "rw" => "Manage",
        _ => "None",
    }
}

/// `Role::normalizePermissions`: every area, missing or unknown => "none", unknown keys dropped, in the areas' order.
pub fn normalize(perms: &Value) -> Vec<(&'static str, String)> {
    RESOURCES
        .iter()
        .map(|(k, _, _)| {
            let l = match perms.get(*k) {
                Some(Value::String(s)) if LEVELS.contains(&s.as_str()) => s.clone(),
                _ => "none".to_string(),
            };
            (*k, l)
        })
        .collect()
}

fn stored_perms(r: &Row) -> Value {
    r.val("permissions").to_php_string().ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(Value::Null)
}

/// `Permissions::LEGACY_USER`, normalised: where a new role starts.
fn baseline() -> Vec<(&'static str, String)> {
    RESOURCES.iter().map(|(k, _, _)| (*k, super::legacy_level(k).to_string())).collect()
}

/// The matrix as the `permissions` column holds it: `json_encode` of the normalised array (Eloquent's `array` cast).
fn encode(perms: &[(&str, String)]) -> String {
    php::json_encode(&php::assoc(perms.iter().map(|(k, v)| (k.to_string(), Val::str(v))))).unwrap_or_else(|| "{}".into())
}

/// `RoleList::summarize`: "device:rw, audit:r" or "no permissions".
fn summarize(perms: &[(&str, String)]) -> String {
    let granted: Vec<String> = perms.iter().filter(|(_, l)| l != "none").map(|(k, l)| format!("{k}:{l}")).collect();
    if granted.is_empty() { "no permissions".into() } else { granted.join(", ") }
}

enum Modal {
    None,
    Edit { id: i64, name: String, description: String, require_two_factor: bool, perms: Vec<(&'static str, String)>, errors: Map<String, Value> },
}

/// `GET /roles`
pub fn index(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    if !ctx.is_admin() {
        // EnsureAdmin
        ctx.flash("denied", json!("That section is restricted to administrators."));
        return Ok(Reply::Redirect("/".into()));
    }
    let modal = if q(req, "create") == "1" {
        Modal::Edit { id: 0, name: String::new(), description: String::new(), require_two_factor: false, perms: baseline(), errors: Map::new() }
    } else if qint(req, "edit") > 0 {
        let Some(r) = find(c, "roles", qint(req, "edit"))? else { return Ok(abort(404)) };
        Modal::Edit {
            id: r.id(),
            name: s(&r, "name"),
            description: s(&r, "description"),
            require_two_factor: r.val("require_two_factor").to_bool(),
            perms: normalize(&stored_perms(&r)),
            errors: Map::new(),
        }
    } else {
        Modal::None
    };
    render(ctx, c, 200, modal)
}

fn render(ctx: &Ctx, c: &Connection, status: u16, modal: Modal) -> Result<Reply, Fault> {
    let roles = db::rows(
        c,
        r#"select "roles".*, (select count(*) from "users" where "roles"."id" = "users"."role_id") as "users_count" from "roles" order by "name" asc"#,
        &[],
    )?;
    let rows: Vec<Value> = roles
        .iter()
        .map(|r| {
            let perms = normalize(&stored_perms(r));
            let granted: Vec<Value> = perms
                .iter()
                .filter(|(_, l)| l != "none")
                .map(|(k, l)| {
                    let label = RESOURCES.iter().find(|x| x.0 == *k).map_or(*k, |x| x.1);
                    json!({"label": label, "level": level_label(l), "manage": l == "rw"})
                })
                .collect();
            let n = r.val("users_count").to_int();
            json!({"id": r.id(), "name": s(r, "name"), "description": s(r, "description"), "granted": granted, "two_factor": r.val("require_two_factor").to_bool(), "users": n, "users_word": plural("user", n)})
        })
        .collect();
    let modal_v = match &modal {
        Modal::None => json!({"kind": ""}),
        Modal::Edit { id, name, description, require_two_factor, perms, errors } => {
            let mut filled = errors.clone();
            for k in ["name", "description", "permissions"] {
                filled.entry(k.to_string()).or_insert(Value::Null);
            }
            let areas: Vec<Value> = RESOURCES
                .iter()
                .map(|(k, label, hint)| {
                    let have = perms.iter().find(|p| p.0 == *k).map(|p| p.1.clone()).unwrap_or_else(|| "none".into());
                    json!({"key": k, "label": label, "hint": hint, "level": have})
                })
                .collect();
            json!({"kind": "edit", "id": id, "editing": *id != 0, "name": name, "description": description, "require_two_factor": require_two_factor, "areas": areas, "errors": filled})
        }
    };
    let levels: Vec<Value> = LEVELS.iter().map(|l| json!({"key": l, "label": level_label(l)})).collect();
    let layout = ctx.layout(c, "roles", "Roles", "Manage")?;
    let page = json!({"rows": rows, "levels": levels, "modal": modal_v});
    Ok(Reply::Html(status, ctx.render("roles/index.html", layout, page)?))
}

/// The posted matrix: `permissions[<area>]` for every area the form sends (anything else is ignored by `normalize`).
fn posted_perms(b: &Body) -> (Value, Val) {
    let mut m = Map::new();
    let mut arr = php::Arr::new();
    if let Some(Val::Arr(a)) = b.a.get_str("permissions") {
        for (k, v) in a.iter() {
            let key = String::from_utf8_lossy(&k.as_bytes()).into_owned();
            let text = match v {
                Val::Str(s) => Some(String::from_utf8_lossy(s).into_owned()),
                Val::Int(i) => Some(i.to_string()),
                _ => None,
            };
            if let Some(t) = &text {
                m.insert(key.clone(), json!(t));
            }
            arr.set(Key::from_bytes(key.as_bytes()), v.clone());
        }
    }
    (Value::Object(m), Val::Arr(arr))
}

/// `POST /roles/save`: `RoleList::save` (create when `id` is 0).
pub fn save(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    if !ctx.is_admin() {
        return Ok(abort(403));
    }
    let b = Body::of(req);
    let id = b.int("id");
    let editing = if id != 0 {
        match find(c, "roles", id)? {
            Some(r) => Some(r),
            None => return Ok(abort(404)),
        }
    } else {
        None
    };
    let name = b.get("name");
    let description = b.get("description");
    let require_two_factor = b.checked("require_two_factor");
    let (perms_json, perms_val) = posted_perms(&b);

    let mut data = php::Arr::new();
    data.set(Key::from_bytes(b"name"), Val::str(&name));
    data.set(Key::from_bytes(b"description"), Val::str(&description));
    data.set(Key::from_bytes(b"require_two_factor"), Val::Bool(require_two_factor));
    data.set(Key::from_bytes(b"permissions"), perms_val);
    let unique = Rule::Unique("roles", "name", editing.as_ref().map(|r| r.id()));
    let name_rules = [Rule::Required, Rule::String, Rule::Max(255), unique];
    let rules: [(&str, &[Rule]); 5] = [
        ("name", &name_rules),
        ("description", &[Rule::Nullable, Rule::String, Rule::Max(255)]),
        ("require_two_factor", &[Rule::Boolean]),
        ("permissions", &[Rule::Array]),
        ("permissions.*", &[Rule::In(&LEVELS)]),
    ];
    let probe_fn = |rule: &Rule, v: &Val| probe(c, rule, v);
    if let Err(body) = validate::validate_db(&data, &rules, &probe_fn)? {
        let all = first_messages(&body);
        let mut errors = Map::new();
        for (k, v) in all {
            // `@error('permissions.*')` shows the first message of any area
            let key = if k.starts_with("permissions.") { "permissions".to_string() } else { k };
            errors.entry(key).or_insert(v);
        }
        // the dialog shows what was typed; an invalid level shows as no choice, as the previous console's radio would
        let perms: Vec<(&'static str, String)> = RESOURCES.iter().map(|(k, _, _)| (*k, perms_json.get(*k).and_then(|v| v.as_str()).unwrap_or("").to_string())).collect();
        return render(ctx, c, 422, Modal::Edit { id, name, description, require_two_factor, perms, errors });
    }

    let perms = normalize(&perms_json);
    let encoded = encode(&perms);
    let desc = if description.is_empty() { Val::Null } else { Val::str(&description) };
    super::strategies_tx(c, || {
        if let Some(mut r) = editing.clone() {
            update(
                c,
                "roles",
                &mut r,
                vec![("name", Val::str(&name), Cast::Plain), ("description", desc.clone(), Cast::Plain), ("require_two_factor", Val::Bool(require_two_factor), Cast::Bool), ("permissions", Val::str(&encoded), Cast::Json)],
                ctx.now,
            )?;
        } else {
            db::insert(
                c,
                "roles",
                vec![("name", Val::str(&name)), ("description", desc.clone()), ("require_two_factor", Val::Bool(require_two_factor)), ("permissions", Val::str(&encoded))],
                &crate::laravel::ts(ctx.now),
            )?;
        }
        Ok(())
    })?;
    audit(
        ctx,
        c,
        if editing.is_some() { "role.update" } else { "role.create" },
        &format!("{} role {} [{}]", if editing.is_some() { "Updated" } else { "Created" }, name, summarize(&perms)),
        Some("role"),
        Some(&name),
    )?;
    Ok(Reply::Redirect("/roles".into()))
}

/// `POST /roles/delete`: `RoleList::deleteRole`. Holders revert to the standard-user baseline (`users.role_id` is
/// `nullOnDelete`; set here as well, in case the live schema lacks the constraint).
pub fn delete(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    if !ctx.is_admin() {
        return Ok(abort(403));
    }
    let b = Body::of(req);
    let Some(r) = find(c, "roles", b.int("id"))? else { return Ok(abort(404)) };
    let name = s(&r, "name");
    let holders = count(c, r#"select count(*) as aggregate from "users" where "users"."role_id" = ? and "users"."role_id" is not null"#, &[P(Val::Int(r.id()))])?;
    super::strategies_tx(c, || {
        db::exec(c, r#"update "users" set "role_id" = null where "role_id" = ?"#, &[P(Val::Int(r.id()))])?;
        db::exec(c, r#"delete from "roles" where "id" = ?"#, &[P(Val::Int(r.id()))])?;
        Ok(())
    })?;
    audit(ctx, c, "role.delete", &format!("Deleted role {name} ({holders} user(s) reverted to standard access)"), Some("role"), Some(&name))?;
    Ok(Reply::Redirect("/roles".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_matrix_normalises_like_phps() {
        let p = normalize(&json!({"device": "rw", "audit": "r", "setting": "admin", "bogus": "rw", "token": 2}));
        assert_eq!(encode(&p), r#"{"device":"rw","user":"none","group":"none","address_book":"none","audit":"r","strategy":"none","setting":"none","token":"none"}"#);
        assert_eq!(summarize(&p), "device:rw, audit:r");
        assert_eq!(summarize(&normalize(&json!({}))), "no permissions");
        assert_eq!(encode(&baseline()), r#"{"device":"rw","user":"none","group":"none","address_book":"rw","audit":"r","strategy":"none","setting":"none","token":"none"}"#);
    }
}
