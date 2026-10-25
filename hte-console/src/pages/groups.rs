//! Groups (Livewire `GroupList`): device groups (folders of machines) and user groups (people), each with a name, a
//! note, the "accessed from" user groups, and, for a user group, the device groups its members get.
//!
//! State is the URL (`?tab=users`, `&create=1`, `&edit=<id>`); the dialog's save and the delete are form posts.

use super::kit::*;
use super::{Ctx, Reply, Req};
use crate::php::{Fault, Val};
use crate::sqlite::{self as db, Row, P};
use crate::validate::{self, Rule};
use rusqlite::Connection;
use serde_json::{json, Map, Value};

fn tab_of(v: &str) -> &'static str {
    if v == "users" { "users" } else { "devices" }
}

fn url_of(tab: &str) -> String {
    if tab == "users" { "/groups?tab=users".into() } else { "/groups".into() }
}

fn join(url: &str, extra: &str) -> String {
    if url.contains('?') { format!("{url}&{extra}") } else { format!("{url}?{extra}") }
}

pub enum Modal {
    None,
    Edit { id: i64, values: Map<String, Value>, errors: Map<String, Value> },
}

fn table_of(tab: &str) -> &'static str {
    if tab == "users" { "user_groups" } else { "device_groups" }
}

fn target_type(tab: &str) -> &'static str {
    if tab == "users" { "user_group" } else { "device_group" }
}

fn accessors(c: &Connection, tab: &str, id: i64) -> Result<Vec<i64>, Fault> {
    Ok(db::rows(c, r#"select "accessor_id" from "group_accesses" where "target_type" = ? and "target_id" = ? and "accessor_type" = ? order by "id" asc"#, &[P(Val::str(target_type(tab))), P(Val::Int(id)), P(Val::str("user_group"))])?
        .iter()
        .map(|r| r.val("accessor_id").to_int())
        .collect())
}

/// `GroupAccess::syncAccessors`
fn sync_accessors(c: &Connection, tab: &str, id: i64, ids: &[i64], now: &str) -> Result<(), Fault> {
    let mut uniq: Vec<i64> = vec![];
    for i in ids {
        if !uniq.contains(i) {
            uniq.push(*i);
        }
    }
    let keep: Vec<i64> = if uniq.is_empty() { vec![0] } else { uniq.clone() };
    let mut params = vec![P(Val::str(target_type(tab))), P(Val::Int(id)), P(Val::str("user_group"))];
    params.extend(ints_val(&keep));
    db::exec(c, &format!(r#"delete from "group_accesses" where "target_type" = ? and "target_id" = ? and "accessor_type" = ? and "accessor_id" not in ({})"#, marks(keep.len())), &params)?;
    for a in uniq {
        let exists = count(
            c,
            r#"select count(*) as aggregate from "group_accesses" where "accessor_type" = ? and "accessor_id" = ? and "target_type" = ? and "target_id" = ?"#,
            &[P(Val::str("user_group")), P(Val::Int(a)), P(Val::str(target_type(tab))), P(Val::Int(id))],
        )?;
        if exists == 0 {
            db::insert(c, "group_accesses", vec![("accessor_type", Val::str("user_group")), ("accessor_id", Val::Int(a)), ("target_type", Val::str(target_type(tab))), ("target_id", Val::Int(id))], now)?;
        }
    }
    Ok(())
}

/// `GroupAccess::purgeFor`
fn purge_for(c: &Connection, kind: &str, id: i64) -> Result<(), Fault> {
    db::exec(
        c,
        r#"delete from "group_accesses" where ("accessor_type" = ? and "accessor_id" = ?) or ("target_type" = ? and "target_id" = ?)"#,
        &[P(Val::str(kind)), P(Val::Int(id)), P(Val::str(kind)), P(Val::Int(id))],
    )?;
    Ok(())
}

fn flag(ctx: &Ctx, key: &str) -> String {
    ctx.flashed.get(key).and_then(|v| v.as_str()).unwrap_or("").to_string()
}

pub fn index(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    let tab = tab_of(&q(req, "tab"));
    let modal = if q(req, "create") == "1" && ctx.allows("group", "rw") {
        Modal::Edit { id: 0, values: values_of(c, tab, None)?, errors: Map::new() }
    } else if qint(req, "edit") > 0 {
        if !ctx.allows("group", "rw") {
            return Ok(abort(403));
        }
        let id = qint(req, "edit");
        let Some(g) = find(c, table_of(tab), id)? else { return Ok(abort(404)) };
        Modal::Edit { id, values: values_of(c, tab, Some(&g))?, errors: Map::new() }
    } else {
        Modal::None
    };
    render(ctx, c, tab, 200, modal)
}

fn values_of(c: &Connection, tab: &str, g: Option<&Row>) -> Result<Map<String, Value>, Fault> {
    let mut m = Map::new();
    match g {
        None => {
            m.insert("name".into(), json!(""));
            m.insert("note".into(), json!(""));
            m.insert("device_group_ids".into(), json!([]));
            m.insert("accessor_group_ids".into(), json!([]));
        }
        Some(g) => {
            m.insert("name".into(), json!(s(g, "name")));
            m.insert("note".into(), json!(s(g, "note")));
            m.insert("device_group_ids".into(), json!(if tab == "users" { granted_device_group_ids(c, g.id())? } else { vec![] }));
            m.insert("accessor_group_ids".into(), json!(accessors(c, tab, g.id())?));
        }
    }
    Ok(m)
}

fn render(ctx: &Ctx, c: &Connection, tab: &str, status: u16, modal: Modal) -> Result<Reply, Fault> {
    let device_groups = db::rows(
        c,
        r#"select "device_groups".*, (select count(*) from "devices" where "device_groups"."id" = "devices"."device_group_id" and "devices"."deleted_at" is null) as "devices_count" from "device_groups" order by "name" asc"#,
        &[],
    )?;
    let user_groups = db::rows(c, r#"select "user_groups".*, (select count(*) from "user_group_user" where "user_groups"."id" = "user_group_user"."user_group_id") as "users_count" from "user_groups" order by "name" asc"#, &[])?;
    let current = if tab == "users" { &user_groups } else { &device_groups };
    let ids: Vec<i64> = user_groups.iter().map(|g| g.id()).collect();
    let granted = if tab == "users" && !ids.is_empty() {
        db::rows(
            c,
            &format!(r#"select "device_groups"."name", "device_group_user_group"."user_group_id" as "pivot_user_group_id" from "device_groups" inner join "device_group_user_group" on "device_groups"."id" = "device_group_user_group"."device_group_id" where "device_group_user_group"."user_group_id" in ({}) order by "device_groups"."id""#, marks(ids.len())),
            &ints_val(&ids),
        )?
    } else {
        vec![]
    };
    let rows: Vec<Value> = current
        .iter()
        .map(|g| {
            let names: Vec<String> = granted.iter().filter(|d| d.val("pivot_user_group_id").to_int() == g.id()).map(|d| s(d, "name")).collect();
            let n = if tab == "users" { g.val("users_count").to_int() } else { g.val("devices_count").to_int() };
            json!({"id": g.id(), "name": s(g, "name"), "note": s(g, "note"), "count": n, "granted": names, "created": ymd(g, "created_at").unwrap_or_default(), "created_at": ts_of(g, "created_at").map(crate::laravel::ts).unwrap_or_default()})
        })
        .collect();
    let url = url_of(tab);
    let layout = ctx.layout(c, "groups", "Groups", "Manage")?;
    let modal_v = match &modal {
        Modal::None => json!({"kind": ""}),
        Modal::Edit { id, values, errors } => {
            let mut filled = errors.clone();
            for k in ["name", "note", "device_group_ids", "accessor_group_ids"] {
                filled.entry(k.to_string()).or_insert(Value::Null);
            }
            let dg: Vec<Value> = grantable_device_groups(ctx, c)?.iter().map(|g| json!({"id": g.id(), "name": s(g, "name")})).collect();
            let af: Vec<Value> = user_groups.iter().filter(|g| g.id() != *id).map(|g| json!({"id": g.id(), "name": s(g, "name")})).collect();
            json!({"kind": "edit", "id": id, "editing": *id != 0, "type": tab, "title": format!("{} {} Group", if *id != 0 { "Edit" } else { "Add" }, if tab == "users" { "User" } else { "Device" }),
                   "values": values, "errors": filled, "device_groups": dg, "accessors": af, "return": url})
        }
    };
    let page = json!({
        "tab": tab, "rows": rows, "device_count": device_groups.len(), "user_count": user_groups.len(), "can_manage": ctx.allows("group", "rw"), "super": ctx.is_admin(),
        "create_url": join(&url, "create=1"), "edit_prefix": join(&url, "edit="), "tab_devices": "/groups", "tab_users": "/groups?tab=users", "modal": modal_v, "result": flag(ctx, "groups_result"),
    });
    Ok(Reply::Html(status, ctx.render("groups/index.html", layout, page)?))
}

/// `POST /groups/save`
pub fn save(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    if !ctx.allows("group", "rw") {
        return Ok(abort(403));
    }
    let body = Body::of(req);
    let tab = tab_of(&body.get("type"));
    let id = body.int("id");
    let editing = if id != 0 { find(c, table_of(tab), id)? } else { None };
    if id != 0 && editing.is_none() {
        return Ok(abort(404));
    }
    let name = body.get("name");
    let note = body.get("note");
    let mut device_group_ids = body.ints("device_group_ids");
    let mut accessor_group_ids = body.ints("accessor_group_ids");

    let mut data = crate::php::Arr::new();
    let mut set = |k: &str, v: Val| data.set(crate::php::Key::Str(k.as_bytes().to_vec()), v);
    set("name", Val::str(&name));
    set("note", Val::str(&note));
    set("device_group_ids", int_array(&device_group_ids));
    set("accessor_group_ids", int_array(&accessor_group_ids));
    let rules: [(&str, &[Rule]); 6] = [
        ("name", &[Rule::Required, Rule::String, Rule::Max(255)]),
        ("note", &[Rule::Nullable, Rule::String, Rule::Max(500)]),
        ("device_group_ids", &[Rule::Array]),
        ("device_group_ids.*", &[Rule::Exists("device_groups", "id")]),
        ("accessor_group_ids", &[Rule::Array]),
        ("accessor_group_ids.*", &[Rule::Exists("user_groups", "id")]),
    ];
    let probe_fn = |rule: &Rule, v: &Val| probe(c, rule, v);
    if let Err(b) = validate::validate_db(&data, &rules, &probe_fn)? {
        let errors = first_messages(&b);
        let mut values = Map::new();
        for (k, v) in [("name", json!(name)), ("note", json!(note)), ("device_group_ids", json!(device_group_ids)), ("accessor_group_ids", json!(accessor_group_ids))] {
            values.insert(k.into(), v);
        }
        return render(ctx, c, tab, 422, Modal::Edit { id, values, errors });
    }
    let now_s = crate::laravel::ts(ctx.now);
    let note_v = if note.is_empty() { Val::Null } else { Val::str(&note) };
    let gid;
    let gname;
    if let Some(mut g) = editing {
        update(c, table_of(tab), &mut g, vec![("name", Val::str(&name), crate::laravel::Cast::Plain), ("note", note_v, crate::laravel::Cast::Plain)], ctx.now)?;
        gid = g.id();
        gname = s(&g, "name");
    } else {
        gid = db::insert(c, table_of(tab), vec![("name", Val::str(&name)), ("note", note_v)], &now_s)?;
        gname = name.clone();
    }

    // ---- escalation guards for a delegated group-manager: pass on only what they can see themselves
    let super_admin = ctx.is_admin();
    if tab == "users" {
        if !super_admin {
            let existing = granted_device_group_ids(c, gid)?;
            let mut out = grantable_device_group_ids(ctx, c, &device_group_ids)?;
            let reach = grantable_device_group_ids(ctx, c, &existing)?;
            for e in existing {
                if !reach.contains(&e) && !out.contains(&e) {
                    out.push(e);
                }
            }
            device_group_ids = out;
        }
        let mut uniq: Vec<i64> = vec![];
        for i in &device_group_ids {
            if !uniq.contains(i) {
                uniq.push(*i);
            }
        }
        sync_pivot(c, "device_group_user_group", "user_group_id", gid, "device_group_id", &uniq)?;
    }
    if tab == "devices" && !super_admin && grantable_device_group_ids(ctx, c, &[gid])?.is_empty() {
        accessor_group_ids = accessors(c, tab, gid)?;
    }
    if tab == "users" {
        accessor_group_ids.retain(|i| *i != gid);
    }
    sync_accessors(c, tab, gid, &accessor_group_ids, &now_s)?;
    let kind = if tab == "users" { "user group" } else { "device group" };
    audit(ctx, c, if id != 0 { "group.update" } else { "group.create" }, &format!("{} {kind} {gname}", if id != 0 { "Updated" } else { "Created" }), Some("group"), Some(&gname))?;
    Ok(Reply::Redirect(url_of(tab)))
}

/// `POST /groups/act`: delete.
pub fn act(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    if !ctx.allows("group", "rw") {
        return Ok(abort(403));
    }
    let body = Body::of(req);
    let tab = tab_of(&body.get("type"));
    let id = body.int("id");
    let back = Reply::Redirect(url_of(tab));
    if body.get("do") != "delete" {
        return Ok(back);
    }
    let Some(g) = find(c, table_of(tab), id)? else { return Ok(abort(404)) };
    let name = s(&g, "name");
    if tab == "devices" {
        db::exec(c, r#"update "devices" set "device_group_id" = ?, "updated_at" = ? where "device_group_id" = ? and "devices"."deleted_at" is null"#, &[P(Val::Null), P(Val::str(&crate::laravel::ts(ctx.now))), P(Val::Int(id))])?;
        purge_for(c, "device_group", id)?;
        db::exec(c, r#"delete from "device_groups" where "id" = ?"#, &[P(Val::Int(id))])?;
        // DeviceGroup::booted(): deleted => Strategy::recomputeAll()
        recompute_all(c, ctx.now)?;
    } else {
        db::exec(c, r#"delete from "user_group_user" where "user_group_id" = ?"#, &[P(Val::Int(id))])?;
        db::exec(c, r#"delete from "device_group_user_group" where "user_group_id" = ?"#, &[P(Val::Int(id))])?;
        purge_for(c, "user_group", id)?;
        db::exec(c, r#"delete from "user_groups" where "id" = ?"#, &[P(Val::Int(id))])?;
    }
    audit(ctx, c, "group.delete", &format!("Deleted {} {name}", if tab == "users" { "user group" } else { "device group" }), Some("group"), Some(&name))?;
    Ok(back)
}
