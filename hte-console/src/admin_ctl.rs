//! Phase 5: the controllers of `/api/v1/*` (app/Http/Controllers/AdminApi/*), statement by statement. `admin.rs`
//! has already authenticated the token, throttled, bound the route's models and checked its ability; what is left
//! is each action's validation, queries, writes (the Eloquent rules in `sqlite.rs`/`Cx`), console-audit line and
//! `{code,data,message}` answer.
//!
//! Notes that hold throughout:
//!  - a loaded model keeps the attributes it was given (a created row answers with the values as sent, not as the
//!    column stores them), so `Cx::create`/`Cx::update` hand back that in-memory row and the answer is built from it;
//!  - a relation read in an answer (`$device->user`, `$book->owner`) is the row the foreign key points at;
//!  - `withCount` and `loadCount` are plain counts, `with()` an extra query per relation for the whole page.

use crate::admin::{enc, filled, flat_first, iso, list, obj, request_boolean, Cx, Op};
use crate::api::Reply;
use crate::duplicates::{self, Duplicates};
use crate::laravel::{self, Cast};
use crate::php::{self, Arr, Fault, Val};
use crate::sqlite::{self as db, Row, P};
use crate::validate::{self, Rule};
use rusqlite::Connection;

type R = Result<Reply, Fault>;

// ---------------------------------------------------------------------------------------------- helpers ---

/// The `where` clause of a query built from `when()` conditions.
struct W {
    conds: Vec<String>,
    params: Vec<P>,
}

impl W {
    fn new() -> W {
        W { conds: vec![], params: vec![] }
    }
    fn add(&mut self, sql: &str, p: Vec<P>) {
        self.conds.push(sql.to_string());
        self.params.extend(p);
    }
    fn sql(&self) -> String {
        if self.conds.is_empty() {
            String::new()
        } else {
            format!(" where {}", self.conds.join(" and "))
        }
    }
}

/// `where($col, $value)`: a null value is `whereNull`, an array binds its first scalar.
fn eq(col: &str, v: &Val) -> (String, Vec<P>) {
    match v {
        Val::Null => (format!("{col} is null"), vec![]),
        other => (format!("{col} = ?"), vec![P(flat_first(other))]),
    }
}

fn text(v: &Val) -> Result<String, Fault> {
    Ok(String::from_utf8_lossy(&v.to_php_string()?).into_owned())
}

fn count(c: &Connection, sql: &str, p: &[P]) -> Result<i64, Fault> {
    Ok(db::first(c, sql, p)?.map_or(0, |r| r.val("aggregate").to_int()))
}

fn int_list(rows: &[Row], col: &str) -> Vec<Val> {
    let mut out: Vec<Val> = vec![];
    for r in rows {
        let v = r.val(col);
        if !matches!(v, Val::Null) && !out.contains(&v) {
            out.push(v);
        }
    }
    out
}

fn marks(n: usize) -> String {
    vec!["?"; n].join(", ")
}

/// `Model::whereIn($key, $ids)->get()` for the rows a page points at.
fn load_in(c: &Connection, table: &str, col: &str, ids: &[Val]) -> Result<Vec<Row>, Fault> {
    if ids.is_empty() {
        return Ok(vec![]);
    }
    db::rows(c, &format!(r#"select * from "{table}" where "{col}" in ({})"#, marks(ids.len())), &ids.iter().map(|v| P(v.clone())).collect::<Vec<_>>())
}

fn by_id<'a>(rows: &'a [Row], id: &Val) -> Option<&'a Row> {
    if matches!(id, Val::Null) {
        return None;
    }
    rows.iter().find(|r| r.val("id").to_int() == id.to_int() && r.val("id").is_numeric())
}

/// `$model->relation` for a belongs-to read one row at a time.
fn belongs_to(c: &Connection, table: &str, fk: &Val) -> Result<Option<Row>, Fault> {
    if matches!(fk, Val::Null) {
        return Ok(None);
    }
    db::first(c, &format!(r#"select * from "{table}" where "id" = ? limit 1"#), &[P(fk.clone())])
}

/// The database side of `unique` and `exists`: does the rule pass?
fn probe(c: &Connection, rule: &Rule, v: &Val) -> Result<bool, Fault> {
    match rule {
        Rule::Unique(table, col, ignore) => {
            let mut sql = format!(r#"select count(*) as aggregate from "{table}" where "{col}" = ?"#);
            let mut p = vec![P(flat_first(v))];
            if let Some(id) = ignore {
                sql.push_str(r#" and "id" <> ?"#);
                p.push(P(Val::Int(*id)));
            }
            Ok(count(c, &sql, &p)? == 0)
        }
        Rule::Exists(table, col) => match v {
            Val::Arr(a) => {
                let mut uniq: Vec<Val> = vec![];
                for (_, x) in a.iter() {
                    if !uniq.contains(x) {
                        uniq.push(x.clone());
                    }
                }
                if uniq.is_empty() {
                    return Ok(true);
                }
                let sql = format!(r#"select count(*) as aggregate from "{table}" where "{col}" in ({})"#, marks(uniq.len()));
                let p: Vec<P> = uniq.iter().map(|x| P(x.clone())).collect();
                Ok(count(c, &sql, &p)? >= uniq.len() as i64)
            }
            other => Ok(count(c, &format!(r#"select count(*) as aggregate from "{table}" where "{col}" = ?"#), &[P(other.clone())])? > 0),
        },
        _ => Ok(true),
    }
}

/// `$request->validate($rules)`: the validated data, or the 422 answer.
fn validated(cx: &Cx, rules: &[(&str, &[Rule])]) -> Result<Result<Arr, Reply>, Fault> {
    let p = |rule: &Rule, v: &Val| probe(cx.c, rule, v);
    Ok(match validate::validate_db(cx.input.all(), rules, &p)? {
        Ok(a) => Ok(a),
        Err(body) => Err(Reply::Json(422, body)),
    })
}

macro_rules! try_valid {
    ($e:expr) => {
        match $e? {
            Ok(a) => a,
            Err(reply) => return Ok(reply),
        }
    };
}

/// The `hashed` cast: a plain value is bcrypted; something already a hash passes through when it is bcrypt at a
/// cost within `BCRYPT_ROUNDS` and is a RuntimeException (500) otherwise.
fn hashed(v: &Val) -> Result<Val, Fault> {
    let b = v.to_php_string()?;
    let argon = b.starts_with(b"$argon2i$") || b.starts_with(b"$argon2id$");
    if laravel::is_php_bcrypt(&b) || argon {
        let cost = if argon {
            None
        } else {
            std::str::from_utf8(&b[4..]).ok().and_then(|s| s.split('$').next()).and_then(|d| d.parse::<i64>().ok())
        };
        return match cost {
            Some(c) if c <= laravel::bcrypt_rounds() as i64 => Ok(Val::Str(b)),
            _ => Err(Fault::Other("Could not verify the hashed value's configuration.".into())),
        };
    }
    Ok(Val::str(&laravel::hash_make(&b)?))
}

/// The validated attributes as `(column, value)` pairs in the validator's order.
fn pairs(data: &Arr) -> Vec<(String, Val)> {
    data.iter().map(|(k, v)| (String::from_utf8_lossy(&k.as_bytes()).into_owned(), v.clone())).collect()
}

fn as_refs(p: &[(String, Val)]) -> Vec<(&str, Val)> {
    p.iter().map(|(k, v)| (k.as_str(), v.clone())).collect()
}

/// The `array` cast on write: JSON text (null stays null).
fn to_json_text(v: &Val) -> Result<Val, Fault> {
    Ok(match v {
        Val::Null => Val::Null,
        other => Val::str(&enc(other)?),
    })
}

fn bool_of(v: &Val) -> Val {
    Val::Bool(v.to_bool())
}

// ----------------------------------------------------------------------------------------------- dispatch ---

pub fn dispatch(cx: &Cx, op: Op) -> R {
    match op {
        Op::UsersIndex => users_index(cx),
        Op::UsersShow => users_show(cx),
        Op::UsersStore => users_store(cx),
        Op::UsersEnable => users_enable(cx),
        Op::UsersDisable => users_disable(cx),
        Op::UsersForceLogout => users_force_logout(cx),
        Op::UsersDestroy => users_destroy(cx),
        Op::DevIndex => dev_index(cx),
        Op::DevShow => dev_show(cx),
        Op::DevEnable => dev_enable(cx),
        Op::DevDisable => dev_disable(cx),
        Op::DevAssign => dev_assign(cx),
        Op::DevDestroy => dev_destroy(cx),
        Op::UgIndex => ug_index(cx),
        Op::UgShow => ug_show(cx),
        Op::UgStore => ug_store(cx),
        Op::UgUpdate => ug_update(cx),
        Op::UgDestroy => ug_destroy(cx),
        Op::UgAddMember => ug_member(cx, true),
        Op::UgRemoveMember => ug_member(cx, false),
        Op::DgIndex => dg_index(cx),
        Op::DgShow => dg_show(cx),
        Op::DgStore => dg_store(cx),
        Op::DgUpdate => dg_update(cx),
        Op::DgDestroy => dg_destroy(cx),
        Op::DgAddMember => dg_member(cx, true),
        Op::DgRemoveMember => dg_member(cx, false),
        Op::AbIndex => ab_index(cx),
        Op::AbShow => ab_show(cx),
        Op::AbStore => ab_store(cx),
        Op::AbUpdate => ab_update(cx),
        Op::AbDestroy => ab_destroy(cx),
        Op::AbPeers => ab_peers(cx),
        Op::AbPeerStore => ab_peer_store(cx),
        Op::AbPeerUpdate => ab_peer_update(cx),
        Op::AbPeerDestroy => ab_peer_destroy(cx),
        Op::AbTags => ab_tags(cx),
        Op::AbTagStore => ab_tag_store(cx),
        Op::AbTagUpdate => ab_tag_update(cx),
        Op::AbTagDestroy => ab_tag_destroy(cx),
        Op::AbRules => ab_rules(cx),
        Op::AbRuleStore => ab_rule_store(cx),
        Op::AbRuleUpdate => ab_rule_update(cx),
        Op::AbRuleDestroy => ab_rule_destroy(cx),
        Op::AuConn => au_conn(cx),
        Op::AuFile => au_file(cx),
        Op::AuAlarm => au_alarm(cx),
        Op::AuConsole => au_console(cx),
        Op::Assign => unreachable!("--assign is device_cli's"),
    }
}

// ----------------------------------------------------------------------------------------------- users ---

fn groups_of_users(cx: &Cx, ids: &[Val]) -> Result<Vec<(Val, Row)>, Fault> {
    if ids.is_empty() {
        return Ok(vec![]);
    }
    let sql = format!(
        r#"select "user_groups".*, "user_group_user"."user_id" as "pivot_user_id", "user_group_user"."user_group_id" as "pivot_user_group_id" from "user_groups" inner join "user_group_user" on "user_groups"."id" = "user_group_user"."user_group_id" where "user_group_user"."user_id" in ({})"#,
        marks(ids.len())
    );
    let rows = db::rows(cx.c, &sql, &ids.iter().map(|v| P(v.clone())).collect::<Vec<_>>())?;
    Ok(rows.into_iter().map(|r| (r.val("pivot_user_id"), r)).collect())
}

fn user_json(u: &Row, groups: Option<Vec<Row>>) -> Result<Val, Fault> {
    let groups = groups.unwrap_or_default().iter().map(|g| obj(vec![("id", g.val("id")), ("name", g.val("name"))])).collect();
    Ok(obj(vec![
        ("id", u.val("id")),
        ("username", u.val("username")),
        ("name", u.val("name")),
        ("email", u.val("email")),
        ("note", u.val("note")),
        ("is_admin", bool_of(&u.val("is_admin"))),
        ("is_active", bool_of(&u.val("is_active"))),
        ("groups", list(groups)),
        ("created_at", iso(&u.val("created_at"))?),
    ]))
}

fn users_index(cx: &Cx) -> R {
    let mut w = W::new();
    if filled(cx.input, "name")? {
        let s = cx.like("name")?;
        w.add(r#"("username" like ? or "name" like ? or "email" like ?)"#, vec![P(s.clone()), P(s.clone()), P(s)]);
    }
    if filled(cx.input, "group")? {
        let group = cx.input.query("group").cloned().unwrap_or(Val::Null);
        let (cond, p) = if group.is_numeric() { (r#""user_groups"."id" = ?"#.to_string(), vec![P(Val::Int(group.to_int()))]) } else { eq(r#""user_groups"."name""#, &group) };
        w.add(
            &format!(r#"exists (select * from "user_groups" inner join "user_group_user" on "user_groups"."id" = "user_group_user"."user_group_id" where "users"."id" = "user_group_user"."user_id" and {cond})"#),
            p,
        );
    }
    if filled(cx.input, "status")? {
        let active = matches!(cx.input.query("status"), Some(Val::Str(s)) if s == b"active");
        w.add(r#""is_active" = ?"#, vec![P(Val::Bool(active))]);
    }
    let sql = w.sql();
    cx.paginated("*", r#""users""#, &sql, w.params, r#""username" asc"#, |rows| {
        let groups = groups_of_users(cx, &int_list(&rows, "id"))?;
        rows.iter()
            .map(|u| {
                let own: Vec<Row> = groups.iter().filter(|(uid, _)| *uid == u.val("id")).map(|(_, g)| g.clone()).collect();
                user_json(u, Some(own))
            })
            .collect()
    })
}

fn users_show(cx: &Cx) -> R {
    let u = &cx.bound[0];
    let groups = groups_of_users(cx, &[u.val("id")])?.into_iter().map(|(_, g)| g).collect();
    cx.ok(user_json(u, Some(groups))?, "")
}

fn users_store(cx: &Cx) -> R {
    let rules: &[(&str, &[Rule])] = &[
        ("username", &[Rule::Required, Rule::String, Rule::Max(255), Rule::Unique("users", "username", None)]),
        ("name", &[Rule::Nullable, Rule::String, Rule::Max(255)]),
        ("email", &[Rule::Nullable, Rule::Email, Rule::Max(255), Rule::Unique("users", "email", None)]),
        ("password", &[Rule::Required, Rule::String, Rule::Min(8)]),
        ("is_active", &[Rule::Boolean]),
        ("note", &[Rule::Nullable, Rule::String]),
    ];
    let data = try_valid!(validated(cx, rules));
    let mut cols: Vec<(String, Val)> = vec![];
    if data.get_str("is_active").is_none() {
        // the model's `$attributes` default
        cols.push(("is_active".into(), Val::Bool(true)));
    }
    for (k, v) in pairs(&data) {
        let v = if k == "password" { hashed(&v)? } else { v };
        cols.push((k, v));
    }
    // admin promotion and delegated roles are deliberately not reachable from the API
    cols.push(("is_admin".into(), Val::Bool(false)));
    cols.push(("role_id".into(), Val::Null));
    let user = cx.create("users", as_refs(&cols))?;
    let name = text(&user.val("username"))?;
    cx.audit("user.create", &format!("Created user {name} (API)"), Some("user"), Some(&name))?;
    cx.created(user_json(&user, None)?, "User created.")
}

fn users_enable(cx: &Cx) -> R {
    let mut u = cx.bound[0].clone();
    cx.update("users", &mut u, vec![("is_active", Val::Bool(true), Cast::Bool)])?;
    let name = text(&u.val("username"))?;
    cx.audit("user.enable", &format!("Enabled user {name} (API)"), Some("user"), Some(&name))?;
    cx.ok(user_json(&u, None)?, "User enabled.")
}

/// `User::revokeAllAccess` as the API's private copy runs it: client tokens, web sessions and trusted browsers go,
/// and the remember token rotates.
fn revoke_all_access(cx: &Cx, u: &mut Row) -> Result<(), Fault> {
    let id = u.val("id");
    db::exec(cx.c, r#"delete from "client_tokens" where "client_tokens"."user_id" = ? and "client_tokens"."user_id" is not null"#, &[P(id.clone())])?;
    db::exec(cx.c, r#"delete from "sessions" where "user_id" = ?"#, &[P(id.clone())])?;
    db::exec(cx.c, r#"delete from "trusted_devices" where "user_id" = ?"#, &[P(id)])?;
    cx.update("users", u, vec![("remember_token", Val::str(&laravel::str_random(60)), Cast::Plain)])?;
    Ok(())
}

fn users_disable(cx: &Cx) -> R {
    let mut u = cx.bound[0].clone();
    if u.val("id") == cx.user.val("id") {
        return cx.fail("You cannot disable the token owner account.", 422, 1);
    }
    cx.update("users", &mut u, vec![("is_active", Val::Bool(false), Cast::Bool)])?;
    revoke_all_access(cx, &mut u)?;
    let name = text(&u.val("username"))?;
    cx.audit("user.disable", &format!("Disabled user {name} (API)"), Some("user"), Some(&name))?;
    cx.ok(user_json(&u, None)?, "User disabled.")
}

fn users_force_logout(cx: &Cx) -> R {
    let mut u = cx.bound[0].clone();
    revoke_all_access(cx, &mut u)?;
    let name = text(&u.val("username"))?;
    cx.audit("user.force-logout", &format!("Forced logout of {name} (API)"), Some("user"), Some(&name))?;
    cx.ok(Val::Null, "User logged out everywhere.")
}

fn users_destroy(cx: &Cx) -> R {
    let u = &cx.bound[0];
    if u.val("id") == cx.user.val("id") {
        return cx.fail("You cannot delete the token owner account.", 422, 1);
    }
    let name = text(&u.val("username"))?;
    let id = u.val("id");
    // $user->devices()->update(['user_id' => null]): the query builder, soft-delete scope on, no model events
    db::exec(cx.c, r#"update "devices" set "user_id" = ?, "updated_at" = ? where "devices"."user_id" = ? and "devices"."deleted_at" is null"#, &[P(Val::Null), P(Val::str(&cx.ts())), P(id.clone())])?;
    // User::deleting: the personal address books of this user go with their contents
    let books = db::rows(cx.c, r#"select * from "address_books" where "owner_user_id" = ? and "is_personal" = ?"#, &[P(id.clone()), P(Val::Bool(true))])?;
    for b in books {
        delete_book(cx, &b)?;
    }
    db::exec(cx.c, r#"delete from "users" where "id" = ?"#, &[P(id)])?;
    // User::deleted
    cx.recompute_all()?;
    cx.audit("user.delete", &format!("Deleted user {name} (API)"), Some("user"), Some(&name))?;
    cx.ok(Val::Null, "User deleted.")
}

fn delete_book(cx: &Cx, b: &Row) -> Result<(), Fault> {
    let id = b.val("id");
    db::exec(cx.c, r#"delete from "address_book_entries" where "address_book_entries"."address_book_id" = ? and "address_book_entries"."address_book_id" is not null"#, &[P(id.clone())])?;
    db::exec(cx.c, r#"delete from "tags" where "tags"."address_book_id" = ? and "tags"."address_book_id" is not null"#, &[P(id.clone())])?;
    db::exec(cx.c, r#"delete from "address_book_rules" where "address_book_rules"."address_book_id" = ? and "address_book_rules"."address_book_id" is not null"#, &[P(id.clone())])?;
    db::exec(cx.c, r#"delete from "address_books" where "id" = ?"#, &[P(id)])?;
    Ok(())
}

// --------------------------------------------------------------------------------------------- devices ---

fn device_json(cx: &Cx, d: &Row, user: Option<&Row>, group: Option<&Row>, dups: &Duplicates, window: i64) -> Result<Val, Fault> {
    let trashed = !d.is_null("deleted_at");
    let status = if trashed {
        "disabled"
    } else if d.val("status") == Val::str("pending") {
        "pending"
    } else {
        "active"
    };
    let online = match d.val("last_online_at") {
        Val::Null => false,
        v => laravel::parse_ts(&v).ok_or_else(|| Fault::Other("unparsable devices.last_online_at".into()))? > cx.now - window,
    };
    let pair = |r: Option<&Row>, col: &str| r.map_or(Val::Null, |r| obj(vec![("id", r.val("id")), (col, r.val(col))]));
    let possible = if trashed { vec![] } else { dups.rustdesk_ids_of(d.id())? };
    Ok(obj(vec![
        ("id", d.val("id")),
        ("rustdesk_id", d.val("rustdesk_id")),
        ("uuid", d.val("uuid")),
        ("alias", d.val("alias")),
        ("hostname", d.val("hostname")),
        ("os", d.val("os")),
        ("platform", Val::str(&duplicates::platform(&d.val("os")))),
        ("cpu", d.val("cpu")),
        ("memory", d.val("memory")),
        ("version", d.val("version")),
        ("username", d.val("username")),
        ("note", d.val("note")),
        ("status", Val::str(status)),
        ("online", Val::Bool(online)),
        ("last_online_at", iso(&d.val("last_online_at"))?),
        ("last_online_ip", d.val("last_online_ip")),
        ("registered_ip", d.val("registered_ip")),
        ("created_at", iso(&d.val("created_at"))?),
        ("updated_at", iso(&d.val("updated_at"))?),
        ("user", pair(user, "username")),
        ("device_group", pair(group, "name")),
        ("disabled", Val::Bool(trashed)),
        ("possible_duplicates", list(possible)),
    ]))
}

/// One device with its owner and folder read the way `$device->user`/`->group` read them, and its twins among the
/// approved devices.
fn device_one(cx: &Cx, d: &Row) -> Result<Val, Fault> {
    let user = belongs_to(cx.c, "users", &d.val("user_id"))?;
    let group = belongs_to(cx.c, "device_groups", &d.val("device_group_id"))?;
    let dups = Duplicates::of(cx.c, d)?;
    device_json(cx, d, user.as_ref(), group.as_ref(), &dups, cx.online_window()?)
}

fn dev_index(cx: &Cx) -> R {
    let mut w = W::new();
    w.add(r#""devices"."deleted_at" is null"#, vec![]);
    if filled(cx.input, "id")? {
        w.add(r#""rustdesk_id" like ?"#, vec![P(Val::Str({
            let mut s = b"%".to_vec();
            s.extend(cx.input.query_string("id")?);
            s.push(b'%');
            s
        }))]);
    }
    if filled(cx.input, "name")? {
        let s = cx.like("name")?;
        w.add(r#"("alias" like ? or "hostname" like ?)"#, vec![P(s.clone()), P(s)]);
    }
    if filled(cx.input, "user")? {
        let s = cx.like("user")?;
        w.add(
            r#"exists (select * from "users" where "devices"."user_id" = "users"."id" and ("username" like ? or "name" like ?))"#,
            vec![P(s.clone()), P(s)],
        );
    }
    if filled(cx.input, "group")? {
        let group = cx.input.query("group").cloned().unwrap_or(Val::Null);
        let (cond, p) = if group.is_numeric() { (r#""user_groups"."id" = ?"#.to_string(), vec![P(Val::Int(group.to_int()))]) } else { eq(r#""user_groups"."name""#, &group) };
        w.add(
            &format!(
                r#"exists (select * from "users" where "devices"."user_id" = "users"."id" and exists (select * from "user_groups" inner join "user_group_user" on "user_groups"."id" = "user_group_user"."user_group_id" where "users"."id" = "user_group_user"."user_id" and {cond}))"#
            ),
            p,
        );
    }
    if filled(cx.input, "device_group")? {
        let dg = cx.input.query("device_group").cloned().unwrap_or(Val::Null);
        if dg.is_numeric() {
            w.add(r#""device_group_id" = ?"#, vec![P(Val::Int(dg.to_int()))]);
        } else {
            let (cond, p) = eq(r#""device_groups"."name""#, &dg);
            w.add(&format!(r#"exists (select * from "device_groups" where "devices"."device_group_id" = "device_groups"."id" and {cond})"#), p);
        }
    }
    if filled(cx.input, "offline_days")? {
        let days = cx.input.query("offline_days").map_or(0, |v| v.to_int());
        let cutoff = cx.now.checked_sub(days.checked_mul(86_400).ok_or_else(|| Fault::Other("offline_days out of range".into()))?).ok_or_else(|| Fault::Other("offline_days out of range".into()))?;
        w.add(r#"("last_online_at" is null or "last_online_at" < ?)"#, vec![P(Val::str(&laravel::ts(cutoff)))]);
    }
    let sql = w.sql();
    let window = cx.online_window()?;
    cx.paginated("*", r#""devices""#, &sql, w.params, r#""rustdesk_id" asc"#, |rows| {
        let users = load_in(cx.c, "users", "id", &int_list(&rows, "user_id"))?;
        let groups = load_in(cx.c, "device_groups", "id", &int_list(&rows, "device_group_id"))?;
        // one pass for the page, not one per device
        let dups = Duplicates::all(cx.c)?;
        rows.iter().map(|d| device_json(cx, d, by_id(&users, &d.val("user_id")), by_id(&groups, &d.val("device_group_id")), &dups, window)).collect()
    })
}

fn dev_show(cx: &Cx) -> R {
    cx.ok(device_one(cx, &cx.bound[0])?, "")
}

fn dev_enable(cx: &Cx) -> R {
    let mut d = cx.bound[0].clone();
    if !d.is_null("deleted_at") {
        cx.update("devices", &mut d, vec![("deleted_at", Val::Null, Cast::Date)])?;
    }
    let rid = text(&d.val("rustdesk_id"))?;
    cx.audit("device.enable", &format!("Enabled device {rid} (API)"), Some("device"), Some(&rid))?;
    cx.ok(device_one(cx, &d)?, "Device enabled.")
}

fn dev_disable(cx: &Cx) -> R {
    let d = &cx.bound[0];
    // SoftDeletes::runSoftDelete: deleted_at and updated_at in one UPDATE
    let ts = cx.ts();
    db::exec(cx.c, r#"update "devices" set "deleted_at" = ?, "updated_at" = ? where "id" = ?"#, &[P(Val::str(&ts)), P(Val::str(&ts)), P(d.val("id"))])?;
    let rid = text(&d.val("rustdesk_id"))?;
    cx.audit("device.disable", &format!("Disabled device {rid} (API)"), Some("device"), Some(&rid))?;
    cx.ok(Val::Null, "Device disabled.")
}

fn dev_destroy(cx: &Cx) -> R {
    let d = &cx.bound[0];
    let from_books = request_boolean(cx.input, "remove_from_address_books");
    if from_books && !crate::admin::token_allows(&cx.token, "address_book", "rw")? {
        return cx.fail("Token lacks 'rw' permission on 'address_book'.", 403, 403);
    }
    let rid_val = d.val("rustdesk_id");
    let rid = text(&rid_val)?;
    db::exec(cx.c, r#"delete from "devices" where "id" = ?"#, &[P(d.val("id"))])?;
    cx.audit("device.destroy", &format!("Destroyed device {rid} (API)"), Some("device"), Some(&rid))?;
    if !from_books {
        return cx.ok(Val::Null, "Device deleted.");
    }
    let removed = remove_entries(cx, &[rid_val], " (API)")?;
    cx.ok(obj(vec![("address_book_entries_removed", Val::Int(removed))]), "Device deleted.")
}

/// `DeviceAddressBooks::remove($ids, null, $source)` (no actor: the token's permission was the whole check):
/// every entry for these RustDesk ids leaves, one audit row per book changed. Returns how many went.
fn remove_entries(cx: &Cx, ids: &[Val], source: &str) -> Result<i64, Fault> {
    if ids.is_empty() {
        return Ok(0);
    }
    let entries = load_in(cx.c, "address_book_entries", "rustdesk_id", ids)?;
    let mut order: Vec<Val> = vec![];
    for e in &entries {
        let b = e.val("address_book_id");
        if !order.contains(&b) {
            order.push(b);
        }
    }
    let mut removed = 0;
    for book_id in order {
        let mine: Vec<&Row> = entries.iter().filter(|e| e.val("address_book_id") == book_id).collect();
        let Some(book) = db::first(cx.c, r#"select * from "address_books" where "id" = ?"#, &[P(book_id.clone())])? else { continue };
        let entry_ids: Vec<Val> = mine.iter().map(|e| e.val("id")).collect();
        db::exec(cx.c, &format!(r#"delete from "address_book_entries" where "id" in ({})"#, marks(entry_ids.len())), &entry_ids.iter().map(|v| P(v.clone())).collect::<Vec<_>>())?;
        let n = mine.len();
        removed += n as i64;
        let mut names: Vec<String> = vec![];
        for e in &mine {
            let r = text(&e.val("rustdesk_id"))?;
            if !names.contains(&r) {
                names.push(r);
            }
        }
        let plural = if n == 1 { "entry" } else { "entries" };
        cx.audit(
            "address-book.peer-delete",
            &format!("Removed {n} {plural} ({}) from address book {} after device delete{source}", names.join(", "), text(&book.val("name"))?),
            Some("address-book"),
            Some(&text(&book.val("name"))?),
        )?;
    }
    Ok(removed)
}

/// `$request->filled($id)` then `Model::find(input)`, else `$request->filled($name)` then `where(col, input)->first()`.
fn resolve(cx: &Cx, table: &str, soft: bool, id_key: &str, name_key: &str, name_col: &str) -> Result<Option<Row>, Fault> {
    if filled(cx.input, id_key)? {
        let v = cx.input.get(id_key).cloned().unwrap_or(Val::Null);
        return cx.find_by_input(table, soft, &v);
    }
    if filled(cx.input, name_key)? {
        let v = cx.input.get(name_key).cloned().unwrap_or(Val::Null);
        return cx.find_by(table, soft, name_col, &v);
    }
    Ok(None)
}

/// After `$device->update(...)`: `Device::updated` re-resolves the strategy when the owner or folder changed.
fn device_updated(cx: &Cx, d: &mut Row, changed: &[String]) -> Result<(), Fault> {
    if changed.iter().any(|c| c == "user_id" || c == "device_group_id") {
        crate::strategy::sync_resolved_for(cx.c, d, &cx.ts())?;
    }
    Ok(())
}

fn dev_assign(cx: &Cx) -> R {
    let mut d = cx.bound[0].clone();
    let mut changes: Vec<(&str, Val, Cast)> = vec![];
    if cx.input.has("user_id") || cx.input.has("user_name") {
        let user = resolve(cx, "users", false, "user_id", "user_name", "username")?;
        if (filled(cx.input, "user_id")? || filled(cx.input, "user_name")?) && user.is_none() {
            return cx.fail("User not found.", 404, 1);
        }
        changes.push(("user_id", user.map_or(Val::Null, |u| u.val("id")), Cast::Plain));
    }
    if cx.input.has("device_group_id") || cx.input.has("device_group_name") {
        let group = resolve(cx, "device_groups", false, "device_group_id", "device_group_name", "name")?;
        if (filled(cx.input, "device_group_id")? || filled(cx.input, "device_group_name")?) && group.is_none() {
            return cx.fail("Device group not found.", 404, 1);
        }
        changes.push(("device_group_id", group.map_or(Val::Null, |g| g.val("id")), Cast::Plain));
    }
    if changes.is_empty() {
        return cx.fail("Nothing to assign; provide user_(id|name) or device_group_(id|name).", 422, 1);
    }
    let changed = cx.update("devices", &mut d, changes)?;
    device_updated(cx, &mut d, &changed)?;
    let rid = text(&d.val("rustdesk_id"))?;
    cx.audit("device.assign", &format!("Reassigned device {rid} (API)"), Some("device"), Some(&rid))?;
    let fresh = db::first(cx.c, r#"select * from "devices" where "id" = ? limit 1"#, &[P(d.val("id"))])?.ok_or_else(|| Fault::Other("device vanished".into()))?;
    cx.ok(device_one(cx, &fresh)?, "Device assigned.")
}

// --------------------------------------------------------------------------------------- user groups ---

fn users_count(cx: &Cx, g: &Row) -> Result<Val, Fault> {
    if let Some(n) = g.get("users_count") {
        return Ok(n.clone());
    }
    Ok(Val::Int(count(
        cx.c,
        r#"select count(*) as aggregate from "users" inner join "user_group_user" on "users"."id" = "user_group_user"."user_id" where "user_group_user"."user_group_id" = ?"#,
        &[P(g.val("id"))],
    )?))
}

const USERS_COUNT_SELECT: &str = r#""user_groups".*, (select count(*) from "users" inner join "user_group_user" on "users"."id" = "user_group_user"."user_id" where "user_groups"."id" = "user_group_user"."user_group_id") as "users_count""#;

fn ug_json(cx: &Cx, g: &Row, members: bool) -> Result<Val, Fault> {
    let mut pairs = vec![("id", g.val("id")), ("name", g.val("name")), ("note", g.val("note")), ("users_count", users_count(cx, g)?)];
    if members {
        let rows = db::rows(
            cx.c,
            r#"select "users"."id", "username" from "users" inner join "user_group_user" on "users"."id" = "user_group_user"."user_id" where "user_group_user"."user_group_id" = ? order by "username" asc"#,
            &[P(g.val("id"))],
        )?;
        pairs.push(("members", list(rows.iter().map(|u| obj(vec![("id", u.val("id")), ("username", u.val("username"))])).collect())));
    }
    Ok(obj(pairs))
}

fn ug_index(cx: &Cx) -> R {
    let mut w = W::new();
    if filled(cx.input, "name")? {
        w.add(r#""name" like ?"#, vec![P(cx.like("name")?)]);
    }
    let sql = w.sql();
    cx.paginated(USERS_COUNT_SELECT, r#""user_groups""#, &sql, w.params, r#""name" asc"#, |rows| rows.iter().map(|g| ug_json(cx, g, false)).collect())
}

fn ug_show(cx: &Cx) -> R {
    cx.ok(ug_json(cx, &cx.bound[0], true)?, "")
}

fn ug_store(cx: &Cx) -> R {
    let rules: &[(&str, &[Rule])] = &[
        ("name", &[Rule::Required, Rule::String, Rule::Max(255), Rule::Unique("user_groups", "name", None)]),
        ("note", &[Rule::Nullable, Rule::String]),
    ];
    let data = try_valid!(validated(cx, rules));
    let g = cx.create("user_groups", as_refs(&pairs(&data)))?;
    let name = text(&g.val("name"))?;
    cx.audit("group.create", &format!("Created user group {name} (API)"), Some("group"), Some(&name))?;
    cx.created(ug_json(cx, &g, false)?, "User group created.")
}

fn ug_update(cx: &Cx) -> R {
    let mut g = cx.bound[0].clone();
    let rules: &[(&str, &[Rule])] = &[
        ("name", &[Rule::Sometimes, Rule::Required, Rule::String, Rule::Max(255), Rule::Unique("user_groups", "name", Some(g.id()))]),
        ("note", &[Rule::Nullable, Rule::String]),
    ];
    let data = try_valid!(validated(cx, rules));
    let changes: Vec<(&str, Val, Cast)> = ["name", "note"].iter().filter_map(|k| data.get_str(k).map(|v| (*k, v.clone(), Cast::Plain))).collect();
    cx.update("user_groups", &mut g, changes)?;
    let name = text(&g.val("name"))?;
    cx.audit("group.update", &format!("Updated user group {name} (API)"), Some("group"), Some(&name))?;
    cx.ok(ug_json(cx, &g, false)?, "User group updated.")
}

fn ug_destroy(cx: &Cx) -> R {
    let g = &cx.bound[0];
    let name = text(&g.val("name"))?;
    db::exec(cx.c, r#"delete from "user_group_user" where "user_group_user"."user_group_id" = ?"#, &[P(g.val("id"))])?;
    db::exec(cx.c, r#"delete from "user_groups" where "id" = ?"#, &[P(g.val("id"))])?;
    cx.audit("group.delete", &format!("Deleted user group {name} (API)"), Some("group"), Some(&name))?;
    cx.ok(Val::Null, "User group deleted.")
}

fn ug_member(cx: &Cx, add: bool) -> R {
    let g = &cx.bound[0];
    let Some(user) = resolve(cx, "users", false, "user_id", "user_name", "username")? else {
        return cx.fail("User not found.", 404, 1);
    };
    let gname = text(&g.val("name"))?;
    let uname = text(&user.val("username"))?;
    if add {
        // syncWithoutDetaching([$user->id])
        let present = db::first(
            cx.c,
            r#"select * from "user_group_user" where "user_group_user"."user_group_id" = ? and "user_group_user"."user_id" = ?"#,
            &[P(g.val("id")), P(user.val("id"))],
        )?;
        if present.is_none() {
            db::exec(cx.c, r#"insert into "user_group_user" ("user_id", "user_group_id") values (?, ?)"#, &[P(user.val("id")), P(g.val("id"))])?;
        }
        cx.audit("group.update", &format!("Added {uname} to user group {gname} (API)"), Some("group"), Some(&gname))?;
        return cx.ok(ug_json(cx, g, true)?, "Member added.");
    }
    db::exec(cx.c, r#"delete from "user_group_user" where "user_group_user"."user_group_id" = ? and "user_group_user"."user_id" in (?)"#, &[P(g.val("id")), P(user.val("id"))])?;
    cx.audit("group.update", &format!("Removed {uname} from user group {gname} (API)"), Some("group"), Some(&gname))?;
    cx.ok(Val::Null, "Member removed.")
}

// -------------------------------------------------------------------------------------- device groups ---

fn devices_count(cx: &Cx, g: &Row) -> Result<Val, Fault> {
    if let Some(n) = g.get("devices_count") {
        return Ok(n.clone());
    }
    Ok(Val::Int(count(cx.c, r#"select count(*) as aggregate from "devices" where "devices"."device_group_id" = ? and "devices"."deleted_at" is null"#, &[P(g.val("id"))])?))
}

const DEVICES_COUNT_SELECT: &str = r#""device_groups".*, (select count(*) from "devices" where "device_groups"."id" = "devices"."device_group_id" and "devices"."deleted_at" is null) as "devices_count""#;

fn dg_json(cx: &Cx, g: &Row, members: bool) -> Result<Val, Fault> {
    let mut pairs = vec![("id", g.val("id")), ("name", g.val("name")), ("note", g.val("note")), ("devices_count", devices_count(cx, g)?)];
    if members {
        let rows = db::rows(
            cx.c,
            r#"select "id", "rustdesk_id", "alias", "hostname" from "devices" where "devices"."device_group_id" = ? and "devices"."device_group_id" is not null and "devices"."deleted_at" is null order by "rustdesk_id" asc"#,
            &[P(g.val("id"))],
        )?;
        pairs.push((
            "devices",
            list(rows.iter().map(|d| obj(vec![("id", d.val("id")), ("rustdesk_id", d.val("rustdesk_id")), ("alias", d.val("alias")), ("hostname", d.val("hostname"))])).collect()),
        ));
    }
    Ok(obj(pairs))
}

fn dg_index(cx: &Cx) -> R {
    let mut w = W::new();
    if filled(cx.input, "name")? {
        w.add(r#""name" like ?"#, vec![P(cx.like("name")?)]);
    }
    let sql = w.sql();
    cx.paginated(DEVICES_COUNT_SELECT, r#""device_groups""#, &sql, w.params, r#""name" asc"#, |rows| rows.iter().map(|g| dg_json(cx, g, false)).collect())
}

fn dg_show(cx: &Cx) -> R {
    cx.ok(dg_json(cx, &cx.bound[0], true)?, "")
}

fn dg_store(cx: &Cx) -> R {
    let rules: &[(&str, &[Rule])] = &[
        ("name", &[Rule::Required, Rule::String, Rule::Max(255), Rule::Unique("device_groups", "name", None)]),
        ("note", &[Rule::Nullable, Rule::String]),
    ];
    let data = try_valid!(validated(cx, rules));
    let g = cx.create("device_groups", as_refs(&pairs(&data)))?;
    let name = text(&g.val("name"))?;
    cx.audit("group.create", &format!("Created device group {name} (API)"), Some("group"), Some(&name))?;
    cx.created(dg_json(cx, &g, false)?, "Device group created.")
}

fn dg_update(cx: &Cx) -> R {
    let mut g = cx.bound[0].clone();
    let rules: &[(&str, &[Rule])] = &[
        ("name", &[Rule::Sometimes, Rule::Required, Rule::String, Rule::Max(255), Rule::Unique("device_groups", "name", Some(g.id()))]),
        ("note", &[Rule::Nullable, Rule::String]),
    ];
    let data = try_valid!(validated(cx, rules));
    let changes: Vec<(&str, Val, Cast)> = ["name", "note"].iter().filter_map(|k| data.get_str(k).map(|v| (*k, v.clone(), Cast::Plain))).collect();
    cx.update("device_groups", &mut g, changes)?;
    let name = text(&g.val("name"))?;
    cx.audit("group.update", &format!("Updated device group {name} (API)"), Some("group"), Some(&name))?;
    cx.ok(dg_json(cx, &g, false)?, "Device group updated.")
}

fn dg_destroy(cx: &Cx) -> R {
    let g = &cx.bound[0];
    let name = text(&g.val("name"))?;
    // detach the devices (keep them), then remove the folder
    db::exec(
        cx.c,
        r#"update "devices" set "device_group_id" = ?, "updated_at" = ? where "devices"."device_group_id" = ? and "devices"."device_group_id" is not null and "devices"."deleted_at" is null"#,
        &[P(Val::Null), P(Val::str(&cx.ts())), P(g.val("id"))],
    )?;
    db::exec(cx.c, r#"delete from "device_group_user_group" where "device_group_user_group"."device_group_id" = ?"#, &[P(g.val("id"))])?;
    db::exec(cx.c, r#"delete from "device_groups" where "id" = ?"#, &[P(g.val("id"))])?;
    // DeviceGroup::deleted
    cx.recompute_all()?;
    cx.audit("group.delete", &format!("Deleted device group {name} (API)"), Some("group"), Some(&name))?;
    cx.ok(Val::Null, "Device group deleted.")
}

fn dg_member(cx: &Cx, add: bool) -> R {
    let g = &cx.bound[0];
    let Some(mut device) = resolve(cx, "devices", true, "device_id", "rustdesk_id", "rustdesk_id")? else {
        return cx.fail("Device not found.", 404, 1);
    };
    let gname = text(&g.val("name"))?;
    let rid = text(&device.val("rustdesk_id"))?;
    if add {
        let changed = cx.update("devices", &mut device, vec![("device_group_id", g.val("id"), Cast::Plain)])?;
        device_updated(cx, &mut device, &changed)?;
        cx.audit("group.update", &format!("Added device {rid} to {gname} (API)"), Some("group"), Some(&gname))?;
        return cx.ok(dg_json(cx, g, true)?, "Device added.");
    }
    if device.val("device_group_id") == g.val("id") {
        let changed = cx.update("devices", &mut device, vec![("device_group_id", Val::Null, Cast::Plain)])?;
        device_updated(cx, &mut device, &changed)?;
    }
    cx.audit("group.update", &format!("Removed device {rid} from {gname} (API)"), Some("group"), Some(&gname))?;
    cx.ok(Val::Null, "Device removed.")
}

// ------------------------------------------------------------------------------------- address books ---

const BOOK_COUNTS_SELECT: &str = r#""address_books".*, (select count(*) from "address_book_entries" where "address_books"."id" = "address_book_entries"."address_book_id") as "entries_count", (select count(*) from "tags" where "address_books"."id" = "tags"."address_book_id") as "tags_count", (select count(*) from "address_book_rules" where "address_books"."id" = "address_book_rules"."address_book_id") as "rules_count""#;

fn book_count(cx: &Cx, b: &Row, key: &str, table: &str) -> Result<Val, Fault> {
    if let Some(n) = b.get(key) {
        return Ok(n.clone());
    }
    Ok(Val::Int(count(cx.c, &format!(r#"select count(*) as aggregate from "{table}" where "{table}"."address_book_id" = ? and "{table}"."address_book_id" is not null"#), &[P(b.val("id"))])?))
}

fn book_json(cx: &Cx, b: &Row, owner: Option<Option<&Row>>) -> Result<Val, Fault> {
    let owner_row;
    let owner = match owner {
        Some(o) => o,
        None => {
            owner_row = belongs_to(cx.c, "users", &b.val("owner_user_id"))?;
            owner_row.as_ref()
        }
    };
    Ok(obj(vec![
        ("id", b.val("id")),
        ("guid", b.val("guid")),
        ("name", b.val("name")),
        ("is_personal", bool_of(&b.val("is_personal"))),
        ("owner", owner.map_or(Val::Null, |u| obj(vec![("id", u.val("id")), ("username", u.val("username"))]))),
        ("note", b.val("note")),
        ("peers_count", book_count(cx, b, "entries_count", "address_book_entries")?),
        ("tags_count", book_count(cx, b, "tags_count", "tags")?),
        ("rules_count", book_count(cx, b, "rules_count", "address_book_rules")?),
    ]))
}

fn ab_index(cx: &Cx) -> R {
    let mut w = W::new();
    if filled(cx.input, "name")? {
        w.add(r#""name" like ?"#, vec![P(cx.like("name")?)]);
    }
    let sql = w.sql();
    cx.paginated(BOOK_COUNTS_SELECT, r#""address_books""#, &sql, w.params, r#""name" asc"#, |rows| {
        let owners = load_in(cx.c, "users", "id", &int_list(&rows, "owner_user_id"))?;
        rows.iter().map(|b| book_json(cx, b, Some(by_id(&owners, &b.val("owner_user_id"))))).collect()
    })
}

fn ab_show(cx: &Cx) -> R {
    cx.ok(book_json(cx, &cx.bound[0], None)?, "")
}

fn ab_store(cx: &Cx) -> R {
    let rules: &[(&str, &[Rule])] = &[
        ("name", &[Rule::Required, Rule::String, Rule::Max(255)]),
        ("owner_user_id", &[Rule::Nullable, Rule::Integer, Rule::Exists("users", "id")]),
        ("is_personal", &[Rule::Boolean]),
        ("note", &[Rule::Nullable, Rule::String]),
    ];
    let data = try_valid!(validated(cx, rules));
    let mut cols = pairs(&data);
    // AddressBook::creating
    cols.insert(0, ("guid".into(), Val::str(&laravel::uuid4())));
    // books need an owner: the token's creator when the caller names none
    match cols.iter_mut().find(|(k, _)| k == "owner_user_id") {
        Some((_, v)) if matches!(v, Val::Null) => *v = cx.user.val("id"),
        Some(_) => {}
        None => cols.push(("owner_user_id".into(), cx.user.val("id"))),
    }
    let book = cx.create("address_books", as_refs(&cols))?;
    let guid = text(&book.val("guid"))?;
    cx.audit("address-book.create", &format!("Created address book {} (API)", text(&book.val("name"))?), Some("address_book"), Some(&guid))?;
    cx.created(book_json(cx, &book, None)?, "Address book created.")
}

fn ab_update(cx: &Cx) -> R {
    let mut b = cx.bound[0].clone();
    let rules: &[(&str, &[Rule])] = &[
        ("name", &[Rule::Sometimes, Rule::Required, Rule::String, Rule::Max(255)]),
        ("owner_user_id", &[Rule::Nullable, Rule::Integer, Rule::Exists("users", "id")]),
        ("note", &[Rule::Nullable, Rule::String]),
    ];
    let data = try_valid!(validated(cx, rules));
    let changes: Vec<(&str, Val, Cast)> = ["name", "owner_user_id", "note"].iter().filter_map(|k| data.get_str(k).map(|v| (*k, v.clone(), Cast::Plain))).collect();
    cx.update("address_books", &mut b, changes)?;
    let guid = text(&b.val("guid"))?;
    cx.audit("address-book.update", &format!("Updated address book {} (API)", text(&b.val("name"))?), Some("address_book"), Some(&guid))?;
    cx.ok(book_json(cx, &b, None)?, "Address book updated.")
}

fn ab_destroy(cx: &Cx) -> R {
    let b = &cx.bound[0];
    let guid = text(&b.val("guid"))?;
    delete_book(cx, b)?;
    cx.audit("address-book.delete", &format!("Deleted address book {} (API)", text(&b.val("name"))?), Some("address_book"), Some(&guid))?;
    cx.ok(Val::Null, "Address book deleted.")
}

fn peer_json(e: &Row) -> Result<Val, Fault> {
    let tags = match laravel::from_json(&e.val("tag_ids")) {
        Val::Null => list(vec![]),
        v => v,
    };
    Ok(obj(vec![
        ("id", e.val("id")),
        ("rustdesk_id", e.val("rustdesk_id")),
        ("alias", e.val("alias")),
        ("hostname", e.val("hostname")),
        ("platform", e.val("platform")),
        ("username", e.val("username")),
        ("login_name", e.val("login_name")),
        ("force_always_relay", bool_of(&e.val("force_always_relay"))),
        ("rdp_port", e.val("rdp_port")),
        ("rdp_username", e.val("rdp_username")),
        ("tags", tags),
    ]))
}

fn ab_peers(cx: &Cx) -> R {
    let rows = db::rows(cx.c, r#"select * from "address_book_entries" where "address_book_entries"."address_book_id" = ? and "address_book_entries"."address_book_id" is not null order by "rustdesk_id" asc"#, &[P(cx.bound[0].val("id"))])?;
    cx.ok(list(rows.iter().map(peer_json).collect::<Result<_, _>>()?), "")
}

fn validate_peer(cx: &Cx, partial: bool) -> Result<Result<Arr, Reply>, Fault> {
    let id_rules: &[Rule] = if partial { &[Rule::Sometimes, Rule::String, Rule::Max(255)] } else { &[Rule::Required, Rule::String, Rule::Max(255)] };
    let rules: &[(&str, &[Rule])] = &[
        ("rustdesk_id", id_rules),
        ("alias", &[Rule::Nullable, Rule::String, Rule::Max(255)]),
        ("hostname", &[Rule::Nullable, Rule::String, Rule::Max(255)]),
        ("platform", &[Rule::Nullable, Rule::String, Rule::Max(64)]),
        ("username", &[Rule::Nullable, Rule::String, Rule::Max(255)]),
        ("login_name", &[Rule::Nullable, Rule::String, Rule::Max(255)]),
        ("force_always_relay", &[Rule::Boolean]),
        ("rdp_port", &[Rule::Nullable, Rule::Integer]),
        ("rdp_username", &[Rule::Nullable, Rule::String, Rule::Max(255)]),
        ("tag_ids", &[Rule::Nullable, Rule::Array]),
    ];
    validated(cx, rules)
}

fn ab_peer_store(cx: &Cx) -> R {
    let b = &cx.bound[0];
    let data = try_valid!(validate_peer(cx, false));
    let mut cols: Vec<(String, Val)> = vec![];
    for (k, v) in pairs(&data) {
        let v = if k == "tag_ids" { to_json_text(&v)? } else { v };
        cols.push((k, v));
    }
    cols.push(("address_book_id".into(), b.val("id")));
    let peer = cx.create("address_book_entries", as_refs(&cols))?;
    let guid = text(&b.val("guid"))?;
    cx.audit("address-book.peer-add", &format!("Added peer {} to {} (API)", text(&peer.val("rustdesk_id"))?, text(&b.val("name"))?), Some("address_book"), Some(&guid))?;
    cx.created(peer_json(&peer)?, "Peer added.")
}

fn ab_peer_update(cx: &Cx) -> R {
    let b = &cx.bound[0];
    let mut peer = cx.bound[1].clone();
    if peer.val("address_book_id") != b.val("id") {
        return cx.abort_404();
    }
    let data = try_valid!(validate_peer(cx, true));
    let mut changes: Vec<(String, Val, Cast)> = vec![];
    for (k, v) in pairs(&data) {
        changes.push(match k.as_str() {
            "tag_ids" => (k, to_json_text(&v)?, Cast::Json),
            "force_always_relay" => (k, v, Cast::Bool),
            _ => (k, v, Cast::Plain),
        });
    }
    let refs: Vec<(&str, Val, Cast)> = changes.iter().map(|(k, v, c)| (k.as_str(), v.clone(), *c)).collect();
    cx.update("address_book_entries", &mut peer, refs)?;
    let guid = text(&b.val("guid"))?;
    cx.audit("address-book.peer-update", &format!("Updated peer {} (API)", text(&peer.val("rustdesk_id"))?), Some("address_book"), Some(&guid))?;
    cx.ok(peer_json(&peer)?, "Peer updated.")
}

fn ab_peer_destroy(cx: &Cx) -> R {
    let b = &cx.bound[0];
    let peer = &cx.bound[1];
    if peer.val("address_book_id") != b.val("id") {
        return cx.abort_404();
    }
    let rid = text(&peer.val("rustdesk_id"))?;
    db::exec(cx.c, r#"delete from "address_book_entries" where "id" = ?"#, &[P(peer.val("id"))])?;
    let guid = text(&b.val("guid"))?;
    cx.audit("address-book.peer-delete", &format!("Deleted peer {rid} (API)"), Some("address_book"), Some(&guid))?;
    cx.ok(Val::Null, "Peer deleted.")
}

fn tag_json(t: &Row) -> Val {
    obj(vec![("id", t.val("id")), ("name", t.val("name")), ("color", t.val("color"))])
}

fn ab_tags(cx: &Cx) -> R {
    let rows = db::rows(cx.c, r#"select * from "tags" where "tags"."address_book_id" = ? and "tags"."address_book_id" is not null order by "name" asc"#, &[P(cx.bound[0].val("id"))])?;
    cx.ok(list(rows.iter().map(tag_json).collect()), "")
}

fn ab_tag_store(cx: &Cx) -> R {
    let b = &cx.bound[0];
    let rules: &[(&str, &[Rule])] = &[("name", &[Rule::Required, Rule::String, Rule::Max(255)]), ("color", &[Rule::Nullable, Rule::String, Rule::Max(32)])];
    let data = try_valid!(validated(cx, rules));
    let mut cols = pairs(&data);
    cols.push(("address_book_id".into(), b.val("id")));
    let tag = cx.create("tags", as_refs(&cols))?;
    let guid = text(&b.val("guid"))?;
    cx.audit("address-book.tag-add", &format!("Added tag {} (API)", text(&tag.val("name"))?), Some("address_book"), Some(&guid))?;
    cx.created(tag_json(&tag), "Tag added.")
}

fn ab_tag_update(cx: &Cx) -> R {
    let b = &cx.bound[0];
    let mut tag = cx.bound[1].clone();
    if tag.val("address_book_id") != b.val("id") {
        return cx.abort_404();
    }
    let rules: &[(&str, &[Rule])] = &[("name", &[Rule::Sometimes, Rule::Required, Rule::String, Rule::Max(255)]), ("color", &[Rule::Nullable, Rule::String, Rule::Max(32)])];
    let data = try_valid!(validated(cx, rules));
    let changes: Vec<(&str, Val, Cast)> = ["name", "color"].iter().filter_map(|k| data.get_str(k).map(|v| (*k, v.clone(), Cast::Plain))).collect();
    cx.update("tags", &mut tag, changes)?;
    let guid = text(&b.val("guid"))?;
    cx.audit("address-book.tag-update", &format!("Updated tag {} (API)", text(&tag.val("name"))?), Some("address_book"), Some(&guid))?;
    cx.ok(tag_json(&tag), "Tag updated.")
}

fn ab_tag_destroy(cx: &Cx) -> R {
    let b = &cx.bound[0];
    let tag = &cx.bound[1];
    if tag.val("address_book_id") != b.val("id") {
        return cx.abort_404();
    }
    let name = text(&tag.val("name"))?;
    db::exec(cx.c, r#"delete from "tags" where "id" = ?"#, &[P(tag.val("id"))])?;
    let guid = text(&b.val("guid"))?;
    cx.audit("address-book.tag-delete", &format!("Deleted tag {name} (API)"), Some("address_book"), Some(&guid))?;
    cx.ok(Val::Null, "Tag deleted.")
}

fn rule_json(r: &Row) -> Val {
    obj(vec![("id", r.val("id")), ("subject_type", r.val("subject_type")), ("subject_id", r.val("subject_id")), ("permission", Val::Int(r.val("permission").to_int()))])
}

fn ab_rules(cx: &Cx) -> R {
    let rows = db::rows(cx.c, r#"select * from "address_book_rules" where "address_book_rules"."address_book_id" = ? and "address_book_rules"."address_book_id" is not null"#, &[P(cx.bound[0].val("id"))])?;
    cx.ok(list(rows.iter().map(rule_json).collect()), "")
}

const SUBJECTS: &[&str] = &["everyone", "user", "group"];
const PERMISSIONS: &[&str] = &["1", "2", "3"];

fn ab_rule_store(cx: &Cx) -> R {
    let b = &cx.bound[0];
    let rules: &[(&str, &[Rule])] = &[
        ("subject_type", &[Rule::Required, Rule::In(SUBJECTS)]),
        ("subject_id", &[Rule::Nullable, Rule::Integer]),
        ("permission", &[Rule::Required, Rule::Integer, Rule::In(PERMISSIONS)]),
    ];
    let data = try_valid!(validated(cx, rules));
    let mut cols = pairs(&data);
    cols.push(("address_book_id".into(), b.val("id")));
    if data.get_str("subject_type") == Some(&Val::str("everyone")) {
        match cols.iter_mut().find(|(k, _)| k == "subject_id") {
            Some((_, v)) => *v = Val::Null,
            None => cols.push(("subject_id".into(), Val::Null)),
        }
    }
    let rule = cx.create("address_book_rules", as_refs(&cols))?;
    let guid = text(&b.val("guid"))?;
    cx.audit("address-book.rule-add", "Added AB rule (API)", Some("address_book"), Some(&guid))?;
    cx.created(rule_json(&rule), "Rule added.")
}

fn ab_rule_update(cx: &Cx) -> R {
    let b = &cx.bound[0];
    let mut rule = cx.bound[1].clone();
    if rule.val("address_book_id") != b.val("id") {
        return cx.abort_404();
    }
    let rules: &[(&str, &[Rule])] = &[
        ("subject_type", &[Rule::Sometimes, Rule::Required, Rule::In(SUBJECTS)]),
        ("subject_id", &[Rule::Nullable, Rule::Integer]),
        ("permission", &[Rule::Sometimes, Rule::Required, Rule::Integer, Rule::In(PERMISSIONS)]),
    ];
    let data = try_valid!(validated(cx, rules));
    let changes: Vec<(&str, Val, Cast)> = ["subject_type", "subject_id", "permission"].iter().filter_map(|k| data.get_str(k).map(|v| (*k, v.clone(), Cast::Plain))).collect();
    cx.update("address_book_rules", &mut rule, changes)?;
    let guid = text(&b.val("guid"))?;
    cx.audit("address-book.rule-update", "Updated AB rule (API)", Some("address_book"), Some(&guid))?;
    cx.ok(rule_json(&rule), "Rule updated.")
}

fn ab_rule_destroy(cx: &Cx) -> R {
    let b = &cx.bound[0];
    let rule = &cx.bound[1];
    if rule.val("address_book_id") != b.val("id") {
        return cx.abort_404();
    }
    db::exec(cx.c, r#"delete from "address_book_rules" where "id" = ?"#, &[P(rule.val("id"))])?;
    let guid = text(&b.val("guid"))?;
    cx.audit("address-book.rule-delete", "Deleted AB rule (API)", Some("address_book"), Some(&guid))?;
    cx.ok(Val::Null, "Rule deleted.")
}

// ---------------------------------------------------------------------------------------------- audits ---

/// `dateRange`: `whereDate('created_at', '>=', date_from)` and `'<=' date_to`.
fn date_range(cx: &Cx, w: &mut W) -> Result<(), Fault> {
    for (key, op) in [("date_from", ">="), ("date_to", "<=")] {
        if filled(cx.input, key)? {
            let v = cx.input.query(key).cloned().unwrap_or(Val::Null);
            w.add(&format!(r#"strftime('%Y-%m-%d', "created_at") {op} cast(? as text)"#), vec![P(flat_first(&v))]);
        }
    }
    Ok(())
}

fn like_filter(cx: &Cx, w: &mut W, key: &str, col: &str) -> Result<(), Fault> {
    if filled(cx.input, key)? {
        w.add(&format!(r#""{col}" like ?"#), vec![P(cx.like(key)?)]);
    }
    Ok(())
}

fn eq_filter(cx: &Cx, w: &mut W, key: &str, col: &str) -> Result<(), Fault> {
    if filled(cx.input, key)? {
        let v = cx.input.query(key).cloned().unwrap_or(Val::Null);
        let (sql, p) = eq(&format!(r#""{col}""#), &v);
        w.add(&sql, p);
    }
    Ok(())
}

fn peer_filter(cx: &Cx, w: &mut W) -> Result<(), Fault> {
    if filled(cx.input, "peer")? {
        let s = cx.like("peer")?;
        w.add(r#"("from_peer" like ? or "from_name" like ?)"#, vec![P(s.clone()), P(s)]);
    }
    Ok(())
}

fn au_conn(cx: &Cx) -> R {
    let mut w = W::new();
    like_filter(cx, &mut w, "id", "rustdesk_id")?;
    peer_filter(cx, &mut w)?;
    eq_filter(cx, &mut w, "action", "action")?;
    date_range(cx, &mut w)?;
    let sql = w.sql();
    cx.paginated("*", r#""audit_connections""#, &sql, w.params, r#""id" desc"#, |rows| {
        let users = load_in(cx.c, "users", "id", &int_list(&rows, "note_user_id"))?;
        rows.iter()
            .map(|r| {
                Ok(obj(vec![
                    ("id", r.val("id")),
                    ("action", r.val("action")),
                    ("rustdesk_id", r.val("rustdesk_id")),
                    ("from_peer", r.val("from_peer")),
                    ("from_name", r.val("from_name")),
                    ("conn_type", r.val("conn_type")),
                    ("ip", r.val("ip")),
                    ("session_id", r.val("session_id")),
                    ("created_at", iso(&r.val("created_at"))?),
                    ("closed_at", iso(&r.val("closed_at"))?),
                    ("note", r.val("note")),
                    ("note_by", by_id(&users, &r.val("note_user_id")).map_or(Val::Null, |u| u.val("username"))),
                    ("noted_at", iso(&r.val("noted_at"))?),
                ]))
            })
            .collect()
    })
}

/// `AuditFileTransfer::transferredFiles()`
fn transferred_files(r: &Row) -> Result<Vec<Val>, Fault> {
    let info = r.val("info").to_php_string()?;
    let decoded = php::json_decode(&info, &php::JsonOpts::default());
    let files = match decoded {
        Some(Val::Arr(a)) => match a.get_str("files") {
            Some(Val::Arr(f)) => Some(f.clone()),
            _ => None,
        },
        _ => None,
    };
    let mut out = vec![];
    for (_, file) in files.iter().flat_map(|f| f.iter()) {
        let name = match file {
            Val::Arr(a) => a.get(&php::Key::Int(0)).cloned().unwrap_or(Val::str("")),
            _ => Val::str(""),
        };
        if let Val::Str(n) = &name {
            if !n.is_empty() {
                let size = match file {
                    Val::Arr(a) => a.get(&php::Key::Int(1)).map_or(0, |v| v.to_int()),
                    _ => 0,
                };
                out.push(obj(vec![("name", name.clone()), ("size", Val::Int(size))]));
            }
        }
    }
    Ok(out)
}

fn au_file(cx: &Cx) -> R {
    let mut w = W::new();
    like_filter(cx, &mut w, "id", "rustdesk_id")?;
    peer_filter(cx, &mut w)?;
    eq_filter(cx, &mut w, "direction", "direction")?;
    date_range(cx, &mut w)?;
    let sql = w.sql();
    cx.paginated("*", r#""audit_file_transfers""#, &sql, w.params, r#""id" desc"#, |rows| {
        rows.iter()
            .map(|r| {
                let files = transferred_files(r)?;
                let clipboard = r.val("path").to_php_string()?.is_empty() && !files.is_empty();
                Ok(obj(vec![
                    ("id", r.val("id")),
                    ("rustdesk_id", r.val("rustdesk_id")),
                    ("from_peer", r.val("from_peer")),
                    ("from_name", r.val("from_name")),
                    ("path", r.val("path")),
                    ("direction", r.val("direction")),
                    ("is_file", bool_of(&r.val("is_file"))),
                    ("file_count", r.val("file_count")),
                    ("ip", r.val("ip")),
                    ("created_at", iso(&r.val("created_at"))?),
                    ("files", list(files)),
                    ("clipboard", Val::Bool(clipboard)),
                ]))
            })
            .collect()
    })
}

/// `AlarmLog::TYPES[$typ]['label'] ?? 'Type '.$typ`
fn alarm_label(typ: &Val) -> String {
    let known = match typ {
        Val::Int(0) => Some("IP whitelist block"),
        Val::Int(1) => Some("Many failed attempts (>30)"),
        Val::Int(2) => Some("Rapid access attempts"),
        Val::Int(6) => Some("IPv6 prefix attempts exceeded"),
        Val::Int(7) => Some("Terminal login backoff"),
        Val::Int(8) => Some("Terminal login concurrency"),
        Val::Int(9) => Some("Session scope violation"),
        Val::Int(10) => Some("ID whitelist block"),
        Val::Int(100) => Some("Console brute force"),
        Val::Int(101) => Some("Console password spraying"),
        Val::Int(102) => Some("Session refused: outside the person's access"),
        Val::Int(103) => Some("Session closed: access removed"),
        _ => None,
    };
    match known {
        Some(l) => l.to_string(),
        None => format!("Type {}", typ.to_php_string().map(|s| String::from_utf8_lossy(&s).into_owned()).unwrap_or_default()),
    }
}

fn au_alarm(cx: &Cx) -> R {
    let mut w = W::new();
    like_filter(cx, &mut w, "id", "rustdesk_id")?;
    if filled(cx.input, "typ")? {
        let typ = cx.input.query("typ").map_or(0, |v| v.to_int());
        w.add(r#""typ" = ?"#, vec![P(Val::Int(typ))]);
    }
    date_range(cx, &mut w)?;
    let sql = w.sql();
    cx.paginated("*", r#""alarm_logs""#, &sql, w.params, r#""id" desc"#, |rows| {
        rows.iter()
            .map(|r| {
                // the `integer` cast: null stays null, anything else is (int)
                let typ = match r.val("typ") {
                    Val::Null => Val::Null,
                    v => Val::Int(v.to_int()),
                };
                Ok(obj(vec![
                    ("id", r.val("id")),
                    ("rustdesk_id", r.val("rustdesk_id")),
                    ("typ", typ.clone()),
                    ("type_label", Val::str(&alarm_label(&typ))),
                    ("info", r.val("info")),
                    ("created_at", iso(&r.val("created_at"))?),
                ]))
            })
            .collect()
    })
}

fn au_console(cx: &Cx) -> R {
    let mut w = W::new();
    like_filter(cx, &mut w, "action", "action")?;
    if filled(cx.input, "operator")? {
        let s = cx.like("operator")?;
        w.add(r#"("username" like ? or "summary" like ?)"#, vec![P(s.clone()), P(s)]);
    }
    date_range(cx, &mut w)?;
    let sql = w.sql();
    cx.paginated("*", r#""console_audits""#, &sql, w.params, r#""id" desc"#, |rows| {
        rows.iter()
            .map(|r| {
                Ok(obj(vec![
                    ("id", r.val("id")),
                    ("username", r.val("username")),
                    ("action", r.val("action")),
                    ("target_type", r.val("target_type")),
                    ("target_id", r.val("target_id")),
                    ("summary", r.val("summary")),
                    ("ip", r.val("ip")),
                    ("created_at", iso(&r.val("created_at"))?),
                ]))
            })
            .collect()
    })
}
