//! Address books (Livewire `AddressBookManager`): the personal and shared books a person can see, the selected
//! book's tags and entries, and its sharing rules.
//!
//! State is the URL (`?tab=`, `?selectedBookId=`, `?search=`, `?page=`, and `?modal=` with `&entry=` while a dialog is
//! open); every change is a form post that redirects back. The tier a person holds on the book (read, read/write,
//! full) is clamped to read when their role has no write on address books, and every mutator checks it again.

use super::kit::*;
use super::{paginate, Ctx, Reply, Req};
use crate::laravel::Cast;
use crate::php::{Fault, Val};
use crate::sqlite::{self as db, Row, P};
use rusqlite::Connection;
use serde_json::{json, Map, Value};

const PER_PAGE: i64 = 15;

#[derive(Clone, Default)]
struct St {
    tab: String,
    book: i64,
    /// the book was named in the URL as `0`: nothing is selected and the other tab is not tried
    none: bool,
    search: String,
    page: i64,
}

impl St {
    fn from(req: &Req) -> St {
        let tab = q(req, "tab");
        St {
            tab: if tab == "personal" || tab == "shared" { tab } else { String::new() },
            book: qint(req, "selectedBookId"),
            none: q(req, "selectedBookId") == "0",
            search: q(req, "search"),
            page: q(req, "page").parse::<i64>().ok().filter(|n| *n >= 1).map_or(1, |n| n.min(1_000_000_000)),
        }
    }

    fn query(&self, with_page: bool) -> String {
        let mut pairs: Vec<(&str, Vec<u8>)> = vec![];
        if !self.tab.is_empty() {
            pairs.push(("tab", self.tab.clone().into_bytes()));
        }
        pairs.push(("selectedBookId", self.book.to_string().into_bytes()));
        if !self.search.is_empty() {
            pairs.push(("search", self.search.clone().into_bytes()));
        }
        if with_page && self.page > 1 {
            pairs.push(("page", self.page.to_string().into_bytes()));
        }
        crate::laravel::http_build_query(&pairs.iter().map(|(k, v)| (*k, v.as_slice())).collect::<Vec<_>>())
    }

    fn url(&self) -> String {
        format!("/address-books?{}", self.query(true))
    }

    fn from_back(back: &str) -> St {
        let input = crate::laravel::Input::new("GET", None, Some(back), b"");
        let req = Req { method: "GET".into(), path: "/address-books".into(), htmx: false, headers: Default::default(), input };
        St::from(&req)
    }
}

fn join(url: &str, extra: &str) -> String {
    if url.contains('?') { format!("{url}&{extra}") } else { format!("{url}?{extra}") }
}

/// What the open dialog holds: the fields as typed and the messages per field.
struct Dialog {
    kind: String,
    entry: i64,
    values: Map<String, Value>,
    errors: Map<String, Value>,
}

/// `color` (a u32 ARGB) as `#RRGGBB`
fn color_to_hex(color: i64) -> String {
    if color == 0 { "#6C757D".into() } else { format!("#{:06X}", color & 0xFFFFFF) }
}

fn hex_to_color(hex: &str) -> i64 {
    let rgb = i64::from_str_radix(hex.trim_start_matches('#'), 16).unwrap_or(0) & 0xFFFFFF;
    0xFF000000 | rgb
}

fn chip_text(hex: &str) -> &'static str {
    let rgb = i64::from_str_radix(hex.trim_start_matches('#'), 16).unwrap_or(0);
    let luma = 0.299 * ((rgb >> 16) & 0xFF) as f64 + 0.587 * ((rgb >> 8) & 0xFF) as f64 + 0.114 * (rgb & 0xFF) as f64;
    if luma > 160.0 { "text-dark" } else { "text-white" }
}

fn tag_ids_of(e: &Row) -> Vec<i64> {
    let raw = s(e, "tag_ids");
    match serde_json::from_str::<Value>(&raw) {
        Ok(Value::Array(a)) => a.iter().map(|v| match v { Value::Number(n) => n.as_i64().unwrap_or(0), Value::String(t) => crate::php::str_to_int(t.as_bytes()), _ => 0 }).collect(),
        _ => vec![],
    }
}

fn json_ids(ids: &[i64]) -> String {
    format!("[{}]", ids.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(","))
}

/// `AddressBook::scopeVisibleTo`: the where clause (empty for an administrator).
fn visible_sql(ctx: &Ctx, c: &Connection) -> Result<(String, Vec<P>), Fault> {
    if ctx.is_admin() {
        return Ok((String::new(), vec![]));
    }
    let groups = user_group_ids(c, ctx.uid())?;
    let mut params = vec![P(Val::Int(ctx.uid())), P(Val::Bool(false)), P(Val::str("everyone")), P(Val::str("user")), P(Val::Int(ctx.uid())), P(Val::str("group"))];
    let in_groups = if groups.is_empty() {
        "0 = 1".to_string()
    } else {
        params.extend(ints_val(&groups));
        format!(r#""subject_id" in ({})"#, marks(groups.len()))
    };
    Ok((
        format!(
            r#" where ("owner_user_id" = ? or ("is_personal" = ? and exists (select * from "address_book_rules" where "address_books"."id" = "address_book_rules"."address_book_id" and ("subject_type" = ? or ("subject_type" = ? and "subject_id" = ?) or ("subject_type" = ? and {in_groups})))))"#
        ),
        params,
    ))
}

fn visible_books(ctx: &Ctx, c: &Connection) -> Result<Vec<Row>, Fault> {
    let (w, params) = visible_sql(ctx, c)?;
    db::rows(
        c,
        &format!(
            r#"select "address_books".*, (select count(*) from "address_book_entries" where "address_books"."id" = "address_book_entries"."address_book_id") as "entries_count", (select count(*) from "tags" where "address_books"."id" = "tags"."address_book_id") as "tags_count" from "address_books"{w} order by "is_personal" desc, "name" asc"#
        ),
        &params,
    )
}

fn visible_book(ctx: &Ctx, c: &Connection, id: i64) -> Result<Option<Row>, Fault> {
    if id <= 0 {
        return Ok(None);
    }
    let (w, mut params) = visible_sql(ctx, c)?;
    let w = if w.is_empty() { r#" where "id" = ?"#.to_string() } else { format!("{w} and \"id\" = ?") };
    params.push(P(Val::Int(id)));
    db::first(c, &format!(r#"select * from "address_books"{w} limit 1"#), &params)
}

/// `permission()`: the tier, clamped to read when the role has no write on address books.
fn permission(ctx: &Ctx, c: &Connection, book: Option<&Row>) -> Result<i64, Fault> {
    let p = match book {
        Some(b) => book_permission(c, &ctx.user, b, None)?,
        None => 0,
    };
    Ok(if ctx.allows("address_book", "rw") { p } else { p.min(PERM_READ) })
}

fn is_default_name(b: &Row) -> bool {
    s(b, "name").trim().eq_ignore_ascii_case("My address book")
}

fn owner_name(owners: &[Row], b: &Row) -> Option<String> {
    owners.iter().find(|o| !b.is_null("owner_user_id") && o.id() == b.val("owner_user_id").to_int()).map(|o| s(o, "username"))
}

fn lower(v: &str) -> String {
    v.to_lowercase()
}

pub fn index(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    let st = St::from(req);
    let modal_kind = q(req, "modal");
    let entry_id = qint(req, "entry");
    let dialog = if modal_kind.is_empty() { None } else { Some(Dialog { kind: modal_kind, entry: entry_id, values: Map::new(), errors: Map::new() }) };
    render(ctx, c, st, 200, dialog)
}

fn render(ctx: &Ctx, c: &Connection, mut st: St, status: u16, dialog: Option<Dialog>) -> Result<Reply, Fault> {
    // mount(): the person's own book exists, then the tab and the selection settle
    personal_book(ctx, c)?;
    let all = visible_books(ctx, c)?;
    let owners = db::rows(c, r#"select "id", "username", "name" from "users" order by "username" asc"#, &[])?;
    let mut personal: Vec<&Row> = all.iter().filter(|b| b.val("is_personal").to_bool()).collect();
    personal.sort_by_key(|b| lower(&owner_name(&owners, b).unwrap_or_default()));
    let shared: Vec<&Row> = all.iter().filter(|b| !b.val("is_personal").to_bool()).collect();
    let default_of = |tab: &str| -> i64 {
        // orderedBooks()->where('is_personal', tab == personal)->value('id'): first by name, personal first
        all.iter().find(|b| b.val("is_personal").to_bool() == (tab == "personal")).map(|b| b.id()).unwrap_or(0)
    };
    let mut tab = if st.tab.is_empty() { (if ctx.is_admin() { "shared" } else { "personal" }).to_string() } else { st.tab.clone() };
    let mut selected = 0;
    if st.book > 0 && all.iter().any(|b| b.id() == st.book) {
        selected = st.book;
        let b = all.iter().find(|b| b.id() == selected).unwrap();
        tab = if b.val("is_personal").to_bool() { "personal".into() } else { "shared".into() };
    } else if !st.none {
        selected = default_of(&tab);
        if selected == 0 {
            tab = if tab == "shared" { "personal".into() } else { "shared".into() };
            selected = default_of(&tab);
        }
    }
    st.tab = tab.clone();
    st.book = selected;
    let book_all = all.iter().find(|b| b.id() == selected);
    let book = match book_all {
        Some(b) => Some(b.clone()),
        None => None,
    };
    let perm = permission(ctx, c, book.as_ref())?;
    let can_write = perm >= PERM_READ_WRITE;
    let can_manage = perm >= PERM_FULL;
    let books: Vec<&Row> = if tab == "personal" { personal.clone() } else { shared.clone() };

    let book_items: Vec<Value> = books
        .iter()
        .map(|b| {
            let owner = owner_name(&owners, b);
            let n = b.val("entries_count").to_int();
            let t = b.val("tags_count").to_int();
            let counts = format!("{n} {} · {t} {}", plural("entry", n), plural("tag", t));
            let (title, sub, label) = if tab == "personal" {
                let o = owner.clone().unwrap_or_else(|| "unknown".into());
                let pre = if is_default_name(b) { String::new() } else { format!("{} · ", s(b, "name")) };
                (o.clone(), format!("{pre}{counts}"), format!("{o}{}", if is_default_name(b) { String::new() } else { format!(" — {}", s(b, "name")) }))
            } else {
                let o = owner.clone().unwrap_or_else(|| "unknown".into());
                (s(b, "name"), format!("{o} · {counts}"), format!("{} ({})", s(b, "name"), owner.clone().unwrap_or_else(|| "?".into())))
            };
            json!({"id": b.id(), "active": b.id() == selected, "title": title, "sub": sub, "label": label, "url": format!("/address-books?selectedBookId={}&tab={}", b.id(), tab)})
        })
        .collect();

    // the selected book
    let mut tags: Vec<Row> = vec![];
    let mut entries: Vec<Row> = vec![];
    let mut total = 0;
    let mut rules: Vec<Row> = vec![];
    if let Some(b) = &book {
        tags = db::rows(c, r#"select * from "tags" where "address_book_id" = ? order by "name" asc"#, &[P(Val::Int(b.id()))])?;
        let mut w = vec![r#""address_book_id" = ?"#.to_string()];
        let mut params = vec![P(Val::Int(b.id()))];
        if !st.search.is_empty() {
            let term = format!("%{}%", st.search.trim());
            w.push(r#"("rustdesk_id" like ? or "hostname" like ? or "alias" like ? or "username" like ?)"#.into());
            params.extend((0..4).map(|_| P(Val::str(&term))));
        }
        let where_sql = w.join(" and ");
        total = count(c, &format!(r#"select count(*) as aggregate from "address_book_entries" where {where_sql}"#), &params)?;
        entries = db::rows(
            c,
            &format!(r#"select * from "address_book_entries" where {where_sql} order by CASE WHEN hostname IS NULL OR hostname = '' THEN 1 ELSE 0 END, "hostname" asc, "rustdesk_id" asc limit {PER_PAGE} offset {}"#, (st.page - 1) * PER_PAGE),
            &params,
        )?;
        if !b.val("is_personal").to_bool() {
            rules = db::rows(c, r#"select * from "address_book_rules" where "address_book_id" = ? order by "id" asc"#, &[P(Val::Int(b.id()))])?;
        }
    }
    let tag_json = |t: &Row| {
        let hex = color_to_hex(t.val("color").to_int());
        json!({"id": t.id(), "name": s(t, "name"), "hex": hex, "text": chip_text(&hex)})
    };
    let tag_items: Vec<Value> = tags.iter().map(tag_json).collect();
    let now = ctx.now;
    let link_scheme_ok = true;
    let _ = link_scheme_ok;
    let mut entry_items = vec![];
    for e in &entries {
        let platform = s(e, "platform");
        let ids = tag_ids_of(e);
        let chips: Vec<Value> = ids.iter().filter_map(|id| tags.iter().find(|t| t.id() == *id)).map(tag_json).collect();
        let ucfirst = { let mut cs = platform.chars(); cs.next().map(|f| f.to_uppercase().collect::<String>() + cs.as_str()).unwrap_or_default() };
        let title = { let h = s(e, "hostname"); if truthy(&h) { h } else { s(e, "rustdesk_id") } };
        let plat = platform_ui(&(if truthy(&platform) { platform.clone() } else { "unknown".to_string() }));
        let link = client_link(c, &s(e, "rustdesk_id"))?;
        let created = human(e, "created_at", now, false);
        let created_short = human(e, "created_at", now, true).unwrap_or_default();
        let created_at = ts_of(e, "created_at").map(crate::laravel::ts).unwrap_or_default();
        entry_items.push(json!({
            "id": e.id(), "rustdesk_id": s(e, "rustdesk_id"), "title": title, "alias": s(e, "alias"), "username": s(e, "username"), "platform": plat,
            "platform_name": ucfirst, "link": link, "chips": chips, "created": created, "created_short": created_short, "created_at": created_at,
        }));
    }
    let users = db::rows(c, r#"select "id", "username", "name" from "users" order by "username" asc"#, &[])?;
    let groups = db::rows(c, r#"select "id", "name" from "user_groups" order by "name" asc"#, &[])?;
    let rule_items: Vec<Value> = rules
        .iter()
        .map(|r| {
            let t = s(r, "subject_type");
            let sid = r.val("subject_id").to_int();
            let (icon, label) = if t == "everyone" {
                ("ri-global-line", "Everyone".to_string())
            } else if t == "user" {
                ("ri-user-line", users.iter().find(|u| u.id() == sid).map(|u| s(u, "username")).unwrap_or_else(|| format!("user #{sid}")))
            } else {
                ("ri-team-line", groups.iter().find(|g| g.id() == sid).map(|g| s(g, "name")).unwrap_or_else(|| format!("group #{sid}")))
            };
            json!({"id": r.id(), "icon": icon, "label": label, "permission": r.val("permission").to_int()})
        })
        .collect();
    let page = paginate::page(st.page, PER_PAGE, total, entries.len() as i64);

    // the dialog
    let url = st.url();
    let back = st.query(true);
    let modal = match &dialog {
        None => json!({"kind": ""}),
        Some(d) => {
            let allowed = match d.kind.as_str() {
                "newBook" => ctx.allows("address_book", "rw"),
                "renameBook" => can_manage && book.as_ref().map_or(false, |b| !b.val("is_personal").to_bool()),
                "addTag" => can_manage,
                "entry" => can_write,
                "addRule" => can_manage && book.as_ref().map_or(false, |b| !b.val("is_personal").to_bool()),
                _ => false,
            };
            if !allowed {
                json!({"kind": ""})
            } else {
                let mut values = d.values.clone();
                let editing = if d.kind == "entry" && d.entry > 0 { entries_for(c, book.as_ref(), d.entry)? } else { None };
                if values.is_empty() {
                    match d.kind.as_str() {
                        "newBook" => { values.insert("book_name".into(), json!("")); values.insert("book_note".into(), json!("")); }
                        "renameBook" => { let b = book.as_ref().unwrap(); values.insert("book_name".into(), json!(s(b, "name"))); values.insert("book_note".into(), json!(s(b, "note"))); }
                        "addTag" => { values.insert("tag_name".into(), json!("")); values.insert("tag_color".into(), json!("#2563EB")); }
                        "entry" => match &editing {
                            Some(e) => { values.insert("rustdesk_id".into(), json!(s(e, "rustdesk_id"))); values.insert("alias".into(), json!(s(e, "alias"))); values.insert("tag_ids".into(), json!(tag_ids_of(e))); }
                            None => { values.insert("rustdesk_id".into(), json!("")); values.insert("alias".into(), json!("")); values.insert("tag_ids".into(), json!([])); }
                        },
                        "addRule" => { values.insert("rule_type".into(), json!("everyone")); values.insert("rule_subject".into(), json!(0)); values.insert("rule_permission".into(), json!(1)); }
                        _ => {}
                    }
                }
                let mut errors = d.errors.clone();
                for k in ["book_name", "book_note", "tag_name", "tag_color", "rustdesk_id", "alias", "rule_type", "rule_subject", "rule_permission"] {
                    errors.entry(k.to_string()).or_insert(Value::Null);
                }
                json!({
                    "kind": d.kind, "values": values, "errors": errors, "return": url, "entry_id": editing.as_ref().map(|e| e.id()).unwrap_or(0),
                    "title": match d.kind.as_str() { "newBook" => "New shared address book", "renameBook" => "Rename address book", "addTag" => "Add tag", "entry" => if editing.is_some() { "Edit entry" } else { "Add entry" }, _ => "Add sharing rule" },
                    "users": users.iter().map(|u| { let n = s(u, "name"); json!({"id": u.id(), "label": if truthy(&n) { format!("{} — {n}", s(u, "username")) } else { s(u, "username") }}) }).collect::<Vec<_>>(),
                    "groups": groups.iter().map(|g| json!({"id": g.id(), "name": s(g, "name")})).collect::<Vec<_>>(),
                })
            }
        }
    };

    let layout = ctx.layout(c, "address-books", "Address Books", "Manage")?;
    let personal_hidden = |b: &Row| b.val("is_personal").to_bool();
    let orphan = book.as_ref().map_or(false, |b| b.val("is_personal").to_bool() && find(c, "users", b.val("owner_user_id").to_int()).ok().flatten().is_none());
    let _ = personal_hidden;
    let owner = book.as_ref().and_then(|b| owner_name(&owners, b));
    let book_json = book.as_ref().map(|b| {
        json!({"id": b.id(), "name": s(b, "name"), "note": s(b, "note"), "personal": b.val("is_personal").to_bool(), "orphan": orphan, "owner": owner.unwrap_or_else(|| "unknown".into())})
    });
    let page_json = json!({
        "tab": tab, "tab_personal": "/address-books?tab=personal", "tab_shared": "/address-books?tab=shared", "personal_count": personal.len(), "shared_count": shared.len(),
        "books": book_items, "book": book_json, "perm": perm, "can_write": can_write, "can_manage": can_manage, "can_create": ctx.allows("address_book", "rw"),
        "tags": tag_items, "entries": entry_items, "pager": page, "total": total, "rules": rule_items, "search": st.search, "selected": selected,
        "back": back, "url": url, "path": "/address-books", "query": format!("{}&", st.query(false)),
        "new_url": join(&url, "modal=newBook"), "rename_url": join(&url, "modal=renameBook"), "tag_url": join(&url, "modal=addTag"),
        "entry_url": join(&url, "modal=entry"), "entry_edit_prefix": join(&url, "modal=entry&entry="), "rule_url": join(&url, "modal=addRule"),
        "modal": modal, "perm_labels": [{"v": 1, "l": "Read"}, {"v": 2, "l": "Read/Write"}, {"v": 3, "l": "Full Control"}],
    });
    Ok(Reply::Html(status, ctx.render("address-books/index.html", layout, page_json)?))
}

fn entries_for(c: &Connection, book: Option<&Row>, id: i64) -> Result<Option<Row>, Fault> {
    match book {
        Some(b) => db::first(c, r#"select * from "address_book_entries" where "address_book_id" = ? and "id" = ? limit 1"#, &[P(Val::Int(b.id())), P(Val::Int(id))]),
        None => Ok(None),
    }
}

// ---------------------------------------------------------------------------------------------- validation ---

fn required(name: &str, v: &str) -> Option<String> {
    if v.trim().is_empty() { Some(format!("The {name} field is required.")) } else { None }
}

fn max_chars(name: &str, v: &str, n: usize) -> Option<String> {
    if crate::validate::mb_strlen(v.as_bytes()) > n { Some(format!("The {name} field must not be greater than {n} characters.")) } else { None }
}

fn first_of(list: Vec<Option<String>>) -> Option<String> {
    list.into_iter().flatten().next()
}

fn errors_of(pairs: Vec<(&str, Option<String>)>) -> Map<String, Value> {
    let mut m = Map::new();
    for (k, v) in pairs {
        if let Some(msg) = v {
            m.insert(k.into(), json!(msg));
        }
    }
    m
}

fn values_of(pairs: Vec<(&str, Value)>) -> Map<String, Value> {
    pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
}

// ------------------------------------------------------------------------------------------------- writes ---

/// `POST /address-books/act`
pub fn act(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    let body = Body::of(req);
    let st = St::from_back(&body.get("back"));
    let back = Reply::Redirect(st.url());
    let book_id = st.book;
    let now = ctx.now;
    let now_s = crate::laravel::ts(now);
    let verb = body.get("do");
    let rw = ctx.allows("address_book", "rw");

    // createBook needs the console verb only; everything else resolves the selected, visible book and its tier
    if verb == "create-book" {
        if !rw {
            return Ok(abort(403));
        }
        let (name, note) = (body.get("book_name"), body.get("book_note"));
        let errs = errors_of(vec![("book_name", first_of(vec![required("name", &name), max_chars("name", &name, 255)])), ("book_note", max_chars("note", &note, 500))]);
        if !errs.is_empty() {
            let d = Dialog { kind: "newBook".into(), entry: 0, values: values_of(vec![("book_name", json!(name)), ("book_note", json!(note))]), errors: errs };
            return render(ctx, c, st, 422, Some(d));
        }
        let id = db::insert(c, "address_books", vec![("guid", Val::str(&crate::laravel::uuid4())), ("name", Val::str(name.trim())), ("note", if note.is_empty() { Val::Null } else { Val::str(&note) }), ("owner_user_id", Val::Int(ctx.uid())), ("is_personal", Val::Bool(false))], &now_s)?;
        audit(ctx, c, "address-book.create", &format!("Created address book {}", name.trim()), Some("address-book"), Some(name.trim()))?;
        return Ok(Reply::Redirect(format!("/address-books?selectedBookId={id}&tab=shared")));
    }

    let book = visible_book(ctx, c, book_id)?;
    let perm = permission(ctx, c, book.as_ref())?;
    let need = match verb.as_str() {
        "rename-book" | "delete-book" | "add-tag" | "delete-tag" | "add-rule" | "rule-perm" | "delete-rule" => PERM_FULL,
        "save-entry" | "delete-entry" => PERM_READ_WRITE,
        _ => return Ok(back),
    };
    let Some(book) = book.filter(|_| perm >= need) else { return Ok(back) };
    let bname = s(&book, "name");
    let personal = book.val("is_personal").to_bool();
    let bid = book.id();
    let reopen = |kind: &str, entry: i64, values: Map<String, Value>, errors: Map<String, Value>| render(ctx, c, st.clone(), 422, Some(Dialog { kind: kind.into(), entry, values, errors }));

    match verb.as_str() {
        "rename-book" => {
            if personal {
                return Ok(back);
            }
            let (name, note) = (body.get("book_name"), body.get("book_note"));
            let errs = errors_of(vec![("book_name", first_of(vec![required("name", &name), max_chars("name", &name, 255)])), ("book_note", max_chars("note", &note, 500))]);
            if !errs.is_empty() {
                return reopen("renameBook", 0, values_of(vec![("book_name", json!(name)), ("book_note", json!(note))]), errs);
            }
            let mut b = book.clone();
            update(c, "address_books", &mut b, vec![("name", Val::str(name.trim()), Cast::Plain), ("note", if note.is_empty() { Val::Null } else { Val::str(&note) }, Cast::Plain)], now)?;
            let new_name = s(&b, "name");
            audit(ctx, c, "address-book.update", &(if bname != new_name { format!("Renamed address book {bname} to {new_name}") } else { format!("Updated address book {new_name}") }), Some("address-book"), Some(&new_name))?;
        }
        "delete-book" => {
            let orphan = personal && find(c, "users", book.val("owner_user_id").to_int())?.is_none();
            if personal && !orphan {
                return Ok(back);
            }
            delete_book_rows(c, bid)?;
            audit(ctx, c, "address-book.delete", &format!("Deleted address book {bname}"), Some("address-book"), Some(&bname))?;
            // the selection falls back to the first book of the tab, which may be none
            let mut after = st.clone();
            after.book = 0;
            after.none = false;
            after.page = 1;
            let (w, params) = visible_sql(ctx, c)?;
            let w = if w.is_empty() { r#" where "is_personal" = ?"#.to_string() } else { format!("{w} and \"is_personal\" = ?") };
            let mut params = params;
            params.push(P(Val::Bool(st.tab == "personal")));
            let next = db::first(c, &format!(r#"select "id" from "address_books"{w} order by "is_personal" desc, "name" asc limit 1"#), &params)?.map(|r| r.id()).unwrap_or(0);
            return Ok(Reply::Redirect(format!("/address-books?selectedBookId={next}&tab={}", st.tab)));
        }
        "add-tag" => {
            let (name, color) = (body.get("tag_name"), body.get("tag_color"));
            let taken = count(c, r#"select count(*) as aggregate from "tags" where "name" = ? and "address_book_id" = ?"#, &[P(Val::str(&name)), P(Val::Int(bid))])? > 0;
            let hex_ok = color.len() == 7 && color.starts_with('#') && color[1..].chars().all(|ch| ch.is_ascii_hexdigit());
            let name_err = first_of(vec![required("tag name", &name), max_chars("tag name", &name, 64)]).or_else(|| if taken { Some("The tag name has already been taken.".to_string()) } else { None });
            let color_err = required("color", &color).or_else(|| if hex_ok { None } else { Some("The color field format is invalid.".to_string()) });
            let errs = errors_of(vec![("tag_name", name_err), ("tag_color", color_err)]);
            if !errs.is_empty() {
                return reopen("addTag", 0, values_of(vec![("tag_name", json!(name)), ("tag_color", json!(color))]), errs);
            }
            db::insert(c, "tags", vec![("address_book_id", Val::Int(bid)), ("name", Val::str(name.trim())), ("color", Val::Int(hex_to_color(&color)))], &now_s)?;
            audit(ctx, c, "address-book.tag-add", &format!("Added tag {} to address book {bname}", name.trim()), Some("address-book"), Some(&bname))?;
        }
        "delete-tag" => {
            let Some(tag) = db::first(c, r#"select * from "tags" where "address_book_id" = ? and "id" = ? limit 1"#, &[P(Val::Int(bid)), P(Val::Int(body.int("id")))])? else { return Ok(abort(404)) };
            for mut e in db::rows(c, r#"select * from "address_book_entries" where "address_book_id" = ?"#, &[P(Val::Int(bid))])? {
                let ids = tag_ids_of(&e);
                if ids.contains(&tag.id()) {
                    let rest: Vec<i64> = ids.into_iter().filter(|i| *i != tag.id()).collect();
                    update(c, "address_book_entries", &mut e, vec![("tag_ids", Val::str(&json_ids(&rest)), Cast::Plain)], now)?;
                }
            }
            db::exec(c, r#"delete from "tags" where "id" = ?"#, &[P(Val::Int(tag.id()))])?;
            audit(ctx, c, "address-book.tag-delete", &format!("Removed tag {} from address book {bname}", s(&tag, "name")), Some("address-book"), Some(&bname))?;
        }
        "save-entry" => {
            let valid: Vec<i64> = db::rows(c, r#"select "id" from "tags" where "address_book_id" = ?"#, &[P(Val::Int(bid))])?.iter().map(|r| r.id()).collect();
            let mut tag_ids: Vec<i64> = vec![];
            for i in body.ints("tag_ids") {
                if valid.contains(&i) && !tag_ids.contains(&i) {
                    tag_ids.push(i);
                }
            }
            // array_intersect keeps the posted order and every duplicate; the dialog never posts one twice
            let alias = body.get("alias");
            let eid = body.int("entry_id");
            let alias_v = if alias.is_empty() { Val::Null } else { Val::str(alias.trim()) };
            if eid != 0 {
                let Some(mut e) = db::first(c, r#"select * from "address_book_entries" where "address_book_id" = ? and "id" = ? limit 1"#, &[P(Val::Int(bid)), P(Val::Int(eid))])? else { return Ok(abort(404)) };
                if let Some(msg) = max_chars("alias", &alias, 255) {
                    let vals = values_of(vec![("rustdesk_id", json!(s(&e, "rustdesk_id"))), ("alias", json!(alias)), ("tag_ids", json!(tag_ids))]);
                    return reopen("entry", eid, vals, errors_of(vec![("alias", Some(msg))]));
                }
                update(c, "address_book_entries", &mut e, vec![("alias", alias_v, Cast::Plain), ("tag_ids", Val::str(&json_ids(&tag_ids)), Cast::Plain)], now)?;
                audit(ctx, c, "address-book.peer-update", &format!("Updated peer {} in address book {bname}", s(&e, "rustdesk_id")), Some("address-book"), Some(&bname))?;
            } else {
                let rid = body.get("rustdesk_id");
                let taken = count(c, r#"select count(*) as aggregate from "address_book_entries" where "rustdesk_id" = ? and "address_book_id" = ?"#, &[P(Val::str(&rid)), P(Val::Int(bid))])? > 0;
                let id_err = first_of(vec![required("RustDesk ID", &rid), max_chars("RustDesk ID", &rid, 255)]).or_else(|| if taken { Some("The RustDesk ID has already been taken.".to_string()) } else { None });
                let errs = errors_of(vec![("rustdesk_id", id_err), ("alias", max_chars("alias", &alias, 255))]);
                if !errs.is_empty() {
                    return reopen("entry", 0, values_of(vec![("rustdesk_id", json!(rid)), ("alias", json!(alias)), ("tag_ids", json!(tag_ids))]), errs);
                }
                db::insert(c, "address_book_entries", vec![("address_book_id", Val::Int(bid)), ("rustdesk_id", Val::str(rid.trim())), ("alias", alias_v), ("tag_ids", Val::str(&json_ids(&tag_ids)))], &now_s)?;
                audit(ctx, c, "address-book.peer-add", &format!("Added peer {} to address book {bname}", rid.trim()), Some("address-book"), Some(&bname))?;
            }
        }
        "delete-entry" => {
            let Some(e) = db::first(c, r#"select * from "address_book_entries" where "address_book_id" = ? and "id" = ? limit 1"#, &[P(Val::Int(bid)), P(Val::Int(body.int("id")))])? else { return Ok(abort(404)) };
            db::exec(c, r#"delete from "address_book_entries" where "id" = ?"#, &[P(Val::Int(e.id()))])?;
            audit(ctx, c, "address-book.peer-delete", &format!("Removed peer {} from address book {bname}", s(&e, "rustdesk_id")), Some("address-book"), Some(&bname))?;
        }
        "add-rule" => {
            if personal {
                return Ok(back);
            }
            let (kind, sid, perm_v) = (body.get("rule_type"), body.get("rule_subject"), body.get("rule_permission"));
            let mut errs: Vec<(&str, Option<String>)> = vec![];
            let kind_ok = ["everyone", "user", "group"].contains(&kind.as_str());
            errs.push(("rule_type", if kind.is_empty() { Some("The subject field is required.".into()) } else if !kind_ok { Some("The selected subject is invalid.".into()) } else { None }));
            let perm_n = crate::php::str_to_int(perm_v.as_bytes());
            let perm_is_int = !perm_v.is_empty() && perm_v.trim().parse::<i64>().is_ok();
            errs.push(("rule_permission", if perm_v.is_empty() { Some("The permission field is required.".into()) } else if !perm_is_int { Some("The permission field must be an integer.".into()) } else if ![1, 2, 3].contains(&perm_n) { Some("The selected permission is invalid.".into()) } else { None }));
            if kind == "user" || kind == "group" {
                let table = if kind == "user" { "users" } else { "user_groups" };
                let sid_n = sid.trim().parse::<i64>().ok();
                let err = if sid.is_empty() { Some("The subject field is required.".to_string()) } else if sid_n.is_none() { Some("The subject field must be an integer.".to_string()) } else if find(c, table, sid_n.unwrap())?.is_none() { Some("The selected subject is invalid.".to_string()) } else { None };
                errs.push(("rule_subject", err));
            }
            let errs = errors_of(errs);
            if !errs.is_empty() {
                return reopen("addRule", 0, values_of(vec![("rule_type", json!(kind)), ("rule_subject", json!(sid.trim().parse::<i64>().unwrap_or(0))), ("rule_permission", json!(perm_n))]), errs);
            }
            let subject = if kind == "everyone" { Val::Null } else { Val::Int(crate::php::str_to_int(sid.as_bytes())) };
            db::insert(c, "address_book_rules", vec![("address_book_id", Val::Int(bid)), ("subject_type", Val::str(&kind)), ("subject_id", subject), ("permission", Val::Int(perm_n))], &now_s)?;
            audit(ctx, c, "address-book.rule-add", &format!("Added sharing rule to address book {bname}"), Some("address-book"), Some(&bname))?;
        }
        "rule-perm" => {
            let p = body.int("permission");
            if ![1, 2, 3].contains(&p) {
                return Ok(back);
            }
            let Some(mut r) = db::first(c, r#"select * from "address_book_rules" where "address_book_id" = ? and "id" = ? limit 1"#, &[P(Val::Int(bid)), P(Val::Int(body.int("id")))])? else { return Ok(abort(404)) };
            update(c, "address_book_rules", &mut r, vec![("permission", Val::Int(p), Cast::Plain)], now)?;
            audit(ctx, c, "address-book.rule-update", &format!("Updated sharing rule on address book {bname}"), Some("address-book"), Some(&bname))?;
        }
        "delete-rule" => {
            let Some(r) = db::first(c, r#"select * from "address_book_rules" where "address_book_id" = ? and "id" = ? limit 1"#, &[P(Val::Int(bid)), P(Val::Int(body.int("id")))])? else { return Ok(abort(404)) };
            db::exec(c, r#"delete from "address_book_rules" where "id" = ?"#, &[P(Val::Int(r.id()))])?;
            audit(ctx, c, "address-book.rule-delete", &format!("Removed sharing rule from address book {bname}"), Some("address-book"), Some(&bname))?;
        }
        _ => {}
    }
    Ok(back)
}
