//! Phase 5: `POST /api/devices/cli`, the RustDesk client's `--assign` (app/Http/Controllers/Api/DeviceCliController).
//! The client reads the answer as text: an empty 200 is "Done!", anything else is printed as it is.
//!
//! The device is matched on the `id` the client posts (`rustdesk_id`) and registered ACTIVE whatever the approval
//! gate says (a token with Device rw is an authenticated, pre-approved registration). `address_book_*` fields need
//! address_book rw on the token and `strategy_name` needs strategy rw, on top of the device rw the route checks.

use crate::admin::{filled, token_allows, Cx, Out};
use crate::api::Reply;
use crate::duplicates;
use crate::laravel::{self, Cast};
use crate::php::{self, Fault, Val};
use crate::sqlite::{self as db, Row, P};

/// Assign flags that, if present, make the request actionable.
const ASSIGN_FLAGS: &[&str] = &["user_name", "strategy_name", "address_book_name", "device_group_name", "note", "device_username", "device_name"];

/// Address-book sub-fields that require an address_book rw token.
const AB_FIELDS: &[&str] = &["address_book_name", "address_book_tag", "address_book_alias", "address_book_password", "address_book_note"];

fn message(text: &str, status: u16) -> Result<Out, Fault> {
    Ok(Out::Plain(status, text.to_string()))
}

/// `(string) $request->input($key)`
fn input_text(cx: &Cx, key: &str) -> Result<String, Fault> {
    Ok(String::from_utf8_lossy(&cx.input.string(key)?).into_owned())
}

fn any_filled(cx: &Cx, keys: &[&str]) -> Result<bool, Fault> {
    for k in keys {
        if filled(cx.input, k)? {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn assign(cx: &Cx) -> Result<Out, Fault> {
    let id = String::from_utf8_lossy(php::trim(&cx.input.string("id")?)).into_owned();
    let uuid = String::from_utf8_lossy(php::trim(&cx.input.string("uuid")?)).into_owned();
    if id.is_empty() || uuid.is_empty() {
        return message("id and uuid are required.", 400);
    }
    if !any_filled(cx, ASSIGN_FLAGS)? {
        return message("No assignment parameters provided.", 400);
    }
    if any_filled(cx, AB_FIELDS)? && !token_allows(&cx.token, "address_book", "rw")? {
        return message("Token lacks 'rw' permission on 'address_book'.", 403);
    }
    // a token scoped `strategy: none` must not push a policy just because it may write devices
    if filled(cx.input, "strategy_name")? && !token_allows(&cx.token, "strategy", "rw")? {
        return message("Token lacks 'rw' permission on 'strategy'.", 403);
    }

    // resolve the named user / group / strategy / book up front, so a bad name fails before anything is written
    let mut user_change: Option<Val> = None;
    if filled(cx.input, "user_name")? {
        let v = cx.input.get("user_name").cloned().unwrap_or(Val::Null);
        match cx.find_by("users", false, "username", &v)? {
            Some(u) => user_change = Some(u.val("id")),
            None => return message(&format!("User '{}' not found.", input_text(cx, "user_name")?), 404),
        }
    }
    let mut group_change: Option<Val> = None;
    if filled(cx.input, "device_group_name")? {
        let v = cx.input.get("device_group_name").cloned().unwrap_or(Val::Null);
        match cx.find_by("device_groups", false, "name", &v)? {
            Some(g) => group_change = Some(g.val("id")),
            None => return message(&format!("Device group '{}' not found.", input_text(cx, "device_group_name")?), 404),
        }
    }
    // a named strategy becomes a DEVICE-level assignment, the highest precedence there is
    let mut strategy_change: Option<Val> = None;
    if filled(cx.input, "strategy_name")? {
        let v = cx.input.get("strategy_name").cloned().unwrap_or(Val::Null);
        match cx.find_by("strategies", true, "name", &v)? {
            Some(s) => strategy_change = Some(s.val("id")),
            None => return message(&format!("Strategy '{}' not found.", input_text(cx, "strategy_name")?), 404),
        }
    }
    let mut book: Option<Row> = None;
    if filled(cx.input, "address_book_name")? {
        let v = cx.input.get("address_book_name").cloned().unwrap_or(Val::Null);
        match cx.find_by("address_books", false, "name", &v)? {
            Some(b) => book = Some(b),
            None => return message(&format!("Address book '{}' not found.", input_text(cx, "address_book_name")?), 404),
        }
    }

    // match/upsert the device on the posting client's identity
    let existing = db::first(cx.c, r#"select * from "devices" where "rustdesk_id" = ? and "devices"."deleted_at" is null limit 1"#, &[P(Val::str(&id))])?;
    let is_new = existing.is_none();

    // `DeviceEnrollment::defaultGroup()`: only for a device the table has not seen
    let default_group: Option<Val> = if group_change.is_none() && is_new {
        let configured = Val::Str(db::setting(cx.c, "default_device_group_id", "0")?).to_int();
        if configured > 0 {
            db::first(cx.c, r#"select * from "device_groups" where "id" = ? limit 1"#, &[P(Val::Int(configured))])?.map(|g| g.val("id"))
        } else {
            None
        }
    } else {
        None
    };

    let mut changes: Vec<(&str, Val, Cast)> = vec![("uuid", Val::str(&uuid), Cast::Plain), ("status", Val::str("active"), Cast::Plain)];
    if let Some(u) = user_change {
        changes.push(("user_id", u, Cast::Plain));
    }
    if let Some(g) = group_change.or(default_group) {
        changes.push(("device_group_id", g, Cast::Plain));
    }
    for (flag, col) in [("note", "note"), ("device_name", "hostname"), ("device_username", "username")] {
        if filled(cx.input, flag)? {
            changes.push((col, Val::str(&input_text(cx, flag)?), Cast::Plain));
        }
    }

    let mut device = match existing {
        Some(mut d) => {
            let changed = cx.update("devices", &mut d, changes)?;
            // Device::updated
            if changed.iter().any(|c| c == "user_id" || c == "device_group_id") {
                crate::strategy::sync_resolved_for(cx.c, &mut d, &cx.ts())?;
            }
            d
        }
        None => {
            let mut cols = vec![("rustdesk_id", Val::str(&id))];
            cols.extend(changes.into_iter().map(|(k, v, _)| (k, v)));
            let mut d = cx.create("devices", cols)?;
            // Device::created
            crate::strategy::sync_resolved_for(cx.c, &mut d, &cx.ts())?;
            d
        }
    };

    if let Some(book) = &book {
        apply_address_book(cx, book, &device)?;
    }

    if let Some(strategy_id) = strategy_change {
        // Strategy::assignTo(LEVEL_DEVICE, $device->id, $strategyId): replace, then re-resolve the device
        db::exec(cx.c, r#"delete from "device_strategy" where "device_id" = ?"#, &[P(device.val("id"))])?;
        db::exec(cx.c, r#"insert into "device_strategy" ("device_id", "strategy_id") values (?, ?)"#, &[P(device.val("id")), P(strategy_id)])?;
        if let Some(mut fresh) = db::first(cx.c, r#"select * from "devices" where "id" = ? limit 1"#, &[P(device.val("id"))])? {
            crate::strategy::sync_resolved_for(cx.c, &mut fresh, &cx.ts())?;
            device = fresh;
        }
    }

    let rid = String::from_utf8_lossy(&device.val("rustdesk_id").to_php_string()?).into_owned();
    let verb = if is_new { "Registered and assigned" } else { "Assigned" };
    cx.audit("device.assign", &format!("{verb} device {rid} via --assign (API)"), Some("device"), Some(&rid))?;

    // empty 200 body: the client prints "Done!"
    Ok(Out::R(Reply::stored()))
}

/// Upsert the device as a peer in the given address book, applying the `address_book_*` display fields.
/// `address_book_note` has no column in the schema and is accepted and ignored.
fn apply_address_book(cx: &Cx, book: &Row, device: &Row) -> Result<(), Fault> {
    let existing = db::first(
        cx.c,
        r#"select * from "address_book_entries" where "address_book_id" = ? and "rustdesk_id" = ? limit 1"#,
        &[P(book.val("id")), P(device.val("rustdesk_id"))],
    )?;
    let mut changes: Vec<(&str, Val, Cast)> = vec![
        ("hostname", device.val("hostname"), Cast::Plain),
        ("platform", Val::str(&duplicates::platform(&device.val("os"))), Cast::Plain),
        ("username", device.val("username"), Cast::Plain),
    ];
    if filled(cx.input, "address_book_alias")? {
        changes.push(("alias", Val::str(&input_text(cx, "address_book_alias")?), Cast::Plain));
    }
    if filled(cx.input, "address_book_password")? {
        let plain = cx.input.string("address_book_password")?;
        changes.push(("password_enc", Val::str(&cx.n.crypt.encrypt_string(&plain)), Cast::Plain));
    }
    if filled(cx.input, "address_book_tag")? {
        let name = input_text(cx, "address_book_tag")?;
        // Tag::firstOrCreate(['address_book_id' => ..., 'name' => ...])
        let tag = match db::first(cx.c, r#"select * from "tags" where "address_book_id" = ? and "name" = ? limit 1"#, &[P(book.val("id")), P(Val::str(&name))])? {
            Some(t) => t,
            None => cx.create("tags", vec![("address_book_id", book.val("id")), ("name", Val::str(&name))])?,
        };
        let mut ids = match existing.as_ref().map(|e| laravel::from_json(&e.val("tag_ids"))) {
            None | Some(Val::Null) => php::Arr::new(),
            Some(Val::Arr(a)) => a,
            // `$tagIds[] = ...` on a scalar
            Some(_) => return Err(Fault::Other("[] operator not supported for the stored tag_ids".into())),
        };
        let tag_id = tag.val("id");
        if !ids.iter().any(|(_, v)| *v == tag_id) {
            ids.push(tag_id);
        }
        changes.push(("tag_ids", Val::str(&crate::admin::enc(&Val::Arr(ids))?), Cast::Json));
    }
    match existing {
        Some(mut e) => {
            cx.update("address_book_entries", &mut e, changes)?;
        }
        None => {
            let mut cols = vec![("address_book_id", book.val("id")), ("rustdesk_id", device.val("rustdesk_id"))];
            cols.extend(changes.into_iter().map(|(k, v, _)| (k, v)));
            cx.create("address_book_entries", cols)?;
        }
    }
    Ok(())
}
