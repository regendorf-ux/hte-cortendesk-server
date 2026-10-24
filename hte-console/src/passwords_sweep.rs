//! Phase 3: the minute half of HTE's per-computer passwords (v1.15.0-hte.1), a port of `App\Hte\Passwords::sweep`,
//! `days`, `bookOwnerId` and `syncBooks` (`hte:passwords`, every minute). The check-in half (`hte_pw`, sealing,
//! confirmation) is phase 1's `passwords.rs`; "Change now" stays the console page's button (PHP) and writes the same
//! row `issue` writes here.
//!
//! A computer gets a new password on schedule (7, 30 or 90 days after it confirmed the last, or never) and at once
//! when someone who could reach it no longer can. Then each active person's automatic book ("HTE Remote", readable
//! by them alone) is brought in step with the computers they may reach and the confirmed passwords. Plaintext
//! passwords exist only inside these functions and are never logged.

use crate::laravel::{self, Cast, Encrypter};
use crate::passwords;
use crate::php::{Fault, Val};
use crate::reach;
use crate::sqlite::{self as db, Row, P};
use rusqlite::Connection;

pub const SETTING_DAYS: &str = "hte_pw_days";
pub const BOOK_NAME: &str = "HTE Remote";
pub const BOOK_NOTE: &str = "Automatic (HTE): the computers this person may reach, kept in step by the console. Not editable.";
/// `AddressBookRule::PERM_READ`
const PERM_READ: i64 = 1;

/// `Passwords::days()`: 7, 30, 90 or 0 (only on access loss); anything else is 30.
pub fn days(c: &Connection) -> Result<i64, Fault> {
    let d = Val::Str(db::setting(c, SETTING_DAYS, "30")?).to_int();
    Ok(if [7, 30, 90, 0].contains(&d) { d } else { 30 })
}

/// `DevicePassword::pending()`
fn pending(row: &Row) -> bool {
    let cur = row.val("current_version").to_int();
    cur > 0 && cur != row.val("confirmed_version").to_int()
}

/// What one sweep did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub issued: usize,
    pub books: usize,
}

/// `Passwords::sweep()`
pub fn sweep(c: &Connection, crypt: &Encrypter, now: i64) -> Result<Stats, Fault> {
    let mut stats = Stats::default();
    if db::setting(c, passwords::SETTING_ENABLED, "0")? != b"1" {
        return Ok(stats);
    }
    let days = days(c)?;
    let ts = laravel::ts(now);
    for mut row in db::rows(c, r#"select * from "hte_device_passwords" where "capable_at" is not null order by "id" asc"#, &[])? {
        let rid = row.val("rustdesk_id").to_php_string()?;
        let Some(device) = db::first(c, r#"select * from "devices" where "rustdesk_id" = ? and "devices"."deleted_at" is null limit 1"#, &[P(Val::Str(rid.clone()))])? else {
            continue;
        };
        if device.val("status") != Val::str("active") {
            continue;
        }
        let issued = reach::atomically(c, || -> Result<bool, Fault> {
            let now_ids = reach::reach_ids(c, &device)?;
            // $row->reach_user_ids (array cast): null unless the stored JSON decodes to an array
            let before = laravel::from_json(&row.val("reach_user_ids"));
            // array_diff($before, $now): compared as strings
            let lost: Vec<Val> = match &before {
                Val::Arr(a) => a
                    .iter()
                    .map(|(_, v)| v.clone())
                    .filter(|v| {
                        let s = v.to_php_string().unwrap_or_default();
                        !now_ids.iter().any(|n| n.to_string().into_bytes() == s)
                    })
                    .collect(),
                _ => vec![],
            };
            let mut list = crate::php::Arr::new();
            for id in &now_ids {
                list.push(Val::Int(*id));
            }
            let encoded = crate::php::json_encode(&Val::Arr(list)).unwrap_or_else(|| "[]".into());
            db::update_dirty(c, "hte_device_passwords", &mut row, vec![("reach_user_ids", Val::str(&encoded), Cast::Json)], &ts)?;

            let reason = if row.val("current_version").to_int() == 0 {
                Some("first password".to_string())
            } else if !lost.is_empty() {
                let names = db::rows(c, &format!(r#"select "username" from "users" where "id" in ({})"#, vec!["?"; lost.len()].join(", ")), &lost.iter().cloned().map(P).collect::<Vec<_>>())?;
                let names: Vec<String> = names.iter().map(|r| String::from_utf8_lossy(&r.val("username").to_php_string().unwrap_or_default()).into_owned()).collect();
                Some(format!("access removed ({})", names.join(", ")))
            } else if days > 0 && !pending(&row) && !row.is_null("confirmed_at") {
                let at = laravel::parse_ts(&row.val("confirmed_at")).ok_or_else(|| Fault::Other("unparsable hte_device_passwords.confirmed_at".into()))?;
                (at < now - days * 86_400).then(|| format!("every {days} days"))
            } else {
                None
            };
            if let Some(reason) = reason {
                if !pending(&row) {
                    passwords::issue(c, crypt, &rid, &reason, &ts)?;
                    let rid_s = String::from_utf8_lossy(&rid).into_owned();
                    reach::console_audit_system(c, "hte.password", &format!("New password for {rid_s}: {reason}"), "device", &rid, now)?;
                    return Ok(true);
                }
            }
            Ok(false)
        })?;
        if issued {
            stats.issued += 1;
        }
    }
    stats.books = sync_books(c, crypt, now)?;
    if stats.issued > 0 || stats.books > 0 {
        tracing::info!("passwords sweep: issued {}, book entries written {}", stats.issued, stats.books);
    }
    Ok(stats)
}

/// `Passwords::bookOwnerId()`: the first administrator, else 0.
fn book_owner_id(c: &Connection) -> Result<i64, Fault> {
    Ok(db::first(c, r#"select "id" from "users" where "is_admin" = ? order by "id" asc limit 1"#, &[P(Val::Bool(true))])?.map_or(0, |r| r.val("id").to_int()))
}

/// `Device::rustdeskPlatform()`, from `platform()`'s reading of the OS string.
pub fn rustdesk_platform(os: &Val) -> &'static str {
    let os = String::from_utf8_lossy(&os.to_php_string().unwrap_or_default()).to_ascii_lowercase();
    let has = |s: &str| os.contains(s);
    if has("windows") {
        "Windows"
    } else if has("mac") || has("darwin") {
        "Mac OS"
    } else if has("android") {
        "Android"
    } else if has("ios") {
        "iOS"
    } else if has("linux") || has("ubuntu") || has("debian") || has("fedora") || has("arch") || has("centos") {
        "Linux"
    } else {
        ""
    }
}

fn decrypt_opt(crypt: &Encrypter, v: &Val) -> Result<Option<Vec<u8>>, Fault> {
    // `$x ? Crypt::decryptString($x) : null`: an empty or "0" ciphertext reads as none
    if !v.to_bool() {
        return Ok(None);
    }
    crypt.decrypt_string(&v.to_php_string()?).map(Some)
}

/// `Passwords::syncBooks()`: one book per active person, a disabled person's book emptied. Returns how many
/// entries were written.
pub fn sync_books(c: &Connection, crypt: &Encrypter, now: i64) -> Result<usize, Fault> {
    let ts = laravel::ts(now);
    // keyBy('rustdesk_id'): the last row wins for a repeated id
    let passwords = db::rows(c, r#"select * from "hte_device_passwords" where "confirmed_version" > ?"#, &[P(Val::Int(0))])?;
    let password_of = |id: &[u8]| passwords.iter().rev().find(|p| p.val("rustdesk_id").to_php_string().ok().as_deref() == Some(id));
    let mut written = 0;
    for user in db::rows(c, r#"select * from "users" order by "id" asc"#, &[])? {
        let map = db::first(c, r#"select * from "hte_auto_books" where "user_id" = ? limit 1"#, &[P(user.val("id"))])?;
        let mut book = match &map {
            Some(m) => db::first(c, r#"select * from "address_books" where "address_books"."id" = ? limit 1"#, &[P(m.val("address_book_id"))])?,
            None => None,
        };
        if !user.val("is_active").to_bool() {
            if let Some(b) = &book {
                db::exec(c, r#"delete from "address_book_entries" where "address_book_entries"."address_book_id" = ? and "address_book_entries"."address_book_id" is not null"#, &[P(b.val("id"))])?;
                db::exec(c, r#"delete from "address_book_rules" where "address_book_rules"."address_book_id" = ? and "address_book_rules"."address_book_id" is not null"#, &[P(b.val("id"))])?;
            }
            continue;
        }
        if book.is_none() {
            let owner = match book_owner_id(c)? {
                0 => user.val("id"),
                id => Val::Int(id),
            };
            let id = db::insert(
                c,
                "address_books",
                vec![
                    ("guid", Val::str(&laravel::uuid4())),
                    ("name", Val::str(BOOK_NAME)),
                    ("owner_user_id", owner),
                    ("is_personal", Val::Bool(false)),
                    ("note", Val::str(BOOK_NOTE)),
                ],
                &ts,
            )?;
            // DB::table('hte_auto_books')->updateOrInsert(['user_id' => ..], ['address_book_id' => .., 'updated_at' => now(), 'created_at' => now()])
            let exists = db::first(c, r#"select exists(select * from "hte_auto_books" where ("user_id" = ?)) as "exists""#, &[P(user.val("id"))])?.map_or(false, |r| r.val("exists").to_bool());
            if exists {
                // `->limit(1)->update(...)`: SQLite's grammar puts the limit in a rowid subquery
                db::exec(
                    c,
                    r#"update "hte_auto_books" set "address_book_id" = ?, "updated_at" = ?, "created_at" = ? where "rowid" in (select "hte_auto_books"."rowid" from "hte_auto_books" where ("user_id" = ?) limit 1)"#,
                    &[P(Val::Int(id)), P(Val::str(&ts)), P(Val::str(&ts)), P(user.val("id"))],
                )?;
            } else {
                db::exec(
                    c,
                    r#"insert into "hte_auto_books" ("user_id", "address_book_id", "updated_at", "created_at") values (?, ?, ?, ?)"#,
                    &[P(user.val("id")), P(Val::Int(id)), P(Val::str(&ts)), P(Val::str(&ts))],
                )?;
            }
            book = db::first(c, r#"select * from "address_books" where "address_books"."id" = ? limit 1"#, &[P(Val::Int(id))])?;
        }
        let Some(book) = book else { continue };
        let bid = book.val("id");
        let has_rule = db::first(
            c,
            r#"select exists(select * from "address_book_rules" where "address_book_rules"."address_book_id" = ? and "address_book_rules"."address_book_id" is not null and "subject_type" = ? and "subject_id" = ?) as "exists""#,
            &[P(bid.clone()), P(Val::str("user")), P(user.val("id"))],
        )?
        .map_or(false, |r| r.val("exists").to_bool());
        if !has_rule {
            db::exec(c, r#"delete from "address_book_rules" where "address_book_rules"."address_book_id" = ? and "address_book_rules"."address_book_id" is not null"#, &[P(bid.clone())])?;
            db::insert(
                c,
                "address_book_rules",
                vec![("address_book_id", bid.clone()), ("subject_type", Val::str("user")), ("subject_id", user.val("id")), ("permission", Val::Int(PERM_READ))],
                &ts,
            )?;
        }

        let want = reach::visible_devices(c, &user, None, "rustdesk_id")?;
        // keyBy('rustdesk_id'): a repeated id keeps its first place and the last row
        let mut wanted: Vec<(Vec<u8>, Row)> = vec![];
        for d in want {
            let id = d.val("rustdesk_id").to_php_string()?;
            match wanted.iter_mut().find(|(k, _)| *k == id) {
                Some(slot) => slot.1 = d,
                None => wanted.push((id, d)),
            }
        }
        // whereNotIn('rustdesk_id', $want->keys() ?: ['-'])
        let keep: Vec<Val> = if wanted.is_empty() { vec![Val::str("-")] } else { wanted.iter().map(|(k, _)| Val::Str(k.clone())).collect() };
        let mut params = vec![P(bid.clone())];
        params.extend(keep.into_iter().map(P));
        db::exec(
            c,
            &format!(
                r#"delete from "address_book_entries" where "address_book_entries"."address_book_id" = ? and "address_book_entries"."address_book_id" is not null and "rustdesk_id" not in ({})"#,
                vec!["?"; params.len() - 1].join(", ")
            ),
            &params,
        )?;
        for (id, device) in &wanted {
            let plain = match password_of(id) {
                Some(pw) => decrypt_opt(crypt, &pw.val("confirmed_enc"))?,
                None => None,
            };
            let entry = db::first(c, r#"select * from "address_book_entries" where ("address_book_id" = ? and "rustdesk_id" = ?) limit 1"#, &[P(bid.clone()), P(Val::Str(id.clone()))])?;
            let current = match &entry {
                Some(e) => decrypt_opt(crypt, &e.val("password_enc"))?,
                None => None,
            };
            let alias = {
                let a = device.val("alias");
                if a.to_bool() { a } else { device.val("hostname") }
            };
            let fields: Vec<(&str, Vec<u8>)> = vec![
                ("alias", alias.to_php_string()?),
                ("hostname", device.val("hostname").to_php_string()?),
                ("platform", rustdesk_platform(&device.val("os")).as_bytes().to_vec()),
                ("username", device.val("username").to_php_string()?),
            ];
            let mut dirty = entry.is_none() || current != plain;
            if let Some(e) = &entry {
                for (k, v) in &fields {
                    dirty = dirty || e.val(k).to_php_string()? != *v;
                }
            }
            if !dirty {
                continue;
            }
            let enc = match &plain {
                Some(p) => Val::str(&crypt.encrypt_string(p)),
                None => Val::Null,
            };
            match entry {
                None => {
                    let mut cols = vec![("address_book_id", bid.clone()), ("rustdesk_id", Val::Str(id.clone()))];
                    cols.extend(fields.into_iter().map(|(k, v)| (k, Val::Str(v))));
                    cols.push(("password_enc", enc));
                    db::insert(c, "address_book_entries", cols, &ts)?;
                }
                Some(mut e) => {
                    let mut changes: Vec<(&str, Val, Cast)> = fields.into_iter().map(|(k, v)| (k, Val::Str(v), Cast::Plain)).collect();
                    changes.push(("password_enc", enc, Cast::Plain));
                    db::update_dirty(c, "address_book_entries", &mut e, changes, &ts)?;
                }
            }
            written += 1;
        }
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platforms_like_the_device_model() {
        for (os, p) in [("windows / Windows 11 Pro", "Windows"), ("Mac OS 15.1", "Mac OS"), ("darwin", "Mac OS"), ("Android 14", "Android"), ("iOS 18", "iOS"), ("Ubuntu 24.04", "Linux"), ("", ""), ("plan9", "")] {
            assert_eq!(rustdesk_platform(&Val::str(os)), p, "{os}");
        }
        assert_eq!(rustdesk_platform(&Val::Null), "");
    }
}
