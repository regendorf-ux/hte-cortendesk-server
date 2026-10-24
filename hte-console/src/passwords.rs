//! HTE's per-computer passwords, the heartbeat half: a port of `App\Hte\Passwords::heartbeat`, `issue`,
//! `sealFor`, `devicePublicKey` and `updateBookEntries` (v1.15.0-hte.1). The minute sweep and the books are phase 3's
//! `passwords_sweep.rs`.
//!
//! The password travels only as a libsodium sealed box to the computer's own ed25519 key (converted to
//! curve25519), as registered with the ID server in hbbs's `peer` table. Plaintext passwords are never logged.

use crate::sqlite::{self as db, Row, P};
use crate::laravel::{Cast, Encrypter};
use crate::php::{self, Fault, Val};
use base64::Engine;
use rusqlite::{Connection, OpenFlags};
use sodiumoxide::crypto::{sealedbox, sign};
use std::path::Path;

pub const SETTING_ENABLED: &str = "hte_pw_enabled";

const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";

/// `Passwords::generate()`: 20 characters from an alphabet without look-alikes.
pub fn generate() -> String {
    use rand::Rng;
    let mut r = rand::rngs::OsRng;
    (0..20).map(|_| ALPHABET[r.gen_range(0..ALPHABET.len())] as char).collect()
}

fn find(c: &Connection, rustdesk_id: &[u8]) -> Result<Option<Row>, Fault> {
    db::first(c, r#"select * from "hte_device_passwords" where "rustdesk_id" = ? limit 1"#, &[P(Val::Str(rustdesk_id.to_vec()))])
}

/// `DevicePassword::firstOrNew(['rustdesk_id' => ...])` followed by `save()` of the given attributes.
fn save_new(c: &Connection, rustdesk_id: &[u8], attrs: Vec<(&str, Val)>, now: &str) -> Result<Row, Fault> {
    let mut cols = vec![("current_version", Val::Int(0)), ("confirmed_version", Val::Int(0)), ("rustdesk_id", Val::Str(rustdesk_id.to_vec()))];
    cols.extend(attrs);
    let id = db::insert(c, "hte_device_passwords", cols, now)?;
    db::first(c, r#"select * from "hte_device_passwords" where "id" = ? limit 1"#, &[P(Val::Int(id))])?.ok_or_else(|| Fault::Other("inserted row vanished".into()))
}

/// `Passwords::devicePublicKey($id)`: the 32-byte ed25519 key hbbs registered, or None (missing file, table,
/// row, or a value of the wrong shape). Opened read-only.
pub fn device_public_key(hbbs_db: &Path, rustdesk_id: &[u8]) -> Option<Vec<u8>> {
    if std::fs::File::open(hbbs_db).is_err() {
        return None;
    }
    let c = Connection::open_with_flags(hbbs_db, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX).ok()?;
    let _ = c.busy_timeout(std::time::Duration::from_secs(5));
    let row = db::first(&c, "select pk from peer where id = ? limit 1", &[P(Val::Str(rustdesk_id.to_vec()))]).ok()??;
    match row.val("pk") {
        Val::Str(pk) if pk.len() == sign::PUBLICKEYBYTES => Some(pk),
        _ => None,
    }
}

/// `Passwords::sealFor($device, $row)`: base64 of `{"v":..,"pw":..}` sealed to the computer's key.
/// A key libsodium cannot convert is a Fault, as PHP's SodiumException is.
pub fn seal_for(hbbs_db: &Path, crypt: &Encrypter, rustdesk_id: &[u8], row: &Row) -> Result<Option<String>, Fault> {
    let Some(pk) = device_public_key(hbbs_db, rustdesk_id) else { return Ok(None) };
    let enc = match row.val("current_enc") {
        Val::Null => return Ok(None),
        v => v.to_php_string()?,
    };
    let pw = crypt.decrypt_string(&enc)?;
    let payload = php::json_encode(&php::assoc(vec![("v".to_string(), Val::Int(row.val("current_version").to_int())), ("pw".to_string(), Val::Str(pw))]))
        .unwrap_or_default(); // json_encode false -> "" (PHP passes false on as an empty string)
    let ed = sign::PublicKey::from_slice(&pk).ok_or_else(|| Fault::Other("public key size".into()))?;
    let curve = sign::to_curve25519_pk(&ed).map_err(|_| Fault::Other("sodium: ed25519 key conversion failed".into()))?;
    let sealed = sealedbox::seal(payload.as_bytes(), &curve);
    Ok(Some(base64::engine::general_purpose::STANDARD.encode(sealed)))
}

/// `Passwords::issue($device, $reason)`; also the sweep's (phase 3).
pub(crate) fn issue(c: &Connection, crypt: &Encrypter, rustdesk_id: &[u8], reason: &str, now: &str) -> Result<Row, Fault> {
    let enc = crypt.encrypt_string(generate().as_bytes());
    // Str::limit($reason, 60, ''): the sweep's "access removed (names)" can be longer
    let reason = crate::validate::str_limit(reason, 60, "");
    match find(c, rustdesk_id)? {
        Some(mut row) => {
            let next = std::cmp::max(row.val("current_version").to_int(), row.val("confirmed_version").to_int()) + 1;
            db::update_dirty(
                c,
                "hte_device_passwords",
                &mut row,
                vec![
                    ("current_version", Val::Int(next), Cast::Int),
                    ("current_enc", Val::str(&enc), Cast::Plain),
                    ("issued_at", Val::str(now), Cast::Date),
                    ("issued_reason", Val::str(&reason), Cast::Plain),
                ],
                now,
            )?;
            Ok(row)
        }
        None => save_new(c, rustdesk_id, vec![("current_version", Val::Int(1)), ("current_enc", Val::str(&enc)), ("issued_at", Val::str(now)), ("issued_reason", Val::str(&reason))], now),
    }
}

/// `Passwords::updateBookEntries($row)`: a confirmed password goes into the automatic books at once.
fn update_book_entries(c: &Connection, crypt: &Encrypter, row: &Row, now: &str) -> Result<(), Fault> {
    let enc = match row.val("confirmed_enc") {
        Val::Null => return Ok(()),
        v => v.to_php_string()?,
    };
    let books = db::rows(c, r#"select "address_book_id" from "hte_auto_books""#, &[])?;
    let fresh = crypt.encrypt_string(&crypt.decrypt_string(&enc)?);
    if books.is_empty() {
        return Ok(()); // whereIn([]) is "0 = 1": no row changes
    }
    let marks = vec!["?"; books.len()].join(", ");
    let sql = format!(r#"update "address_book_entries" set "password_enc" = ?, "updated_at" = ? where "address_book_id" in ({marks}) and "rustdesk_id" = ?"#);
    let mut params = vec![P(Val::str(&fresh)), P(Val::str(now))];
    params.extend(books.into_iter().map(|b| P(b.val("address_book_id"))));
    params.push(P(row.val("rustdesk_id")));
    db::exec(c, &sql, &params)?;
    Ok(())
}

/// What the heartbeat adds: `hte_password` = {v, box}.
pub struct Offer {
    pub v: i64,
    pub sealed: String,
}

/// `Passwords::heartbeat($device, $request, $response)`; `held` is `(int) input('hte_pw')`, called only when
/// the request has `hte_pw`.
pub fn heartbeat(c: &Connection, crypt: &Encrypter, hbbs_db: &Path, device: &Row, held: i64, now: &str) -> Result<Option<Offer>, Fault> {
    let rid = device.val("rustdesk_id").to_php_string()?;
    let mut row = match find(c, &rid)? {
        None => save_new(c, &rid, vec![("capable_at", Val::str(now))], now)?,
        Some(mut row) => {
            let cur = row.val("current_version").to_int();
            if cur > 0 && held == cur && row.val("confirmed_version").to_int() != held {
                let current_enc = row.val("current_enc");
                db::update_dirty(
                    c,
                    "hte_device_passwords",
                    &mut row,
                    vec![
                        ("capable_at", Val::str(now), Cast::Date),
                        ("confirmed_version", Val::Int(held), Cast::Int),
                        ("confirmed_enc", current_enc, Cast::Plain),
                        ("confirmed_at", Val::str(now), Cast::Date),
                    ],
                    now,
                )?;
                update_book_entries(c, crypt, &row, now)?;
            } else {
                db::update_dirty(c, "hte_device_passwords", &mut row, vec![("capable_at", Val::str(now), Cast::Date)], now)?;
            }
            row
        }
    };
    if db::setting(c, SETTING_ENABLED, "0")? != b"1" || device.val("status") != Val::str("active") {
        return Ok(None);
    }
    if row.val("current_version").to_int() == 0 {
        row = issue(c, crypt, &rid, "first check-in", now)?;
    }
    if held != row.val("current_version").to_int() {
        if let Some(sealed) = seal_for(hbbs_db, crypt, &rid, &row)? {
            return Ok(Some(Offer { v: row.val("current_version").to_int(), sealed }));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_uses_the_alphabet() {
        let p = generate();
        assert_eq!(p.len(), 20);
        assert!(p.bytes().all(|c| ALPHABET.contains(&c)));
    }
}
