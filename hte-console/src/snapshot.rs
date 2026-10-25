//! `hte-console snapshot <sqlite>`: the whole database as comparable text, for the replay's "same state after
//! the same requests" check between PHP and hte-console.
//!
//! Every table, every row in rowid order, every column with its SQLite storage class (so an integer stored where
//! PHP stores text is a difference). Masked, and only these: timestamps (`*_at`: the two runs happen at different
//! times), `guid` (a random UUID), `*_enc` (Laravel ciphertext has a random IV) and `strategy_version` (it is
//! `time()`); phase 2 adds what sign-in mints at random (`token`, `access_token`, and `code`, `state`, `nonce`,
//! `verifier` of `oidc_auth_requests`), a bcrypt hash (`$2y$...`, salted) and `totp_last_timestep` (the 30-second step
//! the run happened in). A masked value still shows whether it is null.
//! `HTE_SNAPSHOT_MASK_TOKENS=1` (the page replay) also masks `token_hash` and `token_prefix`.
//! Phase 3: of Laravel's `cache` table only the two keys hte-console writes as PHP does (the policy-pull marker and
//! the scheduler heartbeat: their timestamps and `expiration` masked); PHP's other cache rows (rate limiters, OIDC
//! discovery, the TOTP step) are process memory in hte-console by design. `cache_locks`: owner and expiry masked.

use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags};
use serde_json::{Map, Value};
use std::path::Path;

static ISO: once_cell::sync::Lazy<regex::Regex> =
    once_cell::sync::Lazy::new(|| regex::Regex::new(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00").unwrap());

/// The `cache` rows compared (by key suffix: the key carries PHP's prefix).
fn compared_cache_row(key: &str) -> bool {
    key.ends_with(crate::cache::PULL_KEY) || key.ends_with(crate::cache::SCHEDULER_HEARTBEAT_KEY)
}

fn masked(col: &str) -> Option<&'static str> {
    if col.ends_with("_at") {
        Some("<ts>")
    } else if col == "guid" {
        Some("<uuid>")
    } else if col.ends_with("_enc") {
        Some("<enc>")
    } else if col == "strategy_version" {
        Some("<time>")
    } else if matches!(col, "token" | "access_token" | "code" | "state" | "nonce" | "verifier" | "remember_token") {
        Some("<random>")
    } else if col == "totp_last_timestep" {
        Some("<step>")
    } else if col == "expiration" {
        Some("<time>")
    } else if col == "owner" {
        Some("<owner>")
    } else {
        None
    }
}

fn cell(col: &str, v: ValueRef<'_>) -> Value {
    let mask_tokens = crate::envvar::var("HTE_SNAPSHOT_MASK_TOKENS").map_or(false, |v| v == "1");
    let (class, shown) = match v {
        ValueRef::Null => return Value::Null,
        ValueRef::Integer(i) => ("integer", i.to_string()),
        ValueRef::Real(f) => ("real", format!("{f:?}")),
        ValueRef::Text(t) if t.len() == 60 && t.starts_with(b"$2y$") => ("text", "<bcrypt>".into()),
        // a cached value (PHP serialize) holding an ISO-8601 time: the time masked, its length kept
        // phase 5: a console-audit line names a book it created by its random guid
        ValueRef::Text(t) if col == "target_id" && t.len() == 36 && !t.starts_with(b"00000000-0000-4000-8000-") && t.iter().filter(|b| **b == b'-').count() == 4 => ("text", "<uuid>".into()),
        ValueRef::Text(t) if col == "value" => ("text", ISO.replace_all(&String::from_utf8_lossy(t), "<iso-ts:25>").into_owned()),
        ValueRef::Text(t) => ("text", String::from_utf8_lossy(t).into_owned()),
        ValueRef::Blob(b) => ("blob", hex::encode(b)),
    };
    // phase 7b: a console-made API token is random (the replay creates one on each side); every other run compares the hash
    let hidden = masked(col).or_else(|| (mask_tokens && matches!(col, "token_hash" | "token_prefix")).then_some("<random>"));
    Value::String(format!("{class}:{}", hidden.map(str::to_string).unwrap_or(shown)))
}

pub fn snapshot(path: &Path) -> Result<String, String> {
    let c = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut tables: Vec<String> = vec![];
    {
        let mut st = c.prepare("select name from sqlite_master where type = 'table' and name not like 'sqlite_stat%' order by name").map_err(|e| e.to_string())?;
        let mut rows = st.query([]).map_err(|e| e.to_string())?;
        while let Some(r) = rows.next().map_err(|e| e.to_string())? {
            tables.push(r.get(0).map_err(|e| e.to_string())?);
        }
    }
    let mut out = String::new();
    for t in tables {
        // table names come from sqlite_master, quoted as identifiers
        let quoted = format!("\"{}\"", t.replace('"', "\"\""));
        let order = if t == "sqlite_sequence" { "name" } else { "rowid" };
        let mut st = c.prepare(&format!("select * from {quoted} order by {order}")).map_err(|e| format!("{t}: {e}"))?;
        let names: Vec<String> = st.column_names().iter().map(|s| s.to_string()).collect();
        let mut rows = st.query([]).map_err(|e| e.to_string())?;
        let mut n = 0;
        while let Some(r) = rows.next().map_err(|e| e.to_string())? {
            if t == "cache" {
                let key: String = names.iter().position(|n| n == "key").and_then(|i| r.get::<_, String>(i).ok()).unwrap_or_default();
                if !compared_cache_row(&key) {
                    continue;
                }
            }
            let mut m = Map::new();
            for (i, name) in names.iter().enumerate() {
                m.insert(name.clone(), cell(name, r.get_ref(i).map_err(|e| e.to_string())?));
            }
            out.push_str(&format!("{t} {}\n", Value::Object(m)));
            n += 1;
        }
        out.push_str(&format!("{t}: {n} rows\n"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_only_what_must_differ() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x.sqlite");
        let c = Connection::open(&p).unwrap();
        c.execute_batch(
            "create table t (id integer primary key, guid varchar, created_at datetime, current_enc text, n integer, s varchar);
             insert into t values (1, 'abc', '2026-01-01 00:00:00', 'eyJ', 5, '5');
             insert into t values (2, null, null, null, null, 'x');",
        )
        .unwrap();
        drop(c);
        let s = snapshot(&p).unwrap();
        assert!(s.contains(r#""guid":"text:<uuid>""#));
        assert!(s.contains(r#""created_at":"text:<ts>""#));
        assert!(s.contains(r#""current_enc":"text:<enc>""#));
        assert!(s.contains(r#""n":"integer:5""#));
        assert!(s.contains(r#""s":"text:5""#));
        assert!(s.contains(r#""guid":null"#));
        assert!(s.contains("t: 2 rows"));
    }

    #[test]
    fn cache_rows_compared_are_the_two_phase_3_keys() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x.sqlite");
        let c = Connection::open(&p).unwrap();
        c.execute_batch(
            r#"create table "cache" ("key" varchar primary key, "value" text, "expiration" integer);
             insert into cache values ('p-cortendesk:server-link:last-pull', 'a:2:{s:2:"at";s:25:"2026-10-24T20:39:00+00:00";s:5:"agent";s:1:"x";}', 2000000000);
             insert into cache values ('p-server-link0123', 'i:1;', 2000000000);"#,
        )
        .unwrap();
        drop(c);
        let s = snapshot(&p).unwrap();
        assert!(s.contains(r#"s:25:\"<iso-ts:25>\""#), "{s}");
        assert!(s.contains(r#""expiration":"integer:<time>""#), "{s}");
        assert!(!s.contains("server-link0123") && s.contains("cache: 1 rows"), "{s}");
    }
}
