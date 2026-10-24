//! `hte-console snapshot <sqlite>`: the whole database as comparable text, for the replay's "same state after
//! the same requests" check between PHP and hte-console.
//!
//! Every table, every row in rowid order, every column with its SQLite storage class (so an integer stored where
//! PHP stores text is a difference). Masked, and only these: timestamps (`*_at`: the two runs happen at different
//! times), `guid` (a random UUID), `*_enc` (Laravel ciphertext has a random IV) and `strategy_version` (it is
//! `time()`); phase 2 adds what sign-in mints at random (`token`, `access_token`, and `code`, `state`, `nonce`,
//! `verifier` of `oidc_auth_requests`), a bcrypt hash (`$2y$...`, salted) and `totp_last_timestep` (the 30-second step
//! the run happened in). A masked value still shows whether it is null.

use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags};
use serde_json::{Map, Value};
use std::path::Path;

fn masked(col: &str) -> Option<&'static str> {
    if col.ends_with("_at") {
        Some("<ts>")
    } else if col == "guid" {
        Some("<uuid>")
    } else if col.ends_with("_enc") {
        Some("<enc>")
    } else if col == "strategy_version" {
        Some("<time>")
    } else if matches!(col, "token" | "access_token" | "code" | "state" | "nonce" | "verifier") {
        Some("<random>")
    } else if col == "totp_last_timestep" {
        Some("<step>")
    } else {
        None
    }
}

fn cell(col: &str, v: ValueRef<'_>) -> Value {
    let (class, shown) = match v {
        ValueRef::Null => return Value::Null,
        ValueRef::Integer(i) => ("integer", i.to_string()),
        ValueRef::Real(f) => ("real", format!("{f:?}")),
        ValueRef::Text(t) if t.len() == 60 && t.starts_with(b"$2y$") => ("text", "<bcrypt>".into()),
        ValueRef::Text(t) => ("text", String::from_utf8_lossy(t).into_owned()),
        ValueRef::Blob(b) => ("blob", hex::encode(b)),
    };
    Value::String(format!("{class}:{}", masked(col).map(str::to_string).unwrap_or(shown)))
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
}
