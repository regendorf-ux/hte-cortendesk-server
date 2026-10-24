//! The console's SQLite file, shared with the PHP console (`/data/cortendesk.sqlite`), and Eloquent's write rules.
//!
//! No schema changes: PHP owns the schema and its migrations. Writes bind values with the types PDO uses under
//! Laravel (ints as INTEGER, booleans as 0/1, everything else as TEXT), so SQLite's column affinity stores exactly
//! what PHP would. SQL is never built from input: table and column names are constants of this crate, values are
//! always bound.

use crate::laravel::{self, Cast};
use crate::php::{Fault, Val};
use rusqlite::types::{ToSqlOutput, ValueRef};
use rusqlite::{Connection, OpenFlags, ToSql};
use std::path::Path;
use std::time::Duration;

/// A bound parameter with PDO-under-Laravel typing.
pub struct P(pub Val);

impl ToSql for P {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(match &self.0 {
            Val::Null => ToSqlOutput::Borrowed(ValueRef::Null),
            Val::Bool(b) => ToSqlOutput::Owned(rusqlite::types::Value::Integer(*b as i64)),
            Val::Int(i) => ToSqlOutput::Owned(rusqlite::types::Value::Integer(*i)),
            // PARAM_STR of a float: PHP's string form at `precision`
            Val::Float(f) => ToSqlOutput::Owned(rusqlite::types::Value::Text(crate::php::float_to_string(*f))),
            Val::Str(s) => ToSqlOutput::Borrowed(ValueRef::Text(s)),
            Val::Arr(_) => return Err(rusqlite::Error::ToSqlConversionFailure("array binding".into())),
        })
    }
}

pub fn fault(e: rusqlite::Error) -> Fault {
    Fault::Other(format!("database: {e}"))
}

/// Open the shared database: busy_timeout (PHP's PDO waits up to 60 s, we wait `busy`), foreign keys on (as
/// Laravel's sqlite connection), and WAL when asked (persistent in the file; PHP needs no change for it).
pub fn open(path: &Path, busy: Duration, wal: bool) -> Result<Connection, String> {
    let c = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX)
        .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    c.busy_timeout(busy).map_err(|e| e.to_string())?;
    c.pragma_update(None, "foreign_keys", "ON").map_err(|e| e.to_string())?;
    if wal {
        let mode: String = c.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0)).map_err(|e| format!("cannot switch to WAL: {e}"))?;
        if !mode.eq_ignore_ascii_case("wal") {
            return Err(format!("journal_mode is {mode}, not wal"));
        }
    }
    Ok(c)
}

/// A row as PDO hands it to PHP: column name to PHP value (INTEGER -> int, REAL -> float, TEXT/BLOB -> string).
#[derive(Clone, Debug, Default)]
pub struct Row(pub Vec<(String, Val)>);

impl Row {
    pub fn get(&self, col: &str) -> Option<&Val> {
        self.0.iter().find(|(k, _)| k == col).map(|(_, v)| v)
    }
    /// `$model->col` for a column that may not be loaded: null.
    pub fn val(&self, col: &str) -> Val {
        self.get(col).cloned().unwrap_or(Val::Null)
    }
    pub fn set(&mut self, col: &str, v: Val) {
        match self.0.iter_mut().find(|(k, _)| k == col) {
            Some(slot) => slot.1 = v,
            None => self.0.push((col.to_string(), v)),
        }
    }
    pub fn id(&self) -> i64 {
        self.val("id").to_int()
    }
    pub fn is_null(&self, col: &str) -> bool {
        matches!(self.val(col), Val::Null)
    }
}

fn to_val(v: ValueRef<'_>) -> Val {
    match v {
        ValueRef::Null => Val::Null,
        ValueRef::Integer(i) => Val::Int(i),
        ValueRef::Real(f) => Val::Float(f),
        ValueRef::Text(t) => Val::Str(t.to_vec()),
        ValueRef::Blob(b) => Val::Str(b.to_vec()),
    }
}

/// All rows of a query.
pub fn rows(c: &Connection, sql: &str, params: &[P]) -> Result<Vec<Row>, Fault> {
    let mut st = c.prepare_cached(sql).map_err(fault)?;
    let names: Vec<String> = st.column_names().iter().map(|s| s.to_string()).collect();
    let refs: Vec<&dyn ToSql> = params.iter().map(|p| p as &dyn ToSql).collect();
    let mut q = st.query(refs.as_slice()).map_err(fault)?;
    let mut out = vec![];
    while let Some(r) = q.next().map_err(fault)? {
        let mut row = Row::default();
        for (i, n) in names.iter().enumerate() {
            row.0.push((n.clone(), to_val(r.get_ref(i).map_err(fault)?)));
        }
        out.push(row);
    }
    Ok(out)
}

pub fn first(c: &Connection, sql: &str, params: &[P]) -> Result<Option<Row>, Fault> {
    Ok(rows(c, sql, params)?.into_iter().next())
}

/// A statement that changes rows; returns how many.
pub fn exec(c: &Connection, sql: &str, params: &[P]) -> Result<usize, Fault> {
    let mut st = c.prepare_cached(sql).map_err(fault)?;
    let refs: Vec<&dyn ToSql> = params.iter().map(|p| p as &dyn ToSql).collect();
    st.execute(refs.as_slice()).map_err(fault)
}

/// `Setting::get($key, $default)`: the stored value, or the default when the row is missing or its value null.
pub fn setting(c: &Connection, key: &str, default: &str) -> Result<Vec<u8>, Fault> {
    let row = first(c, r#"select * from "settings" where "settings"."key" = ? limit 1"#, &[P(Val::str(key))])?;
    Ok(match row.map(|r| r.val("value")) {
        None | Some(Val::Null) => default.as_bytes().to_vec(),
        Some(v) => v.to_php_string()?,
    })
}

/// `Model::create($attributes)`: insert with created_at/updated_at = now; returns the new id.
/// `table` and the column names are this crate's constants.
pub fn insert(c: &Connection, table: &str, cols: Vec<(&str, Val)>, now: &str) -> Result<i64, Fault> {
    let mut cols = cols;
    cols.push(("updated_at", Val::str(now)));
    cols.push(("created_at", Val::str(now)));
    let names: Vec<String> = cols.iter().map(|(n, _)| format!("\"{n}\"")).collect();
    let marks = vec!["?"; cols.len()].join(", ");
    let sql = format!("insert into \"{table}\" ({}) values ({marks})", names.join(", "));
    let params: Vec<P> = cols.into_iter().map(|(_, v)| P(v)).collect();
    exec(c, &sql, &params)?;
    Ok(c.last_insert_rowid())
}

/// `$model->forceFill($changes)->save()` on a loaded row: only attributes that Eloquent sees as changed are
/// written, plus updated_at; nothing at all when none changed. The row is updated in memory as PHP's model is.
/// Returns whether an UPDATE ran.
pub fn update_dirty(c: &Connection, table: &str, row: &mut Row, changes: Vec<(&str, Val, Cast)>, now: &str) -> Result<bool, Fault> {
    let mut dirty: Vec<(String, Val)> = vec![];
    for (col, v, cast) in changes {
        let clean = laravel::equivalent(cast, &v, row.get(col))?;
        row.set(col, v.clone());
        if !clean {
            dirty.retain(|(k, _)| k != col);
            dirty.push((col.to_string(), v));
        }
    }
    if dirty.is_empty() {
        return Ok(false);
    }
    if !laravel::equivalent(Cast::Date, &Val::str(now), row.get("updated_at"))? {
        dirty.push(("updated_at".into(), Val::str(now)));
    }
    row.set("updated_at", Val::str(now));
    let sets: Vec<String> = dirty.iter().map(|(k, _)| format!("\"{k}\" = ?")).collect();
    let sql = format!("update \"{table}\" set {} where \"id\" = ?", sets.join(", "));
    let mut params: Vec<P> = dirty.into_iter().map(|(_, v)| P(v)).collect();
    params.push(P(Val::Int(row.id())));
    exec(c, &sql, &params)?;
    Ok(true)
}
