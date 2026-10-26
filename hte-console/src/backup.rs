//! Phase 6: local backups, ported from `App\Services\Backups\BackupService` (1.15.0-hte.1) and
//! `cortendesk:backup` / `cortendesk:restore`. Not ported: the off-site copies (FTP, S3: `syncRemote`, `FtpTarget`,
//! `S3Target`; ported later), the upload/download routes of Settings -> Backups (UI, a later phase), Apprise.
//!
//! The archive is the previous console's, byte layout and all, so one made by the previous console restores here and one made here restores in the previous console:
//!
//! ```text
//!   hte-remote-backup-YYYYMMDD-HHMMSS[-tag].tar      plain tar (tarfile.rs), no directory entries
//!     manifest.json                  {"format":1,"app":"cortendesk","app_version","created_at","trigger","app_url",
//!                                     "db_driver":"sqlite","tables":{name:rows},"files":[...]}  (pretty, 4 spaces)
//!     db/<table>.ndjson.gz           one JSON object per row, columns in table order
//!     files/app_key                  the Laravel APP_KEY as the container has it
//!     files/server_secret            when the server link is on
//!     files/rustdesk/{id_ed25519,id_ed25519.pub,db_v2.sqlite3}
//!   hte-remote-backup-....tar.json   the manifest again (the Settings page lists from it)
//! ```
//!
//! Differences from the previous console, all invisible to its reader: the rows are dumped from one `VACUUM INTO` snapshot of the
//! database (the previous console reads table after table while devices keep writing), a restore is built and checked in a temporary
//! database before the live one is touched and then applied in a single transaction (the previous console deletes and inserts in
//! the live database), an archive that is cut short or whose row counts disagree with its manifest is refused (the previous console
//! would restore a truncated table silently), and `hte_device_passwords` is re-keyed too when the app key differs
//! (the previous console lists only settings, users.totp_secret and address_book_entries.password_enc, which leaves HTE Remote's
//! sealed-at-rest passwords unreadable after a restore into an install with another key).

use crate::cache::Store;
use crate::laravel::Encrypter;
use crate::php::Val;
use crate::sqlite as db;
use crate::tarfile;
use chrono::{DateTime, Datelike, FixedOffset, TimeZone, Utc};
use once_cell::sync::Lazy;
use regex::Regex;
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags};
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const FORMAT: i64 = 1;
/// New archives (phase 9). The content is unchanged (the previous console's format, manifest `"app": "cortendesk"`), so an archive restores into the
/// The previous console image too once renamed to `OLD_PREFIX...`; restore and the lists here accept both names.
pub const PREFIX: &str = "hte-remote-backup-";
pub const OLD_PREFIX: &str = "cortendesk-backup-";
/// Per-process or per-request state, not data: neither backed up nor touched on restore.
/// (`hte_console_sessions`: phase 8's own console sessions, the same kind of state as `sessions`.)
pub const SKIP_TABLES: [&str; 10] = ["cache", "cache_locks", "sessions", "jobs", "job_batches", "failed_jobs", "oidc_auth_requests", "password_reset_tokens", "password_resets", "hte_console_sessions"];
/// In the archive for the record; the live schema owns it on restore.
pub const KEEP_ON_RESTORE: [&str; 1] = ["migrations"];
/// Laravel-encrypted columns, re-keyed on restore when the archive's APP_KEY differs (see the header for the last one).
pub const ENCRYPTED_COLUMNS: [(&str, &[&str]); 4] = [
    ("settings", &["value"]),
    ("users", &["totp_secret"]),
    ("address_book_entries", &["password_enc"]),
    ("hte_device_passwords", &["current_enc", "confirmed_enc"]),
];
pub const RUSTDESK_FILES: [&str; 3] = ["id_ed25519", "id_ed25519.pub", "db_v2.sqlite3"];
pub const DEFAULT_KEEP: Keep = Keep { daily: 7, weekly: 8, monthly: 6 };
pub const MAX_KEEP: i64 = 365;
/// `Cache::lock('cortendesk:backup', 3600)`: shared with the previous console's Settings -> Backups, so a click there and a run here exclude each other.
pub const LOCK_NAME: &str = "cortendesk:backup";
const LOCK_SECONDS: i64 = 3600;
/// `readRows`: longest line accepted.
const MAX_LINE: usize = 16 * 1024 * 1024;

static NAME_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^(?:hte-remote|cortendesk)-backup-\d{8}-\d{6}(?:-[a-z0-9]{1,16})?\.tar$").unwrap());
static IDENT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z0-9_]{1,128}$").unwrap());

pub fn is_backup_name(name: &str) -> bool {
    NAME_RE.is_match(name)
}

/// The `YYYYMMDD-HHMMSS[-tag].tar` part of a backup name, whichever prefix it has: the time order of names.
pub fn stamp_of(name: &str) -> &str {
    name.strip_prefix(PREFIX).or_else(|| name.strip_prefix(OLD_PREFIX)).unwrap_or(name)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Keep {
    pub daily: i64,
    pub weekly: i64,
    pub monthly: i64,
}

/// Everything a backup or restore needs from the environment; built by `housekeeping::Env`.
#[derive(Clone, Debug)]
pub struct Env {
    pub database: PathBuf,
    pub busy: Duration,
    pub backups_dir: PathBuf,
    /// hbbs's data directory; None when the ID server does not run here.
    pub rustdesk_dir: Option<PathBuf>,
    /// `config('app.key')`: holds a secret, never logged.
    pub app_key: String,
    pub server_secret: String,
    pub app_url: String,
    pub app_version: String,
    pub store: Store,
}

impl Env {
    pub fn open(&self) -> Result<Connection, String> {
        db::open(&self.database, self.busy, false)
    }
}

// ------------------------------------------------------------------------------------------------ settings ---

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    pub enabled: bool,
    pub keep: Keep,
    /// `none`, `ftp` or `s3`
    pub target: String,
}

pub fn setting_value(c: &Connection, key: &str, default: &str) -> Result<String, String> {
    setting(c, key, default)
}

fn setting(c: &Connection, key: &str, default: &str) -> Result<String, String> {
    db::setting(c, key, default).map(|v| String::from_utf8_lossy(&v).into_owned()).map_err(|f| format!("{f:?}"))
}

/// `BackupService::settings()`
pub fn settings(c: &Connection) -> Result<Settings, String> {
    let mut keep = [DEFAULT_KEEP.daily, DEFAULT_KEEP.weekly, DEFAULT_KEEP.monthly];
    for (i, tier) in ["daily", "weekly", "monthly"].iter().enumerate() {
        // Setting::get('backup_keep_<tier>'): null -> default; '' -> default; else (int) clamped
        let row = db::first(c, r#"select * from "settings" where "settings"."key" = ? limit 1"#, &[db::P(Val::str(&format!("backup_keep_{tier}")))]).map_err(|f| format!("{f:?}"))?;
        if let Some(v) = row.map(|r| r.val("value")) {
            if !matches!(v, Val::Null) {
                let s = v.to_php_string().map_err(|f| format!("{f:?}"))?;
                if !s.is_empty() {
                    keep[i] = crate::php::str_to_int(&s).clamp(0, MAX_KEEP);
                }
            }
        }
    }
    let target = setting(c, "backup_target", "none")?;
    Ok(Settings {
        enabled: setting(c, "backup_enabled", "1")? == "1",
        keep: Keep { daily: keep[0], weekly: keep[1], monthly: keep[2] },
        target: if ["none", "ftp", "s3"].contains(&target.as_str()) { target } else { "none".into() },
    })
}

/// `Setting::put($key, $value)`: `updateOrCreate`, so an unchanged value writes nothing.
pub fn put_setting(c: &Connection, key: &str, value: &str, now: i64) -> Result<(), String> {
    let ts = crate::laravel::ts(now);
    let row = db::first(c, r#"select * from "settings" where "settings"."key" = ? limit 1"#, &[db::P(Val::str(key))]).map_err(|f| format!("{f:?}"))?;
    match row {
        Some(r) => {
            if r.val("value").to_php_string().ok().as_deref() == Some(value.as_bytes()) && !matches!(r.val("value"), Val::Null) {
                return Ok(());
            }
            db::exec(c, r#"update "settings" set "value" = ?, "updated_at" = ? where "key" = ?"#, &[db::P(Val::str(value)), db::P(Val::str(&ts)), db::P(Val::str(key))]).map_err(|f| format!("{f:?}"))?;
        }
        None => {
            db::exec(
                c,
                r#"insert into "settings" ("key", "value", "updated_at", "created_at") values (?, ?, ?, ?)"#,
                &[db::P(Val::str(key)), db::P(Val::str(value)), db::P(Val::str(&ts)), db::P(Val::str(&ts))],
            )
            .map_err(|f| format!("{f:?}"))?;
        }
    }
    Ok(())
}

/// `Carbon::parse` for the two shapes the console writes (ISO 8601 with offset, and `Y-m-d H:i:s` as UTC).
pub fn parse_when(s: &str) -> Option<DateTime<FixedOffset>> {
    let s = s.trim();
    if let Ok(d) = DateTime::parse_from_rfc3339(s) {
        return Some(d);
    }
    crate::laravel::parse_ts(&Val::str(s)).and_then(|t| Utc.timestamp_opt(t, 0).single()).map(|d| d.fixed_offset())
}

/// `BackupService::due()`: nothing scheduled since midnight (UTC, the app's timezone).
pub fn due(last_scheduled: Option<DateTime<FixedOffset>>, now: i64) -> bool {
    match last_scheduled {
        None => true,
        Some(l) => l.timestamp() < now - now.rem_euclid(86_400),
    }
}

pub fn iso(unix: i64) -> String {
    DateTime::from_timestamp(unix, 0).map(|d| d.format("%Y-%m-%dT%H:%M:%S+00:00").to_string()).unwrap_or_default()
}

// ------------------------------------------------------------------------------------------------ retention ---

/// `BackupService::prunable()`: which backups the retention tiers do not cover, oldest first. A backup is a daily
/// point; the oldest one inside an ISO week (`o-W`) or a month (`Y-m`) is that period's weekly or monthly point;
/// periods are counted from the newest backup. All three tiers 0 keeps everything.
pub fn prunable(entries: &[(String, DateTime<FixedOffset>)], keep: Keep) -> Vec<String> {
    if keep.daily.max(0) + keep.weekly.max(0) + keep.monthly.max(0) <= 0 {
        return vec![];
    }
    let mut sorted: Vec<&(String, DateTime<FixedOffset>)> = entries.iter().collect();
    // created_at descending, then name descending (strcmp)
    sorted.sort_by(|a, b| b.1.timestamp().cmp(&a.1.timestamp()).then_with(|| b.0.as_bytes().cmp(a.0.as_bytes())));
    let mut kept: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for e in sorted.iter().take(keep.daily.max(0) as usize) {
        kept.insert(&e.0);
    }
    for (n, week) in [(keep.weekly, true), (keep.monthly, false)] {
        if n <= 0 {
            continue;
        }
        // Newest first, so the last write per period is the oldest backup in it; keys keep the order of their first
        // appearance, newest period first (a previous-console array does the same).
        let mut periods: Vec<(String, &str)> = vec![];
        for e in &sorted {
            let key = if week {
                let w = e.1.iso_week();
                format!("{}-{:02}", w.year(), w.week())
            } else {
                e.1.format("%Y-%m").to_string()
            };
            match periods.iter_mut().find(|(k, _)| *k == key) {
                Some(slot) => slot.1 = &e.0,
                None => periods.push((key, &e.0)),
            }
        }
        for (_, name) in periods.into_iter().take(n as usize) {
            kept.insert(name);
        }
    }
    sorted.iter().rev().filter(|e| !kept.contains(e.0.as_str())).map(|e| e.0.clone()).collect()
}

// -------------------------------------------------------------------------------------------------- storage ---

#[derive(Clone, Debug)]
pub struct Listed {
    pub name: String,
    pub path: PathBuf,
    pub size: u64,
    pub created_at: DateTime<FixedOffset>,
    pub manifest: Option<serde_json::Value>,
}

/// `directory()`: created 0700 when missing, must be writable.
pub fn directory(env: &Env) -> Result<PathBuf, String> {
    let dir = &env.backups_dir;
    if dir.as_os_str().is_empty() {
        return Err("No backup directory is configured (HTE_REMOTE_BACKUPS_PATH).".into());
    }
    if !dir.is_dir() {
        let _ = fs::DirBuilder::new().recursive(true).mode_0700().create(dir);
        if !dir.is_dir() {
            return Err(format!("Cannot create the backup directory {}.", dir.display()));
        }
    }
    let probe = dir.join(format!(".probe-{}", crate::laravel::str_random(6)));
    if fs::File::create(&probe).is_err() {
        return Err(format!("The backup directory {} is not writable.", dir.display()));
    }
    let _ = fs::remove_file(&probe);
    Ok(dir.clone())
}

trait DirMode {
    fn mode_0700(&mut self) -> &mut Self;
}
impl DirMode for fs::DirBuilder {
    fn mode_0700(&mut self) -> &mut Self {
        use std::os::unix::fs::DirBuilderExt;
        self.mode(0o700)
    }
}

/// `list()`: local backups, newest first (the timestamp is in the name after either prefix, so a stamp sort is a time sort).
pub fn list(env: &Env) -> Result<Vec<Listed>, String> {
    let dir = directory(env)?;
    let mut rows = vec![];
    for ent in fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?.flatten() {
        let name = ent.file_name().to_string_lossy().into_owned();
        if !is_backup_name(&name) || !ent.path().is_file() {
            continue;
        }
        let path = ent.path();
        // A sidecar another user wrote (a command run as root) is skipped, not fatal.
        let manifest: Option<serde_json::Value> = fs::read(format!("{}.json", path.display())).ok().and_then(|b| serde_json::from_slice(&b).ok()).filter(|v: &serde_json::Value| v.is_object());
        let created = manifest.as_ref().and_then(|m| m.get("created_at")).and_then(|v| v.as_str()).and_then(parse_when);
        let mtime = ent.metadata().ok().and_then(|m| m.modified().ok()).and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs() as i64).unwrap_or(0);
        rows.push(Listed {
            name,
            size: ent.metadata().map(|m| m.len()).unwrap_or(0),
            created_at: created.unwrap_or_else(|| Utc.timestamp_opt(mtime, 0).single().unwrap_or_default().fixed_offset()),
            path,
            manifest,
        });
    }
    rows.sort_by(|a, b| stamp_of(&b.name).cmp(stamp_of(&a.name)).then_with(|| b.name.as_bytes().cmp(a.name.as_bytes())));
    Ok(rows)
}

pub fn path_of(env: &Env, name: &str) -> Result<Option<PathBuf>, String> {
    if !is_backup_name(name) {
        return Ok(None);
    }
    let p = directory(env)?.join(name);
    Ok(p.is_file().then_some(p))
}

pub fn delete(env: &Env, name: &str) -> Result<(), String> {
    let path = path_of(env, name)?.ok_or_else(|| format!("No backup named {name}."))?;
    let _ = fs::remove_file(format!("{}.json", path.display()));
    fs::remove_file(&path).map_err(|_| format!("Could not delete {name}."))
}

/// `applyRetention()`: names deleted.
pub fn apply_retention(env: &Env, keep: Keep) -> Result<Vec<String>, String> {
    let entries: Vec<(String, DateTime<FixedOffset>)> = list(env)?.into_iter().map(|l| (l.name, l.created_at)).collect();
    let mut gone = vec![];
    for name in prunable(&entries, keep) {
        delete(env, &name)?;
        gone.push(name);
    }
    Ok(gone)
}

// ---------------------------------------------------------------------------------------------------- lock ---

struct Guard<'a> {
    env: &'a Env,
    c: Connection,
    owner: String,
}

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        let _ = self.env.store.release(&self.c, LOCK_NAME, &self.owner);
    }
}

/// `lock()`: the previous console's own cache lock, so Settings -> Backups and this exclude each other.
fn lock(env: &Env, now: i64) -> Result<Guard<'_>, String> {
    let c = env.open()?;
    let owner = format!("hte-console-backup-{}", crate::laravel::str_random(10));
    match env.store.acquire(&c, LOCK_NAME, LOCK_SECONDS, &owner, now) {
        Ok(true) => Ok(Guard { env, c, owner }),
        Ok(false) => Err("Another backup or restore is still running.".into()),
        Err(f) => Err(format!("cannot take the backup lock: {f:?}")),
    }
}

/// Work directories a killed run left behind: the lock is ours, so none of them is in use.
fn clear_stale(dir: &Path) {
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            if (n.starts_with(".work-") || n.starts_with(".restore-") || n.starts_with(".tar-")) && e.path().is_dir() {
                let _ = fs::remove_dir_all(e.path());
            }
        }
    }
}

struct Work(PathBuf);
impl Drop for Work {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

// ---------------------------------------------------------------------------------------------------- tables ---

fn quote(ident: &str) -> String {
    format!("\"{}\"", ident.replace('"', "\"\""))
}

/// `tables()`: data tables, sorted, without the transient ones.
pub fn tables(c: &Connection) -> Result<Vec<String>, String> {
    let mut st = c.prepare("select name from sqlite_master where type = 'table' and name not like 'sqlite_%'").map_err(|e| e.to_string())?;
    let mut names: Vec<String> = st.query_map([], |r| r.get::<_, String>(0)).map_err(|e| e.to_string())?.collect::<Result<_, _>>().map_err(|e| e.to_string())?;
    names.retain(|n| !SKIP_TABLES.contains(&n.as_str()));
    names.sort();
    Ok(names)
}

fn columns(c: &Connection, schema: &str, table: &str) -> Result<Vec<String>, String> {
    let mut st = c.prepare(&format!("pragma {schema}.table_info({})", quote(table))).map_err(|e| e.to_string())?;
    let v = st.query_map([], |r| r.get::<_, String>(1)).map_err(|e| e.to_string())?.collect::<Result<_, _>>().map_err(|e| e.to_string())?;
    Ok(v)
}

fn json_value(v: ValueRef<'_>) -> serde_json::Value {
    use serde_json::Value;
    match v {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(i) => Value::from(i),
        ValueRef::Real(f) => serde_json::Number::from_f64(f).map(Value::Number).unwrap_or(Value::Null),
        // The previous console substitutes U+FFFD for invalid UTF-8 (JSON_INVALID_UTF8_SUBSTITUTE)
        ValueRef::Text(t) | ValueRef::Blob(t) => Value::String(String::from_utf8_lossy(t).into_owned()),
    }
}

fn dump_table(c: &Connection, table: &str, file: &Path) -> Result<i64, String> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    let out = fs::File::create(file).map_err(|_| format!("Cannot write {}.", file.display()))?;
    let mut gz = GzEncoder::new(std::io::BufWriter::new(out), Compression::new(6));
    let cols = columns(c, "main", table)?;
    let order = if cols.iter().any(|n| n == "id") { " order by \"id\"" } else { "" };
    let mut st = c.prepare(&format!("select * from {}{order}", quote(table))).map_err(|e| e.to_string())?;
    let mut q = st.query([]).map_err(|e| e.to_string())?;
    let mut count = 0;
    while let Some(r) = q.next().map_err(|e| e.to_string())? {
        let mut m = serde_json::Map::new();
        for (i, n) in cols.iter().enumerate() {
            m.insert(n.clone(), json_value(r.get_ref(i).map_err(|e| e.to_string())?));
        }
        let mut line = serde_json::to_vec(&serde_json::Value::Object(m)).map_err(|e| e.to_string())?;
        line.push(b'\n');
        gz.write_all(&line).map_err(|e| e.to_string())?;
        count += 1;
    }
    gz.finish().and_then(|mut w| w.flush()).map_err(|e| e.to_string())?;
    Ok(count)
}

/// A consistent copy of a SQLite file (`VACUUM INTO`); false when it could not be made.
fn vacuum_into(source: &Path, dest: &Path, busy: Duration) -> bool {
    let _ = fs::remove_file(dest);
    let c = match Connection::open_with_flags(source, OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let _ = c.busy_timeout(busy);
    let ok = c.execute("VACUUM INTO ?1", [dest.to_string_lossy().as_ref()]).is_ok() && dest.is_file();
    if !ok {
        let _ = fs::remove_file(dest);
    }
    ok
}

// ---------------------------------------------------------------------------------------------------- create ---

#[derive(Clone, Debug)]
pub struct Created {
    pub name: String,
    pub path: PathBuf,
    pub size: u64,
    pub manifest: serde_json::Value,
    pub rows: i64,
}

fn pretty(v: &serde_json::Value) -> Vec<u8> {
    use serde::Serialize;
    let mut out = vec![];
    let fmt = serde_json::ser::PrettyFormatter::with_indent(b"    ");
    let mut ser = serde_json::Serializer::with_formatter(&mut out, fmt);
    v.serialize(&mut ser).expect("a JSON value serialises");
    out
}

fn chmod(p: &Path, mode: u32) {
    let _ = fs::set_permissions(p, fs::Permissions::from_mode(mode));
}

/// `create($trigger)`
pub fn create(env: &Env, trigger: &str, now: i64) -> Result<Created, String> {
    let _lock = lock(env, now)?;
    let dir = directory(env)?;
    clear_stale(&dir);
    let work = dir.join(format!(".work-{}", crate::laravel::str_random(8).to_lowercase()));
    let _cleanup = Work(work.clone());
    let pkg = work.join("pkg");
    for d in [pkg.join("db"), pkg.join("files").join("rustdesk")] {
        fs::DirBuilder::new().recursive(true).mode_0700().create(&d).map_err(|_| format!("Cannot write to {}.", dir.display()))?;
    }

    // one snapshot, so every table is from the same moment
    let snap = work.join("snapshot.sqlite");
    if !vacuum_into(&env.database, &snap, env.busy) {
        return Err("Cannot take a snapshot of the database.".into());
    }
    let sc = Connection::open_with_flags(&snap, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(|e| e.to_string())?;
    let mut counts = serde_json::Map::new();
    let mut rows = 0;
    for t in tables(&sc)? {
        let n = dump_table(&sc, &t, &pkg.join("db").join(format!("{t}.ndjson.gz")))?;
        rows += n;
        counts.insert(t, n.into());
    }
    drop(sc);
    let _ = fs::remove_file(&snap);

    let files = collect_files(env, &pkg.join("files"))?;
    let manifest = serde_json::json!({
        "format": FORMAT,
        "app": "cortendesk",
        "app_version": env.app_version,
        "created_at": iso(now),
        "trigger": trigger,
        "app_url": env.app_url,
        "db_driver": "sqlite",
        "tables": counts,
        "files": files,
    });
    let manifest_bytes = pretty(&manifest);
    fs::write(pkg.join("manifest.json"), &manifest_bytes).map_err(|e| e.to_string())?;

    let stamp = DateTime::from_timestamp(now, 0).unwrap_or_default().format("%Y%m%d-%H%M%S").to_string();
    let mut name = format!("{PREFIX}{stamp}.tar");
    let mut i = 2;
    while dir.join(&name).exists() {
        name = format!("{PREFIX}{stamp}-{i}.tar");
        i += 1;
    }
    let path = dir.join(&name);

    // Built beside the package and moved into place in one step, so the listing never shows a half-written archive.
    let building = work.join("archive.tar");
    {
        let f = {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&building).map_err(|e| e.to_string())?
        };
        let mut w = tarfile::Writer::new(std::io::BufWriter::new(f), now.max(0) as u64);
        w.add_bytes("manifest.json", &manifest_bytes, 0o644).map_err(|e| e.to_string())?;
        for t in counts.keys() {
            w.add_file(&format!("db/{t}.ndjson.gz"), &pkg.join("db").join(format!("{t}.ndjson.gz")), 0o644).map_err(|e| e.to_string())?;
        }
        for f in &files {
            w.add_file(&format!("files/{f}"), &pkg.join("files").join(f), 0o644).map_err(|e| e.to_string())?;
        }
        let inner = w.finish().map_err(|e| e.to_string())?;
        inner.into_inner().map_err(|e| e.to_string())?.sync_all().map_err(|e| e.to_string())?;
    }
    fs::rename(&building, &path).map_err(|_| format!("Could not write {}.", path.display()))?;
    chmod(&path, 0o600);
    let sidecar = PathBuf::from(format!("{}.json", path.display()));
    fs::write(&sidecar, &manifest_bytes).map_err(|e| e.to_string())?;
    chmod(&sidecar, 0o600);
    let size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    Ok(Created { name, path, size, manifest, rows })
}

/// `collectFiles()`: archive-relative names of what was collected.
fn collect_files(env: &Env, dir: &Path) -> Result<Vec<String>, String> {
    let mut files = vec![];
    fs::write(dir.join("app_key"), &env.app_key).map_err(|e| e.to_string())?;
    files.push("app_key".to_string());
    if !env.server_secret.is_empty() {
        fs::write(dir.join("server_secret"), &env.server_secret).map_err(|e| e.to_string())?;
        files.push("server_secret".into());
    }
    if let Some(rd) = env.rustdesk_dir.as_ref().filter(|d| d.is_dir()) {
        for n in RUSTDESK_FILES {
            let src = rd.join(n);
            if !src.is_file() || fs::File::open(&src).is_err() {
                continue;
            }
            let dest = dir.join("rustdesk").join(n);
            // hbbs keeps its peer database open in WAL mode: a plain copy can miss the last writes
            if n == "db_v2.sqlite3" {
                if !vacuum_into(&src, &dest, env.busy) {
                    fs::copy(&src, &dest).map_err(|e| format!("copy {n}: {e}"))?;
                }
            } else {
                fs::copy(&src, &dest).map_err(|e| format!("copy {n}: {e}"))?;
            }
            files.push(format!("rustdesk/{n}"));
        }
    }
    Ok(files)
}

// --------------------------------------------------------------------------------------------------- restore ---

/// `readManifest()`
pub fn read_manifest(path: &Path) -> Result<serde_json::Value, String> {
    let not_ours = || "That file is not an HTE Remote backup.".to_string();
    let bytes = tarfile::read_entry(path, "manifest.json", 8 << 20).ok().flatten().ok_or_else(not_ours)?;
    let m: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| not_ours())?;
    if m.get("app").and_then(|v| v.as_str()) != Some("cortendesk") {
        return Err(not_ours());
    }
    let format = m.get("format").map(|v| match v {
        serde_json::Value::Number(n) => n.as_i64().unwrap_or(0),
        serde_json::Value::String(s) => crate::php::str_to_int(s.as_bytes()),
        _ => 0,
    });
    if format.unwrap_or(0) != FORMAT {
        return Err("That backup was written in a format this version cannot read. Upgrade HTE Remote first.".into());
    }
    Ok(m)
}

/// `import()`: bring an uploaded file into the backup directory under a name the rest of this module accepts, after
/// checking it is one of ours. Returns the stored name.
pub fn import(env: &Env, source: &Path, original_name: &str, now: i64) -> Result<String, String> {
    let manifest = read_manifest(source)?;
    let dir = directory(env)?;
    let mut name = original_name.to_string();
    if !is_backup_name(&name) || dir.join(&name).is_file() {
        name = format!("{PREFIX}{}-upload.tar", Utc.timestamp_opt(now, 0).single().unwrap_or_default().format("%Y%m%d-%H%M%S"));
    }
    let dest = dir.join(&name);
    fs::copy(source, &dest).map_err(|_| "Could not store the uploaded backup.".to_string())?;
    let side = format!("{}.json", dest.display());
    let mut json = String::new();
    {
        use serde::Serialize;
        let mut buf = vec![];
        let mut ser = serde_json::Serializer::with_formatter(&mut buf, serde_json::ser::PrettyFormatter::with_indent(b"    "));
        manifest.serialize(&mut ser).map_err(|e| e.to_string())?;
        json.push_str(&String::from_utf8_lossy(&buf));
    }
    fs::write(&side, json).map_err(|_| "Could not store the uploaded backup.".to_string())?;
    chmod(&dest, 0o600);
    chmod(Path::new(&side), 0o600);
    Ok(name)
}

#[derive(Clone, Debug, Default)]
pub struct Restored {
    pub tables: usize,
    pub rows: i64,
    pub rekeyed: bool,
    pub files: Vec<String>,
    pub restart_needed: bool,
    pub dropped_columns: BTreeMap<String, Vec<String>>,
    /// rows whose foreign key points nowhere in the archive (reported, as the previous console restores them without a check)
    pub orphans: BTreeMap<String, i64>,
    pub app_version: String,
}

/// Where a restore is, for the tests that cut it short.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Extracted,
    Built,
    Checked,
    Applying,
}

fn rows_of(file: &Path) -> Result<impl Iterator<Item = Result<serde_json::Map<String, serde_json::Value>, String>>, String> {
    let f = fs::File::open(file).map_err(|_| format!("Cannot read {}.", file.display()))?;
    let mut r = BufReader::new(flate2::read::MultiGzDecoder::new(BufReader::new(f)));
    let base = file.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    Ok(std::iter::from_fn(move || loop {
        let mut line = vec![];
        // bounded: one line may not eat the memory
        let mut limited = (&mut r).take(MAX_LINE as u64 + 1);
        match limited.read_until(b'\n', &mut line) {
            Ok(0) => return None,
            Ok(_) => {}
            Err(e) => return Some(Err(format!("The backup is damaged ({base}: {e})."))),
        }
        if line.len() > MAX_LINE {
            return Some(Err(format!("The backup contains a damaged row in {base}.")));
        }
        while matches!(line.last(), Some(b'\n' | b'\r')) {
            line.pop();
        }
        if line.is_empty() {
            continue;
        }
        return Some(match serde_json::from_slice::<serde_json::Value>(&line) {
            Ok(serde_json::Value::Object(m)) => Ok(m),
            _ => Err(format!("The backup contains a damaged row in {base}.")),
        });
    }))
}

use std::io::Read;

/// `rekey()`: one Laravel payload from the archive's key to this install's; anything else passes through.
fn rekey(old: &Encrypter, new: &Encrypter, v: serde_json::Value) -> serde_json::Value {
    let serde_json::Value::String(s) = &v else { return v };
    if s.is_empty() {
        return v;
    }
    let decoded: Option<serde_json::Value> = crate::php::base64_decode_strict(s.as_bytes()).and_then(|b| serde_json::from_slice(&b).ok());
    let looks = decoded.as_ref().and_then(|d| d.as_object()).map_or(false, |o| o.contains_key("iv") && o.contains_key("value") && o.contains_key("mac"));
    if !looks {
        return v;
    }
    match old.decrypt_string(s.as_bytes()) {
        Ok(plain) => serde_json::Value::String(new.encrypt_string(&plain)),
        Err(_) => v,
    }
}

fn to_sql(v: &serde_json::Value) -> Result<rusqlite::types::Value, String> {
    use rusqlite::types::Value as S;
    Ok(match v {
        serde_json::Value::Null => S::Null,
        serde_json::Value::Bool(b) => S::Integer(*b as i64),
        serde_json::Value::Number(n) => match n.as_i64() {
            Some(i) => S::Integer(i),
            // The previous console binds a float as a string (PARAM_STR) and the column's affinity converts it
            None => S::Text(crate::php::float_to_string(n.as_f64().unwrap_or(0.0))),
        },
        serde_json::Value::String(s) => S::Text(s.clone()),
        _ => return Err("The backup contains a damaged row.".into()),
    })
}

/// `restore($path)`: build the new data in a temporary database, check it, then replace the live data in one
/// transaction. Nothing of the live database changes unless every step before the last passed.
pub fn restore(env: &Env, path: &Path, now: i64, hook: &dyn Fn(Stage) -> Result<(), String>) -> Result<Restored, String> {
    let _lock = lock(env, now)?;
    let dir = directory(env)?;
    clear_stale(&dir);
    let manifest = read_manifest(path)?;
    let work = dir.join(format!(".restore-{}", crate::laravel::str_random(8).to_lowercase()));
    let _cleanup = Work(work.clone());
    fs::DirBuilder::new().recursive(true).mode_0700().create(work.join("db")).map_err(|e| e.to_string())?;
    fs::DirBuilder::new().recursive(true).mode_0700().create(work.join("rustdesk")).map_err(|e| e.to_string())?;

    let archived: Vec<(String, i64)> = manifest
        .get("tables")
        .and_then(|t| t.as_object())
        .map(|o| o.iter().map(|(k, v)| (k.clone(), v.as_i64().unwrap_or(-1))).collect())
        .unwrap_or_default();
    // only names this code knows are extracted, and only into paths it builds itself
    tarfile::extract(path, |n| {
        if let Some(t) = n.strip_prefix("db/").and_then(|r| r.strip_suffix(".ndjson.gz")) {
            return (IDENT_RE.is_match(t) && archived.iter().any(|(a, _)| a == t)).then(|| work.join("db").join(format!("{t}.ndjson.gz")));
        }
        match n {
            "files/app_key" => Some(work.join("app_key")),
            _ => n.strip_prefix("files/rustdesk/").filter(|f| RUSTDESK_FILES.contains(f)).map(|f| work.join("rustdesk").join(f)),
        }
    })
    .map_err(|e| format!("That file is not an HTE Remote backup. ({})", e.0))?;
    hook(Stage::Extracted)?;

    let old_key = fs::read_to_string(work.join("app_key")).unwrap_or_default().trim().to_string();
    let rekeying = !old_key.is_empty() && old_key != env.app_key;
    let crypts = if rekeying { Some((Encrypter::from_app_key(&old_key)?, Encrypter::from_app_key(&env.app_key)?)) } else { None };

    // the live schema, as a private copy to build in
    let tmp = work.join("restore.sqlite");
    // read before the copy: a migration landing in between then fails the check in apply() instead of passing it
    let live_schema_version = {
        let c = env.open()?;
        schema_version(&c)?
    };
    if !vacuum_into(&env.database, &tmp, env.busy) {
        return Err("Cannot take a copy of the database to build the restore in.".into());
    }
    let tc = Connection::open_with_flags(&tmp, OpenFlags::SQLITE_OPEN_READ_WRITE).map_err(|e| e.to_string())?;
    let live = tables(&tc)?;
    let restore_tables: Vec<&(String, i64)> = archived.iter().filter(|(t, _)| !KEEP_ON_RESTORE.contains(&t.as_str()) && !SKIP_TABLES.contains(&t.as_str())).collect();
    let unknown: Vec<&str> = restore_tables.iter().map(|(t, _)| t.as_str()).filter(|t| !live.iter().any(|l| l == t)).collect();
    if !unknown.is_empty() {
        return Err(format!(
            "The backup was made with console version {} and contains tables this install does not have ({}). Upgrade first, then restore.",
            manifest.get("app_version").and_then(|v| v.as_str()).unwrap_or("?"),
            unknown.join(", ")
        ));
    }

    let mut out = Restored { rekeyed: rekeying, app_version: manifest.get("app_version").and_then(|v| v.as_str()).unwrap_or("").to_string(), ..Default::default() };
    tc.execute_batch("pragma foreign_keys = off; begin").map_err(|e| e.to_string())?;
    for t in live.iter().filter(|t| !KEEP_ON_RESTORE.contains(&t.as_str())) {
        tc.execute(&format!("delete from {}", quote(t)), []).map_err(|e| e.to_string())?;
    }
    for (t, expected) in &restore_tables {
        let file = work.join("db").join(format!("{t}.ndjson.gz"));
        if !file.is_file() {
            // The previous console writes an (empty) file for every table of the manifest; a missing one with rows is a cut archive
            if *expected > 0 {
                return Err(format!("The backup is incomplete: {t} has no data in the archive, its manifest says {expected} rows."));
            }
            continue;
        }
        let cols = columns(&tc, "main", t)?;
        let mut dropped: Vec<String> = vec![];
        let mut inserted = 0i64;
        for row in rows_of(&file)? {
            let mut row = row?;
            for k in row.keys().cloned().collect::<Vec<_>>() {
                if !cols.contains(&k) {
                    if !dropped.contains(&k) {
                        dropped.push(k.clone());
                    }
                    row.remove(&k);
                }
            }
            if let (Some((old, new)), Some((_, enc_cols))) = (&crypts, ENCRYPTED_COLUMNS.iter().find(|(n, _)| n == t)) {
                for c in *enc_cols {
                    if let Some(v) = row.remove(*c) {
                        row.insert(c.to_string(), rekey(old, new, v));
                    }
                }
            }
            if row.is_empty() {
                // The previous console's insert([[]]) would write a default-only row; nothing in an archive of ours has none
                return Err(format!("The backup contains a damaged row in {t}."));
            }
            let names: Vec<String> = row.keys().map(|k| quote(k)).collect();
            let sql = format!("insert into {} ({}) values ({})", quote(t), names.join(", "), vec!["?"; names.len()].join(", "));
            let params = row.values().map(to_sql).collect::<Result<Vec<_>, _>>().map_err(|e| format!("{e} ({t})"))?;
            tc.prepare_cached(&sql).and_then(|mut st| st.execute(rusqlite::params_from_iter(params))).map_err(|e| format!("{t}: {e}"))?;
            inserted += 1;
        }
        if *expected >= 0 && inserted != *expected {
            return Err(format!("The backup is incomplete: {t} has {inserted} rows, its manifest says {expected}."));
        }
        out.tables += 1;
        out.rows += inserted;
        if !dropped.is_empty() {
            out.dropped_columns.insert(t.clone(), dropped);
        }
    }
    tc.execute_batch("commit").map_err(|e| e.to_string())?;
    hook(Stage::Built)?;

    // the checks, on the temporary database
    let integrity: Vec<String> = tc.prepare("pragma integrity_check").and_then(|mut s| s.query_map([], |r| r.get::<_, String>(0))?.collect()).map_err(|e| e.to_string())?;
    if integrity != ["ok"] {
        return Err(format!("The restored database failed SQLite's integrity check ({}); nothing was changed.", integrity.join("; ")));
    }
    {
        let mut st = tc.prepare("pragma foreign_key_check").map_err(|e| e.to_string())?;
        let mut q = st.query([]).map_err(|e| e.to_string())?;
        while let Some(r) = q.next().map_err(|e| e.to_string())? {
            *out.orphans.entry(r.get::<_, String>(0).map_err(|e| e.to_string())?).or_insert(0) += 1;
        }
    }
    drop(tc);
    hook(Stage::Checked)?;

    apply(env, &tmp, &live, live_schema_version, hook)?;

    out.files = stage_files(env, &work.join("rustdesk")).map_err(|e| format!("The database WAS restored, but the server files could not be staged ({e}); nothing is left half staged. Restore again or copy them by hand."))?;
    out.restart_needed = !out.files.is_empty();
    Ok(out)
}

fn schema_version(c: &Connection) -> Result<i64, String> {
    c.query_row("pragma main.schema_version", [], |r| r.get(0)).map_err(|e| e.to_string())
}

/// The swap: one write transaction on the live file takes every data table's content from the checked temporary
/// database. A crash or an error before COMMIT leaves the old content (SQLite's own atomicity, WAL or not); readers
/// (the previous console, the request handlers) see either all of the old data or all of the new.
fn apply(env: &Env, tmp: &Path, live: &[String], expected_schema: i64, hook: &dyn Fn(Stage) -> Result<(), String>) -> Result<(), String> {
    let c = env.open()?;
    c.pragma_update(None, "foreign_keys", "OFF").map_err(|e| e.to_string())?;
    c.execute("attach database ?1 as bk", [tmp.to_string_lossy().as_ref()]).map_err(|e| e.to_string())?;
    let result = (|| -> Result<(), String> {
        c.execute_batch("begin immediate").map_err(|e| format!("The database is busy: {e}"))?;
        let go = (|| -> Result<(), String> {
            if schema_version(&c)? != expected_schema {
                return Err("The database schema changed while the restore was being prepared; nothing was changed. Run it again.".into());
            }
            for t in live.iter().filter(|t| !KEEP_ON_RESTORE.contains(&t.as_str())) {
                let main_cols = columns(&c, "main", t)?;
                let bk_cols = columns(&c, "bk", t)?;
                let both: Vec<String> = main_cols.iter().filter(|n| bk_cols.contains(n)).map(|n| quote(n)).collect();
                c.execute(&format!("delete from main.{}", quote(t)), []).map_err(|e| e.to_string())?;
                c.execute(&format!("insert into main.{q} ({cols}) select {cols} from bk.{q}", q = quote(t), cols = both.join(", ")), []).map_err(|e| format!("{t}: {e}"))?;
            }
            hook(Stage::Applying)
        })();
        match go {
            Ok(()) => c.execute_batch("commit").map_err(|e| e.to_string()),
            Err(e) => {
                let _ = c.execute_batch("rollback");
                Err(e)
            }
        }
    })();
    let _ = c.execute_batch("detach database bk");
    result
}

/// `stageFiles()`: hbbs may hold its files open, so they are written beside the originals as `<name>.restore` and
/// The CortenDesk image's entrypoint swaps them in at the next start. Each is written whole under a temporary name first.
fn stage_files(env: &Env, dir: &Path) -> Result<Vec<String>, String> {
    let Some(rd) = env.rustdesk_dir.as_ref().filter(|d| d.is_dir()) else { return Ok(vec![]) };
    if fs::File::create(rd.join(format!(".probe-{}", crate::laravel::str_random(6)))).map(|_| ()).is_err() {
        return Ok(vec![]);
    }
    for e in fs::read_dir(rd).into_iter().flatten().flatten() {
        if e.file_name().to_string_lossy().starts_with(".probe-") {
            let _ = fs::remove_file(e.path());
        }
    }
    // every file is copied aside first and the old stagings are dropped, so a failure leaves nothing half staged
    // (a private key without its public key) and an earlier, never adopted restore cannot mix with this one
    let mut copies = vec![];
    let res = (|| -> Result<(), String> {
        for n in RUSTDESK_FILES {
            let src = dir.join(n);
            if !src.is_file() {
                continue;
            }
            let part = rd.join(format!("{n}.restore.part"));
            fs::copy(&src, &part).map_err(|_| format!("Could not stage {n} into {}.", rd.display()))?;
            chmod(&part, if n == "id_ed25519.pub" { 0o644 } else { 0o600 });
            copies.push(n.to_string());
        }
        Ok(())
    })();
    if let Err(e) = res {
        for n in RUSTDESK_FILES {
            let _ = fs::remove_file(rd.join(format!("{n}.restore.part")));
        }
        return Err(e);
    }
    for n in RUSTDESK_FILES {
        let _ = fs::remove_file(rd.join(format!("{n}.restore")));
    }
    let mut staged = vec![];
    for n in copies {
        fs::rename(rd.join(format!("{n}.restore.part")), rd.join(format!("{n}.restore"))).map_err(|_| format!("Could not stage {n} into {}.", rd.display()))?;
        staged.push(n);
    }
    Ok(staged)
}

pub fn human_size(bytes: u64) -> String {
    let r = |x: f64, d: i32| {
        let m = 10f64.powi(d);
        let v = (x * m).round() / m;
        if v == v.trunc() { format!("{}", v as i64) } else { format!("{v}") }
    };
    if bytes >= 1 << 30 {
        format!("{} GB", r(bytes as f64 / (1u64 << 30) as f64, 2))
    } else if bytes >= 1 << 20 {
        format!("{} MB", r(bytes as f64 / (1u64 << 20) as f64, 1))
    } else if bytes >= 1024 {
        format!("{} KB", r(bytes as f64 / 1024.0, 0))
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> DateTime<FixedOffset> {
        DateTime::parse_from_rfc3339(s).unwrap()
    }

    fn names(v: &[&str]) -> Vec<(String, DateTime<FixedOffset>)> {
        v.iter().map(|d| (format!("{PREFIX}{}.tar", d.replace(['-', ':'], "").replace('T', "-").trim_end_matches("+0000")), at(&format!("{d}+00:00")))).collect()
    }

    #[test]
    fn name_pattern() {
        assert!(is_backup_name("cortendesk-backup-20261024-033000.tar"));
        assert!(is_backup_name("cortendesk-backup-20261024-033000-2.tar"));
        assert!(is_backup_name("cortendesk-backup-20261024-033000-upload.tar"));
        assert!(!is_backup_name("cortendesk-backup-20261024-033000.tar.json"));
        assert!(!is_backup_name("../cortendesk-backup-20261024-033000.tar"));
        assert!(!is_backup_name("cortendesk-backup-20261024-033000-UP.tar"));
        assert!(is_backup_name("hte-remote-backup-20261024-033000.tar"));
        assert!(is_backup_name("hte-remote-backup-20261024-033000-upload.tar"));
        assert!(!is_backup_name("hte-remote-backup-20261024-033000.tar.json"));
        assert!(!is_backup_name("other-backup-20261024-033000.tar"));
        assert_eq!(stamp_of("hte-remote-backup-20261024-033000.tar"), stamp_of("cortendesk-backup-20261024-033000.tar"));
    }

    #[test]
    fn retention_matches_php_tiers() {
        // 40 daily backups at 03:30, 2026-09-15 .. 2026-10-24
        let mut days = vec![];
        let mut d = chrono::NaiveDate::from_ymd_opt(2026, 9, 15).unwrap();
        while d <= chrono::NaiveDate::from_ymd_opt(2026, 10, 24).unwrap() {
            days.push(format!("{}T03:30:00", d));
            d = d.succ_opt().unwrap();
        }
        let refs: Vec<&str> = days.iter().map(String::as_str).collect();
        let e = names(&refs);
        // daily 3 only: everything but the newest three goes
        let gone = prunable(&e, Keep { daily: 3, weekly: 0, monthly: 0 });
        assert_eq!(gone.len(), 37);
        assert!(!gone.iter().any(|n| n.contains("20261024") || n.contains("20261023") || n.contains("20261022")));
        // oldest first
        assert!(gone[0].contains("20260915") && gone[1].contains("20260916"));
        // weekly 2: the oldest backup of the newest two ISO weeks survives: week 43 (Mon 10-19) and week 42 (Mon 10-12)
        let gone = prunable(&e, Keep { daily: 0, weekly: 2, monthly: 0 });
        let kept: Vec<&String> = e.iter().map(|x| &x.0).filter(|n| !gone.contains(n)).collect();
        assert_eq!(kept.len(), 2);
        assert!(kept.iter().any(|n| n.contains("20261019")) && kept.iter().any(|n| n.contains("20261012")));
        // monthly 2: first of October and first of September in the list (09-15)
        let gone = prunable(&e, Keep { daily: 0, weekly: 0, monthly: 2 });
        let kept: Vec<&String> = e.iter().map(|x| &x.0).filter(|n| !gone.contains(n)).collect();
        assert!(kept.iter().any(|n| n.contains("20261001")) && kept.iter().any(|n| n.contains("20260915")) && kept.len() == 2);
        // all tiers at once are a union; all zero keeps everything
        let gone = prunable(&e, DEFAULT_KEEP);
        assert!(gone.len() < 40 && !gone.iter().any(|n| n.contains("20261024")));
        assert!(prunable(&e, Keep { daily: 0, weekly: 0, monthly: 0 }).is_empty());
    }

    #[test]
    fn iso_week_year_boundary() {
        // 2026-12-31 is in ISO week 53 of 2026; 2027-01-01 too ("o-W"), so the first of them represents the week
        let e = names(&["2026-12-31T03:30:00", "2027-01-01T03:30:00"]);
        let gone = prunable(&e, Keep { daily: 0, weekly: 1, monthly: 0 });
        assert_eq!(gone, vec![e[1].0.clone()], "the newer one is not the oldest of its week");
    }

    #[test]
    fn due_is_calendar_based() {
        let now: i64 = 1_792_900_000; // some time of day
        let midnight = now - now.rem_euclid(86_400);
        assert!(due(None, now));
        assert!(due(Some(DateTime::from_timestamp(midnight - 1, 0).unwrap().fixed_offset()), now));
        assert!(!due(Some(DateTime::from_timestamp(midnight, 0).unwrap().fixed_offset()), now));
    }

    #[test]
    fn sizes_like_php() {
        assert_eq!(human_size(75264), "74 KB");
        assert_eq!(human_size(12), "12 B");
        assert_eq!(human_size(5 * 1048576 + 300_000), "5.3 MB");
    }
}
