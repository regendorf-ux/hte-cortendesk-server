//! Phase 3: Laravel's `database` cache store and its locks (laravel/framework v13.35.0, `DatabaseStore`,
//! `DatabaseLock`, `CacheEventMutex`), on the shared SQLite file's `cache` and `cache_locks` tables.
//!
//! Two things in PHP live in the cache and have to keep working once hte-console does the work behind them:
//! - the "ID server fetched the policy" marker (`ServerLink::recordPull`, read by Settings -> Server and Fleet
//!   Diagnostics) and the scheduler's heartbeat (`cortendesk:diagnostics-heartbeat`, read by Fleet Diagnostics);
//! - the scheduler's `withoutOverlapping` mutex. hte-console holds the very lock PHP's `schedule:run` would take for
//!   a task it has taken over, so PHP's scheduler skips that task (exactly as it skips one still running) without a
//!   change to PHP. Should hte-console stop, the lock expires and PHP runs the task again by itself.
//!
//! Both need the PHP container on `CACHE_STORE=database` (its image defaults to `file`, inside the container, where
//! nothing else can reach it). The prefix is PHP's `cache.prefix`; keys and values are written byte for byte as
//! `DatabaseStore::putMany` writes them (PHP's `serialize`, base64 only when the text holds a NUL, which ours never do).

use crate::php::{Fault, Key, Val};
use crate::sqlite::{self as db, P};
use rusqlite::Connection;

/// `DatabaseStore::forever`: ten years.
pub const FOREVER_SECONDS: i64 = 315_360_000;

/// `ServerLink::PULL_CACHE_KEY`
pub const PULL_KEY: &str = "cortendesk:server-link:last-pull";
/// `DiagnosticsHeartbeat` / `FleetDiagnostics`
pub const SCHEDULER_HEARTBEAT_KEY: &str = "cortendesk:diagnostics:scheduler-heartbeat";

/// PHP's `serialize()` for the values the console caches (strings, ints, booleans, null and arrays of those).
pub fn serialize(v: &Val) -> Result<Vec<u8>, Fault> {
    let mut out = vec![];
    ser(v, &mut out)?;
    Ok(out)
}

fn ser(v: &Val, out: &mut Vec<u8>) -> Result<(), Fault> {
    match v {
        Val::Null => out.extend_from_slice(b"N;"),
        Val::Bool(b) => out.extend_from_slice(if *b { b"b:1;" } else { b"b:0;" }),
        Val::Int(i) => out.extend_from_slice(format!("i:{i};").as_bytes()),
        Val::Float(_) => return Err(Fault::Other("serialize: floats are not cached by these keys".into())),
        Val::Str(s) => {
            out.extend_from_slice(format!("s:{}:\"", s.len()).as_bytes());
            out.extend_from_slice(s);
            out.extend_from_slice(b"\";");
        }
        Val::Arr(a) => {
            out.extend_from_slice(format!("a:{}:{{", a.len()).as_bytes());
            for (k, x) in a.iter() {
                match k {
                    Key::Int(i) => out.extend_from_slice(format!("i:{i};").as_bytes()),
                    Key::Str(s) => ser(&Val::Str(s.clone()), out)?,
                }
                ser(x, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

/// The store: PHP's `cache.prefix` (`CACHE_PREFIX`, else `Str::slug(APP_NAME).'-cache-'`).
#[derive(Clone, Debug)]
pub struct Store {
    pub prefix: String,
}

impl Store {
    /// `HTE_CONSOLE_CACHE_PREFIX`, else `CACHE_PREFIX`, else Laravel's default from `APP_NAME` (as config/cache.php
    /// builds it). Err for an `APP_NAME` whose slug this crate cannot reproduce (non-ASCII: Laravel transliterates);
    /// the deploy passes PHP's own value, so that only matters by hand.
    pub fn from_env() -> Result<Store, String> {
        let set = |n: &str| std::env::var(n).ok().filter(|v| !v.is_empty());
        if let Some(p) = set("HTE_CONSOLE_CACHE_PREFIX").or_else(|| set("CACHE_PREFIX")) {
            return Ok(Store { prefix: p });
        }
        let name = std::env::var("APP_NAME").ok().unwrap_or_else(|| "laravel".into());
        if !name.is_ascii() {
            return Err("APP_NAME is not ASCII: set HTE_CONSOLE_CACHE_PREFIX to PHP's cache.prefix".into());
        }
        Ok(Store { prefix: format!("{}-cache-", slug(&name)) })
    }

    fn key(&self, k: &str) -> String {
        format!("{}{k}", self.prefix)
    }

    /// `Cache::forever($key, $value)` on the database store: `upsert` of (key, value, expiration).
    pub fn forever(&self, c: &Connection, key: &str, value: &Val, now: i64) -> Result<(), Fault> {
        self.put(c, key, value, FOREVER_SECONDS, now)
    }

    /// `DatabaseStore::putMany` with one item (the builder ksorts the columns; SQLite's grammar).
    pub fn put(&self, c: &Connection, key: &str, value: &Val, seconds: i64, now: i64) -> Result<(), Fault> {
        let mut v = serialize(value)?;
        if v.contains(&0) {
            v = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &v).into_bytes();
        }
        db::exec(
            c,
            r#"insert into "cache" ("expiration", "key", "value") values (?, ?, ?) on conflict ("key") do update set "expiration" = "excluded"."expiration", "key" = "excluded"."key", "value" = "excluded"."value""#,
            &[P(Val::Int(now + seconds)), P(Val::str(&self.key(key))), P(Val::Str(v))],
        )?;
        Ok(())
    }

    /// The raw serialized value, unexpired (tests and the deploy's check).
    pub fn get_raw(&self, c: &Connection, key: &str, now: i64) -> Result<Option<Vec<u8>>, Fault> {
        let row = db::first(c, r#"select * from "cache" where "key" in (?)"#, &[P(Val::str(&self.key(key)))])?;
        Ok(row.filter(|r| r.val("expiration").to_int() > now).map(|r| r.val("value").to_php_string().unwrap_or_default()))
    }

    /// `DatabaseLock::acquire()` for `$store->lock($name, $seconds, $owner)`: insert, or take over a row that is
    /// ours or expired; then, two times in a hundred, prune expired locks.
    pub fn acquire(&self, c: &Connection, name: &str, seconds: i64, owner: &str, now: i64) -> Result<bool, Fault> {
        let key = self.key(name);
        let exp = now + if seconds > 0 { seconds } else { DEFAULT_LOCK_TIMEOUT };
        let inserted = db::exec(
            c,
            r#"insert into "cache_locks" ("key", "owner", "expiration") values (?, ?, ?)"#,
            &[P(Val::str(&key)), P(Val::str(owner)), P(Val::Int(exp))],
        );
        let acquired = match inserted {
            Ok(_) => true,
            // QueryException (the key exists): take it over when it is ours or has expired
            Err(_) => {
                db::exec(
                    c,
                    r#"update "cache_locks" set "owner" = ?, "expiration" = ? where "key" = ? and ("owner" = ? or "expiration" <= ?)"#,
                    &[P(Val::str(owner)), P(Val::Int(exp)), P(Val::str(&key)), P(Val::str(owner)), P(Val::Int(now))],
                )? >= 1
            }
        };
        if rand::random::<u32>() % 100 < 2 {
            db::exec(c, r#"delete from "cache_locks" where "expiration" <= ?"#, &[P(Val::Int(now))])?;
        }
        Ok(acquired)
    }

    /// `DatabaseLock::release()`: only our own row.
    pub fn release(&self, c: &Connection, name: &str, owner: &str) -> Result<bool, Fault> {
        Ok(db::exec(c, r#"delete from "cache_locks" where "key" = ? and "owner" = ?"#, &[P(Val::str(&self.key(name))), P(Val::str(owner))])? > 0)
    }
}

/// `cache.stores.database.lock_timeout` default.
const DEFAULT_LOCK_TIMEOUT: i64 = 86_400;

/// `Str::slug($title)` for ASCII titles: `_` becomes `-`, `@` becomes `-at-`, everything but letters, digits,
/// `-` and whitespace goes, the rest is lowercased, runs of `-` and whitespace become one `-`, trimmed.
pub fn slug(title: &str) -> String {
    let t = title.replace('_', "-").replace('@', "-at-").to_ascii_lowercase();
    let kept: String = t.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || c.is_ascii_whitespace() || *c == '\u{b}').collect();
    let mut out = String::new();
    let mut sep = false;
    for c in kept.chars() {
        if c == '-' || c.is_ascii_whitespace() || c == '\u{b}' {
            sep = true;
        } else {
            if sep && !out.is_empty() {
                out.push('-');
            }
            sep = false;
            out.push(c);
        }
    }
    out
}

/// `Event::mutexName()` for `Schedule::command(...)`: `framework/schedule-` and sha1 of the cron expression and the
/// command as `normalizeCommand` writes it (`php artisan <name>`).
pub fn schedule_mutex_name(expression: &str, command: &str) -> String {
    use sha1::Digest;
    format!("framework/schedule-{}", hex::encode(sha1::Sha1::digest(format!("{expression}php artisan {command}").as_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_like_php() {
        let v = crate::php::assoc(vec![("at".to_string(), Val::str("2026-10-24T20:39:00+00:00")), ("agent".to_string(), Val::str("cortendesk-server/1.1.1"))]);
        assert_eq!(serialize(&v).unwrap(), br#"a:2:{s:2:"at";s:25:"2026-10-24T20:39:00+00:00";s:5:"agent";s:23:"cortendesk-server/1.1.1";}"#.to_vec());
        assert_eq!(serialize(&Val::str("é")).unwrap(), "s:2:\"é\";".as_bytes().to_vec(), "length in bytes");
        assert_eq!(serialize(&Val::Null).unwrap(), b"N;".to_vec());
    }

    #[test]
    fn slug_like_laravel() {
        assert_eq!(slug("HTE Remote"), "hte-remote");
        assert_eq!(slug("CortenDesk"), "cortendesk");
        assert_eq!(slug("laravel"), "laravel");
        assert_eq!(slug("  My_App -- x@y! "), "my-app-x-at-y");
    }

    #[test]
    fn mutex_names() {
        // sha1("* * * * *php artisan hte:reach-sweep")
        let n = schedule_mutex_name("* * * * *", "hte:reach-sweep");
        assert!(n.starts_with("framework/schedule-") && n.len() == "framework/schedule-".len() + 40);
    }

    #[test]
    fn locks_exclude_each_other_and_expire() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(r#"create table "cache_locks" ("key" varchar not null, "owner" varchar not null, "expiration" integer not null, primary key ("key"))"#).unwrap();
        let s = Store { prefix: "p-".into() };
        assert!(s.acquire(&c, "m", 60, "php", 100).unwrap());
        assert!(!s.acquire(&c, "m", 60, "hte", 110).unwrap(), "held by another owner");
        assert!(s.acquire(&c, "m", 60, "php", 120).unwrap(), "the owner refreshes it");
        assert!(s.acquire(&c, "m", 60, "hte", 180).unwrap(), "expired: taken over");
        assert!(!s.release(&c, "m", "php").unwrap());
        assert!(s.release(&c, "m", "hte").unwrap());
        let k: String = c.query_row("select count(*) || '' from cache_locks", [], |r| r.get(0)).unwrap();
        assert_eq!(k, "0");
    }
}
