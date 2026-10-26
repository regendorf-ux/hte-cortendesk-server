//! Phase 9: what the CortenDesk container's scheduler still did that no earlier phase took over, and the small commands the
//! all-in-one image's scripts need (`status`, `release-locks`).
//!
//! `cortendesk:check-device-notifications` (every minute) does two things. With Apprise off (it is off at HTE; the
//! deploy refuses when it is on) the second, sending and retrying notifications, has nothing to do. The first is
//! `DevicePresenceSnooze::pruneForSweep()`: expired snoozes are deleted, and so are week-old ones whose device or group
//! is gone. That is `prune_snoozes` below, run once a minute when `HTE_CONSOLE_SNOOZE_PRUNE=1`. It takes no scheduler
//! lock (the previous console's entry has none we could hold) and is idempotent, so a previous-console scheduler running beside it does no harm.

use crate::api::Native;
use crate::laravel;
use rusqlite::{params, Connection};
use std::sync::Arc;

/// `DevicePresenceSnooze::pruneForSweep()`. Returns the rows deleted.
pub fn prune_snoozes(c: &Connection, now: i64) -> Result<usize, String> {
    let at = laravel::ts(now);
    let week = laravel::ts(now - 7 * 86_400);
    let a = c.execute(r#"delete from "device_presence_snoozes" where "expires_at" <= ?"#, params![at]).map_err(|e| format!("snoozes: {e}"))?;
    let b = c
        .execute(
            r#"delete from "device_presence_snoozes" where "created_at" <= ? and (
                ("target_type" = 'device' and not exists (select 1 from "devices" where "devices"."id" = "device_presence_snoozes"."target_id"))
                or ("target_type" = 'group' and not exists (select 1 from "device_groups" where "device_groups"."id" = "device_presence_snoozes"."target_id")))"#,
            params![week],
        )
        .map_err(|e| format!("snoozes: {e}"))?;
    Ok(a + b)
}

/// `HTE_CONSOLE_SNOOZE_PRUNE=1`: a task that runs `prune_snoozes` every minute.
pub fn start(n: Arc<Native>) {
    if crate::envvar::var("HTE_CONSOLE_SNOOZE_PRUNE").map_or(true, |v| v.trim() != "1") {
        return;
    }
    tokio::spawn(async move {
        let mut every = tokio::time::interval(std::time::Duration::from_secs(60));
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            every.tick().await;
            let n = n.clone();
            let _ = tokio::task::spawn_blocking(move || {
                let c = n.db.lock().unwrap_or_else(|e| e.into_inner());
                match prune_snoozes(&c, n.now()) {
                    Ok(0) => {}
                    Ok(k) => tracing::info!("pruned {k} presence snooze(s)"),
                    Err(e) => tracing::warn!("{e}"),
                }
            })
            .await;
        }
    });
    tracing::info!("presence snoozes are pruned here once a minute (what cortendesk:check-device-notifications did with Apprise off)");
}

/// Give back every scheduler lock a hte-console left in the previous console's `cache_locks` (a service that was killed, a `sweep`).
/// For the rollback to the CortenDesk stack: the previous console's scheduler skips a task while one is held, up to 30 minutes. Returns how many.
pub fn release_locks(c: &Connection, cache_prefix: &str) -> Result<usize, String> {
    let like = format!("{}framework/schedule-%", cache_prefix.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_"));
    // the scheduler's task locks, and the backup lock Settings -> Backups and the nightly run share
    c.execute(
        r#"delete from "cache_locks" where ("key" like ? escape '\' or "key" = ?) and ("owner" like 'hte-console-svc-%' or "owner" like 'hte-console-cli-%')"#,
        params![like, format!("{cache_prefix}cortendesk:backup")],
    )
    .map_err(|e| format!("cache_locks: {e}"))
}

/// `hte-console status`: facts the deploy and rollback scripts read, one `name=value` per line, from a database opened
/// read-only (a copy for the preflight, the live file after the cutover). Counts and ages only, never a secret.
pub fn status(c: &Connection, cache_prefix: &str, now: i64) -> Result<String, String> {
    let one = |sql: &str| -> String { c.query_row(sql, [], |r| r.get::<_, rusqlite::types::Value>(0)).map(|v| match v {
        rusqlite::types::Value::Integer(i) => i.to_string(),
        rusqlite::types::Value::Text(t) => t,
        rusqlite::types::Value::Real(f) => f.to_string(),
        _ => String::new(),
    }).unwrap_or_else(|_| "?".into()) };
    let mut out = vec![format!("version={}", env!("CARGO_PKG_VERSION"))];
    let old = crate::envvar::old_names_in_use();
    out.push(format!("env_old_names={}", if old.is_empty() { "none".to_string() } else { old.join(",") }));
    out.push(format!("update_check={}", if crate::update_check::enabled() { crate::update_check::repo() } else { "off".into() }));
    let latest = crate::cache::Store { prefix: cache_prefix.to_string() }
        .get_raw(c, crate::update_check::CACHE_KEY, now)
        .ok()
        .flatten()
        .and_then(|b| crate::pages::unserialize_string(&b))
        .unwrap_or_else(|| "unknown".into());
    out.push(format!("update_latest={latest}"));
    match crate::migrate::check(c) {
        Ok(r) => {
            out.push(format!("migrations_php={}/{}", r.php_recorded, crate::migrate::PHP_MIGRATIONS.len()));
            out.push(format!("migrations_own_pending={}", r.own_pending.len()));
            out.push(format!("migrations_unknown={}", r.unknown.len()));
        }
        Err(e) => out.push(format!("migrations_error={e}")),
    }
    let recent = laravel::ts(now - 180);
    out.push(format!("devices={}", one(r#"select count(*) from "devices" where "deleted_at" is null"#)));
    out.push(format!("devices_seen_3min={}", one(&format!(r#"select count(*) from "devices" where "deleted_at" is null and "last_online_at" >= '{recent}'"#))));
    out.push(format!("local_active_admins={}", one(r#"select count(*) from "users" where "auth_provider" = 'local' and "is_admin" = 1 and "is_active" = 1"#)));
    out.push(format!("totp_users={}", one(r#"select count(*) from "users" where "totp_enabled" = 1"#)));
    out.push(format!("oidc_enabled={}", one(r#"select coalesce((select "value" from "settings" where "key" = 'oidc_enabled'), '')"#)));
    out.push(format!("apprise_enabled={}", one(r#"select coalesce((select "value" from "settings" where "key" = 'apprise_enabled'), '')"#)));
    out.push(format!("open_sessions={}", one(r#"select count(*) from "audit_connections" where "closed_at" is null"#)));
    out.push(format!("sessions_signed_in={}", one(r#"select count(*) from "hte_console_sessions" where "user_id" is not null"#)));
    let key = format!("{cache_prefix}{}", crate::cache::SCHEDULER_HEARTBEAT_KEY);
    let hb: String = c.query_row(r#"select "value" from "cache" where "key" = ?"#, params![key], |r| r.get(0)).unwrap_or_default();
    // the value is previous-console-serialised: s:25:"2026-10-25T12:00:00+00:00";
    let age = hb
        .split('"')
        .nth(1)
        .and_then(|iso| chrono::DateTime::parse_from_rfc3339(iso).ok())
        .map(|d| (now - d.timestamp()).to_string())
        .unwrap_or_else(|| "?".into());
    out.push(format!("scheduler_heartbeat_age_s={age}"));
    // hbbs's last pull of the policy (the marker the server link writes on every pull): when, and which hbbs
    let pull: String = c.query_row(r#"select "value" from "cache" where "key" = ?"#, params![format!("{cache_prefix}{}", crate::cache::PULL_KEY)], |r| r.get(0)).unwrap_or_default();
    let parts: Vec<&str> = pull.split('"').collect();
    let pull_age = parts.get(3).and_then(|iso| chrono::DateTime::parse_from_rfc3339(iso).ok()).map(|d| (now - d.timestamp()).to_string()).unwrap_or_else(|| "?".into());
    out.push(format!("policy_pull_age_s={pull_age}"));
    out.push(format!("policy_pull_agent={}", parts.get(7).copied().unwrap_or("?")));
    let like = format!("{cache_prefix}framework/schedule-%");
    let held: i64 = c.query_row(r#"select count(*) from "cache_locks" where "key" like ? and "owner" like 'hte-console-svc-%'"#, params![like], |r| r.get(0)).unwrap_or(-1);
    out.push(format!("scheduler_locks_held_by_hte_console={held}"));
    Ok(out.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(
            r#"create table "device_presence_snoozes" ("id" integer primary key autoincrement not null, "target_type" varchar not null, "target_id" integer not null, "expires_at" datetime not null, "created_at" datetime, "updated_at" datetime);
               create table "devices" ("id" integer primary key);
               create table "device_groups" ("id" integer primary key);
               create table "cache_locks" ("key" varchar not null primary key, "owner" varchar not null, "expiration" integer not null);
               insert into devices (id) values (1); insert into device_groups (id) values (1);"#,
        )
        .unwrap();
        c
    }

    #[test]
    fn prunes_expired_and_orphaned_week_old_snoozes_only() {
        let c = db();
        let now = 1_800_000_000;
        let old = laravel::ts(now - 8 * 86_400);
        let fresh = laravel::ts(now - 3600);
        let future = laravel::ts(now + 3600);
        let past = laravel::ts(now - 60);
        for (t, id, exp, created) in [
            ("device", 1, &future, &fresh),  // live: stays
            ("device", 1, &past, &fresh),    // expired: goes (distinct row, the unique index is not in this fixture)
            ("device", 9, &future, &old),    // week old, device gone: goes
            ("device", 9, &future, &fresh),  // device gone but young: stays (as the previous console)
            ("group", 9, &future, &old),     // week old, group gone: goes
            ("group", 1, &future, &old),     // week old, group exists: stays
        ] {
            c.execute(r#"insert into device_presence_snoozes (target_type, target_id, expires_at, created_at) values (?, ?, ?, ?)"#, params![t, id, exp, created]).unwrap();
        }
        assert_eq!(prune_snoozes(&c, now).unwrap(), 3);
        let left: i64 = c.query_row("select count(*) from device_presence_snoozes", [], |r| r.get(0)).unwrap();
        assert_eq!(left, 3);
        assert_eq!(prune_snoozes(&c, now).unwrap(), 0);
    }

    #[test]
    fn releases_only_our_locks() {
        let c = db();
        for (k, o) in [
            ("hte-remote-cache-framework/schedule-aa", "hte-console-svc-xyz"),
            ("hte-remote-cache-framework/schedule-bb", "hte-console-cli-xyz"),
            ("hte-remote-cache-framework/schedule-cc", "AbCdEfGhIjKlMnOp"),
            ("hte-remote-cache-cortendesk:backup", "hte-console-svc-xyz"),
        ] {
            c.execute("insert into cache_locks (key, owner, expiration) values (?, ?, 0)", params![k, o]).unwrap();
        }
        assert_eq!(release_locks(&c, "hte-remote-cache-").unwrap(), 3);
        let left: Vec<String> = c.prepare("select key from cache_locks order by key").unwrap().query_map([], |r| r.get(0)).unwrap().map(|r| r.unwrap()).collect();
        assert_eq!(left, vec!["hte-remote-cache-framework/schedule-cc"]);
    }
}
