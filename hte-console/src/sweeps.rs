//! Phase 3: the scheduled jobs hte-console takes over from PHP's scheduler (routes/console.php, v1.15.0-hte.1):
//!
//!   hte:reach-sweep                      every 15 s   withoutOverlapping(1)    reach::sweep (alarm 103)
//!   hte:passwords                        every minute withoutOverlapping(5)    passwords_sweep::sweep
//!   cortendesk:close-stale-sessions      every 5 min  withoutOverlapping(30)   close_stale_sessions
//!   cortendesk:diagnostics-heartbeat     every minute withoutOverlapping(10)   diagnostics_heartbeat
//!
//! Which ones run here is `HTE_CONSOLE_SWEEPS` (`reach,passwords,stale,diagnostics` or `all`; none by default, so an
//! upgrade alone changes nothing). Before each run hte-console takes the lock PHP's scheduler takes for that task
//! (`cache_locks`, the task's mutex name, PHP's expiry) and keeps it: PHP's `schedule:run` then skips the task, as it
//! skips one still running. If PHP happens to hold it (it was mid-run), this tick is skipped. On a clean stop the
//! locks are released, so PHP resumes at its next tick; if hte-console dies, they expire (1 to 30 minutes).
//! The other scheduled tasks (backups, pruning, device notifications) stay PHP's.

use crate::api::Native;
use crate::cache::{self, Store};
use crate::laravel;
use crate::php::{Fault, Val};
use crate::sqlite::{self as db, P};
use rusqlite::Connection;
use std::sync::Arc;

/// `AuditConnection::STALE_AFTER_MINUTES`
pub const STALE_AFTER_SECONDS: i64 = 5 * 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Job {
    Reach,
    Passwords,
    Stale,
    Diagnostics,
}

pub const ALL: [Job; 4] = [Job::Reach, Job::Passwords, Job::Stale, Job::Diagnostics];

impl Job {
    pub fn name(self) -> &'static str {
        match self {
            Job::Reach => "reach",
            Job::Passwords => "passwords",
            Job::Stale => "stale",
            Job::Diagnostics => "diagnostics",
        }
    }
    pub fn parse(s: &str) -> Option<Job> {
        ALL.iter().copied().find(|j| j.name() == s.trim())
    }
    /// The artisan command PHP schedules.
    pub fn command(self) -> &'static str {
        match self {
            Job::Reach => "hte:reach-sweep",
            Job::Passwords => "hte:passwords",
            Job::Stale => "cortendesk:close-stale-sessions",
            Job::Diagnostics => "cortendesk:diagnostics-heartbeat",
        }
    }
    /// The schedule's cron expression (`everyFifteenSeconds` is `* * * * *` repeated within the minute).
    fn expression(self) -> &'static str {
        match self {
            Job::Stale => "*/5 * * * *",
            _ => "* * * * *",
        }
    }
    /// `withoutOverlapping($expiresAt)`, in minutes.
    fn expires_minutes(self) -> i64 {
        match self {
            Job::Reach => 1,
            Job::Passwords => 5,
            Job::Stale => 30,
            Job::Diagnostics => 10,
        }
    }
    fn every_seconds(self) -> u64 {
        match self {
            Job::Reach => 15,
            Job::Passwords | Job::Diagnostics => 60,
            Job::Stale => 300,
        }
    }
    /// The task's lock name in PHP's scheduler (`Event::mutexName()`), without the cache prefix.
    pub fn mutex_name(self) -> String {
        cache::schedule_mutex_name(self.expression(), self.command())
    }
}

/// `HTE_CONSOLE_SWEEPS`
pub fn from_env() -> Result<Vec<Job>, String> {
    let v = std::env::var("HTE_CONSOLE_SWEEPS").unwrap_or_default();
    let mut jobs = vec![];
    for part in v.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        if part == "all" {
            return Ok(ALL.to_vec());
        }
        let j = Job::parse(part).ok_or_else(|| format!("HTE_CONSOLE_SWEEPS: unknown job {part:?} (reach, passwords, stale, diagnostics, all)"))?;
        if !jobs.contains(&j) {
            jobs.push(j);
        }
    }
    Ok(jobs)
}

/// `AuditConnection::closeStaleSessions()`: sessions of devices with no heartbeat for five minutes are closed
/// (an empty heartbeating set compiles to `1 = 1`: every stale session closes). Returns how many.
pub fn close_stale_sessions(c: &Connection, now: i64) -> Result<usize, Fault> {
    let cutoff = laravel::ts(now - STALE_AFTER_SECONDS);
    let live: Vec<Val> = db::rows(c, r#"select "rustdesk_id" from "devices" where "last_online_at" >= ? and "devices"."deleted_at" is null"#, &[P(Val::str(&cutoff))])?
        .iter()
        .map(|r| r.val("rustdesk_id"))
        .collect();
    let ts = laravel::ts(now);
    let mut sql = String::from(r#"update "audit_connections" set "action" = ?, "closed_at" = ?, "updated_at" = ? where "closed_at" is null and "created_at" < ?"#);
    let mut params = vec![P(Val::str("close")), P(Val::str(&ts)), P(Val::str(&ts)), P(Val::str(&cutoff))];
    if !live.is_empty() {
        sql.push_str(&format!(r#" and "rustdesk_id" not in ({})"#, vec!["?"; live.len()].join(", ")));
        params.extend(live.into_iter().map(P));
    }
    let n = db::exec(c, &sql, &params)?;
    if n > 0 {
        tracing::info!("closed {n} stale session(s) on silent devices");
    }
    Ok(n)
}

/// `DiagnosticsHeartbeat`: `Cache::forever('cortendesk:diagnostics:scheduler-heartbeat', now()->toIso8601String())`.
pub fn diagnostics_heartbeat(c: &Connection, store: &Store, now: i64) -> Result<(), Fault> {
    let at = chrono::DateTime::from_timestamp(now, 0).map(|d| d.format("%Y-%m-%dT%H:%M:%S+00:00").to_string()).unwrap_or_default();
    store.forever(c, cache::SCHEDULER_HEARTBEAT_KEY, &Val::str(&at), now)
}

/// One run of a job's PHP command, without any lock.
pub fn run(n: &Native, c: &Connection, store: &Store, job: Job, now: i64) -> Result<String, Fault> {
    Ok(match job {
        Job::Reach => format!("closed {}", crate::reach::sweep(c, now)?),
        Job::Passwords => {
            let s = crate::passwords_sweep::sweep(c, &n.crypt, now)?;
            format!("issued {}, book entries written {}", s.issued, s.books)
        }
        Job::Stale => format!("closed {}", close_stale_sessions(c, now)?),
        Job::Diagnostics => {
            diagnostics_heartbeat(c, store, now)?;
            "recorded".into()
        }
    })
}

/// The lock owner this process writes into `cache_locks` (PHP's are 16 random letters).
pub fn owner() -> String {
    format!("hte-console-{}", laravel::str_random(12))
}

/// `hte-console sweep <job>...`: each job once, under PHP's lock (taken and released, so a PHP scheduler running at
/// the same moment never overlaps it). Used by the replay and by hand.
pub fn once(n: &Native, store: &Store, jobs: &[Job]) -> Result<Vec<String>, String> {
    let me = owner();
    let c = n.db.lock().unwrap_or_else(|e| e.into_inner());
    let mut out = vec![];
    for &job in jobs {
        let now = n.now();
        let name = job.mutex_name();
        if !store.acquire(&c, &name, job.expires_minutes() * 60, &me, now).map_err(|f| format!("{}: lock: {f:?}", job.name()))? {
            out.push(format!("{}: skipped (PHP's scheduler is running it)", job.name()));
            continue;
        }
        let r = run(n, &c, store, job, now);
        let _ = store.release(&c, &name, &me);
        out.push(format!("{}: {}", job.name(), r.map_err(|f| format!("{}: {f:?}", job.name()))?));
    }
    Ok(out)
}

/// The running scheduler: one task per job, and what to release on shutdown.
pub struct Scheduler {
    native: Arc<Native>,
    store: Store,
    owner: String,
    jobs: Vec<Job>,
}

impl Scheduler {
    pub fn new(native: Arc<Native>, store: Store, jobs: Vec<Job>) -> Arc<Scheduler> {
        Arc::new(Scheduler { native, store, owner: owner(), jobs })
    }

    /// Start a tokio task per job. Each tick: take (or refresh) PHP's lock, run, keep the lock.
    pub fn start(self: &Arc<Self>) {
        for &job in &self.jobs {
            let me = self.clone();
            tokio::spawn(async move {
                let mut every = tokio::time::interval(std::time::Duration::from_secs(job.every_seconds()));
                every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    every.tick().await;
                    let m = me.clone();
                    let _ = tokio::task::spawn_blocking(move || m.tick(job)).await;
                }
            });
        }
        if !self.jobs.is_empty() {
            tracing::info!(jobs = ?self.jobs.iter().map(|j| j.name()).collect::<Vec<_>>(), "scheduled jobs run here; PHP's scheduler skips them while hte-console holds their locks");
        }
    }

    /// One tick of a job: take or refresh its lock, run it (also called by the tests).
    pub fn tick(&self, job: Job) {
        let n = &self.native;
        let c = n.db.lock().unwrap_or_else(|e| e.into_inner());
        let now = n.now();
        match self.store.acquire(&c, &job.mutex_name(), job.expires_minutes() * 60, &self.owner, now) {
            Ok(true) => {}
            Ok(false) => {
                tracing::debug!(job = job.name(), "PHP's scheduler holds the lock: skipped this tick");
                return;
            }
            Err(f) => {
                let _ = crate::api::fail(&format!("{} lock", job.name()), &f);
                return;
            }
        }
        if let Err(f) = run(n, &c, &self.store, job, now) {
            let _ = crate::api::fail(job.command(), &f);
        }
    }

    /// On a clean stop: give the locks back, so PHP's scheduler runs these tasks again at its next tick.
    pub fn release_all(&self) {
        let c = self.native.db.lock().unwrap_or_else(|e| e.into_inner());
        for &job in &self.jobs {
            let _ = self.store.release(&c, &job.mutex_name(), &self.owner);
        }
        if !self.jobs.is_empty() {
            tracing::info!("scheduled jobs: locks released, PHP's scheduler takes them back");
        }
    }
}
