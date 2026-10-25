//! Phase 6: the daily scheduler entries hte-console takes over from PHP's `routes/console.php` (1.15.0-hte.1), the
//! commands behind them, and the command line (`backup`, `restore`, `prune-logs`, `prune-invitations`, `backups`).
//!
//!   cortendesk:backup --scheduled        dailyAt 03:30  withoutOverlapping(30)   backup_scheduled
//!   cortendesk:prune-logs                dailyAt 04:10  (no mutex)               prune::prune_logs
//!   cortendesk:prune-invitations         dailyAt 04:20  (no mutex)               prune::prune_invitations
//!
//! Left to PHP, on purpose: `cortendesk:check-device-notifications` (Apprise, off at HTE; deploy stops if it is on).
//! Phase 3 already took reach, passwords, stale sessions and the diagnostics heartbeat.
//!
//! Which entries run here is `HTE_CONSOLE_JOBS` (`backup,prune-logs,prune-invitations` or `all`; none by default, so
//! an upgrade alone changes nothing). Double running is avoided per entry:
//! - **backup** has a PHP mutex, so phase 3's trick applies: this service holds PHP's lock for that entry (refreshed
//!   every tick, 30 minutes' expiry) and PHP's `schedule:run` skips it. Two more guards behind that: the run itself
//!   takes PHP's `cortendesk:backup` cache lock (Settings -> Backups' "Back up now" uses it too) and `--scheduled`
//!   runs once per calendar day (`backup_last_scheduled_at`), which both sides read and write.
//! - **prune-logs** and **prune-invitations** have no mutex in PHP, so nothing can be held. The deploy removes the two
//!   entries from the PHP container's schedule (a read-only bind mount of `routes/console.php` without them) and
//!   only then lists them here. Running both would be harmless (idempotent deletes by the same cutoff) but is not done.
//! The times are UTC, as the app's timezone is. A tick every 15 seconds sees every minute.

use crate::backup::{self, Env, Stage};
use crate::cache::{self, Store};
use crate::php::Val;
use crate::prune;
use rusqlite::Connection;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Job {
    Backup,
    PruneLogs,
    PruneInvitations,
}

pub const ALL: [Job; 3] = [Job::Backup, Job::PruneLogs, Job::PruneInvitations];

impl Job {
    pub fn name(self) -> &'static str {
        match self {
            Job::Backup => "backup",
            Job::PruneLogs => "prune-logs",
            Job::PruneInvitations => "prune-invitations",
        }
    }
    pub fn parse(s: &str) -> Option<Job> {
        ALL.iter().copied().find(|j| j.name() == s.trim())
    }
    /// The command as `Schedule::command(...)` was given it.
    pub fn command(self) -> &'static str {
        match self {
            Job::Backup => "cortendesk:backup --scheduled",
            Job::PruneLogs => "cortendesk:prune-logs",
            Job::PruneInvitations => "cortendesk:prune-invitations",
        }
    }
    /// `dailyAt('H:M')`
    pub fn at(self) -> (u32, u32) {
        match self {
            Job::Backup => (3, 30),
            Job::PruneLogs => (4, 10),
            Job::PruneInvitations => (4, 20),
        }
    }
    pub fn expression(self) -> String {
        let (h, m) = self.at();
        format!("{m} {h} * * *")
    }
    /// `withoutOverlapping($expiresAt)` in minutes; only the backup has one in PHP.
    pub fn mutex_minutes(self) -> Option<i64> {
        (self == Job::Backup).then_some(30)
    }
    pub fn mutex_name(self) -> String {
        cache::schedule_mutex_name(&self.expression(), self.command())
    }
}

/// `HTE_CONSOLE_JOBS`
pub fn from_env() -> Result<Vec<Job>, String> {
    let v = std::env::var("HTE_CONSOLE_JOBS").unwrap_or_default();
    let mut jobs = vec![];
    for part in v.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        if part == "all" {
            return Ok(ALL.to_vec());
        }
        let j = Job::parse(part).ok_or_else(|| format!("HTE_CONSOLE_JOBS: unknown job {part:?} (backup, prune-logs, prune-invitations, all)"))?;
        if !jobs.contains(&j) {
            jobs.push(j);
        }
    }
    Ok(jobs)
}

// ------------------------------------------------------------------------------------------------ environment ---

/// What the commands need, read as the PHP image gets it. Returns the backup `Env` and the retention default.
pub struct Setup {
    pub env: Env,
    /// `config('cortendesk.log_retention_days')` as a string (`CORTENDESK_LOG_RETENTION_DAYS`, else 365)
    pub retention_default: String,
}

fn set(name: &str) -> Option<String> {
    std::env::var(name).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

impl Setup {
    pub fn from_env() -> Result<Setup, String> {
        let cfg = crate::config::Config::from_env()?;
        let n = cfg.native.ok_or("HTE_CONSOLE_DATABASE is not set")?;
        // the key as the PHP image reads it: APP_KEY, else /data/.app_key (the entrypoint's `$(cat ...)` drops the newline)
        let app_key = match set("APP_KEY") {
            Some(k) => k,
            None => std::fs::read_to_string(&n.app_key_file).map_err(|e| format!("cannot read the app key ({}): {e}", n.app_key_file.display()))?.trim().to_string(),
        };
        let server_secret = match set("CORTENDESK_SERVER_SECRET") {
            Some(s) => s,
            None => std::fs::read_to_string(std::env::var("HTE_CONSOLE_SERVER_SECRET_FILE").unwrap_or_else(|_| "/data/.server_secret".into())).map(|s| s.trim().to_string()).unwrap_or_default(),
        };
        let rustdesk_dir = set("HTE_CONSOLE_RUSTDESK_DIR").map(PathBuf::from).or_else(|| n.hbbs_db.parent().map(|p| p.to_path_buf())).filter(|p| !p.as_os_str().is_empty());
        Ok(Setup {
            env: Env {
                database: n.database,
                busy: n.busy,
                backups_dir: PathBuf::from(set("HTE_CONSOLE_BACKUPS_DIR").or_else(|| set("CORTENDESK_BACKUPS_PATH")).unwrap_or_else(|| "/data/backups".into())),
                rustdesk_dir,
                app_key,
                server_secret,
                app_url: set("HTE_CONSOLE_PUBLIC_URL").or_else(|| set("APP_URL")).unwrap_or_default(),
                app_version: n.api_version,
                store: Store::from_env()?,
            },
            retention_default: set("HTE_CONSOLE_LOG_RETENTION_DAYS").or_else(|| set("CORTENDESK_LOG_RETENTION_DAYS")).unwrap_or_else(|| "365".into()),
        })
    }
}

// ------------------------------------------------------------------------------------------------ the commands ---

/// `Str::limit($value, 250)`: cut to 250 characters, trailing whitespace dropped, "..." appended.
pub fn str_limit(s: &str, limit: usize) -> String {
    if s.chars().count() <= limit {
        return s.to_string();
    }
    let cut: String = s.chars().take(limit).collect();
    format!("{}...", cut.trim_end())
}

/// `ConsoleAudit::system(...)`: a row nobody clicked ("system" in the console log); the table has `created_at` only.
fn audit_system(c: &Connection, now: i64, action: &str, summary: &str, target_type: &str, target_id: Option<&str>) -> Result<(), String> {
    c.execute(
        r#"insert into "console_audits" ("user_id", "username", "action", "target_type", "target_id", "summary", "created_at") values (null, 'system', ?, ?, ?, ?, ?)"#,
        rusqlite::params![action, target_type, target_id, str_limit(summary, 250), crate::laravel::ts(now)],
    )
    .map(|_| ())
    .map_err(|e| format!("console_audits: {e}"))
}

/// `Backup::record()`: the outcome for Settings -> Backups, and the console log line. (Apprise would be told here;
/// it is off at HTE and the deploy refuses to continue when it is on.)
fn record(c: &Connection, now: i64, summary: &[(&str, Val)], trigger: &str, message: &str, name: Option<&str>) -> Result<(), String> {
    let json = crate::php::json_encode(&crate::php::assoc(summary.iter().map(|(k, v)| (k.to_string(), v.clone())))).ok_or("cannot encode the backup result")?;
    backup::put_setting(c, "backup_last_result", &json, now)?;
    let mut line = trigger.to_string();
    if let Some(f) = line.get_mut(0..1) {
        f.make_ascii_uppercase();
    }
    audit_system(c, now, "backup.create", &format!("{line} backup: {message}"), "backup", name)
}

pub struct Outcome {
    pub ok: bool,
    pub lines: Vec<String>,
}

/// `cortendesk:backup [--scheduled] [--no-copy]`
pub fn backup_command(env: &Env, scheduled: bool, now: i64) -> Result<Outcome, String> {
    let c = env.open()?;
    let s = backup::settings(&c)?;
    let mut lines = vec![];
    if scheduled {
        if !s.enabled {
            return Ok(Outcome { ok: true, lines: vec!["Automatic backups are off.".into()] });
        }
        let last = String::from_utf8_lossy(&crate::sqlite::setting(&c, "backup_last_scheduled_at", "").map_err(|f| format!("{f:?}"))?).into_owned();
        let last_at = (!last.is_empty()).then(|| backup::parse_when(&last)).flatten();
        if !backup::due(last_at, now) {
            return Ok(Outcome { ok: true, lines: vec![format!("Not due (last {}).", last_at.map(|d| d.format("%Y-%m-%d %H:%M:%S").to_string()).unwrap_or_default())] });
        }
    }
    let trigger = if scheduled { "scheduled" } else { "manual" };
    let at = backup::iso(now);
    let made = match backup::create(env, trigger, now) {
        Ok(m) => m,
        Err(e) => {
            let msg = format!("Backup failed: {e}");
            tracing::error!("{msg}");
            record(&c, now, &[("at", Val::str(&at)), ("ok", Val::Bool(false)), ("trigger", Val::str(trigger)), ("message", Val::str(&msg))], trigger, &msg, None)?;
            return Ok(Outcome { ok: false, lines: vec![msg] });
        }
    };
    lines.push(format!("Wrote {} ({}, {} rows)", made.name, backup::human_size(made.size), made.rows));
    let mut message = format!("Wrote {}", made.name);
    let mut ok = true;
    if scheduled {
        backup::put_setting(&c, "backup_last_scheduled_at", &at, now)?;
    }
    for name in backup::apply_retention(env, s.keep)? {
        lines.push(format!("Removed {name} (retention)"));
    }
    if s.target != "none" {
        // FTP and S3 copies are not ported (HTE has them off); say so where Settings -> Backups shows it
        let why = format!("Off-site copy failed: hte-console makes no {} copies (the target in Settings is not used)", s.target);
        tracing::warn!("{why}");
        lines.push(why.clone());
        message.push_str(&format!(". {why}"));
        ok = false;
    }
    record(
        &c,
        now,
        &[("at", Val::str(&at)), ("ok", Val::Bool(ok)), ("trigger", Val::str(trigger)), ("message", Val::str(&message)), ("name", Val::str(&made.name))],
        trigger,
        &message,
        Some(&made.name),
    )?;
    Ok(Outcome { ok, lines })
}

// ------------------------------------------------------------------------------------------------- scheduler ---

pub struct Scheduler {
    setup: Arc<Setup>,
    owner: String,
    jobs: Vec<Job>,
    stopped: AtomicBool,
    running: Mutex<HashMap<Job, bool>>,
    fired: Mutex<HashMap<Job, i64>>,
}

impl Scheduler {
    pub fn new(setup: Setup, jobs: Vec<Job>) -> Arc<Scheduler> {
        Arc::new(Scheduler { setup: Arc::new(setup), owner: crate::sweeps::owner(true), jobs, stopped: AtomicBool::new(false), running: Mutex::new(HashMap::new()), fired: Mutex::new(HashMap::new()) })
    }

    pub fn start(self: &Arc<Self>) {
        if self.jobs.is_empty() {
            return;
        }
        self.take_back();
        let me = self.clone();
        tokio::spawn(async move {
            let mut every = tokio::time::interval(Duration::from_secs(15));
            every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                every.tick().await;
                let m = me.clone();
                let _ = tokio::task::spawn_blocking(move || m.tick(chrono::Utc::now().timestamp())).await;
            }
        });
        tracing::info!(jobs = ?self.jobs.iter().map(|j| j.name()).collect::<Vec<_>>(), "daily jobs run here (UTC); PHP's backup entry is skipped while hte-console holds its lock");
    }

    /// One tick: refresh the backup's PHP lock, and start every job whose minute it is (once per minute).
    pub fn tick(self: &Arc<Self>, now: i64) {
        let minute = now.div_euclid(60);
        let (h, m) = (((now.rem_euclid(86_400)) / 3600) as u32, ((now.rem_euclid(3600)) / 60) as u32);
        for &job in &self.jobs {
            if self.stopped.load(Ordering::SeqCst) {
                return;
            }
            if job.mutex_minutes().is_some() && !self.hold(job, now) {
                continue;
            }
            if job.at() != (h, m) || self.fired.lock().unwrap_or_else(|e| e.into_inner()).get(&job) == Some(&minute) {
                continue;
            }
            {
                let mut running = self.running.lock().unwrap_or_else(|e| e.into_inner());
                if running.get(&job) == Some(&true) {
                    continue;
                }
                running.insert(job, true);
            }
            self.fired.lock().unwrap_or_else(|e| e.into_inner()).insert(job, minute);
            let me = self.clone();
            std::thread::spawn(move || {
                let r = me.run(job, now);
                me.running.lock().unwrap_or_else(|e| e.into_inner()).insert(job, false);
                match r {
                    Ok(o) => o.lines.iter().for_each(|l| tracing::info!(job = job.name(), "{l}")),
                    Err(e) => tracing::error!(job = job.name(), "{e}"),
                }
            });
        }
    }

    /// Take or refresh PHP's lock for the entry; false when PHP holds it (it is mid-run), so this tick leaves it be.
    fn hold(&self, job: Job, now: i64) -> bool {
        let env = &self.setup.env;
        let r = env.open().and_then(|c| env.store.acquire(&c, &job.mutex_name(), job.mutex_minutes().unwrap_or(1) * 60, &self.owner, now).map_err(|f| format!("{f:?}")));
        match r {
            Ok(held) => held,
            Err(e) => {
                tracing::error!(job = job.name(), "lock: {e}");
                false
            }
        }
    }

    /// One run of a job's command (also called by the tests and by the `run` CLI).
    pub fn run(&self, job: Job, now: i64) -> Result<Outcome, String> {
        let env = &self.setup.env;
        match job {
            Job::Backup => backup_command(env, true, now),
            Job::PruneLogs => {
                let c = env.open()?;
                let p = prune::prune_logs(&c, now, None, &self.setup.retention_default)?;
                Ok(Outcome { ok: true, lines: p.lines })
            }
            Job::PruneInvitations => {
                let c = env.open()?;
                Ok(Outcome { ok: true, lines: vec![prune::prune_invitations(&c, now, 30)?] })
            }
        }
    }

    /// At start: the lock a previous hte-console service left (killed before it could give it back) is ours at once.
    fn take_back(&self) {
        let env = &self.setup.env;
        let Ok(c) = env.open() else { return };
        for &job in self.jobs.iter().filter(|j| j.mutex_minutes().is_some()) {
            let key = format!("{}{}", env.store.prefix, job.mutex_name());
            let r = c.execute(
                r#"update "cache_locks" set "owner" = ?1 where "key" = ?2 and "owner" like 'hte-console-svc-%' and "owner" != ?1"#,
                rusqlite::params![self.owner, key],
            );
            if let Ok(n) = r {
                if n > 0 {
                    tracing::info!(job = job.name(), "took back the lock a previous hte-console left");
                }
            }
        }
    }

    /// On a clean stop: give the backup's lock back, so PHP's scheduler runs the entry again.
    pub fn release_all(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        let env = &self.setup.env;
        if let Ok(c) = env.open() {
            for &job in self.jobs.iter().filter(|j| j.mutex_minutes().is_some()) {
                let _ = env.store.release(&c, &job.mutex_name(), &self.owner);
            }
        }
        if !self.jobs.is_empty() {
            tracing::info!("daily jobs: the backup's lock is released, PHP's scheduler takes the entry back");
        }
    }
}

// --------------------------------------------------------------------------------------------- command line ---

fn flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn opt(args: &[String], name: &str) -> Option<String> {
    args.iter().find_map(|a| a.strip_prefix(&format!("{name}=")).map(str::to_string))
}

/// `hte-console backup|restore|prune-logs|prune-invitations|backups|housekeeping-locks ...`; exit code.
pub fn cli(args: &[String]) -> i32 {
    let cmd = args.first().map(String::as_str).unwrap_or("");
    if cmd == "housekeeping-locks" {
        // the deploy compares these with what PHP's own scheduler reports for the same entries (needs the prefix only)
        return match Store::from_env() {
            Ok(store) => {
                for j in ALL {
                    println!("{} {}{} {}", j.command(), store.prefix, j.mutex_name(), j.mutex_minutes().map(|m| m.to_string()).unwrap_or_else(|| "-".into()));
                }
                0
            }
            Err(e) => fail(&e),
        };
    }
    let setup = match Setup::from_env() {
        Ok(s) => s,
        Err(e) => return fail(&e),
    };
    let env = &setup.env;
    let now = chrono::Utc::now().timestamp();
    match cmd {
        "backup" => match backup_command(env, flag(args, "--scheduled"), now) {
            Ok(o) => {
                o.lines.iter().for_each(|l| println!("{l}"));
                if o.ok { 0 } else { 1 }
            }
            Err(e) => fail(&e),
        },
        "backups" => match backup::list(env) {
            Ok(rows) => {
                for r in rows {
                    let rows_total: i64 = r.manifest.as_ref().and_then(|m| m.get("tables")).and_then(|t| t.as_object()).map(|o| o.values().filter_map(|v| v.as_i64()).sum()).unwrap_or(0);
                    println!("{}  {}  {}  {} rows  CortenDesk {}", r.name, r.created_at.to_rfc3339(), backup::human_size(r.size), rows_total, r.manifest.as_ref().and_then(|m| m.get("app_version")).and_then(|v| v.as_str()).unwrap_or("?"));
                }
                0
            }
            Err(e) => fail(&e),
        },
        "restore" => {
            let Some(arg) = args.get(1).filter(|a| !a.starts_with("--")) else { return fail("usage: hte-console restore <name in the backup directory | path> [--force]") };
            let path = if std::path::Path::new(arg).is_file() {
                std::fs::canonicalize(arg).ok()
            } else {
                let base = std::path::Path::new(arg).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                backup::path_of(env, &base).ok().flatten()
            };
            let Some(path) = path else { return fail(&format!("No backup found at {arg}.")) };
            let manifest = match backup::read_manifest(&path) {
                Ok(m) => m,
                Err(e) => return fail(&e),
            };
            let total: i64 = manifest.get("tables").and_then(|t| t.as_object()).map(|o| o.values().filter_map(|v| v.as_i64()).sum()).unwrap_or(0);
            println!(
                "Backup from {}, CortenDesk {}, {} rows.",
                manifest.get("created_at").and_then(|v| v.as_str()).unwrap_or("?"),
                manifest.get("app_version").and_then(|v| v.as_str()).unwrap_or("?"),
                total
            );
            if !flag(args, "--force") {
                print!("This replaces every setting, user, device and log in this install. Continue? [y/N] ");
                use std::io::Write;
                let _ = std::io::stdout().flush();
                let mut a = String::new();
                let _ = std::io::stdin().read_line(&mut a);
                if !matches!(a.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
                    return 0;
                }
            }
            match backup::restore(env, &path, now, &|_: Stage| Ok(())) {
                Ok(r) => {
                    println!("Restored {} rows across {} tables.", r.rows, r.tables);
                    if r.rekeyed {
                        println!("Encrypted values were re-keyed to this install's APP_KEY.");
                    }
                    for (t, cols) in &r.dropped_columns {
                        println!("warning: {t}: ignored columns this version does not have ({})", cols.join(", "));
                    }
                    for (t, n) in &r.orphans {
                        println!("warning: {t}: {n} row(s) point at rows that are not in the backup (restored as they were)");
                    }
                    if r.restart_needed {
                        println!("warning: Server files staged ({}). Restart the container to adopt them.", r.files.join(", "));
                    }
                    0
                }
                Err(e) if e.starts_with("The database WAS restored") => fail(&e),
                Err(e) => fail(&format!("Restore failed, nothing was changed: {e}")),
            }
        }
        "prune-logs" => {
            let days = opt(args, "--days").map(|d| crate::php::str_to_int(d.as_bytes()));
            let r = env.open().and_then(|c| prune::prune_logs(&c, now, days, &setup.retention_default));
            match r {
                Ok(p) => {
                    p.lines.iter().for_each(|l| println!("{l}"));
                    0
                }
                Err(e) => fail(&e),
            }
        }
        "prune-invitations" => {
            let days = opt(args, "--days").map(|d| crate::php::str_to_int(d.as_bytes())).unwrap_or(30);
            match env.open().and_then(|c| prune::prune_invitations(&c, now, days)) {
                Ok(l) => {
                    println!("{l}");
                    0
                }
                Err(e) => fail(&e),
            }
        }
        _ => fail("usage: hte-console backup [--scheduled] | backups | restore <name|path> [--force] | prune-logs [--days=N] | prune-invitations [--days=N]"),
    }
}

fn fail(msg: &str) -> i32 {
    eprintln!("{msg}");
    2
}
