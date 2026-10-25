//! hte-console: phase 0's shadow proxy and tools, phase 1's native device endpoints.
//!
//!   hte-console serve                     serve (default); environment: see config.rs
//!   hte-console scan <dir>                fail if any fixture holds anything real
//!   hte-console replay <dir> <base-url>   replay fixtures, print differences (exit 1 when any)
//!   hte-console seed-sql <dir>            SQL (placeholders only) for the replay database
//!   hte-console snapshot <sqlite>         the database as comparable text (replay: PHP's state vs ours)
//!   hte-console seed-expand <sql> <idp>   a phase 2 seed made concrete (fake provider URL, app-key ciphertexts)
//!   hte-console fake-idp                  a fake OpenID provider for the replay (TEST ONLY; see fake_idp.rs)
//!   hte-console sweep <job>...|all        phase 3: run scheduled jobs once (reach, passwords, stale, diagnostics)
//!   hte-console schedule-locks            phase 3: the PHP scheduler lock each job takes over (for the deploy's check)
//!   hte-console backup|backups|restore|prune-logs|prune-invitations   phase 6: see housekeeping.rs
//!   hte-console sql-apply <sqlite> <sql>  phase 3, replay only: apply a scenario step to a throwaway database
//!   hte-console version|migrate [--check]|status|release-locks|db-copy <dest>   phase 9: see migrate.rs and maintenance.rs

use hte_console::config::Config;
use hte_console::{api, fixture, link, proxy, replay, sanitise, seed, snapshot, sweeps};
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

fn sanitiser_from_env() -> sanitise::Sanitiser {
    let literals: Vec<String> = std::env::var("HTE_CONSOLE_SANITISE_LITERALS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let salt = std::env::var("HTE_CONSOLE_SANITISE_SALT").ok().filter(|s| !s.is_empty());
    if salt.is_none() {
        eprintln!("note: HTE_CONSOLE_SANITISE_SALT is not set; placeholders are random for this run only");
    }
    sanitise::Sanitiser::new(salt.as_deref(), &literals)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into())).init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        None | Some("serve") => serve().await,
        Some("scan") => scan(args.get(1)),
        Some("replay") => replay_cmd(args.get(1), args.get(2)).await,
        Some("seed-sql") => match args.get(1).map(|d| seed::sql(&PathBuf::from(d))) {
            Some(Ok(s)) => {
                print!("{s}");
                0
            }
            Some(Err(e)) => fail(&e),
            None => fail("usage: hte-console seed-sql <dir>"),
        },
        Some("snapshot") => match args.get(1).map(|p| snapshot::snapshot(&PathBuf::from(p))) {
            Some(Ok(s)) => {
                print!("{s}");
                0
            }
            Some(Err(e)) => fail(&e),
            None => fail("usage: hte-console snapshot <sqlite>"),
        },
        Some("seed-expand") => match (args.get(1), args.get(2)) {
            (Some(f), Some(idp)) => seed_expand(f, idp),
            _ => fail("usage: hte-console seed-expand <sql> <idp-url>"),
        },
        Some("fake-idp") => match hte_console::fake_idp::serve_from_env().await {
            Ok(()) => 0,
            Err(e) => fail(&e),
        },
        Some("sweep") => sweep_cmd(&args[1..]),
        // phase 9: the PHP-free image (schema ownership, status for the scripts, the rollback's lock release)
        Some("version" | "--version") => {
            println!("hte-console {}", env!("CARGO_PKG_VERSION"));
            0
        }
        Some("migrate") => migrate_cmd(args.iter().any(|a| a == "--check")),
        Some("status") => status_cmd(),
        Some("release-locks") => release_locks_cmd(),
        Some("db-copy") => db_copy_cmd(args.get(1)),
        Some("schedule-locks") => schedule_locks(),
        // phase 6: backups, restore, pruning (housekeeping.rs)
        Some("backup" | "backups" | "restore" | "prune-logs" | "prune-invitations" | "housekeeping-locks") => hte_console::housekeeping::cli(&args),
        // phase 7: the pages, PHP's against ours (pagereplay.rs)
        Some("page-seed") => match args.get(1).and_then(|n| n.parse::<i64>().ok()).map(hte_console::pagereplay::seed_sql) {
            Some(Ok(s)) => {
                print!("{s}");
                0
            }
            Some(Err(e)) => fail(&e),
            None => fail("usage: hte-console page-seed <unix-now>"),
        },
        Some("page-replay") => page_replay(&args[1..]).await,
        // phase 8: phase 2's sign-in seed (accounts, SSO settings) for the web sign-in replay, filled in for a provider
        Some("web-signin-seed") => match args.get(1) {
            Some(idp) => web_signin_seed(idp),
            None => fail("usage: hte-console web-signin-seed <idp-url>"),
        },
        // phase 8: the console's sign-in, PHP against hte-console (replay/replay-signin-web.sh)
        Some("web-signin-replay") => match (args.get(1), args.get(2)) {
            (Some(php), Some(rust)) => match hte_console::webreplay::run(php, rust).await {
                Ok(r) => {
                    println!("{} sign-in steps, {} differences, {} by design", r.total, r.differences.len(), r.by_design.len());
                    r.by_design.iter().for_each(|d| println!("by design: {d}"));
                    r.differences.iter().for_each(|d| println!("DIFFERENCE: {d}"));
                    if r.differences.is_empty() { 0 } else { 1 }
                }
                Err(e) => fail(&e),
            },
            _ => fail("usage: hte-console web-signin-replay <php-url> <rust-url>"),
        },
        // the cookie `page-seed`'s session row for a person goes with (for a browser or curl against the throwaway PHP)
        Some("page-cookie") => match (args.get(1), args.get(2).and_then(|n| n.parse::<i64>().ok())) {
            (Some(who), Some(now)) => page_cookie(who, now),
            _ => fail("usage: hte-console page-cookie <hteadmin|dana|erin> <unix-now>"),
        },
        Some("sql-apply") => match (args.get(1), args.get(2)) {
            (Some(db), Some(file)) => sql_apply(db, file),
            _ => fail("usage: hte-console sql-apply <sqlite> <sql>"),
        },
        Some(other) => fail(&format!("unknown command {other}")),
    };
    std::process::exit(code);
}

/// Phase 7: `hte-console page-replay <php-url> <rust-url> <unix-now>`; the app key from APP_KEY or
/// HTE_CONSOLE_APP_KEY_FILE, the session cookie's name from HTE_CONSOLE_SESSION_COOKIE; HTE_PAGEREPLAY_READS_ONLY=1 skips
/// the writes (the mutation check wants a run that changes nothing).
async fn page_replay(args: &[String]) -> i32 {
    let (Some(php), Some(rust), Some(now)) = (args.first(), args.get(1), args.get(2).and_then(|n| n.parse::<i64>().ok())) else {
        return fail("usage: hte-console page-replay <php-url> <rust-url> <unix-now>");
    };
    let key = match std::env::var("APP_KEY").ok().filter(|k| !k.trim().is_empty()) {
        Some(k) => k,
        None => match std::fs::read_to_string(std::env::var("HTE_CONSOLE_APP_KEY_FILE").unwrap_or_else(|_| "/data/.app_key".into())) {
            Ok(k) => k,
            Err(e) => return fail(&format!("cannot read the app key: {e}")),
        },
    };
    let Some(cookie) = std::env::var("HTE_CONSOLE_SESSION_COOKIE").ok().filter(|c| !c.trim().is_empty()) else {
        return fail("set HTE_CONSOLE_SESSION_COOKIE to the cookie name PHP uses (config('session.cookie'))");
    };
    let writes = std::env::var("HTE_PAGEREPLAY_READS_ONLY").map_or(true, |v| v.trim().is_empty() || v == "0");
    match hte_console::pagereplay::run_with(php, rust, &key, &cookie, now, writes).await {
        Ok(r) => {
            println!("{} page requests, {} differences, {} by design", r.total, r.differences.len(), r.by_design.len());
            r.by_design.iter().for_each(|d| println!("by design: {d}"));
            r.differences.iter().for_each(|d| println!("DIFFERENCE: {d}"));
            if r.differences.is_empty() { 0 } else { 1 }
        }
        Err(e) => fail(&e),
    }
}

/// The sign-in seed (fixtures/signin, embedded) with the provider's URL and ciphertexts under the replay's app key.
fn web_signin_seed(idp: &str) -> i32 {
    const SEED: &str = include_str!("../fixtures/signin/0000000000002-signin-seed.sql");
    let key = match std::fs::read_to_string(std::env::var("HTE_CONSOLE_APP_KEY_FILE").unwrap_or_else(|_| "/data/.app_key".into())) {
        Ok(k) => k,
        Err(e) => return fail(&format!("cannot read the app key: {e}")),
    };
    let crypt = match hte_console::laravel::Encrypter::from_app_key(key.trim()) {
        Ok(c) => c,
        Err(e) => return fail(&e),
    };
    match hte_console::seed::expand(SEED, idp, &crypt) {
        Ok(s) => {
            print!("{s}");
            0
        }
        Err(e) => fail(&e),
    }
}

/// Prints `name=value` (the app key as for `page-replay`, the cookie's name from HTE_CONSOLE_SESSION_COOKIE).
fn page_cookie(who: &str, now: i64) -> i32 {
    if !["hteadmin", "dana", "erin"].contains(&who) {
        return fail("the people are hteadmin, dana and erin");
    }
    let key = match std::env::var("APP_KEY").ok().filter(|k| !k.trim().is_empty()) {
        Some(k) => k,
        None => match std::fs::read_to_string(std::env::var("HTE_CONSOLE_APP_KEY_FILE").unwrap_or_else(|_| "/data/.app_key".into())) {
            Ok(k) => k,
            Err(e) => return fail(&format!("cannot read the app key: {e}")),
        },
    };
    let Some(name) = std::env::var("HTE_CONSOLE_SESSION_COOKIE").ok().filter(|c| !c.trim().is_empty()) else {
        return fail("set HTE_CONSOLE_SESSION_COOKIE to the cookie name PHP uses");
    };
    match hte_console::pagereplay::cookie(&key, &name, who, now) {
        Ok(c) => {
            println!("{c}");
            0
        }
        Err(e) => fail(&e),
    }
}

fn seed_expand(file: &str, idp: &str) -> i32 {
    // the app key as the PHP image reads it: APP_KEY, else the key file
    let key = match std::env::var("APP_KEY").ok().filter(|k| !k.trim().is_empty()) {
        Some(k) => k,
        None => match std::fs::read_to_string(std::env::var("HTE_CONSOLE_APP_KEY_FILE").unwrap_or_else(|_| "/data/.app_key".into())) {
            Ok(k) => k,
            Err(e) => return fail(&format!("cannot read the app key: {e}")),
        },
    };
    let crypt = match hte_console::laravel::Encrypter::from_app_key(&key) {
        Ok(c) => c,
        Err(e) => return fail(&e),
    };
    match std::fs::read_to_string(file).map_err(|e| e.to_string()).and_then(|s| seed::expand(&s, idp, &crypt)) {
        Ok(s) => {
            print!("{s}");
            0
        }
        Err(e) => fail(&e),
    }
}

/// Phase 3: `hte-console sweep <job>...` on the database HTE_CONSOLE_DATABASE names.
fn sweep_cmd(names: &[String]) -> i32 {
    let jobs: Vec<sweeps::Job> = if names.iter().any(|n| n == "all") {
        sweeps::ALL.to_vec()
    } else {
        match names.iter().map(|n| sweeps::Job::parse(n).ok_or(n)).collect::<Result<Vec<_>, _>>() {
            Ok(j) if !j.is_empty() => j,
            Ok(_) => return fail("usage: hte-console sweep <reach|passwords|stale|diagnostics>...|all"),
            Err(n) => return fail(&format!("unknown job {n}")),
        }
    };
    let cfg = match Config::from_env() {
        Ok(Config { native: Some(n), .. }) => n,
        Ok(_) => return fail("HTE_CONSOLE_DATABASE is not set"),
        Err(e) => return fail(&e),
    };
    let native = match api::Native::open(&cfg) {
        Ok(n) => n,
        Err(e) => return fail(&e),
    };
    let store = match hte_console::cache::Store::from_env() {
        Ok(s) => s,
        Err(e) => return fail(&e),
    };
    match sweeps::once(&native, &store, &jobs) {
        Ok(lines) => {
            lines.iter().for_each(|l| println!("{l}"));
            0
        }
        Err(e) => fail(&e),
    }
}

/// Phase 3: each job's lock key in `cache_locks` (with PHP's cache prefix) and expiry, one per line.
/// The database named by HTE_CONSOLE_DATABASE, as the other commands read their environment.
fn native_config() -> Result<hte_console::config::NativeConfig, String> {
    Config::from_env()?.native.ok_or_else(|| "HTE_CONSOLE_DATABASE is not set".to_string())
}

fn read_only(path: &std::path::Path) -> Result<rusqlite::Connection, String> {
    let c = rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX)
        .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    let _ = c.busy_timeout(std::time::Duration::from_secs(10));
    Ok(c)
}

/// `hte-console migrate [--check]`: phase 9's schema ownership (migrate.rs). `--check` writes nothing and exits 1 when a PHP
/// migration is missing; without it our pending migrations are applied.
fn migrate_cmd(check_only: bool) -> i32 {
    let n = match native_config() {
        Ok(n) => n,
        Err(e) => return fail(&e),
    };
    let report = if check_only {
        read_only(&n.database).and_then(|c| hte_console::migrate::check(&c))
    } else {
        hte_console::sqlite::open(&n.database, n.busy, n.wal).and_then(|c| hte_console::migrate::run(&c))
    };
    match report {
        Ok(r) if r.php_missing.is_empty() => {
            println!("PHP migrations recorded: {}/{}; ours pending: {}; recorded but unknown: {}", r.php_recorded, hte_console::migrate::PHP_MIGRATIONS.len(), r.own_pending.len(), r.unknown.len());
            r.unknown.iter().for_each(|u| println!("unknown: {u}"));
            0
        }
        Ok(r) => {
            println!("PHP migrations recorded: {}/{}; missing:", r.php_recorded, hte_console::migrate::PHP_MIGRATIONS.len());
            r.php_missing.iter().for_each(|m| println!("  {m}"));
            1
        }
        Err(e) => fail(&e),
    }
}

/// `hte-console status`: name=value lines for the deploy and rollback scripts, from a read-only open.
fn status_cmd() -> i32 {
    let n = match native_config() {
        Ok(n) => n,
        Err(e) => return fail(&e),
    };
    let prefix = hte_console::cache::Store::from_env().map(|s| s.prefix).unwrap_or_default();
    match read_only(&n.database).and_then(|c| hte_console::maintenance::status(&c, &prefix, chrono::Utc::now().timestamp())) {
        Ok(s) => {
            println!("{s}");
            0
        }
        Err(e) => fail(&e),
    }
}

/// `hte-console db-copy <dest>`: a consistent copy of the live database (`VACUUM INTO`, taken while the console runs; WAL
/// readers and writers are not blocked for long). Refuses to overwrite. What `upgrade.sh` takes before an image swap, now
/// that no PHP container is there to do it.
fn db_copy_cmd(dest: Option<&String>) -> i32 {
    let Some(dest) = dest else { return fail("usage: hte-console db-copy <dest.sqlite>") };
    if std::path::Path::new(dest).exists() {
        return fail(&format!("{dest} already exists; not overwriting it"));
    }
    let n = match native_config() {
        Ok(n) => n,
        Err(e) => return fail(&e),
    };
    match hte_console::sqlite::open(&n.database, n.busy, false).and_then(|c| c.execute("VACUUM INTO ?", [dest]).map_err(|e| format!("VACUUM INTO: {e}"))) {
        Ok(_) => {
            println!("copied to {dest}");
            0
        }
        Err(e) => fail(&e),
    }
}

/// `hte-console release-locks`: the rollback to the PHP stack gives PHP's scheduler its tasks back at once.
fn release_locks_cmd() -> i32 {
    let n = match native_config() {
        Ok(n) => n,
        Err(e) => return fail(&e),
    };
    let store = match hte_console::cache::Store::from_env() {
        Ok(s) => s,
        Err(e) => return fail(&e),
    };
    match hte_console::sqlite::open(&n.database, n.busy, false).and_then(|c| hte_console::maintenance::release_locks(&c, &store.prefix)) {
        Ok(k) => {
            println!("released {k} lock(s)");
            0
        }
        Err(e) => fail(&e),
    }
}

fn schedule_locks() -> i32 {
    match hte_console::cache::Store::from_env() {
        Ok(store) => {
            for j in sweeps::ALL {
                println!("{} {}{}", j.command(), store.prefix, j.mutex_name());
            }
            0
        }
        Err(e) => fail(&e),
    }
}

/// The replay's sweeps scenario: a step's SQL on hte-console's copy of the throwaway database (PHP's copy gets the
/// same file through PDO). Never pointed at the live database by any script.
fn sql_apply(db: &str, file: &str) -> i32 {
    let sql = match std::fs::read_to_string(file) {
        Ok(s) => s,
        Err(e) => return fail(&format!("{file}: {e}")),
    };
    let c = match rusqlite::Connection::open(db) {
        Ok(c) => c,
        Err(e) => return fail(&format!("{db}: {e}")),
    };
    let _ = c.busy_timeout(std::time::Duration::from_secs(10));
    match c.execute_batch(&sql) {
        Ok(()) => {
            println!("applied {file}");
            0
        }
        Err(e) => fail(&format!("{file}: {e}")),
    }
}

fn fail(msg: &str) -> i32 {
    eprintln!("{msg}");
    2
}

async fn serve() -> i32 {
    let cfg = match Config::from_env() {
        Ok(c) => c,
        Err(e) => return fail(&e),
    };
    let listener = match tokio::net::TcpListener::bind(&cfg.listen).await {
        Ok(l) => l,
        Err(e) => return fail(&format!("cannot listen on {}: {e}", cfg.listen)),
    };
    let native = match &cfg.native {
        None => None,
        Some(n) => match api::Native::open(n) {
            Ok(x) => Some(Arc::new(x)),
            Err(e) => return fail(&e),
        },
    };
    // phase 9: PHP no longer owns the schema. Check the 41 PHP migrations are recorded and apply our own additive ones
    // (HTE_CONSOLE_MIGRATE=0 skips it: the PHP stack's hte-console images never needed it).
    if let Some(x) = &native {
        if std::env::var("HTE_CONSOLE_MIGRATE").map_or(false, |v| v.trim() == "1") {
            let r = hte_console::migrate::run(&x.db.lock().unwrap_or_else(|e| e.into_inner()));
            match r {
                Ok(r) => {
                    tracing::info!("schema: {}/{} PHP migrations recorded, ours up to date", r.php_recorded, hte_console::migrate::PHP_MIGRATIONS.len());
                    if !r.unknown.is_empty() {
                        tracing::warn!(unknown = ?r.unknown, "schema: migrations recorded that this version does not know (a newer PHP release?)");
                    }
                }
                Err(e) => return fail(&e),
            }
        }
        hte_console::maintenance::start(x.clone());
    }
    tracing::info!(
        "hte-console listening on {}; device endpoints {}; other paths {}; recording {}",
        cfg.listen,
        if native.is_some() { "answered here" } else { "forwarded" },
        if cfg.upstream.is_empty() { "404" } else { "forwarded" },
        if cfg.fixtures.is_some() { "on" } else { "off" }
    );
    let shadow = (!cfg.upstream.is_empty()).then(|| {
        proxy::router(Arc::new(proxy::App {
            client: proxy::build_client(&cfg),
            sanitiser: sanitiser_from_env(),
            seq: AtomicU64::new(0),
            cfg: cfg.clone(),
        }))
    });
    // phase 3: the server link and the scheduled jobs, beside the native routes
    let mut scheduler = None;
    let mut daily = None;
    let app = match (native, shadow) {
        (Some(n), fallback) => {
            let (l, jobs) = match (link::Link::from_env(), sweeps::from_env()) {
                (Ok(l), Ok(j)) => (Arc::new(l), j),
                (Err(e), _) | (_, Err(e)) => return fail(&e),
            };
            let s = sweeps::Scheduler::new(n.clone(), l.store.clone(), jobs);
            s.start();
            scheduler = Some(s);
            // phase 6: the daily entries (backup, pruning), none unless HTE_CONSOLE_JOBS lists them
            let daily_jobs = match hte_console::housekeeping::from_env() {
                Ok(j) => j,
                Err(e) => return fail(&e),
            };
            if !daily_jobs.is_empty() {
                match hte_console::housekeeping::Setup::from_env() {
                    Ok(setup) => {
                        let d = hte_console::housekeeping::Scheduler::new(setup, daily_jobs);
                        d.start();
                        daily = Some(d);
                    }
                    Err(e) => return fail(&e),
                }
            }
            // phase 7: the console's pages behind the Laravel session (HTE_CONSOLE_PAGES=0 leaves them all to PHP)
            let pages = if std::env::var("HTE_CONSOLE_PAGES").map_or(false, |v| v.trim() == "0") {
                axum::Router::new()
            } else {
                match hte_console::pages::routes(n.clone(), fallback.clone()) {
                    Ok(r) => r,
                    Err(e) => return fail(&e),
                }
            };
            link::routes(n.clone(), l).merge(pages).merge(api::router(n, fallback))
        }
        (None, Some(s)) => s,
        (None, None) => return fail("nothing to serve: set HTE_CONSOLE_UPSTREAM or HTE_CONSOLE_DATABASE"),
    };
    let svc = app.into_make_service_with_connect_info::<std::net::SocketAddr>();
    let shutdown = async {
        // SIGINT or SIGTERM (`docker stop`): finish the requests in flight, then close the database cleanly.
        let mut term = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(t) => t,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    };
    let served = axum::serve(listener, svc).with_graceful_shutdown(shutdown).await;
    if let Some(s) = scheduler {
        s.release_all();
    }
    if let Some(d) = daily {
        d.release_all();
    }
    if let Err(e) = served {
        return fail(&format!("server: {e}"));
    }
    0
}

fn scan(dir: Option<&String>) -> i32 {
    let Some(dir) = dir else { return fail("usage: hte-console scan <dir>") };
    match fixture::scan(&sanitiser_from_env(), &PathBuf::from(dir)) {
        Ok(v) if v.is_empty() => {
            println!("clean");
            0
        }
        Ok(v) => {
            for (f, p) in v {
                println!("{f}: {p}");
            }
            1
        }
        Err(e) => fail(&e.to_string()),
    }
}

async fn replay_cmd(dir: Option<&String>, base: Option<&String>) -> i32 {
    let (Some(dir), Some(base)) = (dir, base) else { return fail("usage: hte-console replay <dir> <base-url>") };
    let s = sanitiser_from_env();
    match replay::run(&PathBuf::from(dir), base, &s).await {
        Ok(r) => {
            println!("{} fixtures, {} skipped, {} differences", r.total, r.skipped, r.differences.len());
            r.differences.iter().for_each(|d| println!("{d}"));
            if r.differences.is_empty() { 0 } else { 1 }
        }
        Err(e) => fail(&e),
    }
}
