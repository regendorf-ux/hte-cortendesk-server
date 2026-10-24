//! hte-console: phase 0's shadow proxy and tools, phase 1's native device endpoints.
//!
//!   hte-console serve                     serve (default); environment: see config.rs
//!   hte-console scan <dir>                fail if any fixture holds anything real
//!   hte-console replay <dir> <base-url>   replay fixtures, print differences (exit 1 when any)
//!   hte-console seed-sql <dir>            SQL (placeholders only) for the replay database
//!   hte-console snapshot <sqlite>         the database as comparable text (replay: PHP's state vs ours)
//!   hte-console seed-expand <sql> <idp>   a phase 2 seed made concrete (fake provider URL, app-key ciphertexts)
//!   hte-console fake-idp                  a fake OpenID provider for the replay (TEST ONLY; see fake_idp.rs)

use hte_console::config::Config;
use hte_console::{api, fixture, proxy, replay, sanitise, seed, snapshot};
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
        Some(other) => fail(&format!("unknown command {other}")),
    };
    std::process::exit(code);
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
    let app = match (native, shadow) {
        (Some(n), fallback) => api::router(n, fallback),
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
    if let Err(e) = axum::serve(listener, svc).with_graceful_shutdown(shutdown).await {
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
