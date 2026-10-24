//! hte-console, phase 0: a shadow proxy and the tools around it.
//!
//!   hte-console serve                     the proxy (default); environment: see config.rs
//!   hte-console scan <dir>                fail if any fixture holds anything real
//!   hte-console replay <dir> <base-url>   replay fixtures, print differences (exit 1 when any)
//!   hte-console seed-sql <dir>            SQL (placeholders only) for the replay database

use hte_console::config::Config;
use hte_console::{fixture, proxy, replay, sanitise, seed};
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
        Some(other) => fail(&format!("unknown command {other}")),
    };
    std::process::exit(code);
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
    tracing::info!(
        "hte-console shadow listening on {}; recording {}",
        cfg.listen,
        if cfg.fixtures.is_some() { "on" } else { "off" }
    );
    let app = Arc::new(proxy::App {
        client: proxy::build_client(&cfg),
        sanitiser: sanitiser_from_env(),
        seq: AtomicU64::new(0),
        cfg,
    });
    let svc = proxy::router(app).into_make_service_with_connect_info::<std::net::SocketAddr>();
    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
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
    match replay::run(&PathBuf::from(dir), base, |v| s.json(v, "")).await {
        Ok(r) => {
            println!("{} fixtures, {} skipped, {} differences", r.total, r.skipped, r.differences.len());
            r.differences.iter().for_each(|d| println!("{d}"));
            if r.differences.is_empty() { 0 } else { 1 }
        }
        Err(e) => fail(&e),
    }
}
