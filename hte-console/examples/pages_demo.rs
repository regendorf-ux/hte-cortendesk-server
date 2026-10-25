//! A throwaway console on synthetic data, for looking at the pages (the screenshot harness): the schema of a live
//! database, `hte-console page-seed`'s people, devices and log rows, the pages' routes, and `/__demo/login/<user>`
//! (hteadmin, dana or erin), which signs the browser in by setting the session cookie. Nothing here is real data and
//! nothing leaves the machine.
//!
//!   cargo run -p hte-console --example pages_demo -- 8089
//!   open http://127.0.0.1:8089/__demo/login/hteadmin

use axum::extract::Path;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use hte_console::api::{Limiter, Native, Nonces};
use hte_console::laravel::{self, Encrypter};
use hte_console::oidc::Oidc;
use hte_console::pages::{self, session};
use std::sync::{Arc, Mutex};

const APP_KEY: &str = "base64:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

#[tokio::main]
async fn main() {
    sodiumoxide::init().unwrap();
    std::env::set_var("BCRYPT_ROUNDS", "4");
    let port: u16 = std::env::args().nth(1).and_then(|p| p.parse().ok()).unwrap_or(8089);
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("cortendesk.sqlite");
    let now = chrono::Utc::now().timestamp();
    {
        let c = rusqlite::Connection::open(&db).unwrap();
        c.execute_batch(include_str!("../tests/schema_live.sql")).unwrap();
        c.execute_batch(&hte_console::pagereplay::seed_sql(now).unwrap()).unwrap();
    }
    let native = Arc::new(Native {
        db: Mutex::new(hte_console::sqlite::open(&db, std::time::Duration::from_secs(5), true).unwrap()),
        crypt: Encrypter::from_app_key(APP_KEY).unwrap(),
        hbbs_db: dir.path().join("none.sqlite3"),
        trusted: laravel::parse_trusted(laravel::DEFAULT_TRUSTED),
        api_version: env!("CARGO_PKG_VERSION").into(),
        max_body: 1 << 20,
        limiter: Mutex::new(Limiter::default()),
        nonces: Mutex::new(Nonces::default()),
        signin: hte_console::signin::State::new(Oidc::new(true, false), None, "HTE Remote".into()),
        clock: Box::new(|| chrono::Utc::now().timestamp()),
    });
    let crypt = Encrypter::from_app_key(APP_KEY).unwrap();
    let cfg = session::SessionConfig::from_env("HTE Remote");
    let login = move |Path(user): Path<String>| {
        let (crypt, cfg) = (crypt.clone(), cfg.clone());
        async move {
            let id = {
                let mut s = user.repeat(40 / user.len().max(1) + 1);
                s.truncate(40);
                s
            };
            let cookie = session::set_cookie(&cfg, &crypt, &id, false, chrono::Utc::now().timestamp());
            let r: Response = (StatusCode::FOUND, [(header::LOCATION, "/logs/alarms".to_string()), (header::SET_COOKIE, cookie)]).into_response();
            r
        }
    };
    let app = pages::routes(native, None).unwrap().route("/__demo/login/:user", get(login));
    let l = tokio::net::TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    eprintln!("pages demo on http://127.0.0.1:{port}/__demo/login/hteadmin (also dana, erin); Ctrl-C to stop");
    axum::serve(l, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await.unwrap();
}
