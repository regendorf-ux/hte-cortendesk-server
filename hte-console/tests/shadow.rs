//! The proxy end to end: a fake previous console, the shadow in front of it, a client in front of that.

use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{any, post};
use axum::Router;
use hte_console::config::Config;
use hte_console::proxy::{build_client, router, App};
use hte_console::sanitise::Sanitiser;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

async fn fake_upstream() -> String {
    let app = Router::new()
        .route(
            "/api/heartbeat",
            post(|h: HeaderMap, b: Bytes| async move {
                let seen = format!("{}|{}", h.get("x-forwarded-for").and_then(|v| v.to_str().ok()).unwrap_or("-"), b.len());
                (
                    StatusCode::CREATED,
                    [("content-type", "application/json"), ("x-odd", "kept"), ("set-cookie", "s=REALSESSION; Path=/")],
                    format!(r#"{{"sysinfo":1,"seen":"{seen}","note":"device 123456789"}}"#),
                )
            }),
        )
        .route("/slow", any(|| async { tokio::time::sleep(Duration::from_secs(5)).await; "late" }))
        .route("/page", any(|| async { ([("content-type", "text/html")], "<html>jsmith</html>") }));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    format!("http://{addr}")
}

async fn shadow(upstream: String, dir: Option<std::path::PathBuf>, timeout: u64) -> String {
    let cfg = Config {
        upstream,
        listen: String::new(),
        fixtures: dir,
        capture_prefixes: vec!["/api/".into()],
        capture_max_bytes: 4096,
        connect_timeout: Duration::from_secs(1),
        request_timeout: Duration::from_secs(timeout),
        max_body: 1 << 20,
        native: None,
    };
    let app = Arc::new(App {
        client: build_client(&cfg),
        sanitiser: Sanitiser::new(Some("salt"), &[]),
        seq: AtomicU64::new(0),
        cfg,
    });
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let svc = router(app).into_make_service_with_connect_info::<std::net::SocketAddr>();
    tokio::spawn(async move { axum::serve(l, svc).await.unwrap() });
    format!("http://{addr}")
}

#[tokio::test]
async fn answer_is_php_answer_and_fixture_is_clean() {
    let dir = tempfile::tempdir().unwrap();
    let upstream = fake_upstream().await;
    let base = shadow(upstream.clone(), Some(dir.path().to_path_buf()), 5).await;
    let c = reqwest::Client::new();
    let body = r#"{"id":"123456789","uuid":"AAAAAAAAAAAAAAAAAAAAAA=="}"#;
    let direct = c.post(format!("{upstream}/api/heartbeat")).header("x-forwarded-for", "203.0.113.9").header("content-type", "application/json").body(body).send().await.unwrap();
    let via = c.post(format!("{base}/api/heartbeat")).header("x-forwarded-for", "203.0.113.9").header("content-type", "application/json").body(body).send().await.unwrap();
    assert_eq!(direct.status(), via.status());
    assert_eq!(via.headers()["x-odd"], "kept");
    assert_eq!(via.headers()["set-cookie"], "s=REALSESSION; Path=/");
    assert_eq!(direct.text().await.unwrap(), via.text().await.unwrap());

    // a page is forwarded and never recorded
    let page = c.get(format!("{base}/page")).send().await.unwrap();
    assert_eq!(page.text().await.unwrap(), "<html>jsmith</html>");

    tokio::time::sleep(Duration::from_millis(300)).await;
    let files = hte_console::fixture::list(dir.path()).unwrap();
    assert_eq!(files.len(), 1, "{files:?}");
    let text = std::fs::read_to_string(&files[0]).unwrap();
    for real in ["123456789", "203.0.113.9", "REALSESSION", "AAAAAAAAAAAAAAAAAAAAAA=="] {
        assert!(!text.contains(real), "{real} in the fixture: {text}");
    }
    assert!(text.contains("\"status\": 201"));
    let s = Sanitiser::new(Some("salt"), &[]);
    let found = hte_console::fixture::scan(&s, dir.path()).unwrap();
    assert!(found.is_empty(), "{found:?}\n{text}");
}

#[tokio::test]
async fn recording_off_still_forwards_and_upstream_trouble_is_a_502_or_504() {
    let upstream = fake_upstream().await;
    let base = shadow(upstream, None, 1).await;
    let c = reqwest::Client::new();
    let r = c.post(format!("{base}/api/heartbeat")).body("{}").send().await.unwrap();
    assert_eq!(r.status(), 201);
    let slow = c.get(format!("{base}/slow")).send().await.unwrap();
    assert_eq!(slow.status(), 504);
    let down = shadow("http://127.0.0.1:1".into(), None, 1).await;
    assert_eq!(c.get(format!("{down}/x")).send().await.unwrap().status(), 502);
    assert_eq!(c.get(format!("{down}/__hte-console/health")).send().await.unwrap().text().await.unwrap(), "ok");
}

#[tokio::test]
async fn replay_finds_no_difference_against_the_same_answers_and_one_against_changed_ones() {
    let dir = tempfile::tempdir().unwrap();
    let upstream = fake_upstream().await;
    let base = shadow(upstream.clone(), Some(dir.path().to_path_buf()), 5).await;
    let c = reqwest::Client::new();
    c.post(format!("{base}/api/heartbeat")).header("content-type", "application/json").body(r#"{"id":"123456789"}"#).send().await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let s = Sanitiser::new(Some("salt"), &[]);
    let same = hte_console::replay::run(dir.path(), &upstream, &s).await.unwrap();
    assert_eq!((same.total, same.differences.len()), (1, 0), "{:?}", same.differences);

    // an answer that is not the recorded one
    let changed = Router::new().route("/api/heartbeat", post(|| async { ([("content-type", "application/json")], r#"{"sysinfo":2}"#) }));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, changed).await.unwrap() });
    let diff = hte_console::replay::run(dir.path(), &format!("http://{addr}"), &s).await.unwrap();
    assert_eq!(diff.differences.len(), 2, "{:?}", diff.differences); // status 200 vs 201, and the body
}

#[test]
fn sign_in_paths_are_never_recorded() {
    let cfg = Config {
        upstream: String::new(),
        listen: String::new(),
        fixtures: Some(std::path::PathBuf::from("/tmp/x")),
        capture_prefixes: vec!["/".into()],
        capture_max_bytes: 1,
        connect_timeout: Duration::from_secs(1),
        request_timeout: Duration::from_secs(1),
        max_body: 1,
        native: None,
    };
    for p in ["/api/login", "/api/login-options", "/api/logout", "/api/currentUser", "/api/oidc/auth", "/api/oidc/auth-query", "/login/oidc/client-callback", "/login"] {
        assert!(!hte_console::proxy::captured(&cfg, p), "{p}");
    }
    assert!(hte_console::proxy::captured(&cfg, "/api/heartbeat"));
}
