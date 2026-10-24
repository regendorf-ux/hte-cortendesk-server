//! Shadow mode: forward every request to the PHP console, return its answer unchanged, record a sanitised
//! fixture of the pair on the side. Nothing here computes an answer.

use crate::config::Config;
use crate::fixture::{self, RawPair};
use crate::sanitise::Sanitiser;
use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode};
use axum::Router;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub struct App {
    pub cfg: Config,
    pub client: reqwest::Client,
    pub sanitiser: Sanitiser,
    pub seq: AtomicU64,
}

const HOP_BY_HOP: &[&str] =
    &["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"];

pub fn router(app: Arc<App>) -> Router {
    Router::new().fallback(handle).with_state(app)
}

pub fn build_client(cfg: &Config) -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(cfg.connect_timeout)
        .timeout(cfg.request_timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("http client")
}

fn plain(status: StatusCode, text: &'static str) -> Response<Body> {
    Response::builder().status(status).header(header::CONTENT_TYPE, "text/plain").body(Body::from(text)).unwrap()
}

/// Sign-in traffic carries passwords, codes and tokens: it is never recorded, whatever the capture prefixes say
/// (phase 2 answers these paths itself; this holds when they are forwarded too, e.g. after a rollback).
pub const NEVER_RECORDED: &[&str] = &["/api/login", "/api/logout", "/api/currentUser", "/api/oidc/", "/login"];

pub fn captured(cfg: &Config, path: &str) -> bool {
    cfg.fixtures.is_some()
        && cfg.capture_prefixes.iter().any(|p| path.starts_with(p.as_str()))
        && !NEVER_RECORDED.iter().any(|p| path.starts_with(p))
}

fn pairs(h: &HeaderMap) -> Vec<(String, String)> {
    h.iter().map(|(k, v)| (k.as_str().to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned())).collect()
}

async fn handle(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request<Body>,
) -> Response<Body> {
    let (parts, body) = req.into_parts();
    let path = parts.uri.path().to_string();
    if path == "/__hte-console/health" {
        return plain(StatusCode::OK, "ok");
    }
    let body = match axum::body::to_bytes(body, app.cfg.max_body).await {
        Ok(b) => b,
        Err(_) => return plain(StatusCode::PAYLOAD_TOO_LARGE, "request too large"),
    };
    let pq = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let url = format!("{}{}", app.cfg.upstream, pq);
    let mut out = app.client.request(parts.method.clone(), url);
    for (k, v) in parts.headers.iter() {
        if HOP_BY_HOP.contains(&k.as_str()) || k == header::CONTENT_LENGTH {
            continue;
        }
        out = out.header(k, v);
    }
    // Same view of the client as today: pass Caddy's headers through; add the peer only when nobody did.
    if !parts.headers.contains_key("x-forwarded-for") {
        out = out.header("x-forwarded-for", peer.ip().to_string());
    }
    let sent = out.body(body.clone()).send().await;
    let resp = match sent {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("upstream: {}", if e.is_timeout() { "timeout" } else if e.is_connect() { "connect failed" } else { "error" });
            return plain(
                if e.is_timeout() { StatusCode::GATEWAY_TIMEOUT } else { StatusCode::BAD_GATEWAY },
                "upstream unavailable",
            );
        }
    };
    let status = resp.status();
    let resp_headers = resp.headers().clone();
    let record = captured(&app.cfg, &path)
        && body.len() <= app.cfg.capture_max_bytes
        && resp.content_length().map_or(true, |n| n as usize <= app.cfg.capture_max_bytes);

    let mut builder = Response::builder().status(status);
    for (k, v) in resp_headers.iter() {
        if HOP_BY_HOP.contains(&k.as_str()) || k == header::CONTENT_LENGTH {
            continue;
        }
        builder = builder.header(HeaderName::from(k.clone()), HeaderValue::from(v.clone()));
    }
    if !record {
        return builder.body(Body::from_stream(resp.bytes_stream())).unwrap();
    }
    let bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(_) => return plain(StatusCode::BAD_GATEWAY, "upstream unavailable"),
    };
    let mut raw_req_headers = pairs(&parts.headers);
    if !parts.headers.contains_key("x-forwarded-for") {
        raw_req_headers.push(("x-forwarded-for".into(), peer.ip().to_string())); // what PHP was told
    }
    let raw_resp_headers = pairs(&resp_headers);
    let (method, query) = (parts.method.to_string(), parts.uri.query().map(str::to_string));
    let (req_body, resp_body, code) = (body, bytes.clone(), status.as_u16());
    let a = app.clone();
    tokio::task::spawn_blocking(move || {
        let seq = a.seq.fetch_add(1, Ordering::Relaxed);
        let pair = RawPair {
            method: &method,
            path: &path,
            query: query.as_deref(),
            request_headers: raw_req_headers,
            request_body: &req_body,
            status: code,
            response_headers: raw_resp_headers,
            response_body: &resp_body,
        };
        let v = fixture::build(&a.sanitiser, seq, &pair);
        let millis = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
        if let Some(dir) = &a.cfg.fixtures {
            if let Err(e) = fixture::write(dir, &v, millis) {
                tracing::warn!("fixture not written: {e}");
            }
        }
    });
    builder.body(Body::from(bytes)).unwrap()
}
