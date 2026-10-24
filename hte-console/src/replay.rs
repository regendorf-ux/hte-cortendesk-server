//! Replay recorded fixtures against a base URL and report differences.
//! Compared: status, content type, body. Ignored: timestamps, database ids, freshly minted tokens.
//! Paced below the console's rate limit per address and device (see `Pace`).
//!
//! Synthetic fixtures (never captured ones) may also use, for phase 2's sign-in flows:
//! - `{{name}}` in the request (query values, JSON body strings, the Authorization header): a value captured from an
//!   earlier answer by `"capture": {"name": "/json/pointer"}`; `{{totp}}` is the current code of
//!   `totp::REPLAY_SECRET` (and is kept as `{{totp_last}}`), `{{totp_wrong}}` six digits that are not;
//! - `"browser": {"authorize": "<var holding an authorize URL>", "mode": "<fake mode>", "profile": "<fake person>",
//!   "keep": "<var>"}` (key names the leftover scan reads as plain):
//!   the URL is fetched from the fake identity provider like a browser would, and the page its redirect points to is
//!   requested from the console under test (the fixture's answer is that page); `{"again": "<var>"}` requests a
//!   saved callback once more;
//! - an expected body `{"kind": "html", "contains": [...]}`: the page must contain each text.

use crate::fixture::{body_value, list, query_string};
use crate::sanitise::Sanitiser;
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::Value;
use std::path::Path;

static ISO_TS: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}").unwrap());
static TOKEN: Lazy<Regex> = Lazy::new(|| Regex::new(r"tok-[0-9a-f]{16}").unwrap());
static ALNUM40: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z0-9]{40}$").unwrap());
static ALNUM48: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z0-9]{48}$").unwrap());
static SECONDS: Lazy<Regex> = Lazy::new(|| Regex::new(r"Try again in \d+ seconds\.").unwrap());
static ATOM_TS: Lazy<Regex> = Lazy::new(|| Regex::new(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00").unwrap());
static TEMPLATE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\{\{([a-z0-9_:.-]{1,40})\}\}").unwrap());

/// An authorize URL as the console builds it, reduced to a marker when every parameter has the right shape (the
/// random ones, state, nonce and the PKCE challenge, cannot be compared between two runs).
pub fn oidc_url_shape(u: &str) -> String {
    let Ok(p) = url::Url::parse(u) else { return "bad oidc url (not a URL)".into() };
    let q: std::collections::HashMap<String, String> = p.query_pairs().into_owned().collect();
    let g = |k: &str| q.get(k).map(String::as_str).unwrap_or("");
    let checks = [
        ("response_type", g("response_type") == "code"),
        ("code_challenge_method", g("code_challenge_method") == "S256"),
        ("code_challenge", g("code_challenge").len() == 43 && g("code_challenge").bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')),
        ("state", ALNUM40.is_match(g("state"))),
        ("nonce", ALNUM40.is_match(g("nonce"))),
        ("client_id", !g("client_id").is_empty()),
        ("scope", g("scope").split(' ').any(|x| x == "openid")),
        ("redirect_uri", g("redirect_uri").ends_with("/login/oidc/client-callback")),
    ];
    let bad: Vec<&str> = checks.iter().filter(|(_, ok)| !ok).map(|(k, _)| *k).collect();
    if bad.is_empty() { "{{oidc-url}}".into() } else { format!("bad oidc url ({})", bad.join(", ")) }
}

/// Make a value comparable: timestamps, database ids and token placeholders become fixed markers.
pub fn normalise(v: &mut Value, key: &str) {
    match v {
        Value::Object(m) => {
            let keys: Vec<String> = m.keys().cloned().collect();
            for k in keys {
                if let Some(x) = m.get_mut(&k) {
                    normalise(x, &k);
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(|x| normalise(x, key)),
        Value::String(s) => {
            if key == "error" && (SECONDS.is_match(s) || ATOM_TS.is_match(s)) {
                let t = SECONDS.replace_all(s, "Try again in {{n}} seconds.").into_owned();
                *s = ATOM_TS.replace_all(&t, "{{ts}}").into_owned();
            } else if ISO_TS.is_match(s) || key.ends_with("_at") || key == "time" || key == "timestamp" {
                *v = Value::String("<ts>".into());
            } else if TOKEN.is_match(s) {
                *s = TOKEN.replace_all(s, "<tok>").into_owned();
            }
        }
        Value::Number(n) => {
            let k = key.to_ascii_lowercase();
            if k.ends_with("_at") || k == "time" || k == "timestamp" || k == "modified_at" {
                *v = Value::String("<ts>".into());
            } else if (k == "id" || k.ends_with("_id")) && n.as_u64().map_or(false, |u| u < 100_000_000) {
                *v = Value::String("<id>".into());
            }
        }
        _ => {}
    }
}

/// Before the live answer is sanitised: what sign-in mints at random becomes a marker when it has the right shape
/// (a 48-character token, a 40-character secret or code), and an authorize URL its shape check.
pub fn mark_random(v: &mut Value, key: &str) {
    match v {
        Value::Object(m) => {
            for (k, x) in m.iter_mut() {
                mark_random(x, k);
            }
        }
        Value::Array(a) => a.iter_mut().for_each(|x| mark_random(x, key)),
        Value::String(s) => {
            if (key == "access_token" && ALNUM48.is_match(s)) || ((key == "secret" || key == "code") && ALNUM40.is_match(s)) {
                *v = Value::String("{{random}}".into());
            } else if key == "url" && s.starts_with("http") {
                *v = Value::String(oidc_url_shape(s));
            }
        }
        _ => {}
    }
}

fn body_json(b: &Value) -> Value {
    let mut v = match b["kind"].as_str() {
        Some("json") => b["value"].clone(),
        Some("form") => b["fields"].clone(),
        Some("text") => b["text"].clone(),
        other => Value::String(format!("<{}>", other.unwrap_or("none"))),
    };
    normalise(&mut v, "");
    v
}

fn request_body(b: &Value) -> Option<(String, Vec<u8>)> {
    match b["kind"].as_str() {
        Some("json") => Some(("application/json".into(), serde_json::to_vec(&b["value"]).ok()?)),
        Some("form") => Some(("application/x-www-form-urlencoded".into(), query_string(&b["fields"]).into_bytes())),
        // synthetic fixtures only: a body as given, to test what malformed input gets (never recorded by capture)
        Some("raw") => Some((b["content_type"].as_str()?.to_string(), b["text"].as_str()?.as_bytes().to_vec())),
        _ => None,
    }
}

/// Recorded traffic is hours of heartbeats; replayed in one burst it would trip the console's own `device-sync`
/// limit (120 a minute per address and device) on both sides and compare 429s. So the replay sends at most
/// `HTE_CONSOLE_REPLAY_PER_MINUTE` (default 110) requests a minute per address and device id, waiting when needed.
struct Pace {
    per_minute: usize,
    window: std::time::Duration,
    sent: std::collections::HashMap<String, std::collections::VecDeque<std::time::Instant>>,
}

impl Pace {
    fn from_env() -> Pace {
        let per_minute = std::env::var("HTE_CONSOLE_REPLAY_PER_MINUTE").ok().and_then(|v| v.trim().parse().ok()).filter(|&n| n > 0).unwrap_or(110);
        Pace::new(per_minute, std::time::Duration::from_secs(61))
    }

    fn new(per_minute: usize, window: std::time::Duration) -> Pace {
        Pace { per_minute, window, sent: Default::default() }
    }

    /// The limiter's key as PHP builds it: the client address (the fixture's X-Forwarded-For) and the device id.
    fn key(fx: &Value) -> String {
        let xff = fx["request"]["headers"]["x-forwarded-for"].as_str().unwrap_or("");
        let id = |v: &Value| match v {
            Value::String(s) => s.clone(),
            Value::Null => String::new(),
            other => other.to_string(),
        };
        let body_id = &fx["request"]["body"]["value"]["id"];
        let id = if body_id.is_null() { id(&fx["query"]["id"]) } else { id(body_id) };
        format!("{xff}|{id}")
    }

    async fn wait(&mut self, fx: &Value) {
        let (per_minute, window) = (self.per_minute, self.window);
        let q = self.sent.entry(Self::key(fx)).or_default();
        while q.front().map_or(false, |t| t.elapsed() >= window) {
            q.pop_front();
        }
        if q.len() >= per_minute {
            if let Some(oldest) = q.front() {
                let left = window.saturating_sub(oldest.elapsed());
                tokio::time::sleep(left).await;
            }
            q.pop_front();
        }
        q.push_back(std::time::Instant::now());
    }
}

/// Fill `{{name}}` from the captured values (and `{{totp}}`); unknown names stay as they are.
fn fill(t: &str, vars: &mut std::collections::HashMap<String, String>, now: i64) -> String {
    TEMPLATE
        .replace_all(t, |c: &regex::Captures| {
            let name = &c[1];
            let key = crate::totp::base32_decode(crate::totp::REPLAY_SECRET.as_bytes()).unwrap_or_default();
            let step = now.div_euclid(crate::totp::PERIOD);
            if name == "totp" {
                let code = crate::totp::at(&key, step);
                vars.insert("totp_last".into(), code.clone());
                return code;
            }
            if name == "totp_wrong" {
                // six digits that are no code of the window around now
                let window: Vec<String> = (-1..=1).map(|o| crate::totp::at(&key, step + o)).collect();
                return (0..10u32).map(|d| d.to_string().repeat(6)).find(|c| !window.contains(c)).unwrap_or_default();
            }
            vars.get(name).cloned().unwrap_or_else(|| c[0].to_string())
        })
        .into_owned()
}

fn fill_json(v: &Value, vars: &mut std::collections::HashMap<String, String>, now: i64) -> Value {
    match v {
        Value::String(s) => Value::String(fill(s, vars, now)),
        Value::Array(a) => Value::Array(a.iter().map(|x| fill_json(x, vars, now)).collect()),
        Value::Object(m) => Value::Object(m.iter().map(|(k, x)| (k.clone(), fill_json(x, vars, now))).collect()),
        other => other.clone(),
    }
}

pub struct Report {
    pub total: usize,
    pub skipped: usize,
    pub differences: Vec<String>,
}

pub async fn run(dir: &Path, base: &str, s: &Sanitiser) -> Result<Report, String> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;
    let mut report = Report { total: 0, skipped: 0, differences: vec![] };
    let mut pace = Pace::from_env();
    let mut vars: std::collections::HashMap<String, String> = Default::default();
    for p in list(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        let fx: Value = serde_json::from_slice(&std::fs::read(&p).map_err(|e| e.to_string())?).map_err(|e| format!("{name}: {e}"))?;
        report.total += 1;
        let now = chrono::Utc::now().timestamp();
        let (method, mut path) = (fx["method"].as_str().unwrap_or("GET"), fx["path"].as_str().unwrap_or("/").to_string());
        let mut q = query_string(&fill_json(&fx["query"], &mut vars, now));
        if let Some(b) = fx.get("browser").filter(|b| b.is_object()) {
            match browser(&client, b, &mut vars).await {
                Ok(pq) => match pq.split_once('?') {
                    Some((pa, qu)) => {
                        path = pa.to_string();
                        q = qu.to_string();
                    }
                    None => {
                        path = pq;
                        q = String::new();
                    }
                },
                Err(e) => {
                    report.differences.push(format!("{name}: browser step: {e}"));
                    continue;
                }
            }
        }
        let url = format!("{}{}{}{}", base.trim_end_matches('/'), path, if q.is_empty() { "" } else { "?" }, q);
        let mut rq = client.request(method.parse().map_err(|_| format!("{name}: bad method"))?, url);
        let h = &fx["request"]["headers"];
        for k in ["accept", "user-agent", "authorization", "x-requested-with", "x-forwarded-for"] {
            if let Some(v) = h[k].as_str() {
                rq = rq.header(k, fill(v, &mut vars, now));
            }
        }
        let req_body = fill_json(&fx["request"]["body"], &mut vars, now);
        if let Some((ct, body)) = request_body(&req_body) {
            rq = rq.header("content-type", ct).body(body);
        } else if fx["request"]["body"]["kind"] == "omitted" {
            report.skipped += 1;
            continue;
        }
        pace.wait(&fx).await;
        let resp = match rq.send().await {
            Ok(r) => r,
            Err(e) => {
                report.differences.push(format!("{name}: request failed: {e}"));
                continue;
            }
        };
        let status = resp.status().as_u16();
        let ct = resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
        let marked = match serde_json::from_slice::<Value>(&bytes) {
            Ok(mut v) if ct.contains("json") => {
                mark_random(&mut v, "");
                serde_json::to_vec(&v).unwrap_or_else(|_| bytes.to_vec())
            }
            _ => bytes.to_vec(),
        };
        let got_body = body_value(s, &ct.to_ascii_lowercase(), &marked);
        let want = &fx["response"];
        if want["status"].as_u64() != Some(status as u64) {
            report.differences.push(format!("{name}: status {} expected {}", status, want["status"]));
        }
        let want_ct = want["headers"]["content-type"].as_str().unwrap_or("");
        if !want_ct.is_empty() && want_ct.split(';').next() != ct.split(';').next() {
            report.differences.push(format!("{name}: content-type {ct:?} expected {want_ct:?}"));
        }
        if want["body"]["kind"] == "html" {
            let text = String::from_utf8_lossy(&bytes);
            for c in want["body"]["contains"].as_array().into_iter().flatten().filter_map(Value::as_str) {
                if !text.contains(c) {
                    report.differences.push(format!("{name}: page does not contain {c:?}"));
                }
            }
        } else {
            let (a, b) = (body_json(want.get("body").unwrap_or(&Value::Null)), body_json(&got_body));
            if want["body"]["kind"] != "omitted" && a != b {
                report.differences.push(format!("{name}: body differs\n  expected {a}\n  got      {b}"));
            }
        }
        if let Some(caps) = fx["capture"].as_object() {
            let parsed: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
            for (var, ptr) in caps {
                match parsed.pointer(ptr.as_str().unwrap_or("")).and_then(Value::as_str) {
                    Some(v) => {
                        vars.insert(var.clone(), v.to_string());
                    }
                    None => report.differences.push(format!("{name}: nothing to capture at {ptr} for {{{{{var}}}}}")),
                }
            }
        }
    }
    Ok(report)
}

/// The browser half of an OIDC sign-in: fetch the authorize URL from the (fake) provider, return the path and
/// query its redirect points to on the console.
async fn browser(client: &reqwest::Client, b: &Value, vars: &mut std::collections::HashMap<String, String>) -> Result<String, String> {
    if let Some(again) = b["again"].as_str() {
        return vars.get(again).cloned().ok_or_else(|| format!("no saved callback {again}"));
    }
    let from = b["authorize"].as_str().ok_or("browser step without authorize")?;
    let authorize = vars.get(from).cloned().ok_or_else(|| format!("no captured {from}"))?;
    let extra = crate::laravel::http_build_query(&[
        ("hte_fake", b["mode"].as_str().unwrap_or("ok").as_bytes()),
        ("hte_user", b["profile"].as_str().unwrap_or("anna").as_bytes()),
    ]);
    let u = format!("{authorize}{}{extra}", if authorize.contains('?') { '&' } else { '?' });
    let r = client.get(&u).send().await.map_err(|e| format!("authorize: {e}"))?;
    if r.status().as_u16() != 302 {
        return Err(format!("authorize answered {}", r.status().as_u16()));
    }
    let loc = r.headers().get("location").and_then(|v| v.to_str().ok()).ok_or("authorize: no Location")?;
    let parsed = url::Url::parse(loc).map_err(|e| format!("authorize: {e}"))?;
    let pq = format!("{}{}", parsed.path(), parsed.query().map(|q| format!("?{q}")).unwrap_or_default());
    if let Some(save) = b["keep"].as_str() {
        vars.insert(save.to_string(), pq.clone());
    }
    Ok(pq)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn pace_waits_per_address_and_device_only() {
        let mut p = Pace::new(2, std::time::Duration::from_millis(300));
        let a = json!({"request": {"headers": {"x-forwarded-for": "198.18.0.1"}, "body": {"value": {"id": "990000001"}}}});
        let b = json!({"request": {"headers": {"x-forwarded-for": "198.18.0.1"}, "body": {"value": {"id": "990000002"}}}});
        let t = std::time::Instant::now();
        p.wait(&a).await;
        p.wait(&a).await;
        p.wait(&b).await;
        assert!(t.elapsed() < std::time::Duration::from_millis(100), "under the limit nothing waits");
        p.wait(&a).await;
        assert!(t.elapsed() >= std::time::Duration::from_millis(290), "the third request of one key waits for the window");
    }

    #[test]
    fn normalise_ignores_timestamps_ids_and_tokens_only() {
        let mut a = json!({"id": 7, "created_at": "2026-10-24T10:00:00Z", "access_token": "tok-0123456789abcdef", "peer": "992345678", "n": 3});
        let mut b = json!({"id": 9, "created_at": "2026-10-25T11:00:00Z", "access_token": "tok-fedcba9876543210", "peer": "992345678", "n": 3});
        normalise(&mut a, "");
        normalise(&mut b, "");
        assert_eq!(a, b);
        let mut c = json!({"id": 7, "peer": "992345679", "n": 3});
        normalise(&mut c, "");
        assert_ne!(a["peer"], c["peer"]);
        let mut d = json!({"n": 4});
        let mut e = json!({"n": 3});
        normalise(&mut d, "");
        normalise(&mut e, "");
        assert_ne!(d, e);
    }
}
