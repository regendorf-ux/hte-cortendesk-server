//! Replay recorded fixtures against a base URL and report differences.
//! Compared: status, content type, body. Ignored: timestamps, database ids, freshly minted tokens.

use crate::fixture::{list, query_string};
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::Value;
use std::path::Path;

static ISO_TS: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}").unwrap());
static TOKEN: Lazy<Regex> = Lazy::new(|| Regex::new(r"tok-[0-9a-f]{16}").unwrap());

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
            if ISO_TS.is_match(s) || key.ends_with("_at") || key == "time" || key == "timestamp" {
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
        _ => None,
    }
}

pub struct Report {
    pub total: usize,
    pub skipped: usize,
    pub differences: Vec<String>,
}

pub async fn run(dir: &Path, base: &str, sanitise: impl Fn(&mut Value)) -> Result<Report, String> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;
    let mut report = Report { total: 0, skipped: 0, differences: vec![] };
    for p in list(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        let fx: Value = serde_json::from_slice(&std::fs::read(&p).map_err(|e| e.to_string())?).map_err(|e| format!("{name}: {e}"))?;
        report.total += 1;
        let (method, path) = (fx["method"].as_str().unwrap_or("GET"), fx["path"].as_str().unwrap_or("/"));
        let q = query_string(&fx["query"]);
        let url = format!("{}{}{}{}", base.trim_end_matches('/'), path, if q.is_empty() { "" } else { "?" }, q);
        let mut rq = client.request(method.parse().map_err(|_| format!("{name}: bad method"))?, url);
        let h = &fx["request"]["headers"];
        for k in ["accept", "user-agent", "authorization", "x-requested-with", "x-forwarded-for"] {
            if let Some(v) = h[k].as_str() {
                rq = rq.header(k, v);
            }
        }
        if let Some((ct, body)) = request_body(&fx["request"]["body"]) {
            rq = rq.header("content-type", ct).body(body);
        } else if fx["request"]["body"]["kind"] == "omitted" {
            report.skipped += 1;
            continue;
        }
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
        let got_body = match serde_json::from_slice::<Value>(&bytes) {
            Ok(mut v) => {
                sanitise(&mut v);
                serde_json::json!({"kind": "json", "value": v})
            }
            Err(_) => serde_json::json!({"kind": "omitted", "len": bytes.len()}),
        };
        let want = &fx["response"];
        if want["status"].as_u64() != Some(status as u64) {
            report.differences.push(format!("{name}: status {} expected {}", status, want["status"]));
        }
        let want_ct = want["headers"]["content-type"].as_str().unwrap_or("");
        if want_ct.split(';').next() != ct.split(';').next() {
            report.differences.push(format!("{name}: content-type {ct:?} expected {want_ct:?}"));
        }
        let (a, b) = (body_json(want.get("body").unwrap_or(&Value::Null)), body_json(&got_body));
        if want["body"]["kind"] != "omitted" && a != b {
            report.differences.push(format!("{name}: body differs\n  expected {a}\n  got      {b}"));
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
