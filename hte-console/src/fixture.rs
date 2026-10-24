//! A fixture: one request/response pair, already sanitised. This is the only thing written to disk.

use crate::sanitise::Sanitiser;
use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};

/// Request headers worth keeping. Everything else is dropped, never sanitised-and-kept.
const REQUEST_HEADERS: &[&str] = &[
    "content-type", "accept", "user-agent", "authorization", "x-requested-with", "x-forwarded-proto", "x-forwarded-for",
    "origin", "referer", "host", "x-csrf-token", "x-xsrf-token",
];
const RESPONSE_HEADERS: &[&str] = &[
    "content-type", "cache-control", "location", "retry-after", "x-ratelimit-limit", "x-ratelimit-remaining",
    "access-control-allow-origin", "access-control-allow-methods", "access-control-allow-headers", "www-authenticate",
];

pub struct RawPair<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: Option<&'a str>,
    pub request_headers: Vec<(String, String)>,
    pub request_body: &'a [u8],
    pub status: u16,
    pub response_headers: Vec<(String, String)>,
    pub response_body: &'a [u8],
}

pub fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() && s.is_char_boundary(i + 1) && s.is_char_boundary(i + 3) => {
                if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(v);
                    i += 2;
                } else {
                    out.push(b'%');
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn percent_encode(s: &str) -> String {
    let mut out = String::new();
    for c in s.bytes() {
        if c.is_ascii_alphanumeric() || b"-_.~".contains(&c) {
            out.push(c as char);
        } else {
            out.push_str(&format!("%{c:02X}"));
        }
    }
    out
}

pub fn parse_pairs(s: &str) -> Vec<(String, String)> {
    s.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (percent_decode(k), percent_decode(v)),
            None => (percent_decode(p), String::new()),
        })
        .collect()
}

fn header<'a>(h: &'a [(String, String)], name: &str) -> Option<&'a str> {
    h.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

fn learn_body(s: &Sanitiser, content_type: &str, body: &[u8]) {
    if let Some(v) = parse_json(content_type, body) {
        s.learn_json(&v, "");
    } else if content_type.contains("x-www-form-urlencoded") {
        if let Ok(t) = std::str::from_utf8(body) {
            s.learn_pairs(&parse_pairs(t));
        }
    }
}

fn parse_json(content_type: &str, body: &[u8]) -> Option<Value> {
    let looks_json = content_type.contains("json") || content_type.is_empty() || content_type.starts_with("text/plain");
    if !looks_json || body.is_empty() {
        return None;
    }
    serde_json::from_slice(body).ok()
}

fn body_value(s: &Sanitiser, content_type: &str, body: &[u8]) -> Value {
    if body.is_empty() {
        return json!({"kind": "empty"});
    }
    if let Some(mut v) = parse_json(content_type, body) {
        s.json(&mut v, "");
        return json!({"kind": "json", "value": v});
    }
    if content_type.contains("x-www-form-urlencoded") {
        if let Ok(t) = std::str::from_utf8(body) {
            return json!({"kind": "form", "fields": s.pairs(&parse_pairs(t))});
        }
    }
    // Pages and other text are never recorded (they carry names, tokens and sessions in forms we do not parse).
    json!({"kind": "omitted", "len": body.len()})
}

fn headers_value(s: &Sanitiser, allow: &[&str], h: &[(String, String)]) -> Value {
    let mut m = Map::new();
    for (k, v) in h {
        let k = k.to_ascii_lowercase();
        if !allow.contains(&k.as_str()) {
            continue;
        }
        let nv = match k.as_str() {
            "host" => s.host(v),
            "authorization" | "x-csrf-token" | "x-xsrf-token" | "www-authenticate" => s.scalar("authorization", v),
            "location" | "origin" | "referer" => s.scrub_str(v),
            _ => s.scalar(&k, v),
        };
        m.insert(k, Value::String(nv));
    }
    Value::Object(m)
}

fn cookie_pairs(h: &[(String, String)], request: bool) -> Vec<(String, String)> {
    let mut out = vec![];
    for (k, v) in h {
        if request && k.eq_ignore_ascii_case("cookie") {
            for part in v.split(';') {
                if let Some((n, val)) = part.trim().split_once('=') {
                    out.push((n.to_string(), val.to_string()));
                }
            }
        } else if !request && k.eq_ignore_ascii_case("set-cookie") {
            if let Some((n, val)) = v.split(';').next().and_then(|p| p.split_once('=')) {
                out.push((n.trim().to_string(), val.to_string()));
            }
        }
    }
    out
}

/// Sanitise a pair into a fixture value. Learns the pair's identities first.
pub fn build(s: &Sanitiser, seq: u64, p: &RawPair) -> Value {
    let req_ct = header(&p.request_headers, "content-type").unwrap_or("").to_ascii_lowercase();
    let resp_ct = header(&p.response_headers, "content-type").unwrap_or("").to_ascii_lowercase();
    let query_pairs = p.query.map(parse_pairs).unwrap_or_default();
    s.learn_pairs(&query_pairs);
    learn_body(s, &req_ct, p.request_body);
    learn_body(s, &resp_ct, p.response_body);
    json!({
        "format": 1,
        "seq": seq,
        "method": p.method,
        "path": s.path(p.path),
        "query": s.pairs(&query_pairs),
        "request": {
            "headers": headers_value(s, REQUEST_HEADERS, &p.request_headers),
            "cookies": s.cookies(&cookie_pairs(&p.request_headers, true)),
            "body": body_value(s, &req_ct, p.request_body),
        },
        "response": {
            "status": p.status,
            "headers": headers_value(s, RESPONSE_HEADERS, &p.response_headers),
            "cookies": s.cookies(&cookie_pairs(&p.response_headers, false)),
            "body": body_value(s, &resp_ct, p.response_body),
        },
    })
}

pub fn file_name(v: &Value, millis: u128) -> String {
    let seq = v["seq"].as_u64().unwrap_or(0);
    let method = v["method"].as_str().unwrap_or("X").to_ascii_lowercase();
    let slug: String = v["path"]
        .as_str()
        .unwrap_or("")
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect::<String>()
        .trim_matches('_')
        .chars()
        .take(60)
        .collect();
    format!("{millis:013}-{seq:06}-{method}-{slug}.json")
}

pub fn write(dir: &Path, v: &Value, millis: u128) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(file_name(v, millis));
    let tmp = dir.join(format!(".{}.tmp", path.file_name().unwrap().to_string_lossy()));
    std::fs::write(&tmp, serde_json::to_vec_pretty(v).unwrap())?;
    std::fs::rename(&tmp, &path)?;
    Ok(path)
}

pub fn list(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().map_or(false, |x| x == "json"))
        .collect();
    v.sort();
    Ok(v)
}

/// Scan every fixture in `dir` for anything real. Returns `(file, problem)` pairs; empty = clean.
pub fn scan(s: &Sanitiser, dir: &Path) -> std::io::Result<Vec<(String, String)>> {
    let mut out = vec![];
    for p in list(dir)? {
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        let text = std::fs::read_to_string(&p)?;
        match serde_json::from_str::<Value>(&text) {
            Ok(v) => {
                for d in s.leftovers(&v) {
                    out.push((name.clone(), d));
                }
                for lit in s.literals() {
                    if text.to_ascii_lowercase().contains(&lit.to_ascii_lowercase()) {
                        out.push((name.clone(), "contains a configured literal".into()));
                    }
                }
            }
            Err(e) => out.push((name, format!("not JSON: {e}"))),
        }
    }
    Ok(out)
}

/// The query string of a fixture, re-encoded for a request.
pub fn query_string(v: &Value) -> String {
    let mut parts = vec![];
    if let Some(m) = v.as_object() {
        for (k, x) in m {
            let vals: Vec<&Value> = match x {
                Value::Array(a) => a.iter().collect(),
                other => vec![other],
            };
            for val in vals {
                parts.push(format!("{}={}", percent_encode(k), percent_encode(val.as_str().unwrap_or(""))));
            }
        }
    }
    parts.join("&")
}
