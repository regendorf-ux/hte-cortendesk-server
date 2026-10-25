//! `hte-console page-seed <now>` and `hte-console page-replay <php-url> <rust-url> <now>`: the console's pages
//! (phase 7) asked of the PHP console and of hte-console, each in a throwaway container on its own copy of the same
//! synthetic database, and compared.
//!
//! `page-seed` prints the SQL that makes the people, devices, log rows and sessions both sides start from. Rows are
//! timed from `<now>` in the middle of a unit ("5 minutes 30 seconds ago"), so the seconds that pass between the PHP
//! answer and the hte-console answer to the same request cannot move a relative time across a boundary. The sessions
//! are the Laravel `database` driver's rows; the cookies are minted here with the throwaway database's app key
//! (`HTE_CONSOLE_APP_KEY_FILE`) and the cookie name PHP derives (`HTE_CONSOLE_SESSION_COOKIE`).
//!
//! `page-replay` asks each page of both, one after the other, and compares what a person reads: the status and the
//! redirect, and for an HTML page the visible text and the sequence of `class` attributes (Livewire's own wire:*
//! attributes, scripts and the markup that carries no class are not part of what the page looks like); a CSV exactly.
//! Then it makes the same writes on both (hte-console through its forms, PHP through the Livewire protocol, which is
//! what its page speaks) and the caller compares the two databases with `hte-console snapshot`.

use crate::laravel::{self, Encrypter};
use crate::pages::session;
use once_cell::sync::Lazy;
use regex::Regex;

/// The session token every seeded session carries (the CSRF token the forms send back).
pub const TOKEN: &str = "REPLAYtokenREPLAYtokenREPLAYtokenREPLAYtk";
const PASSWORD: &str = "oldpass123";

fn sid(tag: &str) -> String {
    let mut s = tag.repeat(40 / tag.len() + 1);
    s.truncate(40);
    s
}

const USERS: [(i64, &str, &str, &str, bool, Option<i64>); 3] = [
    (1, "hteadmin", "HTE Admin", "admin@example.test", true, None),
    (2, "dana", "", "dana@example.test", false, None),
    (3, "erin", "Erin", "erin@example.test", false, Some(1)),
];

fn q(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// The seed: replaces the throwaway database's people (the first-start administrator included).
pub fn seed_sql(now: i64) -> Result<String, String> {
    let hash = laravel::hash_make(PASSWORD.as_bytes()).map_err(|_| "cannot hash".to_string())?;
    let t = |ago: i64| q(&laravel::ts(now - ago));
    let mut s = String::from("PRAGMA foreign_keys = OFF;\nDELETE FROM users; DELETE FROM sessions; DELETE FROM roles; DELETE FROM devices; DELETE FROM device_groups; DELETE FROM user_groups; DELETE FROM strategies; DELETE FROM address_books; DELETE FROM tags; DELETE FROM address_book_entries;\nDELETE FROM alarm_logs; DELETE FROM audit_connections; DELETE FROM audit_file_transfers; DELETE FROM login_logs; DELETE FROM console_audits; DELETE FROM trusted_devices;\n");
    s.push_str("INSERT INTO roles (id, name, permissions, require_two_factor, created_at, updated_at) VALUES (1, 'Auditor', '{\"audit\":\"rw\"}', 0, '2025-01-01 00:00:00', '2025-01-01 00:00:00');\n");
    s.push_str("INSERT INTO device_groups (id, name, created_at, updated_at) VALUES (1, 'Front desk', '2025-01-01 00:00:00', '2025-01-01 00:00:00');\n");
    // 7c, Fleet diagnostics: an ID and a relay server that refuse at once on both sides (nothing listens on port 9 in either
    // container), so both probes run and fail the same way
    s.push_str("DELETE FROM settings WHERE key IN ('id_server', 'relay_server');\nINSERT INTO settings (key, value, created_at, updated_at) VALUES ('id_server', '127.0.0.1:9', '2025-01-01 00:00:00', '2025-01-01 00:00:00'), ('relay_server', 'localhost:9', '2025-01-01 00:00:00', '2025-01-01 00:00:00');\n");
    for (id, rd, owner) in [(1, "1001", "2"), (2, "1002", "null"), (3, "1003", "2")] {
        s.push_str(&format!("INSERT INTO devices (id, rustdesk_id, uuid, user_id, status, created_at, updated_at) VALUES ({id}, '{rd}', 'uuid-{id}', {owner}, 'active', '2025-01-01 00:00:00', '2025-01-01 00:00:00');\n"));
    }
    s.push_str("UPDATE devices SET deleted_at = '2025-10-01 00:00:00' WHERE id = 3;\n");
    // what the 7b pages show: computers with names, systems, versions and a group, a user group, a strategy, an address book
    // with a tag and an entry, one session still open
    s.push_str(&format!(
        "UPDATE devices SET hostname = 'FRONT-PC', os = 'windows / Windows 11', version = '1.4.0', alias = 'Front PC', username = 'dana', device_group_id = 1, last_online_at = {}, last_online_ip = '10.0.0.1' WHERE id = 1;\n\
         UPDATE devices SET hostname = 'BACK-PC', os = 'macos / macOS 14', version = '1.3.9', username = 'erin', device_group_id = 2, last_online_at = {}, last_online_ip = '10.0.0.2' WHERE id = 2;\n\
         INSERT INTO devices (id, rustdesk_id, uuid, hostname, os, version, username, status, last_online_at, last_online_ip, created_at, updated_at) VALUES (4, '1004', 'uuid-4', 'NEW-PC', 'windows / Windows 10', '1.4.0', 'dana', 'pending', {}, '10.0.0.4', '2025-01-01 00:00:00', '2025-01-01 00:00:00');\n\n",
        t(30), t(500_000), t(60)
    ));
    s.push_str("INSERT INTO device_groups (id, name, created_at, updated_at) VALUES (2, 'Back office', '2025-01-01 00:00:00', '2025-01-01 00:00:00');\n");
    s.push_str("INSERT INTO user_groups (id, name, created_at, updated_at) VALUES (1, 'Techs', '2025-01-01 00:00:00', '2025-01-01 00:00:00');\n");
    s.push_str("INSERT INTO strategies (id, name, note, enabled, is_default, enforce, options, created_at, updated_at) VALUES (1, 'Baseline', 'Everyone', 1, 1, 0, '{\"enable-keyboard\":\"Y\"}', '2025-01-01 00:00:00', '2025-01-01 00:00:00');\n");
    s.push_str("INSERT INTO address_books (id, guid, name, owner_user_id, is_personal, note, created_at, updated_at) VALUES (1, 'guid-shared', 'Shared', 1, 0, 'For the team', '2025-01-01 00:00:00', '2025-01-01 00:00:00');\n");
    s.push_str("INSERT INTO tags (id, address_book_id, name, color, created_at, updated_at) VALUES (1, 1, 'Servers', 4278190335, '2025-01-01 00:00:00', '2025-01-01 00:00:00');\n");
    s.push_str("INSERT INTO address_book_entries (id, address_book_id, rustdesk_id, alias, hostname, platform, tag_ids, created_at, updated_at) VALUES (1, 1, '1001', 'Front PC', 'FRONT-PC', 'Windows', '[1]', '2025-01-01 00:00:00', '2025-01-01 00:00:00');\n");
    s.push_str(&format!(
        "INSERT INTO audit_connections (id, action, conn_id, rustdesk_id, from_peer, from_name, ip, conn_type, created_at, updated_at) VALUES (900, 'new', 900, '1001', '555', 'Ticket desk', '10.0.0.9', 0, {}, {});\n",
        t(330), t(330)
    ));
    for (id, username, name, email, admin, role) in USERS {
        s.push_str(&format!(
            "INSERT INTO users (id, username, name, email, password, is_admin, is_active, role_id, created_at, updated_at) VALUES ({id}, {}, {}, {}, {}, {}, 1, {}, '2025-01-01 00:00:00', '2025-01-01 00:00:00');\n",
            q(username),
            if name.is_empty() { "null".into() } else { q(name) },
            q(email),
            q(&hash),
            admin as i32,
            role.map_or("null".into(), |r| r.to_string()),
        ));
        let payload = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(format!("{{\"_token\":\"{TOKEN}\",\"{}\":{id},\"_flash\":{{\"old\":[],\"new\":[]}}}}", session::LOGIN_KEY))
        };
        s.push_str(&format!("INSERT INTO sessions (id, user_id, ip_address, user_agent, payload, last_activity) VALUES ('{}', {id}, '198.18.9.1', 'replay', '{payload}', {now});\n", sid(username)));
    }
    s.push_str("INSERT INTO trusted_devices (user_id, token_hash, expires_at, created_at, updated_at) VALUES (3, 'h1', '2030-01-01 00:00:00', '2025-01-01 00:00:00', '2025-01-01 00:00:00'), (1, 'h2', '2030-01-01 00:00:00', '2025-01-01 00:00:00', '2025-01-01 00:00:00');\n");
    // alarms: 27 of a device dana owns (a second page), one of another's, one of the console's, one of a recycled device
    for i in 0..27 {
        s.push_str(&format!(
            "INSERT INTO alarm_logs (rustdesk_id, typ, info, conn_id, created_at, updated_at) VALUES ('1001', {}, {}, {}, {}, {});\n",
            [2, 0, 7, 1][i % 4],
            q(&format!("{{\"ip\":\"10.0.0.{i}\",\"n\":{i}}}")),
            if i % 3 == 0 { "null".to_string() } else { (100 + i).to_string() },
            t(330 + i as i64 * 3_000),
            t(330),
        ));
    }
    for (rd, typ, info, ago) in [("1002", 0, "someone else's computer", 7_300), ("console", 100, "Console brute force from 10.9.9.9", 9_000), ("1003", 9, "recycled computer", 11_000), ("1001", 55, "not json at all", 13_000), ("1001", 102, "=cmd|' /C calc'!A0", 15_000)] {
        s.push_str(&format!("INSERT INTO alarm_logs (rustdesk_id, typ, info, created_at, updated_at) VALUES ('{rd}', {typ}, {}, {}, {});\n", q(info), t(ago), t(ago)));
    }
    // connections: open and closed, every type, a note with its author
    for (i, (rd, peer, name, ip, ty, ago, dur, note)) in [
        ("1001", "555", "Front PC", "10.1.1.1", 0, 4_000, Some(125), Some("ticket 42")),
        ("1001", "556", "", "10.1.1.2", 1, 8_000, Some(3_725), None),
        ("1002", "", "", "", 2, 20_000, None, None),
        ("1001", "557", "Back office", "10.1.1.3", 3, 90_000, Some(59), Some("camera check")),
        ("1001", "558", "Mac", "10.1.1.4", 4, 400_000, Some(7_300), None),
        ("1002", "559", "Other", "10.1.1.5", 9, 2_000_000, Some(1), None),
    ]
    .into_iter()
    .enumerate()
    {
        let closed = dur.map_or("null".to_string(), |d| t(ago - d));
        s.push_str(&format!(
            "INSERT INTO audit_connections (rustdesk_id, from_peer, from_name, ip, conn_type, created_at, updated_at, closed_at, note, note_user_id) VALUES ({}, {}, {}, {}, {ty}, {}, {}, {closed}, {}, {});\n",
            q(rd),
            q(peer),
            q(name),
            q(ip),
            t(ago),
            t(ago),
            note.map_or("null".to_string(), q),
            if note.is_some() { (i as i64 % 3 + 1).to_string() } else { "null".into() },
        ));
    }
    // file transfers: a path, a clipboard paste, both directions
    for (rd, peer, path, info, dir, n, ago) in [
        ("1001", "555", "/home/dana/report.pdf", "", 0, 1, 5_000),
        ("1001", "555", "", "{\"files\":[[\"a.txt\",1],[\"b.txt\",2],[\"c.txt\",3],[\"d.txt\",4]]}", 1, 4, 9_000),
        ("1002", "556", "C:\\Users\\x\\y.docx", "", 1, 1, 30_000),
        ("1001", "557", "", "{\"files\":[[\"only.png\",9]]}", 0, 1, 200_000),
    ] {
        s.push_str(&format!(
            "INSERT INTO audit_file_transfers (rustdesk_id, from_peer, from_name, path, info, direction, file_count, ip, created_at, updated_at) VALUES ('{rd}', '{peer}', 'Front PC', {}, {}, {dir}, {n}, '10.1.1.1', {}, {});\n",
            q(path),
            if info.is_empty() { "null".into() } else { q(info) },
            t(ago),
            t(ago),
        ));
    }
    for (name, client, dev, os, ip, ok, note, ago) in [
        ("hteadmin", "web", "", "", "10.9.9.9", 1, "", 600),
        ("dana", "desktop", "1001", "Windows 11", "10.1.1.1", 1, "", 7_000),
        ("mallory", "mobile", "77", "Android", "10.9.9.8", 0, "bad password", 50_000),
        ("erin", "weird", "", "", "", 0, "", 150_000),
    ] {
        s.push_str(&format!(
            "INSERT INTO login_logs (username, client, device_id, device_os, ip, successful, note, created_at, updated_at) VALUES ({}, '{client}', {}, {}, {}, {ok}, {}, {}, {});\n",
            q(name),
            q(dev),
            q(os),
            q(ip),
            if note.is_empty() { "null".into() } else { q(note) },
            t(ago),
            t(ago)
        ));
    }
    for (i, (user, action, tt, tid, summary, ago)) in [
        (1, "user.create", "user", "2", "Created user dana", 700),
        (1, "device.update", "device", "1001", "Updated device 1001", 9_000),
        (2, "account.update", "user", "2", "Updated own profile", 20_000),
        (1, "settings.update", "", "", "Saved settings", 70_000),
        (1, "weird.action", "thing", "", "A <b>tag</b> & an 'apostrophe'", 500_000),
    ]
    .into_iter()
    .enumerate()
    {
        let uname = USERS[user - 1].1;
        s.push_str(&format!(
            "INSERT INTO console_audits (user_id, username, action, target_type, target_id, summary, ip, created_at) VALUES ({user}, '{uname}', '{action}', {}, {}, {}, '10.9.9.9', {});\n",
            if tt.is_empty() { "null".into() } else { q(tt) },
            if tid.is_empty() { "null".into() } else { q(tid) },
            q(summary),
            t(ago + i as i64)
        ));
    }
    Ok(s)
}

// ------------------------------------------------------------------------------------------------ the replay ---

#[derive(Debug)]
struct Out {
    /// when it was asked (unix seconds): kept in a capture, so a local run can render its side at the same second
    at: i64,
    status: u16,
    ctype: String,
    location: String,
    disposition: String,
    body: String,
}

/// Where PHP's half comes from. `HTE_PAGEREPLAY_CAPTURE_TO=<dir>`: the live PHP, and each answer the comparison uses is
/// also saved there. `HTE_PAGEREPLAY_PHP_FROM=<dir>`: no PHP at all, the answers saved by an earlier run are read back,
/// so a build can be compared on a machine without PHP (`replay/compare-local.sh`): pages and dialogs only (the CSV
/// exports and the writes need PHP's Livewire).
#[derive(Clone)]
enum Side {
    Live,
    Save(std::path::PathBuf),
    From(std::path::PathBuf),
}

fn side() -> Side {
    let dir = |k: &str| crate::envvar::var(k).ok().filter(|v| !v.trim().is_empty()).map(std::path::PathBuf::from);
    match (dir("HTE_PAGEREPLAY_PHP_FROM"), dir("HTE_PAGEREPLAY_CAPTURE_TO")) {
        (Some(d), _) => Side::From(d),
        (None, Some(d)) => Side::Save(d),
        _ => Side::Live,
    }
}

fn save_out(dir: &std::path::Path, key: &str, label: &str, o: &Out) -> Result<(), String> {
    let v = serde_json::json!({"label": label, "at": o.at, "status": o.status, "ctype": o.ctype, "location": o.location, "disposition": o.disposition, "body": o.body});
    std::fs::write(dir.join(format!("{key}.json")), serde_json::to_vec(&v).unwrap_or_default()).map_err(|e| format!("cannot save PHP's answer in {}: {e}", dir.display()))
}

fn load_out(dir: &std::path::Path, key: &str, label: &str) -> Result<Out, String> {
    let path = dir.join(format!("{key}.json"));
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).map_err(|e| format!("{}: {e} (capture from an older replay? take a new one)", path.display()))?).map_err(|e| format!("{}: {e}", path.display()))?;
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    if s("label") != label {
        return Err(format!("{}: saved for «{}», asked for «{label}»: the capture is from another version of the replay; take a new one", path.display(), s("label")));
    }
    Ok(Out { at: v.get("at").and_then(|x| x.as_i64()).unwrap_or(0), status: v.get("status").and_then(|x| x.as_u64()).unwrap_or(0) as u16, ctype: s("ctype"), location: s("location"), disposition: s("disposition"), body: s("body") })
}

fn one_second_apart(hunk: &str) -> bool {
    static N: Lazy<Regex> = Lazy::new(|| Regex::new(r"PHP has «(\d+)(s?)» / hte-console has «(\d+)(s?)»$").unwrap());
    N.captures(hunk).map_or(false, |m| {
        let (a, b) = (m[1].parse::<i64>().unwrap_or(-9), m[3].parse::<i64>().unwrap_or(9));
        m[2] == m[4] && (a - b).abs() <= 1
    })
}

/// PHP's answer to a page request, live, live and saved, or read back.
async fn php_get(side: &Side, key: &str, label: &str, c: &reqwest::Client, php: &str, cookie: &str, path: &str) -> Result<Out, String> {
    match side {
        Side::From(d) => load_out(d, key, label),
        Side::Live => fetch(c, php, cookie, "GET", path, None, String::new(), &[]).await,
        Side::Save(d) => {
            let a = fetch(c, php, cookie, "GET", path, None, String::new(), &[]).await?;
            save_out(d, key, label, &a)?;
            Ok(a)
        }
    }
}

fn cookie_for(cfg: &session::SessionConfig, crypt: &Encrypter, user: &str, now: i64) -> String {
    session::set_cookie(cfg, crypt, &sid(user), false, now).split(';').next().unwrap_or("").to_string()
}

/// `name=value` of the session cookie for one of the seeded people.
pub fn cookie(key: &str, name: &str, who: &str, now: i64) -> Result<String, String> {
    let crypt = Encrypter::from_app_key(key)?;
    let cfg = session::SessionConfig { cookie: name.to_string(), lifetime_min: 120, secure: None };
    Ok(cookie_for(&cfg, &crypt, who, now))
}

/// Livewire 4 posts to a hashed address the page announces (`data-update-uri`), in full: only its path is ours to use.
fn update_uri(page: &str) -> String {
    static URI: Lazy<Regex> = Lazy::new(|| Regex::new(r#"data-update-uri="([^"]+)""#).unwrap());
    let uri = URI.captures(page).map(|m| m[1].to_string()).unwrap_or_else(|| "/livewire/update".into());
    match uri.find("://") {
        Some(i) => uri[i + 3..].find('/').map(|j| uri[i + 3 + j..].to_string()).unwrap_or(uri),
        None => uri,
    }
}

async fn fetch(c: &reqwest::Client, base: &str, cookie: &str, method: &str, path: &str, ct: Option<&str>, body: String, extra: &[(&str, &str)]) -> Result<Out, String> {
    let at = chrono::Utc::now().timestamp();
    let mut rq = c.request(method.parse().map_err(|_| "method")?, format!("{base}{path}")).header("cookie", cookie).header("x-forwarded-for", "198.18.9.1");
    if let Some(ct) = ct {
        rq = rq.header("content-type", ct);
    }
    for (k, v) in extra {
        rq = rq.header(*k, *v);
    }
    let r = rq.body(body).send().await.map_err(|e| format!("{method} {base}{path}: {e}"))?;
    let status = r.status().as_u16();
    let h = |n: &str| r.headers().get(n).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let (ctype, mut location, disposition) = (h("content-type"), h("location"), h("content-disposition"));
    if let Some(i) = location.find("://") {
        // "http://host" is the same place as "http://host/"
        location = location[i + 3..].find('/').map(|j| location[i + 3 + j..].to_string()).unwrap_or_else(|| "/".into());
    }
    Ok(Out { at, status, ctype, location, disposition, body: r.text().await.map_err(|e| e.to_string())? })
}

static TAG: Lazy<Regex> = Lazy::new(|| Regex::new(r#"(?s)<!--.*?-->|<(/?)([A-Za-z][A-Za-z0-9]*)((?:[^>"']|"[^"]*"|'[^']*')*)>"#).unwrap());
static CLASS: Lazy<Regex> = Lazy::new(|| Regex::new(r#"(?s)\sclass\s*=\s*"([^"]*)""#).unwrap());

fn decode(s: &str) -> String {
    let mut out = s.replace("&nbsp;", " ").replace("&lsaquo;", "‹").replace("&rsaquo;", "›").replace("&laquo;", "«").replace("&raquo;", "»");
    out = out.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&#039;", "'").replace("&#39;", "'").replace("&amp;", "&");
    out
}

/// What a person reads (the text, in order) and what the page looks like (the `class` attributes, in order), from
/// the page body between `<body>` and the Bootstrap script, with scripts and styles skipped.
pub fn shape(html: &str) -> (Vec<String>, Vec<String>) {
    // what PHP shows only while a Livewire call is under way ("Saving…", "Calculating…"): no person reads it
    static LOADING: Lazy<Regex> = Lazy::new(|| Regex::new(r#"(?s)<span\b[^>]*\bwire:loading\b[^>]*>.*?</span>|<div\b[^>]*\bwire:loading\b[^>]*>.*?</div>"#).unwrap());
    let cleaned = LOADING.replace_all(html, |m: &regex::Captures| {
        let tag = &m[0][..m[0].find('>').unwrap_or(0)];
        if tag.contains("wire:loading.remove") || tag.contains("wire:loading.attr") || tag.contains("wire:loading.class") { m[0].to_string() } else { String::new() }
    });
    let html: &str = &cleaned;
    let start = html.find("<body").unwrap_or(0);
    let end = html.find("bootstrap.bundle").map(|i| html[..i].rfind("<script").unwrap_or(i)).unwrap_or(html.len());
    let html = &html[start..end.max(start)];
    let (mut text, mut classes) = (vec![], vec![]);
    let (mut last, mut skip) = (0usize, false);
    let push = |chunk: &str, text: &mut Vec<String>| {
        for w in decode(chunk).split_whitespace() {
            text.push(w.to_string());
        }
    };
    for m in TAG.find_iter(html) {
        if !skip {
            push(&html[last..m.start()], &mut text);
        }
        last = m.end();
        let Some(cap) = TAG.captures(m.as_str()) else { continue };
        let (closing, name) = (!cap.get(1).map_or(true, |c| c.as_str().is_empty()), cap.get(2).map_or("", |c| c.as_str()).to_ascii_lowercase());
        if name == "script" || name == "style" {
            skip = !closing;
            continue;
        }
        if !closing && !skip {
            if let Some(c) = cap.get(3).and_then(|a| CLASS.captures(a.as_str())) {
                classes.push(c[1].split_whitespace().collect::<Vec<_>>().join(" "));
            }
        }
    }
    (text, classes)
}

/// Every place where the two sequences differ (a longest-common-subsequence walk, so one extra element does not make
/// everything after it look different), each with a little context. Empty = equal. At most `MAX_HUNKS` are listed.
const MAX_HUNKS: usize = 25;

fn all_differences(a: &[String], b: &[String]) -> Vec<String> {
    if a == b {
        return vec![];
    }
    let pre = a.iter().zip(b).take_while(|(x, y)| x == y).count();
    let suf = a[pre..].iter().rev().zip(b[pre..].iter().rev()).take_while(|(x, y)| x == y).count();
    let (ma, mb) = (&a[pre..a.len() - suf], &b[pre..b.len() - suf]);
    let show = |v: &[String]| -> String {
        let mut t = v.iter().take(14).cloned().collect::<Vec<_>>().join(" ");
        if v.len() > 14 {
            t.push_str(&format!(" … (+{})", v.len() - 14));
        }
        t
    };
    let hunk = |at: usize, gone: &[String], added: &[String]| -> String {
        let ctx = a[at.saturating_sub(4)..at].join(" ");
        format!("at item {at}, after «{ctx}»: PHP has «{}» / hte-console has «{}»", show(gone), show(added))
    };
    if ma.len().saturating_mul(mb.len()) > 25_000_000 {
        return vec![hunk(pre, ma, mb)];
    }
    let w = mb.len() + 1;
    let mut dp = vec![0u16; (ma.len() + 1) * w];
    for i in (0..ma.len()).rev() {
        for j in (0..mb.len()).rev() {
            dp[i * w + j] = if ma[i] == mb[j] { dp[(i + 1) * w + j + 1] + 1 } else { dp[(i + 1) * w + j].max(dp[i * w + j + 1]) };
        }
    }
    let (mut i, mut j) = (0usize, 0usize);
    let (mut out, mut gone, mut added, mut at) = (vec![], vec![], vec![], 0usize);
    let mut flush = |gone: &mut Vec<String>, added: &mut Vec<String>, at: usize, out: &mut Vec<String>| {
        if !gone.is_empty() || !added.is_empty() {
            out.push(hunk(pre + at, gone, added));
            gone.clear();
            added.clear();
        }
    };
    while i < ma.len() || j < mb.len() {
        if i < ma.len() && j < mb.len() && ma[i] == mb[j] {
            flush(&mut gone, &mut added, at, &mut out);
            i += 1;
            j += 1;
            continue;
        }
        if gone.is_empty() && added.is_empty() {
            at = i;
        }
        if j >= mb.len() || (i < ma.len() && dp[(i + 1) * w + j] >= dp[i * w + j + 1]) {
            gone.push(ma[i].clone());
            i += 1;
        } else {
            added.push(mb[j].clone());
            j += 1;
        }
    }
    flush(&mut gone, &mut added, at, &mut out);
    if out.len() > MAX_HUNKS {
        let more = out.len() - MAX_HUNKS;
        out.truncate(MAX_HUNKS);
        out.push(format!("… and {more} more places"));
    }
    out
}

pub struct Report {
    pub total: usize,
    pub differences: Vec<String>,
    /// Known, deliberate differences, each with its reason (never counted as a difference).
    pub by_design: Vec<String>,
}

/// The htmx fragments the dashboard refreshes itself with: PHP does the same through Livewire polling, which has no
/// URL of its own, so PHP answers 404 where hte-console answers 200 (the same permission and reach checks as the page).
const FRAGMENTS: [&str; 2] = ["/dashboard/stats", "/dashboard/sessions"];
const FRAGMENT_REASON: &str = "by design (own htmx refresh URL; PHP refreshes the same cards through Livewire polling, which has no URL; same permission checks as the page)";
const INVITE_REASON: &str = "by design (the Invitations card at the end of Users: inviting by email is not available in this console; the rest of the page is compared)";

const DIALOG_LAYOUT_REASON: &str = "by design (the CSS classes of a dialog are not compared: hte-console lays dialogs out its own way; their text, fields and buttons are)";
const GROUPS_REASON: &str = "by design (Settings: an option group the page hides with d-none and shows with a click handler, e.g. the other Apprise mode, is in the page; PHP re-renders the form from the server instead; only the group in force is compared; the About card lists different things: PHP its Laravel and PHP versions, hte-console its own)";

/// Where the `<div>` opened at `from` (the end of its opening tag) closes.
fn div_end(html: &str, from: usize) -> usize {
    let mut depth = 1i32;
    for t in TAG.captures_iter(&html[from..]) {
        let whole = t.get(0).unwrap();
        if whole.as_str().starts_with("<!--") || !t.get(2).map_or(false, |n| n.as_str().eq_ignore_ascii_case("div")) {
            continue;
        }
        depth += if t.get(1).map_or(false, |c| !c.as_str().is_empty()) { -1 } else if whole.as_str().ends_with("/>") { 0 } else { 1 };
        if depth == 0 {
            return from + whole.end();
        }
    }
    html.len()
}

/// The html without the `data-rd-group` blocks that are hidden (`d-none`): hte-console ships every variant and shows one,
/// PHP renders only the one in force. The About card (the stack's versions: PHP lists Laravel and PHP, hte-console itself) goes too.
fn without_hidden_groups(html: &str) -> String {
    static OPEN: Lazy<Regex> = Lazy::new(|| Regex::new(r#"<div\b[^>]*\bdata-rd-group="[^"]*"[^>]*>"#).unwrap());
    let mut out = String::new();
    let mut pos = 0usize;
    while let Some(m) = OPEN.find_at(html, pos) {
        let hidden = CLASS.captures(m.as_str()).map_or(false, |c| c[1].split_whitespace().any(|w| w == "d-none"));
        if !hidden {
            out.push_str(&html[pos..m.end()]);
            pos = m.end();
            continue;
        }
        out.push_str(&html[pos..m.start()]);
        pos = div_end(html, m.end());
    }
    out.push_str(&html[pos..]);
    match out.find(">About<").and_then(|i| out[..i].rfind("<div class=\"card\">")) {
        Some(i) => {
            let open_end = i + "<div class=\"card\">".len();
            let end = div_end(&out, open_end);
            format!("{}{}", &out[..i], &out[end..])
        }
        None => out,
    }
}

/// The html without the Invitations card, which closes the Users page on both sides.
fn without_invitations(html: &str) -> &str {
    match html.find(">Invitations<").and_then(|i| html[..i].rfind("<div class=\"card\">")) {
        Some(i) => &html[..i],
        None => html,
    }
}

/// A Livewire component's snapshot from a page: the first `wire:snapshot` whose memo name is `name`.
fn snapshot(html: &str, name: &str) -> Option<String> {
    static SNAP: Lazy<Regex> = Lazy::new(|| Regex::new(r#"wire:snapshot="([^"]*)""#).unwrap());
    SNAP.captures_iter(html).map(|c| decode(&c[1])).find(|s| s.contains(&format!("\"name\":\"{name}\"")))
}

pub async fn run(php: &str, rust: &str, key: &str, cookie_name: &str, now: i64) -> Result<Report, String> {
    run_with(php, rust, key, cookie_name, now, true).await
}

/// `writes` false: only the reads (the writes need PHP's Livewire endpoint; a run of hte-console against itself,
/// which checks this tool, has none).
pub async fn run_with(php: &str, rust: &str, key: &str, cookie_name: &str, now: i64, writes: bool) -> Result<Report, String> {
    let mut diffs: Vec<String> = vec![];
    let mut total = 0usize;
    let mut by_design: Vec<String> = vec![];
    // an error part way (a write PHP will not take, say) is reported with the differences found before it, not instead of them
    if let Err(e) = run_inner(php, rust, key, cookie_name, now, writes, &mut diffs, &mut by_design, &mut total).await {
        diffs.push(format!("the replay stopped: {e}"));
    }
    by_design.sort();
    by_design.dedup();
    Ok(Report { total, differences: diffs, by_design })
}

async fn run_inner(php: &str, rust: &str, key: &str, cookie_name: &str, now: i64, writes: bool, diffs: &mut Vec<String>, by_design: &mut Vec<String>, total: &mut usize) -> Result<(), String> {
    let crypt = Encrypter::from_app_key(key)?;
    // HTE_PAGEREPLAY_RUST_ONLY=1: the writes run on hte-console alone (no Livewire), so the Rust half can be checked where
    // there is no PHP; the comparison with PHP is the server run's
    let side = side();
    let offline = matches!(side, Side::From(_));
    let rust_only = offline || crate::envvar::var("HTE_PAGEREPLAY_RUST_ONLY").map_or(false, |v| !v.trim().is_empty() && v != "0");
    let cfg = session::SessionConfig { cookie: cookie_name.to_string(), lifetime_min: 120, secure: None };
    let c = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().map_err(|e| e.to_string())?;
    let (day, week) = (laravel::ts(now - 90_000)[..10].to_string(), laravel::ts(now - 9_000)[..10].to_string());
    let mut cases: Vec<(&str, String)> = vec![];
    for user in ["hteadmin", "dana", "erin"] {
        for path in [
            "/logs/alarms",
            "/logs/alarms?page=2",
            "/logs/alarms?page=3",
            "/logs/alarms?type=0",
            "/logs/alarms?search=10.0.0.1",
            "/logs/alarms?search=console",
            "/logs/connections",
            "/logs/connections?search=ticket",
            "/logs/file-transfers",
            "/logs/file-transfers?search=a.txt",
            "/logs/logins",
            "/logs/logins?search=mallory",
            "/logs/console",
            "/logs/console?action=device.update",
            "/logs/console?action=weird",
            "/account",
            "/",
            "/dashboard/stats",
            "/dashboard/sessions",
            "/webclient",
            "/webclient?id=1001",
            "/devices",
            "/devices?status=online",
            "/devices?search=front",
            "/devices/1",
            "/users",
            "/users?search=dana",
            "/users/2",
            "/groups",
            "/address-books",
            "/strategies",
            "/settings",
        ] {
            cases.push((user, path.to_string()));
        }
    }
    for path in [
        format!("/logs/alarms?dateFrom={day}&dateTo={day}"),
        format!("/logs/connections?dateFrom={week}"),
    ] {
        for user in ["hteadmin", "dana"] {
            cases.push((user, path.clone()));
        }
    }
    // 7c, after everything 7b asked, so a 7b capture still lines up up to here
    for user in ["hteadmin", "dana", "erin"] {
        for path in ["/diagnostics", "/diagnostics/export", "/roles"] {
            cases.push((user, path.to_string()));
        }
    }
    // the health routes answer without a session
    for path in ["/health/live", "/health/ready"] {
        cases.push(("hteadmin", path.to_string()));
    }
    for (i, (user, path)) in cases.iter().enumerate() {
        let cookie = cookie_for(&cfg, &crypt, user, now);
        let a = match php_get(&side, &format!("p{i:03}"), &format!("{user} GET {path}"), &c, php, &cookie, path).await {
            // a capture taken by an older replay ends before the pages added since: those are not compared (said, not counted)
            Err(e) if offline && e.contains("capture from an older replay") => {
                eprintln!("not in this capture (added after it was taken), not compared: {user} GET {path}");
                continue;
            }
            r => r?,
        };
        let clock = a.at.to_string();
        let at: &[(&str, &str)] = if offline { &[("x-hte-replay-clock", clock.as_str())] } else { &[] };
        let b = fetch(&c, rust, &cookie, "GET", path, None, String::new(), at).await?;
        *total += 1;
        let label = format!("{user} GET {path}");
        if FRAGMENTS.contains(&path.as_str()) && a.status == 404 && b.status == 200 {
            by_design.push(format!("{path}: {FRAGMENT_REASON}"));
            continue;
        }
        if (a.status, &a.location) != (b.status, &b.location) {
            diffs.push(format!("{label}: PHP {} {} / hte-console {} {}", a.status, a.location, b.status, b.location));
            continue;
        }
        if a.status != 200 {
            // a redirect: the status and where to are what a person gets (its body names the host)
        } else if path == "/diagnostics/export" {
            // the JSON download: the same report, but the second it was made and how long each probe took are the clock's
            let mask = |s: &str| -> Option<serde_json::Value> {
                let mut v: serde_json::Value = serde_json::from_str(s).ok()?;
                v["generated_at"] = serde_json::Value::Null;
                for k in ["id_server", "relay_server"] {
                    if v["services"][k].get("latency_ms").is_some() {
                        v["services"][k]["latency_ms"] = serde_json::Value::Null;
                    }
                }
                Some(v)
            };
            match (mask(&a.body), mask(&b.body)) {
                (Some(x), Some(y)) if x == y && a.ctype == b.ctype && a.disposition == b.disposition => {}
                (Some(x), Some(y)) => diffs.push(format!("{label}: the JSON differs (content types «{}» / «{}», dispositions «{}» / «{}»): PHP {x} / hte-console {y}", a.ctype, b.ctype, a.disposition, b.disposition)),
                _ => diffs.push(format!("{label}: not JSON on one side (PHP {} bytes, hte-console {})", a.body.len(), b.body.len())),
            }
        } else if path.contains("/export") {
            // streamDownload's headers and the exact file
            if a.body != b.body || a.ctype != b.ctype {
                diffs.push(format!("{label}: the CSV differs (PHP {} bytes, hte-console {}; content types «{}» / «{}»)", a.body.len(), b.body.len(), a.ctype, b.ctype));
            }
        } else if a.status == 200 {
            let users = path.starts_with("/users");
            let (pa, pb) = if users && (a.body.contains(">Invitations<") || b.body.contains(">Invitations<")) {
                by_design.push(format!("/users*: {INVITE_REASON}"));
                (without_invitations(&a.body), without_invitations(&b.body))
            } else {
                (a.body.as_str(), b.body.as_str())
            };
            let (ga, gb);
            let (pa, pb) = if path.starts_with("/settings") && (pa.contains("data-rd-group") || pb.contains("data-rd-group")) {
                by_design.push(format!("/settings: {GROUPS_REASON}"));
                ga = without_hidden_groups(pa);
                gb = without_hidden_groups(pb);
                (ga.as_str(), gb.as_str())
            } else {
                (pa, pb)
            };
            let ((ta, ca), (tb, cb)) = (shape(pa), shape(pb));
            for d in all_differences(&ta, &tb) {
                // read back from a capture, a page is rendered at the second PHP was asked, and PHP may have answered a
                // second later: "43s" against "42s" is that, not a difference
                if offline && one_second_apart(&d) {
                    continue;
                }
                diffs.push(format!("{label}: text {d}"));
            }
            for d in all_differences(&ca, &cb) {
                diffs.push(format!("{label}: classes {d}"));
            }
        }
    }
    // the CSV exports: PHP's are a Livewire call (`export`) answered with a download effect, hte-console's a GET of its own;
    // the same filters on both, the exact bytes and the file name compared
    // (this needs PHP's Livewire: a run of hte-console against itself has none, and skips it)
    for (user, page, component, filters, query) in if writes { vec![
        ("hteadmin", "/logs/alarms", "alarm-log-list", vec![], ""),
        ("dana", "/logs/alarms", "alarm-log-list", vec![], ""),
        ("hteadmin", "/logs/alarms", "alarm-log-list", vec![("type", "2"), ("search", "10.0.0")], "?type=2&search=10.0.0"),
        ("hteadmin", "/logs/connections", "connection-log", vec![], ""),
        ("dana", "/logs/connections", "connection-log", vec![], ""),
        ("hteadmin", "/logs/file-transfers", "file-transfer-log", vec![], ""),
        ("dana", "/logs/file-transfers", "file-transfer-log", vec![], ""),
        ("hteadmin", "/logs/logins", "login-log-list", vec![], ""),
        ("hteadmin", "/logs/console", "console-audit-list", vec![], ""),
    ] } else { vec![] } {
        if rust_only {
            break;
        }
        let cookie = cookie_for(&cfg, &crypt, user, now);
        let label = format!("{user} export {page}{query}");
        *total += 1;
        let page_php = fetch(&c, php, &cookie, "GET", page, None, String::new(), &[]).await?;
        let Some(snap) = snapshot(&page_php.body, component) else {
            diffs.push(format!("{label}: PHP's page has no {component} snapshot (status {})", page_php.status));
            continue;
        };
        let uri = update_uri(&page_php.body);
        let upd: serde_json::Map<String, serde_json::Value> = filters.iter().map(|(k, v)| (k.to_string(), serde_json::json!(v))).collect();
        let body = serde_json::json!({"_token": TOKEN, "components": [{"snapshot": snap, "updates": upd, "calls": [{"path": "", "method": "export", "params": []}]}]});
        let a = fetch(&c, php, &cookie, "POST", &uri, Some("application/json"), body.to_string(), &[("x-livewire", "true"), ("x-csrf-token", TOKEN)]).await?;
        let b = fetch(&c, rust, &cookie, "GET", &format!("{page}/export{query}"), None, String::new(), &[]).await?;
        let download = serde_json::from_str::<serde_json::Value>(&a.body).ok().and_then(|v| v["components"][0]["effects"]["download"].as_object().cloned());
        match (a.status, download, b.status) {
            (200, Some(d), 200) => {
                use base64::Engine;
                let content = d.get("content").and_then(|v| v.as_str()).and_then(|v| base64::engine::general_purpose::STANDARD.decode(v).ok()).unwrap_or_default();
                let name = d.get("name").and_then(|v| v.as_str()).unwrap_or("");
                if content != b.body.as_bytes() {
                    diffs.push(format!("{label}: the CSV differs (PHP {} bytes, hte-console {})", content.len(), b.body.len()));
                }
                if !b.disposition.contains(&format!("filename={name}")) && !b.disposition.contains(&format!("filename=\"{name}\"")) {
                    diffs.push(format!("{label}: file name PHP «{name}», hte-console «{}»", b.disposition));
                }
            }
            (_, None, 302) => {} // a section the person may not use: PHP's component refuses, hte-console redirects
            (sa, d, sb) => diffs.push(format!("{label}: PHP answered {sa} (download {}), hte-console {sb}: {}", d.is_some(), &a.body[..a.body.len().min(200)])),
        }
    }
    if !writes {
        return Ok(());
    }
    // the writes, hte-console through its forms, PHP through Livewire; the caller compares the databases afterwards
    let post_form = |path: &'static str, fields: Vec<(&'static str, String)>| {
        let body = laravel::http_build_query(&fields.iter().map(|(k, v)| (*k, v.as_bytes())).collect::<Vec<_>>());
        (path, body)
    };
    let wire = |user: &'static str, component: &'static str, updates: Vec<(&'static str, &'static str)>, method: &'static str| {
        let (c, php, cookie) = (c.clone(), php.to_string(), cookie_for(&cfg, &crypt, user, now));
        async move {
            if rust_only {
                return Ok::<(), String>(());
            }
            let page = fetch(&c, &php, &cookie, "GET", "/account", None, String::new(), &[]).await?;
            let snap = snapshot(&page.body, component).ok_or_else(|| format!("PHP's /account has no {component} snapshot"))?;
            let upd: serde_json::Map<String, serde_json::Value> = updates.into_iter().map(|(k, v)| (k.to_string(), serde_json::json!(v))).collect();
            let body = serde_json::json!({"_token": TOKEN, "components": [{"snapshot": snap, "updates": upd, "calls": [{"path": "", "method": method, "params": []}]}]});
            let uri = update_uri(&page.body);
            let r = fetch(&c, &php, &cookie, "POST", &uri, Some("application/json"), body.to_string(), &[("x-livewire", "true"), ("x-csrf-token", TOKEN)]).await?;
            if r.status != 200 {
                return Err(format!("PHP's Livewire ({uri}) answered {} to {component}.{method}: {}", r.status, &r.body[..r.body.len().min(300)]));
            }
            Ok::<(), String>(())
        }
    };
    let rust_post = |user: &'static str, path: &'static str, body: String, ct: &'static str| {
        let (c, rust, cookie) = (c.clone(), rust.to_string(), cookie_for(&cfg, &crypt, user, now));
        async move { fetch(&c, &rust, &cookie, "POST", path, Some(ct), body, &[("x-csrf-token", TOKEN)]).await }
    };
    // the profile: a name and an email, then blanks (dana), a taken email (rejected on both: nothing written)
    wire("dana", "account-profile", vec![("name", "Dana S"), ("email", "dana2@example.test")], "saveProfile").await?;
    let (p, b) = post_form("/account/profile", vec![("name", "Dana S".into()), ("email", "dana2@example.test".into())]);
    let r = rust_post("dana", p, b, "application/x-www-form-urlencoded").await?;
    *total += 1;
    if r.status != 302 {
        diffs.push(format!("dana POST /account/profile: hte-console answered {}", r.status));
    }
    wire("dana", "account-profile", vec![("name", "Dana S"), ("email", "admin@example.test")], "saveProfile").await?;
    let (p, b) = post_form("/account/profile", vec![("name", "Dana S".into()), ("email", "admin@example.test".into())]);
    let r = rust_post("dana", p, b, "application/x-www-form-urlencoded").await?;
    *total += 1;
    if r.status != 422 {
        diffs.push(format!("dana POST /account/profile (a taken email): hte-console answered {}, not 422", r.status));
    }
    wire("dana", "account-profile", vec![("name", ""), ("email", "")], "saveProfile").await?;
    let (p, b) = post_form("/account/profile", vec![("name", "".into()), ("email", "".into())]);
    rust_post("dana", p, b, "application/x-www-form-urlencoded").await?;
    // the password (erin): wrong current, mismatch, then the change
    wire("erin", "account-profile", vec![("currentPassword", "wrong password"), ("password", "newpassword1"), ("passwordConfirmation", "newpassword1")], "updatePassword").await?;
    let (p, b) = post_form("/account/password", vec![("current_password", "wrong password".into()), ("password", "newpassword1".into()), ("password_confirmation", "newpassword1".into())]);
    let r = rust_post("erin", p, b, "application/x-www-form-urlencoded").await?;
    *total += 1;
    if r.status != 422 || !r.body.contains("That is not your current password.") {
        diffs.push(format!("erin POST /account/password (wrong current): hte-console answered {}", r.status));
    }
    wire("erin", "account-profile", vec![("currentPassword", PASSWORD), ("password", "newpassword1"), ("passwordConfirmation", "newpassword1")], "updatePassword").await?;
    let (p, b) = post_form("/account/password", vec![("current_password", PASSWORD.into()), ("password", "newpassword1".into()), ("password_confirmation", "newpassword1".into())]);
    let r = rust_post("erin", p, b, "application/x-www-form-urlencoded").await?;
    *total += 1;
    if r.status != 302 {
        diffs.push(format!("erin POST /account/password: hte-console answered {}", r.status));
    }
    // the theme (the top bar's and the page's): PHP's controller and hte-console's, the same JSON
    let both = ["php", "rust"];
    for (side, base) in both.iter().zip([php, rust]).filter(|(s, _)| !rust_only || **s == "rust") {
        let cookie = cookie_for(&cfg, &crypt, "hteadmin", now);
        let r = fetch(&c, base, &cookie, "POST", "/account/theme", Some("application/json"), r#"{"theme":"light"}"#.into(), &[("x-csrf-token", TOKEN), ("accept", "application/json")]).await?;
        *total += 1;
        if r.status != 204 {
            diffs.push(format!("hteadmin POST /account/theme on {side}: {}", r.status));
        }
        let r = fetch(&c, base, &cookie, "POST", "/account/theme", Some("application/json"), r#"{"theme":"purple"}"#.into(), &[("x-csrf-token", TOKEN), ("accept", "application/json")]).await?;
        // deliberate difference (phase7/NOTES.md): a refusal is PHP's redirect back (JSON errors are for /api/* only) and
        // hte-console's 422 with the messages
        let want = if *side == "php" { 302 } else { 422 };
        if r.status != want {
            diffs.push(format!("hteadmin POST /account/theme (purple) on {side}: {}, not {want}", r.status));
        }
    }
    // a write with no token is refused by both
    for (side, base) in both.iter().zip([php, rust]).filter(|(s, _)| !rust_only || **s == "rust") {
        let cookie = cookie_for(&cfg, &crypt, "hteadmin", now);
        let r = fetch(&c, base, &cookie, "POST", "/account/theme", Some("application/json"), r#"{"theme":"dark"}"#.into(), &[]).await?;
        *total += 1;
        if r.status != 419 {
            diffs.push(format!("POST /account/theme without a token on {side}: {}, not 419", r.status));
        }
    }
    if (writes && !rust_only) || offline {
        dialogs(&c, php, rust, &side, &cfg, &crypt, now, diffs, by_design, total).await;
    }
    if offline {
        return Ok(());
    }
    write_steps(&c, php, rust, &cfg, &crypt, now, rust_only, diffs, total).await;
    Ok(())
}

type Round = (Vec<(&'static str, serde_json::Value)>, Vec<(&'static str, Vec<serde_json::Value>)>);

/// PHP's side of a write: Livewire calls on a page's component, in rounds (each round's answer carries the snapshot the
/// next one is sent against, as the browser does). A validation error is not an HTTP error: the databases show it.
async fn livewire(c: &reqwest::Client, php: &str, cookie: &str, page: &str, component: &str, rounds: Vec<Round>) -> Result<(), String> {
    livewire_html(c, php, cookie, page, component, rounds).await.map(|_| ())
}

/// The same, answering with the html the last round rendered for the component (what the browser swaps into the page).
async fn livewire_html(c: &reqwest::Client, php: &str, cookie: &str, page: &str, component: &str, rounds: Vec<Round>) -> Result<String, String> {
    let mut html = String::new();
    let first = fetch(c, php, cookie, "GET", page, None, String::new(), &[]).await?;
    if first.status != 200 {
        return Err(format!("PHP answered {} to GET {page}", first.status));
    }
    let mut snap = snapshot(&first.body, component).ok_or_else(|| format!("PHP's {page} has no {component} snapshot"))?;
    let uri = update_uri(&first.body);
    for (updates, calls) in rounds {
        let upd: serde_json::Map<String, serde_json::Value> = updates.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
        let calls: Vec<serde_json::Value> = calls.into_iter().map(|(m, p)| serde_json::json!({"path": "", "method": m, "params": p})).collect();
        let body = serde_json::json!({"_token": TOKEN, "components": [{"snapshot": snap, "updates": upd, "calls": calls}]});
        let r = fetch(c, php, cookie, "POST", &uri, Some("application/json"), body.to_string(), &[("x-livewire", "true"), ("x-csrf-token", TOKEN)]).await?;
        if r.status != 200 {
            return Err(format!("PHP's Livewire ({uri}) answered {} to {component}: {}", r.status, &r.body[..r.body.len().min(300)]));
        }
        let v: serde_json::Value = serde_json::from_str(&r.body).map_err(|e| format!("PHP's Livewire answer is not JSON: {e}"))?;
        if let Some(next) = v["components"][0]["snapshot"].as_str() {
            snap = next.to_string();
        }
        if let Some(h) = v["components"][0]["effects"]["html"].as_str() {
            html = h.to_string();
        }
    }
    Ok(html)
}

/// The dialog in a page or a component's html: the `modal fade show` element (its backdrop is a sibling and is left out).
fn dialog_of(html: &str) -> Option<&str> {
    // the last one: a dialog opened over another (PHP's delete review sits over the edit form) is the one in front
    let i = html.rfind("modal fade show")?;
    let start = html[..i].rfind("<div")?;
    let open_end = start + html[start..].find('>')? + 1;
    Some(&html[start..div_end(html, open_end)])
}

/// Dialogs: PHP opens them with a Livewire call on the component (their state is not in the URL), hte-console with a query
/// on the same page; what each shows (text and classes) is compared like a page.
async fn dialogs(c: &reqwest::Client, php: &str, rust: &str, side: &Side, cfg: &session::SessionConfig, crypt: &Encrypter, now: i64, diffs: &mut Vec<String>, by_design: &mut Vec<String>, total: &mut usize) {
    let mut layout = 0usize;
    let mut helper = 0usize;
    use serde_json::json;
    // (what, page, component, method, params, hte-console's query)
    let cases: Vec<(&str, &str, &str, &str, Vec<serde_json::Value>, &str)> = vec![
        ("strategies: add", "/strategies", "strategy-list", "create", vec![], "?create=1"),
        ("strategies: edit", "/strategies", "strategy-list", "edit", vec![json!(1)], "?edit=1"),
        ("strategies: assign", "/strategies", "strategy-list", "openAssign", vec![json!(1)], "?assign=1"),
        ("strategies: history", "/strategies", "strategy-list", "showHistory", vec![json!(1)], "?history=1"),
        ("strategies: compliance", "/strategies", "strategy-list", "showCompliance", vec![json!(1)], "?compliance=1"),
        ("strategies: delete", "/strategies", "strategy-list", "deleteStrategy", vec![json!(1)], "?delete=1"),
        ("users: add", "/users", "user-list", "create", vec![], "?create=1"),
        ("users: edit", "/users", "user-list", "edit", vec![json!(2)], "?edit=2"),
        ("users: devices", "/users", "user-list", "openAssign", vec![json!(2)], "?assign=2"),
        ("groups: add (devices)", "/groups", "group-list", "create", vec![json!("devices")], "?tab=devices&create=1"),
        ("groups: add (users)", "/groups", "group-list", "create", vec![json!("users")], "?tab=users&create=1"),
        ("groups: edit (devices)", "/groups", "group-list", "edit", vec![json!("devices"), json!(2)], "?tab=devices&edit=2"),
        ("devices: add", "/devices", "device-list", "create", vec![], "?create=1"),
        ("devices: delete", "/devices", "device-list", "confirmDelete", vec![json!(1)], "?delete=1"),
        ("device 1: edit", "/devices/1", "device-detail", "editDevice", vec![], "?edit=1"),
        ("device 1: delete", "/devices/1", "device-detail", "confirmDelete", vec![], "?delete=1"),
        ("roles: new", "/roles", "role-list", "create", vec![], "?create=1"),
        ("roles: edit", "/roles", "role-list", "edit", vec![json!(1)], "?edit=1"),
    ];
    let n_cases = cases.len();
    let cookie = cookie_for(cfg, crypt, "hteadmin", now);
    for (i, (what, page, component, method, params, query)) in cases.into_iter().enumerate() {
        *total += 1;
        let label = format!("hteadmin dialog {what}");
        let key = format!("d{i:02}");
        let mut clock = String::new();
        let got = match side {
            Side::From(d) => load_out(d, &key, &label).map(|o| {
                clock = o.at.to_string();
                o.body
            }),
            _ => {
                let at = chrono::Utc::now().timestamp();
                let h = livewire_html(c, php, &cookie, page, component, vec![(vec![], vec![(method, params)])]).await;
                if let (Side::Save(d), Ok(body)) = (side, &h) {
                    let o = Out { at, status: 200, ctype: String::new(), location: String::new(), disposition: String::new(), body: body.clone() };
                    if let Err(e) = save_out(d, &key, &label, &o) {
                        diffs.push(e);
                    }
                }
                h
            }
        };
        let php_html = match got {
            Ok(h) => h,
            Err(e) if matches!(side, Side::From(_)) && e.contains("capture from an older replay") => {
                *total -= 1;
                eprintln!("not in this capture (added after it was taken), not compared: {label}");
                continue;
            }
            Err(e) => {
                diffs.push(format!("{label} (PHP): {e}"));
                continue;
            }
        };
        let at: &[(&str, &str)] = if clock.is_empty() { &[] } else { &[("x-hte-replay-clock", clock.as_str())] };
        let ours = match fetch(c, rust, &cookie, "GET", &format!("{page}{query}"), None, String::new(), at).await {
            Ok(r) if r.status == 200 => r.body,
            Ok(r) => {
                diffs.push(format!("{label}: hte-console answered {} to GET {page}{query}", r.status));
                continue;
            }
            Err(e) => {
                diffs.push(format!("{label}: {e}"));
                continue;
            }
        };
        let (Some(a), Some(b)) = (dialog_of(&php_html), dialog_of(&ours)) else {
            diffs.push(format!("{label}: no dialog in {}", match (dialog_of(&php_html).is_some(), dialog_of(&ours).is_some()) { (false, false) => "either page", (false, true) => "PHP's answer", _ => "hte-console's page" }));
            continue;
        };
        let ((ta, ca), (tb, cb)) = (shape(a), shape(b));
        // text only: a dialog is hte-console's own layout (tabs or pills, widths, helper lines); what it says and offers is what is compared
        for d in all_differences(&ta, &tb) {
            // helper lines hte-console adds where PHP says nothing: an improvement, listed once as by design
            if d.contains("PHP has «» /") && (d.contains("«Ignored for an administrator.»") || d.contains("«Not used for an administrator.»")) {
                helper += 1;
                continue;
            }
            diffs.push(format!("{label}: text {d}"));
        }
        if ca != cb {
            layout += 1;
        }
    }
    if helper > 0 {
        by_design.push(format!("dialogs: by design (Users add/edit: hte-console says in a helper line that a role or the device groups do not apply to an administrator; PHP shows the field without saying so) ({helper} lines)"));
    }
    if layout > 0 {
        by_design.push(format!("dialogs: {DIALOG_LAYOUT_REASON} ({layout} of {n_cases} differ)"));
    }
}

/// The fields a browser would post for the form with this action: what each input, select and textarea holds now.
fn scrape_form(html: &str, action: &str) -> Vec<(String, String)> {
    static INPUT: Lazy<Regex> = Lazy::new(|| Regex::new(r#"(?s)<input\b([^>]*)>"#).unwrap());
    static SELECT: Lazy<Regex> = Lazy::new(|| Regex::new(r#"(?s)<select\b([^>]*)>(.*?)</select>"#).unwrap());
    static AREA: Lazy<Regex> = Lazy::new(|| Regex::new(r#"(?s)<textarea\b([^>]*)>(.*?)</textarea>"#).unwrap());
    static OPTION: Lazy<Regex> = Lazy::new(|| Regex::new(r#"(?s)<option\b([^>]*)>"#).unwrap());
    let attr = |tag: &str, name: &str| -> Option<String> {
        Regex::new(&format!(r#"(?s)(?:^|\s){name}\s*=\s*"([^"]*)""#)).unwrap().captures(tag).map(|m| decode(&m[1]))
    };
    let flag = |tag: &str, name: &str| Regex::new(&format!(r#"(?:^|\s){name}(?:\s|=|$|/)"#)).unwrap().is_match(tag);
    let Some(start) = html.find(&format!(r#"action="{action}""#)) else { return vec![] };
    let end = html[start..].find("</form>").map_or(html.len(), |e| start + e);
    let region = &html[start..end];
    let mut out = vec![];
    for m in INPUT.captures_iter(region) {
        let tag = &m[1];
        let (Some(name), false, false) = (attr(tag, "name"), flag(tag, "disabled"), attr(tag, "form").is_some()) else { continue };
        let kind = attr(tag, "type").unwrap_or_else(|| "text".into());
        match kind.as_str() {
            "checkbox" | "radio" => {
                if flag(tag, "checked") {
                    out.push((name, attr(tag, "value").unwrap_or_else(|| "on".into())));
                }
            }
            "submit" | "button" | "file" => {}
            _ => out.push((name, attr(tag, "value").unwrap_or_default())),
        }
    }
    for m in SELECT.captures_iter(region) {
        let (Some(name), false) = (attr(&m[1], "name"), flag(&m[1], "disabled") || attr(&m[1], "form").is_some()) else { continue };
        let opts: Vec<(String, bool)> = OPTION.captures_iter(&m[2]).map(|o| (attr(&o[1], "value").unwrap_or_default(), flag(&o[1], "selected"))).collect();
        if let Some((v, _)) = opts.iter().find(|(_, sel)| *sel).or(opts.first()) {
            out.push((name, v.clone()));
        }
    }
    for m in AREA.captures_iter(region) {
        if let (Some(name), false) = (attr(&m[1], "name"), flag(&m[1], "disabled")) {
            out.push((name, decode(m[2].trim_start_matches('\n'))));
        }
    }
    out
}

fn flag_error(diffs: &mut Vec<String>, label: &str, r: Result<(), String>) {
    if let Err(e) = r {
        diffs.push(format!("{label}: {e}"));
    }
}

/// The writes of the pages 7b ported, one per kind of change. Each is PHP's own Livewire call and hte-console's form post
/// of the same thing; the caller then compares the two databases row by row. A step that fails is reported and the
/// next one still runs, so one wrong guess about a PHP component does not hide the rest.
#[allow(clippy::too_many_arguments)]
async fn write_steps(c: &reqwest::Client, php: &str, rust: &str, cfg: &session::SessionConfig, crypt: &Encrypter, now: i64, rust_only: bool, diffs: &mut Vec<String>, total: &mut usize) {
    use serde_json::json;
    let int = |n: i64| json!(n);
    let ok = |st: u16| st == 302 || st == 200;
    let rust_form = |user: &'static str, path: String, fields: Vec<(String, String)>| {
        let (c, rust, cookie) = (c.clone(), rust.to_string(), cookie_for(cfg, crypt, user, now));
        async move {
            let body = laravel::http_build_query(&fields.iter().map(|(k, v)| (k.as_str(), v.as_bytes())).collect::<Vec<_>>());
            fetch(&c, &rust, &cookie, "POST", &path, Some("application/x-www-form-urlencoded"), body, &[("x-csrf-token", TOKEN)]).await
        }
    };
    let f = |pairs: &[(&str, &str)]| -> Vec<(String, String)> { pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect() };
    // (label, user, PHP page, component, rounds, hte-console path, hte-console fields, expected statuses)
    struct Step {
        label: &'static str,
        user: &'static str,
        page: &'static str,
        component: &'static str,
        rounds: Vec<Round>,
        path: &'static str,
        fields: Vec<(String, String)>,
    }
    let mut steps: Vec<Step> = vec![
        Step { label: "devices: approve a pending computer", user: "hteadmin", page: "/devices", component: "device-list", rounds: vec![(vec![], vec![("approveDevice", vec![int(4)])])], path: "/devices/act", fields: f(&[("do", "approve"), ("id", "4")]) },
        Step { label: "devices: delete a computer (the recycle bin)", user: "hteadmin", page: "/devices", component: "device-list", rounds: vec![(vec![], vec![("deleteDevice", vec![int(2)])])], path: "/devices/delete", fields: f(&[("ids[]", "2")]) },
        Step { label: "devices: restore it", user: "hteadmin", page: "/devices", component: "device-list", rounds: vec![(vec![], vec![("restoreDevice", vec![int(2)])])], path: "/devices/act", fields: f(&[("do", "restore"), ("id", "2")]) },
        Step { label: "device page: save the note", user: "hteadmin", page: "/devices/1", component: "device-detail", rounds: vec![(vec![("note", json!("Reception desk, left monitor"))], vec![("saveNote", vec![])])], path: "/devices/1/do", fields: f(&[("do", "note"), ("note", "Reception desk, left monitor")]) },
        Step { label: "groups: create a device group", user: "hteadmin", page: "/groups", component: "group-list", rounds: vec![(vec![], vec![("create", vec![json!("devices")])]), (vec![("name", json!("Lab")), ("note", json!("Test bench"))], vec![("save", vec![])])], path: "/groups/save", fields: f(&[("type", "devices"), ("name", "Lab"), ("note", "Test bench")]) },
        Step { label: "groups: delete a device group that has a computer in it", user: "hteadmin", page: "/groups", component: "group-list", rounds: vec![(vec![], vec![("deleteGroup", vec![json!("devices"), int(2)])])], path: "/groups/act", fields: f(&[("do", "delete"), ("type", "devices"), ("id", "2")]) },
        Step { label: "users: disable a person", user: "hteadmin", page: "/users", component: "user-list", rounds: vec![(vec![], vec![("toggleActive", vec![int(3)])])], path: "/users/act", fields: f(&[("do", "toggle"), ("id", "3")]) },
        Step { label: "users: enable them again", user: "hteadmin", page: "/users", component: "user-list", rounds: vec![(vec![], vec![("toggleActive", vec![int(3)])])], path: "/users/act", fields: f(&[("do", "toggle"), ("id", "3")]) },
        Step { label: "strategies: switch one off", user: "hteadmin", page: "/strategies", component: "strategy-list", rounds: vec![(vec![], vec![("toggleEnabled", vec![int(1)])])], path: "/strategies/toggle", fields: f(&[("id", "1")]) },
        Step { label: "address books: create a shared book", user: "hteadmin", page: "/address-books", component: "address-book-manager", rounds: vec![(vec![], vec![("openNewBook", vec![])]), (vec![("bookName", json!("Field techs")), ("bookNote", json!("Shared"))], vec![("createBook", vec![])])], path: "/address-books/act", fields: f(&[("do", "create-book"), ("book_name", "Field techs"), ("book_note", "Shared")]) },
        Step { label: "settings, Backups: schedule and retention", user: "hteadmin", page: "/settings", component: "backup-manager", rounds: vec![(vec![("enabled", json!(false)), ("keepDaily", int(3)), ("keepWeekly", int(2)), ("keepMonthly", int(1))], vec![("save", vec![])])], path: "/settings/backups/save", fields: f(&[("keep_daily", "3"), ("keep_weekly", "2"), ("keep_monthly", "1")]) },
        // 7c, Roles: a new role (the form posts every area, as the browser does), an edit, and the delete of a role someone holds
        Step {
            label: "roles: create a role",
            user: "hteadmin",
            page: "/roles",
            component: "role-list",
            rounds: vec![
                (vec![], vec![("create", vec![])]),
                (vec![("name", json!("Helpdesk")), ("description", json!("Front line")), ("permissions.device", json!("r")), ("permissions.setting", json!("rw")), ("require_two_factor", json!(true))], vec![("save", vec![])]),
            ],
            path: "/roles/save",
            fields: f(&[("id", "0"), ("name", "Helpdesk"), ("description", "Front line"), ("permissions[device]", "r"), ("permissions[user]", "none"), ("permissions[group]", "none"), ("permissions[address_book]", "rw"), ("permissions[audit]", "r"), ("permissions[strategy]", "none"), ("permissions[setting]", "rw"), ("permissions[token]", "none"), ("require_two_factor", "1")]),
        },
        Step {
            label: "roles: a name that is taken (refused on both)",
            user: "hteadmin",
            page: "/roles",
            component: "role-list",
            rounds: vec![(vec![], vec![("create", vec![])]), (vec![("name", json!("Auditor"))], vec![("save", vec![])])],
            path: "/roles/save",
            fields: f(&[("id", "0"), ("name", "Auditor"), ("description", ""), ("permissions[device]", "rw"), ("permissions[address_book]", "rw"), ("permissions[audit]", "r")]),
        },
        Step {
            label: "roles: edit a role",
            user: "hteadmin",
            page: "/roles",
            component: "role-list",
            rounds: vec![(vec![], vec![("edit", vec![int(1)])]), (vec![("description", json!("Read-only logs")), ("permissions.device", json!("r"))], vec![("save", vec![])])],
            path: "/roles/save",
            fields: f(&[("id", "1"), ("name", "Auditor"), ("description", "Read-only logs"), ("permissions[device]", "r"), ("permissions[user]", "none"), ("permissions[group]", "none"), ("permissions[address_book]", "none"), ("permissions[audit]", "rw"), ("permissions[strategy]", "none"), ("permissions[setting]", "none"), ("permissions[token]", "none")]),
        },
        Step { label: "roles: delete a role someone holds", user: "hteadmin", page: "/roles", component: "role-list", rounds: vec![(vec![], vec![("deleteRole", vec![int(1)])])], path: "/roles/delete", fields: f(&[("id", "1")]) },
        Step { label: "settings, Maintenance: Prune now", user: "hteadmin", page: "/settings", component: "settings-page", rounds: vec![(vec![("logRetentionDays", int(30))], vec![("pruneNow", vec![])])], path: "/settings/prune", fields: f(&[("log_retention_days", "30")]) },
    ];
    let mut phase = 0;
    let mut steps = steps;
    loop {
        for st in steps.drain(..) {
            *total += 1;
            if !rust_only {
                let cookie = cookie_for(cfg, crypt, st.user, now);
                flag_error(diffs, &format!("{} (PHP)", st.label), livewire(c, php, &cookie, st.page, st.component, st.rounds).await);
            }
            match rust_form(st.user, st.path.to_string(), st.fields).await {
                Ok(r) if ok(r.status) || (st.label.contains("refused on both") && r.status == 422) => {}
                Ok(r) => diffs.push(format!("{}: hte-console answered {} to POST {}", st.label, r.status, st.path)),
                Err(e) => diffs.push(format!("{}: {e}", st.label)),
            }
        }
        if phase == 1 {
            break;
        }
        phase = 1;
    // the Settings form: PHP saves the page as it loaded with one field changed; hte-console posts the form it rendered, the same field changed
        let rust_page = match fetch(c, rust, &cookie_for(cfg, crypt, "hteadmin", now), "GET", "/settings", None, String::new(), &[]).await {
            Ok(p) => p,
            Err(e) => {
                diffs.push(format!("settings: cannot read hte-console's page: {e}"));
                return;
            }
        };
        let mut form = scrape_form(&rust_page.body, "/settings/save");
        for (k, v) in form.iter_mut() {
            if k == "online_window" {
                *v = "45".into();
            }
        }
        if !form.iter().any(|(k, _)| k == "online_window") {
            diffs.push("settings: hte-console's form has no online_window field".into());
        }
            steps.push(Step { label: "settings: save the server tab", user: "hteadmin", page: "/settings", component: "settings-page", rounds: vec![(vec![("onlineWindow", int(45))], vec![("save", vec![])])], path: "/settings/save", fields: form });

    }
    // an API token (in PHP a Livewire component inside Settings, which has no /api-tokens page): the plaintext and the hash are random, so only that both sides made one, with the same name,
    // permissions and expiry, is compared (the caller masks token_hash, token_prefix and the date it computes)
    *total += 1;
    if !rust_only {
        let cookie = cookie_for(cfg, crypt, "hteadmin", now);
        flag_error(
            diffs,
            "api tokens: create (PHP)",
            livewire(c, php, &cookie, "/settings", "api-token-manager", vec![(vec![], vec![("create", vec![])]), (vec![("name", json!("ci")), ("expiresDays", int(30)), ("permissions.device", json!("rw")), ("permissions.audit", json!("r"))], vec![("save", vec![])])]).await,
        );
    }
    match rust_form("hteadmin", "/api-tokens".into(), f(&[("name", "ci"), ("expires_days", "30"), ("perm_device", "rw"), ("perm_audit", "r")])).await {
        Ok(r) if r.status == 200 && r.body.contains("cdk_") => {}
        Ok(r) => diffs.push(format!("api tokens: hte-console answered {} to the create post", r.status)),
        Err(e) => diffs.push(format!("api tokens: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_of_clock_is_not_a_difference_read_back() {
        assert!(one_second_apart("at item 142, after «dana · v1.4.0 ·»: PHP has «43s» / hte-console has «42s»"));
        assert!(one_second_apart("at item 127, after «x»: PHP has «43» / hte-console has «42»"));
        assert!(!one_second_apart("at item 127, after «x»: PHP has «43» / hte-console has «41»"));
        assert!(!one_second_apart("at item 127, after «x»: PHP has «3s» / hte-console has «3m»"));
    }

    #[test]
    fn a_saved_php_answer_reads_back_only_for_the_same_request() {
        let dir = tempfile::tempdir().unwrap();
        let o = Out { at: 1_761_400_000, status: 302, ctype: "text/html".into(), location: "/login".into(), disposition: String::new(), body: "<p>é</p>".into() };
        save_out(dir.path(), "p007", "dana GET /devices", &o).unwrap();
        let back = load_out(dir.path(), "p007", "dana GET /devices").unwrap();
        assert_eq!((back.at, back.status, back.location.as_str(), back.body.as_str()), (1_761_400_000, 302, "/login", "<p>é</p>"));
        // another request at that place: the capture belongs to another version of the replay
        assert!(load_out(dir.path(), "p007", "erin GET /devices").unwrap_err().contains("take a new one"));
        assert!(load_out(dir.path(), "p008", "dana GET /users").unwrap_err().contains("take a new one"));
    }

    #[test]
    fn hidden_groups_are_cut_whole_and_shown_ones_kept() {
        let html = r#"<p>a</p><div class="mb-3 d-none" data-rd-group="m" data-rd-when="x"><div>inner</div><span>gone</span></div><div class="mb-3" data-rd-group="m" data-rd-when="y"><b>kept</b></div><p>z</p>"#;
        assert_eq!(without_hidden_groups(html), r#"<p>a</p><div class="mb-3" data-rd-group="m" data-rd-when="y"><b>kept</b></div><p>z</p>"#);
    }

    #[test]
    fn shape_reads_text_and_classes_not_livewire() {
        let a = r#"<html><body class="x"><div wire:id="1" wire:snapshot="{&quot;a&quot;:1}"><button type="button" class="btn  btn-primary" wire:click="go">Go &amp; <b>stop</b></button><script>var x = "<p>";</script><!-- note --></div><script src="/bootstrap.bundle.min.js"></script><p>after</p>"#;
        let b = r#"<html><body class="x"><div><a class="btn btn-primary" href="/go">Go &amp; <b>stop</b></a></div><script src="x/bootstrap.bundle.min.js"></script>"#;
        assert_eq!(shape(a), shape(b));
        assert_eq!(shape(a).0, vec!["Go", "&", "stop"]);
        assert_eq!(shape(a).1, vec!["x", "btn btn-primary"]);
        let d = all_differences(&["a".into(), "b".into()], &["a".into(), "c".into()]);
        assert!(d.len() == 1 && d[0].contains("item 1"), "{d:?}");
        // one extra element, then more differences: each place once, not everything after the first
        let (x, y): (Vec<String>, Vec<String>) = ("a b c d e f g".split(' ').map(String::from).collect(), "a X b c d Y f g".split(' ').map(String::from).collect());
        let d = all_differences(&x, &y);
        assert_eq!(d.len(), 2, "{d:?}");
        assert!(all_differences(&x, &x).is_empty());
    }

    #[test]
    fn the_seed_is_sql_with_relative_times_and_every_person() {
        std::env::set_var("BCRYPT_ROUNDS", "4");
        let s = seed_sql(1_761_362_400).unwrap();
        assert!(s.contains("INSERT INTO users") && s.contains("INSERT INTO sessions") && s.contains("'dana'"));
        assert_eq!(s.matches("INSERT INTO alarm_logs").count(), 27 + 5);
        let c = rusqlite::Connection::open_in_memory().unwrap();
        c.execute_batch(include_str!("../tests/schema_live.sql")).unwrap();
        c.execute_batch(&s).unwrap();
        let n: i64 = c.query_row("select count(*) from sessions", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 3);
    }
}
