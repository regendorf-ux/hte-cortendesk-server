//! `hte-console page-seed <now>` and `hte-console page-replay <reference-url> <candidate-url> <now>`: the console's pages
//! asked of two hte-console instances (a reference build and a candidate), each on its own copy of the same synthetic
//! database, and compared.
//!
//! `page-seed` prints the SQL that makes the people, devices, log rows and sessions both sides start from. Rows are
//! timed from `<now>` in the middle of a unit ("5 minutes 30 seconds ago"), so the seconds that pass between the two
//! answers to the same request cannot move a relative time across a boundary. The sessions are rows of the database's
//! `sessions` table in the format inherited from the previous console; the cookies are minted here with the database's
//! app key and the session cookie's name.
//!
//! `page-replay` asks each page of both, one after the other, and compares what a person reads: the status and the
//! redirect, and for an HTML page the visible text and the sequence of `class` attributes (scripts and markup that carries
//! no class are not part of what the page looks like); a CSV or JSON download exactly. The dialogs (opened by a query on
//! their page) are compared the same way. With writes, the candidate then takes the form posts of every kind of change;
//! the caller compares its database with what it expects (or with the reference's after the same posts).

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
    status: u16,
    ctype: String,
    location: String,
    disposition: String,
    body: String,
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

async fn fetch(c: &reqwest::Client, base: &str, cookie: &str, method: &str, path: &str, ct: Option<&str>, body: String, extra: &[(&str, &str)]) -> Result<Out, String> {
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
    Ok(Out { status, ctype, location, disposition, body: r.text().await.map_err(|e| e.to_string())? })
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
        format!("at item {at}, after «{ctx}»: the reference has «{}» / the candidate has «{}»", show(gone), show(added))
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

pub async fn run(reference: &str, candidate: &str, key: &str, cookie_name: &str, now: i64) -> Result<Report, String> {
    run_with(reference, candidate, key, cookie_name, now, true).await
}

/// `writes` false: only the reads (pages, downloads, dialogs). With writes, the candidate also takes the form posts.
pub async fn run_with(reference: &str, candidate: &str, key: &str, cookie_name: &str, now: i64, writes: bool) -> Result<Report, String> {
    let mut diffs: Vec<String> = vec![];
    let mut total = 0usize;
    // an error part way is reported with the differences found before it, not instead of them
    if let Err(e) = run_inner(reference, candidate, key, cookie_name, now, writes, &mut diffs, &mut total).await {
        diffs.push(format!("the replay stopped: {e}"));
    }
    Ok(Report { total, differences: diffs, by_design: vec![] })
}

#[allow(clippy::too_many_arguments)]
async fn run_inner(reference: &str, candidate: &str, key: &str, cookie_name: &str, now: i64, writes: bool, diffs: &mut Vec<String>, total: &mut usize) -> Result<(), String> {
    let crypt = Encrypter::from_app_key(key)?;
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
    // the CSV exports: the same filters on both, the exact bytes, the content type and the file name compared
    for (user, page, query) in [
        ("hteadmin", "/logs/alarms", ""),
        ("dana", "/logs/alarms", ""),
        ("hteadmin", "/logs/alarms", "?type=2&search=10.0.0"),
        ("hteadmin", "/logs/connections", ""),
        ("dana", "/logs/connections", ""),
        ("hteadmin", "/logs/file-transfers", ""),
        ("dana", "/logs/file-transfers", ""),
        ("hteadmin", "/logs/logins", ""),
        ("hteadmin", "/logs/console", ""),
    ] {
        cases.push((user, format!("{page}/export{query}")));
    }
    for (user, path) in cases.iter() {
        let cookie = cookie_for(&cfg, &crypt, user, now);
        let a = fetch(&c, reference, &cookie, "GET", path, None, String::new(), &[]).await?;
        let b = fetch(&c, candidate, &cookie, "GET", path, None, String::new(), &[]).await?;
        *total += 1;
        let label = format!("{user} GET {path}");
        if (a.status, &a.location) != (b.status, &b.location) {
            diffs.push(format!("{label}: reference {} {} / candidate {} {}", a.status, a.location, b.status, b.location));
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
                (Some(x), Some(y)) => diffs.push(format!("{label}: the JSON differs (content types «{}» / «{}», dispositions «{}» / «{}»): reference {x} / candidate {y}", a.ctype, b.ctype, a.disposition, b.disposition)),
                _ => diffs.push(format!("{label}: not JSON on one side (reference {} bytes, candidate {})", a.body.len(), b.body.len())),
            }
        } else if path.contains("/export") {
            if a.body != b.body || a.ctype != b.ctype || a.disposition != b.disposition {
                diffs.push(format!("{label}: the download differs (reference {} bytes, candidate {}; content types «{}» / «{}»; «{}» / «{}»)", a.body.len(), b.body.len(), a.ctype, b.ctype, a.disposition, b.disposition));
            }
        } else {
            let ((ta, ca), (tb, cb)) = (shape(&a.body), shape(&b.body));
            for d in all_differences(&ta, &tb) {
                diffs.push(format!("{label}: text {d}"));
            }
            for d in all_differences(&ca, &cb) {
                diffs.push(format!("{label}: classes {d}"));
            }
        }
    }
    dialogs(&c, reference, candidate, &cfg, &crypt, now, diffs, total).await;
    if !writes {
        return Ok(());
    }
    // the writes, on the candidate: the account (profile, password, theme), then every kind of change the pages make
    let post_form = |path: &'static str, fields: Vec<(&'static str, String)>| {
        let body = laravel::http_build_query(&fields.iter().map(|(k, v)| (*k, v.as_bytes())).collect::<Vec<_>>());
        (path, body)
    };
    let post = |user: &'static str, path: &'static str, body: String, ct: &'static str| {
        let (c, base, cookie) = (c.clone(), candidate.to_string(), cookie_for(&cfg, &crypt, user, now));
        async move { fetch(&c, &base, &cookie, "POST", path, Some(ct), body, &[("x-csrf-token", TOKEN)]).await }
    };
    // the profile: a name and an email, a taken email (refused: nothing written), then blanks
    for (fields, want) in [
        (vec![("name", "Dana S".to_string()), ("email", "dana2@example.test".to_string())], 302),
        (vec![("name", "Dana S".to_string()), ("email", "admin@example.test".to_string())], 422),
        (vec![("name", String::new()), ("email", String::new())], 0),
    ] {
        let (p, b) = post_form("/account/profile", fields);
        let r = post("dana", p, b, "application/x-www-form-urlencoded").await?;
        if want != 0 {
            *total += 1;
            if r.status != want {
                diffs.push(format!("dana POST /account/profile: {}, not {want}", r.status));
            }
        }
    }
    // the password (erin): wrong current, then the change
    let (p, b) = post_form("/account/password", vec![("current_password", "wrong password".into()), ("password", "newpassword1".into()), ("password_confirmation", "newpassword1".into())]);
    let r = post("erin", p, b, "application/x-www-form-urlencoded").await?;
    *total += 1;
    if r.status != 422 || !r.body.contains("That is not your current password.") {
        diffs.push(format!("erin POST /account/password (wrong current): {}", r.status));
    }
    let (p, b) = post_form("/account/password", vec![("current_password", PASSWORD.into()), ("password", "newpassword1".into()), ("password_confirmation", "newpassword1".into())]);
    let r = post("erin", p, b, "application/x-www-form-urlencoded").await?;
    *total += 1;
    if r.status != 302 {
        diffs.push(format!("erin POST /account/password: {}", r.status));
    }
    // the theme: taken, a bad value refused with the messages, no token refused
    let cookie = cookie_for(&cfg, &crypt, "hteadmin", now);
    for (body, headers, want) in [
        (r#"{"theme":"light"}"#, vec![("x-csrf-token", TOKEN), ("accept", "application/json")], 204),
        (r#"{"theme":"purple"}"#, vec![("x-csrf-token", TOKEN), ("accept", "application/json")], 422),
        (r#"{"theme":"dark"}"#, vec![], 419),
    ] {
        let r = fetch(&c, candidate, &cookie, "POST", "/account/theme", Some("application/json"), body.into(), &headers).await?;
        *total += 1;
        if r.status != want {
            diffs.push(format!("hteadmin POST /account/theme {body}: {}, not {want}", r.status));
        }
    }
    write_steps(&c, candidate, &cfg, &crypt, now, diffs, total).await;
    Ok(())
}

/// The dialog in a page or a component's html: the `modal fade show` element (its backdrop is a sibling and is left out).
fn dialog_of(html: &str) -> Option<&str> {
    // the last one: a dialog opened over another (a delete review sits over the edit form) is the one in front
    let i = html.rfind("modal fade show")?;
    let start = html[..i].rfind("<div")?;
    let open_end = start + html[start..].find('>')? + 1;
    Some(&html[start..div_end(html, open_end)])
}

/// Dialogs open with a query on their page (their state is in the URL); what each shows (text and classes) is compared like a page.
#[allow(clippy::too_many_arguments)]
async fn dialogs(c: &reqwest::Client, reference: &str, candidate: &str, cfg: &session::SessionConfig, crypt: &Encrypter, now: i64, diffs: &mut Vec<String>, total: &mut usize) {
    let cases: [(&str, &str); 18] = [
        ("strategies: add", "/strategies?create=1"),
        ("strategies: edit", "/strategies?edit=1"),
        ("strategies: assign", "/strategies?assign=1"),
        ("strategies: history", "/strategies?history=1"),
        ("strategies: compliance", "/strategies?compliance=1"),
        ("strategies: delete", "/strategies?delete=1"),
        ("users: add", "/users?create=1"),
        ("users: edit", "/users?edit=2"),
        ("users: devices", "/users?assign=2"),
        ("groups: add (devices)", "/groups?tab=devices&create=1"),
        ("groups: add (users)", "/groups?tab=users&create=1"),
        ("groups: edit (devices)", "/groups?tab=devices&edit=2"),
        ("devices: add", "/devices?create=1"),
        ("devices: delete", "/devices?delete=1"),
        ("device 1: edit", "/devices/1?edit=1"),
        ("device 1: delete", "/devices/1?delete=1"),
        ("roles: new", "/roles?create=1"),
        ("roles: edit", "/roles?edit=1"),
    ];
    let cookie = cookie_for(cfg, crypt, "hteadmin", now);
    for (what, path) in cases {
        *total += 1;
        let label = format!("hteadmin dialog {what}");
        let mut pages = vec![];
        for base in [reference, candidate] {
            match fetch(c, base, &cookie, "GET", path, None, String::new(), &[]).await {
                Ok(r) if r.status == 200 => pages.push(r.body),
                Ok(r) => diffs.push(format!("{label}: {} answered {} to GET {path}", if base == reference { "the reference" } else { "the candidate" }, r.status)),
                Err(e) => diffs.push(format!("{label}: {e}")),
            }
        }
        let [a, b] = pages.as_slice() else { continue };
        let (Some(a), Some(b)) = (dialog_of(a), dialog_of(b)) else {
            diffs.push(format!("{label}: no dialog on {}", match (dialog_of(a).is_some(), dialog_of(b).is_some()) { (false, false) => "either side", (false, true) => "the reference", _ => "the candidate" }));
            continue;
        };
        let ((ta, ca), (tb, cb)) = (shape(a), shape(b));
        for d in all_differences(&ta, &tb) {
            diffs.push(format!("{label}: text {d}"));
        }
        for d in all_differences(&ca, &cb) {
            diffs.push(format!("{label}: classes {d}"));
        }
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

/// The writes of the pages, one form post per kind of change, on the candidate. A step that fails is reported and the
/// next one still runs, so one refusal does not hide the rest.
async fn write_steps(c: &reqwest::Client, candidate: &str, cfg: &session::SessionConfig, crypt: &Encrypter, now: i64, diffs: &mut Vec<String>, total: &mut usize) {
    let form = |user: &'static str, path: String, fields: Vec<(String, String)>| {
        let (c, base, cookie) = (c.clone(), candidate.to_string(), cookie_for(cfg, crypt, user, now));
        async move {
            let body = laravel::http_build_query(&fields.iter().map(|(k, v)| (k.as_str(), v.as_bytes())).collect::<Vec<_>>());
            fetch(&c, &base, &cookie, "POST", &path, Some("application/x-www-form-urlencoded"), body, &[("x-csrf-token", TOKEN)]).await
        }
    };
    let f = |pairs: &[(&str, &str)]| -> Vec<(String, String)> { pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect() };
    // (what, user, path, fields, a refusal expected)
    let mut steps: Vec<(&str, &str, &str, Vec<(String, String)>, bool)> = vec![
        ("devices: approve a pending computer", "hteadmin", "/devices/act", f(&[("do", "approve"), ("id", "4")]), false),
        ("devices: delete a computer (the recycle bin)", "hteadmin", "/devices/delete", f(&[("ids[]", "2")]), false),
        ("devices: restore it", "hteadmin", "/devices/act", f(&[("do", "restore"), ("id", "2")]), false),
        ("device page: save the note", "hteadmin", "/devices/1/do", f(&[("do", "note"), ("note", "Reception desk, left monitor")]), false),
        ("groups: create a device group", "hteadmin", "/groups/save", f(&[("type", "devices"), ("name", "Lab"), ("note", "Test bench")]), false),
        ("groups: delete a device group that has a computer in it", "hteadmin", "/groups/act", f(&[("do", "delete"), ("type", "devices"), ("id", "2")]), false),
        ("users: disable a person", "hteadmin", "/users/act", f(&[("do", "toggle"), ("id", "3")]), false),
        ("users: enable them again", "hteadmin", "/users/act", f(&[("do", "toggle"), ("id", "3")]), false),
        ("strategies: switch one off", "hteadmin", "/strategies/toggle", f(&[("id", "1")]), false),
        ("address books: create a shared book", "hteadmin", "/address-books/act", f(&[("do", "create-book"), ("book_name", "Field techs"), ("book_note", "Shared")]), false),
        ("settings, Backups: schedule and retention", "hteadmin", "/settings/backups/save", f(&[("keep_daily", "3"), ("keep_weekly", "2"), ("keep_monthly", "1")]), false),
        // Roles: a new role (the form posts every area, as the browser does), a taken name, an edit, and the delete of a role someone holds
        ("roles: create a role", "hteadmin", "/roles/save", f(&[("id", "0"), ("name", "Helpdesk"), ("description", "Front line"), ("permissions[device]", "r"), ("permissions[user]", "none"), ("permissions[group]", "none"), ("permissions[address_book]", "rw"), ("permissions[audit]", "r"), ("permissions[strategy]", "none"), ("permissions[setting]", "rw"), ("permissions[token]", "none"), ("require_two_factor", "1")]), false),
        ("roles: a name that is taken", "hteadmin", "/roles/save", f(&[("id", "0"), ("name", "Auditor"), ("description", ""), ("permissions[device]", "rw"), ("permissions[address_book]", "rw"), ("permissions[audit]", "r")]), true),
        ("roles: edit a role", "hteadmin", "/roles/save", f(&[("id", "1"), ("name", "Auditor"), ("description", "Read-only logs"), ("permissions[device]", "r"), ("permissions[user]", "none"), ("permissions[group]", "none"), ("permissions[address_book]", "none"), ("permissions[audit]", "rw"), ("permissions[strategy]", "none"), ("permissions[setting]", "none"), ("permissions[token]", "none")]), false),
        ("roles: delete a role someone holds", "hteadmin", "/roles/delete", f(&[("id", "1")]), false),
        ("settings, Maintenance: Prune now", "hteadmin", "/settings/prune", f(&[("log_retention_days", "30")]), false),
    ];
    // the Settings form: posted as the page renders it, one field changed
    match fetch(c, candidate, &cookie_for(cfg, crypt, "hteadmin", now), "GET", "/settings", None, String::new(), &[]).await {
        Ok(page) => {
            let mut fields = scrape_form(&page.body, "/settings/save");
            if !fields.iter().any(|(k, _)| k == "online_window") {
                diffs.push("settings: the form has no online_window field".into());
            }
            for (k, v) in fields.iter_mut() {
                if k == "online_window" {
                    *v = "45".into();
                }
            }
            steps.insert(steps.len() - 1, ("settings: save the server tab", "hteadmin", "/settings/save", fields, false));
        }
        Err(e) => diffs.push(format!("settings: cannot read the page: {e}")),
    }
    for (what, user, path, fields, refused) in steps {
        *total += 1;
        match form(user, path.to_string(), fields).await {
            Ok(r) if (!refused && (r.status == 302 || r.status == 200)) || (refused && r.status == 422) => {}
            Ok(r) => diffs.push(format!("{what}: {} to POST {path}", r.status)),
            Err(e) => diffs.push(format!("{what}: {e}")),
        }
    }
    // an API token: the plaintext and the hash are random, so only that one was made (shown once) is checked here
    *total += 1;
    match form("hteadmin", "/api-tokens".into(), f(&[("name", "ci"), ("expires_days", "30"), ("perm_device", "rw"), ("perm_audit", "r")])).await {
        Ok(r) if r.status == 200 && r.body.contains("cdk_") => {}
        Ok(r) => diffs.push(format!("api tokens: {} to the create post", r.status)),
        Err(e) => diffs.push(format!("api tokens: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shape_reads_text_and_classes_only() {
        let a = r#"<html><body class="x"><div data-id="1" data-state="{&quot;a&quot;:1}"><button type="button" class="btn  btn-primary" data-go="1">Go &amp; <b>stop</b></button><script>var x = "<p>";</script><!-- note --></div><script src="/bootstrap.bundle.min.js"></script><p>after</p>"#;
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
