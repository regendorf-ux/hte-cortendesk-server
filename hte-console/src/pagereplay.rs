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
    for (id, rd, owner) in [(1, "1001", "2"), (2, "1002", "null"), (3, "1003", "2")] {
        s.push_str(&format!("INSERT INTO devices (id, rustdesk_id, uuid, user_id, status, created_at, updated_at) VALUES ({id}, '{rd}', 'uuid-{id}', {owner}, 'active', '2025-01-01 00:00:00', '2025-01-01 00:00:00');\n"));
    }
    s.push_str("UPDATE devices SET deleted_at = '2025-10-01 00:00:00' WHERE id = 3;\n");
    // what the 7b pages show: computers with names, systems, versions and a group, a user group, a strategy, an address book
    // with a tag and an entry, one session still open
    s.push_str(&format!(
        "UPDATE devices SET hostname = 'FRONT-PC', os = 'windows / Windows 11', version = '1.4.0', alias = 'Front PC', username = 'dana', device_group_id = 1, last_online_at = {}, last_online_ip = '10.0.0.1' WHERE id = 1;\n\
         UPDATE devices SET hostname = 'BACK-PC', os = 'macos / macOS 14', version = '1.3.9', username = 'erin', last_online_at = {}, last_online_ip = '10.0.0.2' WHERE id = 2;\n",
        t(30), t(500_000)
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

fn first_difference(a: &[String], b: &[String]) -> Option<String> {
    if a == b {
        return None;
    }
    let i = a.iter().zip(b).position(|(x, y)| x != y).unwrap_or(a.len().min(b.len()));
    let ctx = |v: &[String]| v[i.saturating_sub(6)..(i + 8).min(v.len())].join(" ");
    Some(format!("at item {i}: PHP «{}» / hte-console «{}»", ctx(a), ctx(b)))
}

pub struct Report {
    pub total: usize,
    pub differences: Vec<String>,
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
    // an error part way (a write PHP will not take, say) is reported with the differences found before it, not instead of them
    if let Err(e) = run_inner(php, rust, key, cookie_name, now, writes, &mut diffs, &mut total).await {
        diffs.push(format!("the replay stopped: {e}"));
    }
    Ok(Report { total, differences: diffs })
}

async fn run_inner(php: &str, rust: &str, key: &str, cookie_name: &str, now: i64, writes: bool, diffs: &mut Vec<String>, total: &mut usize) -> Result<(), String> {
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
    for (user, path) in &cases {
        let cookie = cookie_for(&cfg, &crypt, user, now);
        let a = fetch(&c, php, &cookie, "GET", path, None, String::new(), &[]).await?;
        let b = fetch(&c, rust, &cookie, "GET", path, None, String::new(), &[]).await?;
        *total += 1;
        let label = format!("{user} GET {path}");
        if (a.status, &a.location) != (b.status, &b.location) {
            diffs.push(format!("{label}: PHP {} {} / hte-console {} {}", a.status, a.location, b.status, b.location));
            continue;
        }
        if a.status != 200 {
            // a redirect: the status and where to are what a person gets (its body names the host)
        } else if path.contains("/export") {
            // streamDownload's headers and the exact file
            if a.body != b.body || a.ctype != b.ctype {
                diffs.push(format!("{label}: the CSV differs (PHP {} bytes, hte-console {}; content types «{}» / «{}»)", a.body.len(), b.body.len(), a.ctype, b.ctype));
            }
        } else if a.status == 200 {
            let ((ta, ca), (tb, cb)) = (shape(&a.body), shape(&b.body));
            if let Some(d) = first_difference(&ta, &tb) {
                diffs.push(format!("{label}: text {d}"));
            }
            if let Some(d) = first_difference(&ca, &cb) {
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
    for (side, base) in both.iter().zip([php, rust]) {
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
    for (side, base) in both.iter().zip([php, rust]) {
        let cookie = cookie_for(&cfg, &crypt, "hteadmin", now);
        let r = fetch(&c, base, &cookie, "POST", "/account/theme", Some("application/json"), r#"{"theme":"dark"}"#.into(), &[]).await?;
        *total += 1;
        if r.status != 419 {
            diffs.push(format!("POST /account/theme without a token on {side}: {}, not 419", r.status));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shape_reads_text_and_classes_not_livewire() {
        let a = r#"<html><body class="x"><div wire:id="1" wire:snapshot="{&quot;a&quot;:1}"><button type="button" class="btn  btn-primary" wire:click="go">Go &amp; <b>stop</b></button><script>var x = "<p>";</script><!-- note --></div><script src="/bootstrap.bundle.min.js"></script><p>after</p>"#;
        let b = r#"<html><body class="x"><div><a class="btn btn-primary" href="/go">Go &amp; <b>stop</b></a></div><script src="x/bootstrap.bundle.min.js"></script>"#;
        assert_eq!(shape(a), shape(b));
        assert_eq!(shape(a).0, vec!["Go", "&", "stop"]);
        assert_eq!(shape(a).1, vec!["x", "btn btn-primary"]);
        assert!(first_difference(&["a".into(), "b".into()], &["a".into(), "c".into()]).unwrap().contains("item 1"));
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
