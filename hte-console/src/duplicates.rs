//! `App\Services\DuplicateDevices` (issue #91) and `Device::platform()`, for the admin API's `possible_duplicates`.
//!
//! The same two grouped queries and one fetch as PHP; the pairing, the dismissals and the ordering of the twins are
//! PHP's, rule for rule. Only rows in the scope take part (the admin API passes the approved, not trashed devices).

use crate::laravel;
use crate::php::{self, Fault, Val};
use crate::sqlite::{self as db, Row, P};
use regex::Regex;
use rusqlite::Connection;
use std::collections::HashMap;

const HOST_SQL: &str = "LOWER(TRIM(devices.hostname))";
const USER_SQL: &str = "LOWER(TRIM(devices.username))";
const COLUMNS: &str = r#""devices"."id", "devices"."rustdesk_id", "devices"."uuid", "devices"."hostname", "devices"."username", "devices"."os", "devices"."alias", "devices"."last_online_at", "devices"."created_at""#;
/// `Device::query()->approved()`: the soft-delete scope and `status = 'active'`.
const SCOPE: &str = r#""status" = 'active' and "devices"."deleted_at" is null"#;

const GENERIC_HOSTNAMES: &[&str] = &[
    "localhost", "localhost.localdomain", "localdomain", "ubuntu", "debian", "raspberrypi", "kali", "fedora", "centos", "archlinux", "linux",
    "android", "windows", "pc", "desktop", "laptop", "computer", "workstation", "server", "host", "user-pc", "admin-pc", "vm", "unknown",
    "default", "none", "(none)",
];

fn strength(reason: &str) -> u8 {
    if reason == "uuid" { 2 } else { 1 }
}

/// `Device::platform()`: windows, macos, android, ios, linux or unknown, from the OS string.
pub fn platform(os: &Val) -> String {
    let os = match os {
        Val::Null => String::new(),
        v => String::from_utf8_lossy(&v.to_php_string().unwrap_or_default()).to_ascii_lowercase(),
    };
    let has = |s: &str| os.contains(s);
    if has("windows") {
        "windows"
    } else if has("mac") || has("darwin") {
        "macos"
    } else if has("android") {
        "android"
    } else if has("ios") {
        "ios"
    } else if has("linux") || has("ubuntu") || has("debian") || has("fedora") || has("arch") || has("centos") {
        "linux"
    } else {
        "unknown"
    }
    .to_string()
}

/// `mb_strtolower(trim($value))`
fn normalize(v: &Val) -> Result<String, Fault> {
    let s = v.to_php_string()?;
    Ok(String::from_utf8_lossy(php::trim(&s)).to_lowercase())
}

pub fn is_generic_hostname(hostname: &str) -> bool {
    static PATTERN: once_cell::sync::Lazy<Regex> =
        once_cell::sync::Lazy::new(|| Regex::new(r"^(macbook(-?pro|-?air)?|imac(-?pro)?|mac-?(mini|studio|pro)|iphone|ipad)(-\d+)?(\.local)?$").unwrap());
    let host = hostname.trim_matches([' ', '\t', '\n', '\r', '\0', '\x0b']).to_lowercase();
    host.is_empty() || GENERIC_HOSTNAMES.contains(&host.as_str()) || PATTERN.is_match(&host)
}

/// Grouping key for the hostname signal: hostname, OS user and platform, or None.
fn match_key(d: &Row) -> Result<Option<Vec<u8>>, Fault> {
    let host = normalize(&d.val("hostname"))?;
    let user = normalize(&d.val("username"))?;
    let platform = platform(&d.val("os"));
    if host.is_empty() || user.is_empty() || is_generic_hostname(&host) || platform == "android" || platform == "ios" {
        return Ok(None);
    }
    let mut k = host.into_bytes();
    k.push(0);
    k.extend_from_slice(user.as_bytes());
    k.push(0);
    k.extend_from_slice(platform.as_bytes());
    Ok(Some(k))
}

fn ts_of(d: &Row) -> Result<i64, Fault> {
    match d.val("last_online_at") {
        Val::Null => Ok(0),
        v => laravel::parse_ts(&v).ok_or_else(|| Fault::Other("unparsable devices.last_online_at".into())),
    }
}

pub struct Duplicates {
    /// device id -> [(twin id, reason)] in the order PHP's array holds them
    pairs: HashMap<i64, Vec<(i64, &'static str)>>,
    devices: HashMap<i64, Row>,
}

impl Duplicates {
    fn empty() -> Duplicates {
        Duplicates { pairs: HashMap::new(), devices: HashMap::new() }
    }

    /// Duplicates among every approved device (`DuplicateDevices::in`).
    pub fn all(c: &Connection) -> Result<Duplicates, Fault> {
        let uuids: Vec<Vec<u8>> = db::rows(
            c,
            &format!(r#"select "devices"."uuid" from "devices" where {SCOPE} and "devices"."uuid" != ? group by "devices"."uuid" having COUNT(*) > 1"#),
            &[P(Val::str(""))],
        )?
        .into_iter()
        .map(|r| r.val("uuid").to_php_string())
        .collect::<Result<_, _>>()?;

        let host_rows = db::rows(
            c,
            &format!(
                r#"select {HOST_SQL} as host_key from "devices" where {SCOPE} and "devices"."hostname" is not null and "devices"."username" is not null and {USER_SQL} != '' group by {HOST_SQL}, {USER_SQL} having COUNT(*) > 1"#
            ),
            &[],
        )?;
        let mut hosts: Vec<Vec<u8>> = vec![];
        for r in host_rows {
            let h = r.val("host_key").to_php_string()?;
            if is_generic_hostname(&String::from_utf8_lossy(&h)) || hosts.contains(&h) {
                continue;
            }
            hosts.push(h);
        }
        if uuids.is_empty() && hosts.is_empty() {
            return Ok(Duplicates::empty());
        }
        let mut conds: Vec<String> = vec![];
        let mut params: Vec<P> = vec![];
        if !uuids.is_empty() {
            conds.push(format!(r#""devices"."uuid" in ({})"#, vec!["?"; uuids.len()].join(", ")));
            params.extend(uuids.into_iter().map(|u| P(Val::Str(u))));
        }
        if !hosts.is_empty() {
            conds.push(format!("{HOST_SQL} in ({})", vec!["?"; hosts.len()].join(", ")));
            params.extend(hosts.into_iter().map(|h| P(Val::Str(h))));
        }
        let rows = db::rows(c, &format!(r#"select {COLUMNS} from "devices" where {SCOPE} and ({}) "#, conds.join(" or ")), &params)?;
        Duplicates::build(c, rows)
    }

    /// Duplicates of one device among the approved devices (`DuplicateDevices::of`).
    pub fn of(c: &Connection, device: &Row) -> Result<Duplicates, Fault> {
        if !device.is_null("deleted_at") {
            return Ok(Duplicates::empty());
        }
        let uuid = device.val("uuid").to_php_string()?;
        let host = match_key(device)?;
        if uuid.is_empty() && host.is_none() {
            return Ok(Duplicates::empty());
        }
        let mut conds: Vec<String> = vec![];
        let mut params: Vec<P> = vec![];
        if !uuid.is_empty() {
            conds.push(r#""devices"."uuid" = ?"#.into());
            params.push(P(Val::Str(uuid)));
        }
        if host.is_some() {
            conds.push(format!("({HOST_SQL} = ? and {USER_SQL} = ?)"));
            params.push(P(Val::str(&normalize(&device.val("hostname"))?)));
            params.push(P(Val::str(&normalize(&device.val("username"))?)));
        }
        let rows = db::rows(c, &format!(r#"select {COLUMNS} from "devices" where {SCOPE} and ({}) "#, conds.join(" or ")), &params)?;
        // outside the scope (pending): nothing to say
        if !rows.iter().any(|r| r.id() == device.id()) {
            return Ok(Duplicates::empty());
        }
        Duplicates::build(c, rows)
    }

    fn build(c: &Connection, rows: Vec<Row>) -> Result<Duplicates, Fault> {
        let mut d = Duplicates { pairs: HashMap::new(), devices: HashMap::new() };
        for r in &rows {
            d.devices.insert(r.id(), r.clone());
        }
        // groupBy('uuid') over the rows whose uuid is not empty, groups in order of first appearance
        let mut by_uuid: Vec<(Vec<u8>, Vec<i64>)> = vec![];
        for r in &rows {
            let u = r.val("uuid").to_php_string()?;
            if u.is_empty() {
                continue;
            }
            match by_uuid.iter_mut().find(|(k, _)| *k == u) {
                Some((_, g)) => g.push(r.id()),
                None => by_uuid.push((u, vec![r.id()])),
            }
        }
        for (_, g) in &by_uuid {
            d.pair_up(g, "uuid");
        }
        let mut by_host: Vec<(Vec<u8>, Vec<i64>)> = vec![];
        for r in &rows {
            let Some(k) = match_key(r)? else { continue };
            match by_host.iter_mut().find(|(x, _)| *x == k) {
                Some((_, g)) => g.push(r.id()),
                None => by_host.push((k, vec![r.id()])),
            }
        }
        for (_, g) in &by_host {
            d.pair_up(g, "hostname_user");
        }
        d.drop_dismissed(c)?;
        Ok(d)
    }

    fn pair_up(&mut self, group: &[i64], why: &'static str) {
        for i in 0..group.len() {
            for j in i + 1..group.len() {
                let (a, b) = (group[i], group[j]);
                let current = self.pairs.get(&a).and_then(|l| l.iter().find(|(o, _)| *o == b)).map(|(_, r)| *r);
                if current.map_or(true, |cur| strength(why) > strength(cur)) {
                    for (x, y) in [(a, b), (b, a)] {
                        let list = self.pairs.entry(x).or_default();
                        match list.iter_mut().find(|(o, _)| *o == y) {
                            Some(slot) => slot.1 = why,
                            None => list.push((y, why)),
                        }
                    }
                }
            }
        }
    }

    fn drop_dismissed(&mut self, c: &Connection) -> Result<(), Fault> {
        if self.pairs.is_empty() {
            return Ok(());
        }
        let ids: Vec<i64> = self.pairs.keys().copied().collect();
        let marks = vec!["?"; ids.len()].join(", ");
        let sql = format!(r#"select "device_id", "other_device_id" from "device_duplicate_dismissals" where "device_id" in ({marks}) and "other_device_id" in ({marks})"#);
        let params: Vec<P> = ids.iter().chain(ids.iter()).map(|i| P(Val::Int(*i))).collect();
        for r in db::rows(c, &sql, &params)? {
            let (a, b) = (r.val("device_id").to_int(), r.val("other_device_id").to_int());
            for (x, y) in [(a, b), (b, a)] {
                if let Some(l) = self.pairs.get_mut(&x) {
                    l.retain(|(o, _)| *o != y);
                }
            }
        }
        self.pairs.retain(|_, l| !l.is_empty());
        Ok(())
    }

    /// `rustdeskIdsOf($id)`: the twins' RustDesk ids, strongest reason first, then most recently seen.
    pub fn rustdesk_ids_of(&self, id: i64) -> Result<Vec<Val>, Fault> {
        let mut twins: Vec<(u8, i64, Vec<u8>)> = vec![];
        for (other, reason) in self.pairs.get(&id).map(|l| l.as_slice()).unwrap_or(&[]) {
            let Some(d) = self.devices.get(other) else { continue };
            twins.push((strength(reason), ts_of(d)?, d.val("rustdesk_id").to_php_string()?));
        }
        // usort is stable: [$y.strength, $y.ts] <=> [$x.strength, $x.ts]
        twins.sort_by(|x, y| (y.0, y.1).cmp(&(x.0, x.1)));
        Ok(twins.into_iter().map(|t| Val::Str(t.2)).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_like_the_model() {
        for (os, p) in [
            ("windows / Windows 10", "windows"),
            ("Mac OS 14", "macos"),
            ("Darwin", "macos"),
            ("Android 13", "android"),
            ("iOS 17", "ios"),
            ("Ubuntu 22.04", "linux"),
            ("freebsd", "unknown"),
        ] {
            assert_eq!(platform(&Val::str(os)), p, "{os}");
        }
        assert_eq!(platform(&Val::Null), "unknown");
    }

    #[test]
    fn generic_hostnames() {
        for g in ["localhost", "MacBook-Pro", "macbook-air-2.local", "iPhone", "imac-pro", "mac-mini", "UBUNTU", "  pc "] {
            assert!(is_generic_hostname(g), "{g}");
        }
        for s in ["RECEPTION", "desktop-ab12cd3", "macbook-pro-of-ana", "iphone-x"] {
            assert!(!is_generic_hostname(s), "{s}");
        }
    }
}
