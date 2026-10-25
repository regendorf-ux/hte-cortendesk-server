//! Phase 3: `$request->validate([...])` as Laravel 13.35 runs it, for the rules the server-link routes use:
//! `required`, `nullable`, `array`, `string`, `integer`, `ip`, `max:n`, `min:n`, on keys with `*` wildcards.
//! Ported from `Validator::passes`/`validateAttribute`/`isValidatable`/`shouldStopValidating`/`validated`,
//! `ValidationRuleParser::explodeWildcardRules`, `ValidationData::initializeAndGatherData`, `data_set`, `Arr::dot`,
//! `Arr::get`/`has`, `ValidatesAttributes`, `FormatsMessages` and the English `validation.php` lines, so a bad body
//! gets PHP's 422 (`{"message": ..., "errors": {...}}`, rendered as JSON on `api/*`), keys in PHP's order.
//!
//! Also `Str::limit` (with `mb_strwidth`) and `mb_strlen`, which the sweeps and the validator share.

use crate::php::{self, Arr, Key, Val};
use regex::Regex;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    Required,
    Nullable,
    Array,
    String,
    Integer,
    Ip,
    Max(i64),
    Min(i64),
    // phase 5 (the admin API)
    Sometimes,
    Boolean,
    Email,
    /// `Rule::in([...])`: strict string comparison of `(string) $value`
    In(&'static [&'static str]),
    /// `Rule::unique(table, column)`, optionally `->ignore($id)` (an `id <> ?` condition)
    Unique(&'static str, &'static str, Option<i64>),
    /// `Rule::exists(table, column)`
    Exists(&'static str, &'static str),
}

impl Rule {
    fn implicit(self) -> bool {
        self == Rule::Required
    }
}

/// The validator's outcome: the validated data (`$validator->validated()`), or the 422 body.
pub type Outcome = Result<Arr, String>;

fn key_text(k: &Key) -> String {
    String::from_utf8_lossy(&k.as_bytes()).into_owned()
}

/// `Arr::exists($array, $key)` for a string key (PHP normalises "0" to 0).
fn exists<'a>(a: &'a Arr, seg: &str) -> Option<&'a Val> {
    a.get(&Key::from_bytes(seg.as_bytes()))
}

/// Walk `key` segment by segment, by reference.
fn walk<'a>(data: &'a Arr, key: &str) -> Option<&'a Val> {
    let mut segs = key.split('.');
    let mut cur = exists(data, segs.next()?)?;
    for seg in segs {
        cur = match cur {
            Val::Arr(a) => exists(a, seg)?,
            _ => return None,
        };
    }
    Some(cur)
}

/// `Arr::get($array, $key)`: the whole key first, then segment by segment.
fn arr_get<'a>(data: &'a Arr, key: &str) -> Option<&'a Val> {
    if let Some(v) = exists(data, key) {
        return Some(v);
    }
    if !key.contains('.') {
        return None;
    }
    walk(data, key)
}

/// `Arr::has($array, $key)`
fn arr_has(data: &Arr, key: &str) -> bool {
    !data.is_empty() && (exists(data, key).is_some() || walk(data, key).is_some())
}

/// `data_get($target, $key)`: segment by segment only (`validated()` reads the data this way).
fn data_get<'a>(data: &'a Arr, key: &str) -> Option<&'a Val> {
    walk(data, key)
}

/// `Arr::set($array, $key, $value)`
fn arr_set(data: &mut Arr, key: &str, v: Val) {
    let segs: Vec<&str> = key.split('.').collect();
    let mut cur = data;
    for (i, seg) in segs.iter().enumerate() {
        let k = Key::from_bytes(seg.as_bytes());
        if i == segs.len() - 1 {
            cur.set(k, v);
            return;
        }
        if !matches!(cur.get(&k), Some(Val::Arr(_))) {
            cur.set(k.clone(), Val::Arr(Arr::new()));
        }
        cur = match cur.get_mut(&k) {
            Some(Val::Arr(a)) => a,
            _ => return,
        };
    }
}

/// `data_set($target, $segments, null, true)` (overwrite): the shape the wildcard expansion walks.
fn data_set_null(target: &mut Val, segs: &[&str]) {
    let Some((first, rest)) = segs.split_first() else { return };
    if *first == "*" {
        if !matches!(target, Val::Arr(_)) {
            *target = Val::Arr(Arr::new());
        }
        if let Val::Arr(a) = target {
            for (_, inner) in a.iter_mut() {
                if rest.is_empty() {
                    *inner = Val::Null;
                } else {
                    data_set_null(inner, rest);
                }
            }
        }
        return;
    }
    if !matches!(target, Val::Arr(_)) {
        *target = Val::Arr(Arr::new());
    }
    let Val::Arr(a) = target else { return };
    let k = Key::from_bytes(first.as_bytes());
    if rest.is_empty() {
        a.set(k, Val::Null);
    } else {
        if a.get(&k).is_none() {
            a.set(k.clone(), Val::Arr(Arr::new()));
        }
        if let Some(inner) = a.get_mut(&k) {
            data_set_null(inner, rest);
        }
    }
}

/// `Arr::dot($array)`: leaves (and empty arrays) under dotted keys, in order.
fn arr_dot(a: &Arr, prefix: &str, out: &mut Vec<(String, Val)>) {
    for (k, v) in a.iter() {
        let key = format!("{prefix}{}", key_text(k));
        match v {
            Val::Arr(inner) if !inner.is_empty() => arr_dot(inner, &format!("{key}."), out),
            _ => out.push((key, v.clone())),
        }
    }
}

/// `str_replace('\*', '[^\.]*', preg_quote($attribute, '/'))`
fn wildcard_pattern(attribute: &str) -> String {
    regex::escape(attribute).replace(r"\*", r"[^\.]*")
}

/// The keys `explodeWildcardRules` gives rules to, for one wildcard attribute.
fn expand(attribute: &str, data: &Arr) -> Vec<String> {
    // initializeAttributeOnData: the leading explicit path, then data_set(..., null, true)
    let lead = attribute.split('*').next().unwrap_or("").trim_end_matches('.');
    let mut copy = Val::Arr(Arr::new());
    if !lead.is_empty() {
        if let Some(v) = arr_get(data, lead) {
            if let Val::Arr(c) = &mut copy {
                arr_set(c, lead, v.clone());
            }
        }
    }
    if attribute.contains('*') && !attribute.ends_with('*') {
        let segs: Vec<&str> = attribute.split('.').collect();
        data_set_null(&mut copy, &segs);
    }
    let mut dotted = vec![];
    if let Val::Arr(c) = &copy {
        arr_dot(c, "", &mut dotted);
    }
    let pattern = wildcard_pattern(attribute);
    let full = Regex::new(&format!(r"^{pattern}\z")).ok();
    let prefix = Regex::new(&format!(r"^{pattern}")).ok();
    // array_merge($dotted, extractValuesForWildcards(...)): new keys appended, existing ones keep their place
    let mut keys: Vec<String> = dotted.iter().map(|(k, _)| k.clone()).collect();
    for (k, _) in &dotted {
        if let Some(m) = prefix.as_ref().and_then(|r| r.find(k)) {
            let m = m.as_str().to_string();
            if !keys.contains(&m) {
                keys.push(m);
            }
        }
    }
    keys.into_iter().filter(|k| k.starts_with(attribute) || full.as_ref().map_or(false, |r| r.is_match(k))).collect()
}

struct Exploded {
    rules: Vec<(String, Vec<Rule>)>,
    /// expanded key -> the wildcard attribute it came from (`implicitAttributes`)
    implicit: Vec<(String, String)>,
}

fn explode(rules: &[(&str, &[Rule])], data: &Arr) -> Exploded {
    let mut out: Vec<(String, Vec<Rule>)> = rules.iter().map(|(k, r)| (k.to_string(), r.to_vec())).collect();
    let mut implicit = vec![];
    for (attr, rs) in rules {
        if !attr.contains('*') {
            continue;
        }
        let expanded = expand(attr, data);
        out.retain(|(k, _)| k != attr);
        for key in expanded {
            implicit.push((key.clone(), attr.to_string()));
            match out.iter_mut().find(|(k, _)| *k == key) {
                Some((_, existing)) => existing.extend_from_slice(rs),
                None => out.push((key, rs.to_vec())),
            }
        }
    }
    Exploded { rules: out, implicit }
}

/// `filter_var($v, FILTER_VALIDATE_INT) !== false`
pub fn filter_int(v: &Val) -> bool {
    let s = match v {
        Val::Int(_) => return true,
        Val::Arr(_) | Val::Null => return false,
        Val::Bool(false) => return false,
        other => other.to_php_string().unwrap_or_default(),
    };
    let t: &[u8] = {
        let ws = |b: &u8| matches!(b, b' ' | b'\t' | b'\r' | b'\n' | b'\x0b');
        let start = s.iter().position(|b| !ws(b)).unwrap_or(s.len());
        let end = s.iter().rposition(|b| !ws(b)).map_or(start, |p| p + 1);
        &s[start..end]
    };
    let digits = t.strip_prefix(b"-").or_else(|| t.strip_prefix(b"+")).unwrap_or(t);
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) || (digits.len() > 1 && digits[0] == b'0') {
        return false;
    }
    std::str::from_utf8(t).ok().and_then(|x| x.trim_start_matches('+').parse::<i64>().ok()).is_some()
}

/// PHP's IPv4 rule: four decimal parts 0-255, no leading zeros.
fn ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()) && !(p.len() > 1 && p.starts_with('0')) && p.parse::<u16>().map_or(false, |n| n <= 255))
}

/// `filter_var($v, FILTER_VALIDATE_IP) !== false`
pub fn filter_ip(v: &Val) -> bool {
    let Ok(s) = v.to_php_string() else { return false };
    let Ok(s) = std::str::from_utf8(&s) else { return false };
    if s.contains(':') {
        // the embedded IPv4 tail follows the IPv4 rule
        let tail_ok = match s.rsplit_once(':') {
            Some((_, tail)) if tail.contains('.') => ipv4(tail),
            _ => true,
        };
        return tail_ok && s.parse::<std::net::Ipv6Addr>().is_ok();
    }
    ipv4(s)
}

/// `mb_strlen($s)` on UTF-8 (characters counted by their lead byte, as mbstring's table does).
pub fn mb_strlen(s: &[u8]) -> usize {
    let mut i = 0;
    let mut n = 0;
    while i < s.len() {
        i += match s[i] {
            0xC0..=0xDF => 2,
            0xE0..=0xEF => 3,
            0xF0..=0xF7 => 4,
            _ => 1,
        };
        n += 1;
    }
    n
}

/// mbstring's East Asian width: 2 for wide and fullwidth characters (the main blocks), else 1.
fn char_width(c: char) -> usize {
    let u = c as u32;
    let wide = matches!(u, 0x1100..=0x115F | 0x2E80..=0x303E | 0x3041..=0x33FF | 0x3400..=0x4DBF | 0x4E00..=0x9FFF | 0xA000..=0xA4CF | 0xAC00..=0xD7A3 | 0xF900..=0xFAFF | 0xFE30..=0xFE4F | 0xFF00..=0xFF60 | 0xFFE0..=0xFFE6 | 0x1F300..=0x1F64F | 0x1F900..=0x1F9FF | 0x20000..=0x2FFFD | 0x30000..=0x3FFFD);
    if wide { 2 } else { 1 }
}

/// `Str::limit($value, $limit, $end)`: unchanged when `mb_strwidth` fits, else `rtrim(mb_strimwidth(...)).$end`.
pub fn str_limit(value: &str, limit: usize, end: &str) -> String {
    if value.chars().map(char_width).sum::<usize>() <= limit {
        return value.to_string();
    }
    let mut w = 0;
    let mut cut = String::new();
    for c in value.chars() {
        w += char_width(c);
        if w > limit {
            break;
        }
        cut.push(c);
    }
    format!("{}{end}", cut.trim_end_matches([' ', '\n', '\r', '\t', '\u{b}', '\0']))
}

fn is_numeric_val(v: &Val) -> bool {
    v.is_numeric()
}

/// `getSize()`: the number for a numeric attribute, the count of an array, else `mb_strlen`.
fn size(v: &Val, numeric: bool) -> Option<f64> {
    if numeric && is_numeric_val(v) {
        let s = v.to_php_string().ok()?;
        let t = String::from_utf8_lossy(php::trim(&s)).into_owned();
        return t.parse::<f64>().ok().filter(|f| f.is_finite());
    }
    match v {
        Val::Arr(a) => Some(a.len() as f64),
        other => Some(mb_strlen(&other.to_php_string().ok()?) as f64),
    }
}

/// The database side of `unique` and `exists`: how many rows hold the value. Faults are kept for the caller.
pub type Probe<'a> = &'a dyn Fn(&Rule, &Val) -> Result<bool, crate::php::Fault>;

fn passes(rule: Rule, v: &Val, numeric: bool, probe: Probe, fault: &std::cell::RefCell<Option<crate::php::Fault>>) -> bool {
    match rule {
        Rule::Required => match v {
            Val::Null => false,
            Val::Str(s) => !php::trim(s).is_empty(),
            Val::Arr(a) => !a.is_empty(),
            _ => true,
        },
        Rule::Nullable => true,
        Rule::Array => matches!(v, Val::Arr(_)),
        Rule::String => matches!(v, Val::Str(_)),
        Rule::Integer => filter_int(v),
        Rule::Ip => filter_ip(v),
        Rule::Max(n) => size(v, numeric).map_or(false, |s| s <= n as f64),
        Rule::Min(n) => size(v, numeric).map_or(false, |s| s >= n as f64),
        Rule::Sometimes => true,
        // in_array($value, [true, false, 0, 1, '0', '1'], true)
        Rule::Boolean => match v {
            Val::Bool(_) => true,
            Val::Int(i) => *i == 0 || *i == 1,
            Val::Str(s) => s == b"0" || s == b"1",
            _ => false,
        },
        Rule::Email => match v {
            Val::Str(s) => crate::email::is_valid(s),
            _ => false,
        },
        // ! is_array($value) && in_array((string) $value, $parameters, true)
        Rule::In(list) => match v {
            Val::Arr(_) => false,
            other => other.to_php_string().map_or(false, |s| list.iter().any(|p| p.as_bytes() == s.as_slice())),
        },
        Rule::Unique(..) | Rule::Exists(..) => match probe(&rule, v) {
            Ok(b) => b,
            Err(f) => {
                fault.borrow_mut().get_or_insert(f);
                true
            }
        },
    }
}

fn message(rule: Rule, attr: &str, numeric: bool, array: bool) -> String {
    let kind = if numeric { "numeric" } else if array { "array" } else { "string" };
    let m = match (rule, kind) {
        (Rule::Required, _) => "The :attribute field is required.".to_string(),
        (Rule::Array, _) => "The :attribute field must be an array.".to_string(),
        (Rule::String, _) => "The :attribute field must be a string.".to_string(),
        (Rule::Integer, _) => "The :attribute field must be an integer.".to_string(),
        (Rule::Ip, _) => "The :attribute field must be a valid IP address.".to_string(),
        (Rule::Max(n), "numeric") => format!("The :attribute field must not be greater than {n}."),
        (Rule::Max(n), "array") => format!("The :attribute field must not have more than {n} items."),
        (Rule::Max(n), _) => format!("The :attribute field must not be greater than {n} characters."),
        (Rule::Min(n), "numeric") => format!("The :attribute field must be at least {n}."),
        (Rule::Min(n), "array") => format!("The :attribute field must have at least {n} items."),
        (Rule::Min(n), _) => format!("The :attribute field must be at least {n} characters."),
        (Rule::Nullable, _) | (Rule::Sometimes, _) => String::new(),
        (Rule::Boolean, _) => "The :attribute field must be true or false.".to_string(),
        (Rule::Email, _) => "The :attribute field must be a valid email address.".to_string(),
        (Rule::In(_), _) | (Rule::Exists(..), _) => "The selected :attribute is invalid.".to_string(),
        (Rule::Unique(..), _) => "The :attribute has already been taken.".to_string(),
    };
    m.replace(":attribute", attr)
}

/// `Str::snake` then `_` to a space, for an attribute that is not a wildcard expansion.
fn displayable(attr: &str) -> String {
    let mut out = String::new();
    if attr.chars().all(|c| c.is_ascii_lowercase()) {
        out.push_str(attr);
    } else {
        let no_ws: String = attr.split_whitespace().map(|w| {
            let mut cs = w.chars();
            cs.next().map(|f| f.to_uppercase().collect::<String>() + cs.as_str()).unwrap_or_default()
        }).collect();
        for c in no_ws.chars() {
            if c.is_uppercase() {
                if !out.is_empty() {
                    out.push('_');
                }
                out.extend(c.to_lowercase());
            } else {
                out.push(c);
            }
        }
    }
    out.replace('_', " ")
}

/// Run the rules over `$request->all()`.
pub fn validate(data: &Arr, rules: &[(&str, &[Rule])]) -> Outcome {
    // no database rule in these lists: the probe is never asked
    match validate_db(data, rules, &|_, _| Ok(true)) {
        Ok(o) => o,
        Err(_) => Err(r#"{"message":"The given data was invalid."}"#.into()),
    }
}

/// `validate`, with the database rules (`unique`, `exists`) answered by `probe`; a database fault is the caller's 500.
pub fn validate_db(data: &Arr, rules: &[(&str, &[Rule])], probe: Probe) -> Result<Outcome, crate::php::Fault> {
    let fault = std::cell::RefCell::new(None);
    let out = validate_inner(data, rules, probe, &fault);
    match fault.into_inner() {
        Some(f) => Err(f),
        None => Ok(out),
    }
}

fn validate_inner(data: &Arr, rules: &[(&str, &[Rule])], probe: Probe, fault: &std::cell::RefCell<Option<crate::php::Fault>>) -> Outcome {
    let ex = explode(rules, data);
    let mut errors: Vec<(String, Vec<String>)> = vec![];
    for (attr, rs) in &ex.rules {
        let numeric = rs.contains(&Rule::Integer);
        let array = rs.contains(&Rule::Array);
        let nullable = rs.contains(&Rule::Nullable);
        let has_implicit = rs.iter().any(|r| r.implicit());
        // passesOptionalCheck: `sometimes` skips an attribute the request does not carry
        let sometimes = rs.contains(&Rule::Sometimes) && exists(data, attr).is_none();
        let null = Val::Null;
        let value = arr_get(data, attr).unwrap_or(&null);
        let present_any = arr_has(data, attr);
        let is_null = matches!(arr_get(data, attr), Some(Val::Null));
        let mut failed_implicit = false;
        for &rule in rs {
            // isValidatable: present (or the rule is implicit), and not null when nullable
            let present = match value {
                Val::Str(s) if php::trim(s).is_empty() => rule.implicit(),
                _ => present_any || rule.implicit(),
            };
            let not_null = rule.implicit() || !nullable || !is_null;
            // hasNotFailedPreviousRuleIfPresenceRule: unique and exists are not run for an attribute that already failed a rule
            let skipped = matches!(rule, Rule::Unique(..) | Rule::Exists(..)) && errors.iter().any(|(k, _)| k == attr);
            if present && not_null && !sometimes && !skipped && !passes(rule, value, numeric, probe, fault) {
                let shown = if ex.implicit.iter().any(|(k, _)| k == attr) { attr.clone() } else { displayable(attr) };
                let msg = message(rule, &shown, numeric, array);
                match errors.iter_mut().find(|(k, _)| k == attr) {
                    Some((_, list)) => list.push(msg),
                    None => errors.push((attr.clone(), vec![msg])),
                }
                if rule.implicit() {
                    failed_implicit = true;
                }
            }
            // shouldStopValidating: an implicit rule failed on an attribute that has one
            if has_implicit && failed_implicit {
                break;
            }
        }
    }
    if !errors.is_empty() {
        let all: Vec<&String> = errors.iter().flat_map(|(_, l)| l.iter()).collect();
        let mut summary = all[0].clone();
        let more = all.len() - 1;
        if more > 0 {
            summary.push_str(&format!(" (and {more} more {})", if more == 1 { "error" } else { "errors" }));
        }
        let mut e = Arr::new();
        for (k, list) in &errors {
            let mut l = Arr::new();
            for m in list {
                l.push(Val::str(m));
            }
            e.set(Key::Str(k.as_bytes().to_vec()), Val::Arr(l));
        }
        let body = php::assoc(vec![("message".to_string(), Val::str(&summary)), ("errors".to_string(), Val::Arr(e))]);
        return Err(php::json_encode(&body).unwrap_or_else(|| r#"{"message":"The given data was invalid."}"#.into()));
    }
    Ok(validated(data, &ex))
}

/// `$validator->validated()`: each rule key that is present, set by dotted path; an array that has rules on its
/// children is not copied whole (`excludeUnvalidatedArrayKeys`).
fn validated(data: &Arr, ex: &Exploded) -> Arr {
    let mut out = Arr::new();
    for (key, rs) in &ex.rules {
        let Some(v) = data_get(data, key).cloned() else { continue };
        let has_children = ex.rules.iter().any(|(k, _)| k.len() > key.len() && k.starts_with(key.as_str()) && k.as_bytes()[key.len()] == b'.');
        if rs.contains(&Rule::Array) && !matches!(v, Val::Null) && has_children {
            continue;
        }
        arr_set(&mut out, key, v);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(j: &str) -> Arr {
        php::json_decode(j.as_bytes(), &php::JsonOpts::default()).unwrap().to_array()
    }

    const ADDRS: &[(&str, &[Rule])] = &[
        ("addrs", &[Rule::Required, Rule::Array, Rule::Max(500)]),
        ("addrs.*.id", &[Rule::Required, Rule::String, Rule::Max(100)]),
        ("addrs.*.ip", &[Rule::Required, Rule::Ip]),
        ("addrs.*.seen_at", &[Rule::Nullable, Rule::Integer, Rule::Min(0)]),
    ];

    #[test]
    fn messages_and_order_like_laravel() {
        let e = validate(&data(r#"{}"#), ADDRS).unwrap_err();
        assert_eq!(e, r#"{"message":"The addrs field is required.","errors":{"addrs":["The addrs field is required."]}}"#);
        let e = validate(&data(r#"{"addrs":[{"id":5,"ip":"300.1.1.1","seen_at":-1},{"ip":"10.0.0.1"}]}"#), ADDRS).unwrap_err();
        assert_eq!(
            e,
            r#"{"message":"The addrs.0.id field must be a string. (and 3 more errors)","errors":{"addrs.0.id":["The addrs.0.id field must be a string."],"addrs.1.id":["The addrs.1.id field is required."],"addrs.0.ip":["The addrs.0.ip field must be a valid IP address."],"addrs.0.seen_at":["The addrs.0.seen_at field must be at least 0."]}}"#
        );
        let e = validate(&data(r#"{"addrs":"x"}"#), ADDRS).unwrap_err();
        assert!(e.starts_with(r#"{"message":"The addrs field must be an array.""#), "{e}");
        let e = validate(&data(r#"{"addrs":["x"]}"#), ADDRS).unwrap_err();
        assert!(e.contains(r#""addrs.0.id":["The addrs.0.id field is required."]"#), "{e}");
    }

    #[test]
    fn validated_keeps_only_rule_keys() {
        let v = validate(&data(r#"{"addrs":[{"id":"990000001","ip":"192.168.1.20","extra":1}],"other":2}"#), ADDRS).unwrap();
        assert_eq!(php::json_encode(&Val::Arr(v)).unwrap(), r#"{"addrs":[{"id":"990000001","ip":"192.168.1.20"}]}"#);
        // a nullable key sent as null is kept as null; one not sent is absent
        let v = validate(&data(r#"{"addrs":[{"id":"1","ip":"::1","seen_at":null}]}"#), ADDRS).unwrap();
        assert_eq!(php::json_encode(&Val::Arr(v)).unwrap(), r#"{"addrs":[{"id":"1","ip":"::1","seen_at":null}]}"#);
    }

    #[test]
    fn php_filters() {
        for ok in ["0", "-0", "+7", " 12 ", "9223372036854775807"] {
            assert!(filter_int(&Val::str(ok)), "{ok}");
        }
        for bad in ["007", "1.0", "", "9223372036854775808", "1e3", "x"] {
            assert!(!filter_int(&Val::str(bad)), "{bad}");
        }
        assert!(filter_int(&Val::Bool(true)) && filter_int(&Val::Float(3.0)) && !filter_int(&Val::Float(3.5)));
        for ok in ["10.0.0.1", "0.0.0.0", "::", "::1", "fe80::1", "::ffff:10.1.2.3", "2001:db8::8a2e:370:7334"] {
            assert!(filter_ip(&Val::str(ok)), "{ok}");
        }
        for bad in ["010.0.0.1", "1.2.3", "256.1.1.1", "1.2.3.4.5", "fe80::1%eth0", "[::1]", "::ffff:010.1.2.3", "x"] {
            assert!(!filter_ip(&Val::str(bad)), "{bad}");
        }
    }

    #[test]
    fn str_limit_like_laravel() {
        assert_eq!(str_limit("short", 10, "..."), "short");
        assert_eq!(str_limit("abc def ghi", 8, "..."), "abc def...");
        assert_eq!(str_limit("abcdefgh", 4, ""), "abcd");
        assert_eq!(str_limit("日本語テキスト", 6, ""), "日本語");
    }
}
