//! The sanitiser: runs at capture time, before anything touches disk.
//!
//! THE RULES (this module is the one place they are written down; `SANITISER.md` explains them):
//!
//! 1. Nothing is stored that was not passed through here. A body that is not JSON, a form or text is not
//!    stored at all (only its length). Headers are an allow-list; everything else is dropped.
//! 2. Placeholders are stable: the same real value always becomes the same placeholder, because the
//!    placeholder is `HMAC-SHA256(salt, kind | value)` cut short. The salt comes from the environment
//!    (`HTE_CONSOLE_SANITISE_SALT`; random per run when unset). No table of real values is ever written.
//! 3. Placeholders have a recognisable shape (see `is_placeholder`) and are fixed points of the
//!    sanitiser: sanitising a sanitised fixture changes nothing. `leftovers` uses exactly that to scan
//!    fixtures for anything real.
//! 4. By key (JSON keys, form fields, query fields): device ids, uuids, e-mails, user names, host names,
//!    free-text names/notes, and anything whose key says token, secret, password, key, pk, code, session,
//!    cookie, hash, ticket... Flags and short switches (`Y`, `N`, `true`, `0`, empty) are kept so the
//!    contract stays readable.
//! 5. By shape, in every string: e-mail addresses, URL hosts, JWTs, dashed uuids, base64 uuids, IPv4,
//!    IPv6, long opaque tokens (32+ characters with a digit or `+/=`), host names with a real top-level
//!    domain, and every literal listed in `HTE_CONSOLE_SANITISE_LITERALS`.
//! 6. By learning: any device id, user name or host name seen under its key in one pair is also replaced
//!    wherever it appears as free text, in that pair and in every later one of the run (memory only).

use base64::Engine;
use hmac::{Hmac, Mac};
use once_cell::sync::Lazy;
use regex::{Captures, Regex};
use serde_json::{Map, Value};
use sha2::Sha256;
use std::sync::Mutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    DeviceId,
    Uuid,
    Token,
    Email,
    HostName,
    Domain,
    Ip4,
    Ip6,
    User,
    Text,
}

impl Kind {
    fn tag(self) -> &'static str {
        match self {
            Kind::DeviceId => "id",
            Kind::Uuid => "uuid",
            Kind::Token => "tok",
            Kind::Email => "mail",
            Kind::HostName => "host",
            Kind::Domain => "dom",
            Kind::Ip4 => "ip4",
            Kind::Ip6 => "ip6",
            Kind::User => "user",
            Kind::Text => "text",
        }
    }
}

const B64_MARK: &str = "UExBQ0VIT0xERVIh"; // base64 of "PLACEHOLDER!"

static PLACEHOLDER: Lazy<Regex> = Lazy::new(|| {
    Regex::new(concat!(
        r"^(?:99\d{7}",
        r"|00000000-0000-4000-8000-[0-9a-f]{12}",
        r"|UExBQ0VIT0xERVIh[A-Za-z0-9+/]{6}==",
        r"|tok-[0-9a-f]{16}",
        r"|user-[0-9a-f]{10}@example\.invalid",
        r"|(?:host|dom)-[0-9a-f]{10}\.example\.invalid",
        r"|198\.1[89]\.\d{1,3}\.\d{1,3}",
        r"|2001:db8::[0-9a-f]{4}:[0-9a-f]{4}",
        r"|(?:user|host|text)-[0-9a-f]{8})$"
    ))
    .unwrap()
});

pub fn is_placeholder(s: &str) -> bool {
    let s = s
        .strip_prefix("Bearer ")
        .or_else(|| s.strip_prefix("Basic "))
        .unwrap_or(s);
    PLACEHOLDER.is_match(s)
}

static EMAIL: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)[A-Z0-9._%+'-]+@[A-Z0-9-]+(?:\.[A-Z0-9-]+)+").unwrap());
static URL_HOST: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\b((?:https?|wss?)://)(?:[^\s/@"'<>]*@)?(\[[0-9a-f:]+\]|[A-Z0-9.-]+)(:\d+)?"#).unwrap()
});
static JWT: Lazy<Regex> = Lazy::new(|| Regex::new(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*").unwrap());
static UUID: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}").unwrap()
});
static UUID_B64: Lazy<Regex> = Lazy::new(|| Regex::new(r"[A-Za-z0-9+/]{22}==").unwrap());
static IP4: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b").unwrap());
static IP6: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,6}:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,5})?|::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6})").unwrap()
});
static LONG_TOKEN: Lazy<Regex> = Lazy::new(|| Regex::new(r"[A-Za-z0-9+/_-]{32,}={0,2}").unwrap());
static FQDN: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\b(?:[A-Z0-9](?:[A-Z0-9-]*[A-Z0-9])?\.)+[A-Z]{2,24}\b").unwrap());

/// "app.js" and friends are file names, not host names.
const FILE_EXTENSIONS: &[&str] = &[
    "json", "js", "css", "png", "jpg", "jpeg", "gif", "ico", "svg", "html", "htm", "php", "txt", "log", "csv", "zip",
    "exe", "msi", "pkg", "dmg", "xml", "yml", "yaml", "sqlite", "db", "map", "woff", "woff2", "ttf", "md", "sh", "bat",
    "conf", "ini", "toml", "tar", "gz", "bin", "dll", "so", "apk", "deb", "rpm", "pdf",
];

/// Values that are switches, not secrets, even under a secret-sounding key (`enable-keyboard: Y`).
fn is_switch(v: &str) -> bool {
    matches!(v, "" | "Y" | "N" | "y" | "n" | "true" | "false" | "0" | "1" | "on" | "off" | "default" | "null")
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum KeyClass {
    Id,
    Uuid,
    Email,
    User,
    HostName,
    Secret,
    Text,
    Plain,
}

fn classify(key: &str) -> KeyClass {
    let k = key.to_ascii_lowercase().replace('-', "_");
    match k.as_str() {
        "id" | "peer_id" | "device_id" | "rustdesk_id" | "from_id" | "to_id" | "remote_id" | "peer" | "from_peer"
        | "to_peer" | "target" | "target_id" | "client_id" | "from" | "to" | "ids" | "peers" | "devices" => KeyClass::Id,
        "uuid" | "device_uuid" | "guid" => KeyClass::Uuid,
        "email" | "mail" | "e_mail" => KeyClass::Email,
        "username" | "user_name" | "login" | "owner" | "os_user" | "user" | "operator" | "created_by" | "account" => {
            KeyClass::User
        }
        "hostname" | "host_name" | "computer_name" | "device_name" | "host" | "machine" | "server" => KeyClass::HostName,
        "name" | "display_name" | "alias" | "note" | "title" | "description" | "label" | "group" | "tags" | "tag"
        | "address" | "url" | "domain" | "realm" | "tenant" | "organisation" | "organization" | "company" => KeyClass::Text,
        _ => {
            const SECRET: &[&str] = &[
                "token", "secret", "password", "passwd", "pwd", "pw", "key", "pk", "sign", "code", "authorization",
                "cookie", "session", "csrf", "xsrf", "hash", "salt", "nonce", "otp", "cred", "bearer", "jwt", "ticket",
                "license", "verifier", "challenge", "state",
            ];
            if SECRET.iter().any(|s| k.contains(s)) {
                KeyClass::Secret
            } else {
                KeyClass::Plain
            }
        }
    }
}

struct Learned {
    items: Vec<(String, Kind)>,
    regex: Option<Regex>,
}

pub struct Sanitiser {
    salt: Vec<u8>,
    literals: Vec<String>,
    literal_re: Option<Regex>,
    learned: Mutex<Learned>,
}

fn escape_alt(items: &[String]) -> String {
    let mut v: Vec<&String> = items.iter().collect();
    v.sort_by_key(|s| std::cmp::Reverse(s.len()));
    v.iter().map(|s| regex::escape(s)).collect::<Vec<_>>().join("|")
}

impl Sanitiser {
    pub fn new(salt: Option<&str>, literals: &[String]) -> Sanitiser {
        let salt = match salt {
            Some(s) => s.as_bytes().to_vec(),
            None => {
                use rand::RngCore;
                let mut b = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut b);
                b.to_vec()
            }
        };
        let lits: Vec<String> = literals.iter().filter(|s| s.len() >= 3).cloned().collect();
        let literal_re = if lits.is_empty() {
            None
        } else {
            Some(Regex::new(&format!("(?i){}", escape_alt(&lits))).unwrap())
        };
        Sanitiser { salt, literals: lits, literal_re, learned: Mutex::new(Learned { items: vec![], regex: None }) }
    }

    fn hash(&self, kind: Kind, value: &str) -> Vec<u8> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.salt).unwrap();
        mac.update(kind.tag().as_bytes());
        mac.update(&[0]);
        mac.update(value.as_bytes());
        mac.finalize().into_bytes().to_vec()
    }

    /// The placeholder for `value` of `kind`. Placeholders map to themselves.
    pub fn placeholder(&self, kind: Kind, value: &str) -> String {
        if is_placeholder(value) {
            return value.to_string();
        }
        let value = value.trim();
        let norm = match kind {
            Kind::Email | Kind::HostName | Kind::Domain | Kind::User => value.to_ascii_lowercase(),
            _ => value.to_string(),
        };
        let h = self.hash(kind, &norm);
        let hx = hex::encode(&h);
        match kind {
            Kind::DeviceId => {
                let n = u64::from_be_bytes(h[..8].try_into().unwrap()) % 10_000_000;
                format!("99{n:07}")
            }
            Kind::Uuid => {
                if value.len() == 36 && value.contains('-') {
                    format!("00000000-0000-4000-8000-{}", &hx[..12])
                } else {
                    let mut raw = b"PLACEHOLDER!".to_vec();
                    raw.extend_from_slice(&h[..4]);
                    base64::engine::general_purpose::STANDARD.encode(raw)
                }
            }
            Kind::Token => format!("tok-{}", &hx[..16]),
            Kind::Email => format!("user-{}@example.invalid", &hx[..10]),
            Kind::HostName => format!("host-{}", &hx[..8]),
            Kind::Domain => format!("dom-{}.example.invalid", &hx[..10]),
            Kind::Ip4 => format!("198.{}.{}.{}", 18 + (h[0] & 1), h[1], h[2]),
            Kind::Ip6 => format!("2001:db8::{}:{}", &hx[..4], &hx[4..8]),
            Kind::User => format!("user-{}", &hx[..8]),
            Kind::Text => format!("text-{}", &hx[..8]),
        }
    }

    /// A `host[:port]` value (Host header, `host` field): the host part becomes a placeholder, the port stays.
    pub fn host(&self, value: &str) -> String {
        let (h, port) = match value.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') && p.chars().all(|c| c.is_ascii_digit()) => (h, format!(":{p}")),
            _ => (value, String::new()),
        };
        let h = h.trim_matches(|c| c == '[' || c == ']');
        if is_placeholder(h) || h.ends_with("example.invalid") || h.eq_ignore_ascii_case("localhost") {
            return value.to_string();
        }
        let ph = if IP4.is_match(h) {
            self.placeholder(Kind::Ip4, h)
        } else if h.contains(':') {
            return self.placeholder(Kind::Ip6, h);
        } else {
            self.placeholder(Kind::Domain, h)
        };
        format!("{ph}{port}")
    }

    fn fqdn_placeholder(&self, host: &str) -> String {
        self.placeholder(Kind::Domain, host)
    }

    fn learn(&self, kind: Kind, value: &str) {
        let min = if kind == Kind::DeviceId { 6 } else { 4 };
        if value.len() < min || is_placeholder(value) || is_switch(value) {
            return;
        }
        let mut l = self.learned.lock().unwrap();
        if l.items.iter().any(|(v, _)| v == value) {
            return;
        }
        l.items.push((value.to_string(), kind));
        let all: Vec<String> = l.items.iter().map(|(v, _)| v.clone()).collect();
        l.regex = Some(
            Regex::new(&format!("(?i)(^|[^A-Za-z0-9])({})([^A-Za-z0-9]|$)", escape_alt(&all))).unwrap(),
        );
    }

    /// Replace every shape and literal in a free-text string.
    pub fn scrub_str(&self, s: &str) -> String {
        let mut out = s.to_string();
        out = EMAIL
            .replace_all(&out, |c: &Captures| {
                let m = &c[0];
                if is_placeholder(m) { m.to_string() } else { self.placeholder(Kind::Email, m) }
            })
            .into_owned();
        out = URL_HOST
            .replace_all(&out, |c: &Captures| {
                let host = c[2].trim_matches(|ch| ch == '[' || ch == ']');
                let port = c.get(3).map_or("", |p| p.as_str());
                if is_placeholder(host) || host.eq_ignore_ascii_case("localhost") || host.ends_with("example.invalid") {
                    return c[0].to_string();
                }
                let ph = if IP4.is_match(host) {
                    self.placeholder(Kind::Ip4, host)
                } else if host.contains(':') {
                    format!("[{}]", self.placeholder(Kind::Ip6, host))
                } else {
                    self.placeholder(Kind::Domain, host)
                };
                format!("{}{}{}", &c[1], ph, port)
            })
            .into_owned();
        if let Some(re) = &self.literal_re {
            out = re
                .replace_all(&out, |c: &Captures| {
                    let m = &c[0];
                    let kind = if m.contains('.') { Kind::Domain } else { Kind::Text };
                    self.placeholder(kind, m)
                })
                .into_owned();
        }
        for _ in 0..3 {
            let (re, items) = {
                let l = self.learned.lock().unwrap();
                match &l.regex {
                    Some(r) => (r.clone(), l.items.clone()),
                    None => break,
                }
            };
            let next = re
                .replace_all(&out, |c: &Captures| {
                    let val = &c[2];
                    let kind = items
                        .iter()
                        .find(|(v, _)| v.eq_ignore_ascii_case(val))
                        .map(|(_, k)| *k)
                        .unwrap_or(Kind::Text);
                    format!("{}{}{}", &c[1], self.placeholder(kind, val), &c[3])
                })
                .into_owned();
            if next == out {
                break;
            }
            out = next;
        }
        out = JWT.replace_all(&out, |c: &Captures| self.placeholder(Kind::Token, &c[0])).into_owned();
        out = UUID
            .replace_all(&out, |c: &Captures| {
                let m = &c[0];
                if is_placeholder(m) { m.to_string() } else { self.placeholder(Kind::Uuid, m) }
            })
            .into_owned();
        out = UUID_B64
            .replace_all(&out, |c: &Captures| {
                let m = &c[0];
                if m.starts_with(B64_MARK) || !m.chars().any(|ch| ch.is_ascii_alphanumeric()) {
                    m.to_string()
                } else {
                    self.placeholder(Kind::Uuid, m)
                }
            })
            .into_owned();
        out = IP4
            .replace_all(&out, |c: &Captures| {
                let m = &c[0];
                if is_placeholder(m) { m.to_string() } else { self.placeholder(Kind::Ip4, m) }
            })
            .into_owned();
        out = IP6
            .replace_all(&out, |c: &Captures| {
                let m = &c[0];
                if is_placeholder(m) || m.starts_with("2001:db8::") { m.to_string() } else { self.placeholder(Kind::Ip6, m) }
            })
            .into_owned();
        out = LONG_TOKEN
            .replace_all(&out, |c: &Captures| {
                let m = &c[0];
                let plain_word = m.chars().all(|ch| ch.is_ascii_alphabetic() || ch == '-' || ch == '_');
                if plain_word { m.to_string() } else { self.placeholder(Kind::Token, m) }
            })
            .into_owned();
        out = FQDN
            .replace_all(&out, |c: &Captures| {
                let m = &c[0];
                let tld = m.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
                if m.ends_with("example.invalid") || is_placeholder(m) || FILE_EXTENSIONS.contains(&tld.as_str()) {
                    m.to_string()
                } else {
                    self.fqdn_placeholder(m)
                }
            })
            .into_owned();
        out
    }

    /// One value under a key (JSON string, form field, query field).
    pub fn scalar(&self, key: &str, value: &str) -> String {
        if is_placeholder(value) {
            return value.to_string();
        }
        match classify(key) {
            KeyClass::Id => {
                if value.len() >= 6 && value.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
                    self.placeholder(Kind::DeviceId, value)
                } else {
                    self.scrub_str(value)
                }
            }
            KeyClass::Uuid if !value.is_empty() => self.placeholder(Kind::Uuid, value),
            KeyClass::Email if !value.is_empty() => self.placeholder(Kind::Email, value),
            KeyClass::User if !is_switch(value) => self.placeholder(Kind::User, value),
            KeyClass::HostName if !is_switch(value) => {
                if value.contains('.') || value.contains(':') { self.host(value) } else { self.placeholder(Kind::HostName, value) }
            }
            KeyClass::Secret if !is_switch(value) => {
                let v = value.strip_prefix("Bearer ").or_else(|| value.strip_prefix("Basic ")).unwrap_or(value);
                let prefix = &value[..value.len() - v.len()];
                format!("{}{}", prefix, self.placeholder(Kind::Token, v))
            }
            KeyClass::Text if !is_switch(value) => self.placeholder(Kind::Text, value),
            _ => self.scrub_str(value),
        }
    }

    /// Learn identities from a JSON value before anything of the pair is sanitised.
    pub fn learn_json(&self, v: &Value, key: &str) {
        match v {
            Value::Object(m) => m.iter().for_each(|(k, x)| self.learn_json(x, k)),
            Value::Array(a) => a.iter().for_each(|x| self.learn_json(x, key)),
            Value::String(s) => self.learn_pair(key, s),
            _ => {}
        }
    }

    pub fn learn_pair(&self, key: &str, value: &str) {
        match classify(key) {
            KeyClass::Id if value.chars().all(|c| c.is_ascii_alphanumeric()) => self.learn(Kind::DeviceId, value),
            KeyClass::User => self.learn(Kind::User, value),
            KeyClass::HostName => self.learn(Kind::HostName, value),
            KeyClass::Email => self.learn(Kind::Email, value),
            _ => {}
        }
    }

    /// Sanitise a JSON value in place. `key` is the key the value sits under (arrays inherit it).
    pub fn json(&self, v: &mut Value, key: &str) {
        match v {
            Value::Object(m) => {
                let old = std::mem::take(m);
                let mut new = Map::new();
                for (k, mut x) in old {
                    self.json(&mut x, &k);
                    new.insert(self.scrub_key(&k), x);
                }
                *m = new;
            }
            Value::Array(a) => a.iter_mut().for_each(|x| self.json(x, key)),
            Value::String(s) => *s = self.scalar(key, s),
            Value::Number(n) => {
                if classify(key) == KeyClass::Id {
                    if let Some(u) = n.as_u64() {
                        if u >= 100_000_000 && !is_placeholder(&u.to_string()) {
                            *v = Value::String(self.placeholder(Kind::DeviceId, &u.to_string()));
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn scrub_key(&self, k: &str) -> String {
        if is_placeholder(k) { k.to_string() } else { self.scrub_str(k) }
    }

    /// Fields of a query string or a form body, in order, values percent-decoded.
    pub fn pairs(&self, pairs: &[(String, String)]) -> Value {
        let mut m = Map::new();
        for (k, v) in pairs {
            let nv = Value::String(self.scalar(k, v));
            let nk = self.scrub_key(k);
            match m.get_mut(&nk) {
                Some(Value::Array(a)) => a.push(nv),
                Some(old) => {
                    let first = old.clone();
                    *old = Value::Array(vec![first, nv]);
                }
                None => {
                    m.insert(nk, nv);
                }
            }
        }
        Value::Object(m)
    }

    pub fn learn_pairs(&self, pairs: &[(String, String)]) {
        pairs.iter().for_each(|(k, v)| self.learn_pair(k, v));
    }

    pub fn path(&self, path: &str) -> String {
        path.split('/').map(|seg| if seg.is_empty() { String::new() } else { self.scalar("path", seg) }).collect::<Vec<_>>().join("/")
    }

    /// Cookie names with placeholder values (the values are sessions and tokens).
    pub fn cookies(&self, pairs: &[(String, String)]) -> Value {
        let mut m = Map::new();
        for (k, v) in pairs {
            let name = self.scrub_key(k);
            m.insert(name, Value::String(if v.is_empty() { String::new() } else { self.placeholder(Kind::Token, v) }));
        }
        Value::Object(m)
    }

    /// Report anything in an already-sanitised value that sanitising again would change. Empty = clean.
    pub fn leftovers(&self, v: &Value) -> Vec<String> {
        let mut again = v.clone();
        self.json(&mut again, "");
        let mut out = vec![];
        diff_paths(v, &again, "", &mut out);
        out
    }

    pub fn literals(&self) -> &[String] {
        &self.literals
    }
}

fn diff_paths(a: &Value, b: &Value, at: &str, out: &mut Vec<String>) {
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            for ((ka, va), (kb, vb)) in x.iter().zip(y.iter()) {
                if ka != kb {
                    out.push(format!("{at}/{ka}: key would become {kb}"));
                }
                diff_paths(va, vb, &format!("{at}/{ka}"), out);
            }
        }
        (Value::Array(x), Value::Array(y)) => {
            for (i, (va, vb)) in x.iter().zip(y.iter()).enumerate() {
                diff_paths(va, vb, &format!("{at}[{i}]"), out);
            }
        }
        _ if a != b => out.push(format!("{at}: not a placeholder (would become {})", short(b))),
        _ => {}
    }
}

fn short(v: &Value) -> String {
    let s = v.to_string();
    if s.len() > 60 { format!("{}...", &s[..60]) } else { s }
}
