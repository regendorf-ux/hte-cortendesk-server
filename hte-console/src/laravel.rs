//! The parts of Laravel 13 (and Symfony underneath) that decide what a device endpoint sees and stores:
//! the request input bag, the client address behind trusted proxies, `Crypt::encryptString`, timestamps.
//! Written from the framework source the PHP console runs (laravel/framework v13.35.0).

use crate::php::{self, Arr, Fault, Key, Val};
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::net::IpAddr;

// ------------------------------------------------------------------------------------------------- input ---

/// `$request->input()`, after the global middleware (TrimStrings, ConvertEmptyStringsToNull).
pub struct Input {
    bag: Arr,
    /// `$request->isJson()`: the Content-Type contains "/json" or "+json" (case-sensitive, as Laravel checks it).
    pub is_json: bool,
    /// `$request->getContent()`
    pub raw: Vec<u8>,
}

/// TrimStrings never trims these (top-level keys only, as `Str::is` matches them).
const NEVER_TRIM: &[&[u8]] = &[b"current_password", b"password", b"password_confirmation"];

fn clean(a: &mut Arr, prefix: &[u8]) {
    for (k, v) in a.iter_mut() {
        let mut path = prefix.to_vec();
        path.extend_from_slice(&k.as_bytes());
        match v {
            Val::Arr(inner) => {
                let mut p = path.clone();
                p.push(b'.');
                clean(inner, &p);
            }
            Val::Str(s) => {
                if !NEVER_TRIM.contains(&path.as_slice()) {
                    *s = php::laravel_trim(s);
                }
                if s.is_empty() {
                    *v = Val::Null;
                }
            }
            _ => {}
        }
    }
}

impl Input {
    /// `content_type` is the raw header; `query` the raw query string (without `?`).
    pub fn new(method: &str, content_type: Option<&str>, query: Option<&str>, body: &[u8]) -> Input {
        let ct = content_type.unwrap_or("");
        let is_json = ct.contains("/json") || ct.contains("+json");
        let mut query_bag = php::parse_str(query.unwrap_or("").as_bytes());
        clean(&mut query_bag, b"");
        let source = if is_json {
            // `(array) json_decode(trim($content) === '' ? '[]' : $content, true)`
            let decoded = if php::trim(body).is_empty() { Some(Val::Arr(Arr::new())) } else { php::json_decode(body, &php::JsonOpts::default()) };
            let mut bag = match decoded {
                None => Arr::new(),
                Some(v) => v.to_array(),
            };
            clean(&mut bag, b"");
            bag
        } else if method == "GET" || method == "HEAD" {
            query_bag.clone()
        } else if is_form(ct) && method == "POST" {
            let mut bag = php::parse_str(body);
            clean(&mut bag, b"");
            bag
        } else {
            // PHP fills $_POST only for urlencoded and multipart bodies. Multipart is not parsed here (no RustDesk
            // client sends it to these endpoints): its fields are absent, a documented divergence.
            Arr::new()
        };
        Input { bag: source.union(&query_bag), is_json, raw: body.to_vec() }
    }

    /// `$request->input($key)`: None when the key is absent (the caller applies the default), Some(Null) when present and null.
    pub fn get(&self, key: &str) -> Option<&Val> {
        self.bag.get_str(key)
    }

    /// `$request->input($key, $default)`
    pub fn or<'a>(&'a self, key: &str, default: &'a Val) -> &'a Val {
        self.get(key).unwrap_or(default)
    }

    /// `(string) $request->input($key, '')`
    pub fn string(&self, key: &str) -> Result<Vec<u8>, Fault> {
        self.get(key).map_or(Ok(vec![]), |v| v.to_php_string())
    }

    /// `(int) $request->input($key, 0)`
    pub fn int(&self, key: &str) -> i64 {
        self.get(key).map_or(0, |v| v.to_int())
    }

    /// `$request->has($key)`
    pub fn has(&self, key: &str) -> bool {
        self.bag.contains(key)
    }
}

fn is_form(ct: &str) -> bool {
    ct.split(';').next().unwrap_or("").trim().eq_ignore_ascii_case("application/x-www-form-urlencoded")
}

// ------------------------------------------------------------------------------------------- client ip ---

#[derive(Clone, Debug)]
pub struct Cidr {
    net: IpAddr,
    bits: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Option<Cidr> {
        let (a, b) = match s.split_once('/') {
            Some((a, b)) => (a, Some(b)),
            None => (s, None),
        };
        let net: IpAddr = a.trim().parse().ok()?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        let bits = match b {
            Some(b) => b.trim().parse::<u8>().ok().filter(|&n| n <= max)?,
            None => max,
        };
        Some(Cidr { net, bits })
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self.net, ip) {
            (IpAddr::V4(n), IpAddr::V4(i)) => {
                let mask = if self.bits == 0 { 0 } else { u32::MAX << (32 - self.bits as u32) };
                (u32::from(n) & mask) == (u32::from(*i) & mask)
            }
            (IpAddr::V6(n), IpAddr::V6(i)) => {
                let mask = if self.bits == 0 { 0 } else { u128::MAX << (128 - self.bits as u32) };
                (u128::from(n) & mask) == (u128::from(*i) & mask)
            }
            _ => false,
        }
    }
}

/// The PHP console's default `TRUSTED_PROXIES` (config/trustedproxy.php).
pub const DEFAULT_TRUSTED: &str = "127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16";

pub fn parse_trusted(list: &str) -> Vec<Cidr> {
    list.split(',').filter_map(|s| Cidr::parse(s.trim())).collect()
}

/// `$request->ip()`: Symfony's `getClientIps()[0]` with only X-Forwarded-For trusted, and only from a trusted peer.
pub fn client_ip(peer: IpAddr, xff: &[&str], trusted: &[Cidr]) -> String {
    let peer_s = peer.to_string();
    if !trusted.iter().any(|c| c.contains(&peer)) || xff.is_empty() {
        return peer_s;
    }
    let mut chain: Vec<String> = xff.iter().flat_map(|v| v.split(',').map(|s| s.trim().to_string())).collect();
    chain.push(peer_s.clone());
    let mut first_trusted: Option<String> = None;
    let mut kept: Vec<String> = vec![];
    for mut ip in chain {
        if ip.find('.').map_or(false, |p| p > 0) {
            if let Some(i) = ip.find(':').filter(|&i| i > 0) {
                ip.truncate(i);
            }
        } else if ip.starts_with('[') {
            ip = match ip[1..].find(']') {
                Some(i) => ip[1..1 + i].to_string(),
                // substr($ip, 1, false - 1): PHP takes everything but the last character
                None => ip.get(1..ip.len().saturating_sub(1)).unwrap_or("").to_string(),
            };
        }
        let Ok(parsed) = ip.parse::<IpAddr>() else { continue };
        if trusted.iter().any(|c| c.contains(&parsed)) {
            if first_trusted.is_none() {
                first_trusted = Some(ip);
            }
            continue;
        }
        kept.push(ip);
    }
    match kept.pop() {
        Some(ip) => ip,
        None => first_trusted.unwrap_or(peer_s),
    }
}

// ------------------------------------------------------------------------------------------------ crypt ---

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// Laravel's `Encrypter` with AES-256-CBC (the console's cipher) and the app key from `/data/.app_key`.
#[derive(Clone)]
pub struct Encrypter {
    key: [u8; 32],
}

impl std::fmt::Debug for Encrypter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Encrypter(<key>)")
    }
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// PHP's non-strict `base64_decode`: foreign bytes skipped, data after padding still read.
fn base64_decode_lenient(s: &[u8]) -> Vec<u8> {
    let filtered: Vec<u8> = s.iter().copied().filter(|c| c.is_ascii_alphanumeric() || *c == b'+' || *c == b'/').collect();
    let mut out = vec![];
    let mut buf = 0u32;
    let mut n = 0;
    for c in filtered {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            _ => 63,
        } as u32;
        buf = (buf << 6) | v;
        n += 6;
        if n >= 8 {
            n -= 8;
            out.push((buf >> n) as u8);
            buf &= (1 << n) - 1;
        }
    }
    out
}

impl Encrypter {
    /// `APP_KEY`: `base64:<32 bytes>` (what `key:generate` writes) or 32 raw characters.
    pub fn from_app_key(app_key: &str) -> Result<Encrypter, String> {
        let k = app_key.trim();
        let bytes = match k.strip_prefix("base64:") {
            Some(b) => b64().decode(b).map_err(|_| "the app key is not valid base64".to_string())?,
            None => k.as_bytes().to_vec(),
        };
        let key: [u8; 32] = bytes.try_into().map_err(|_| "the app key is not 32 bytes (AES-256-CBC)".to_string())?;
        Ok(Encrypter { key })
    }

    fn mac(&self, iv_b64: &[u8], value: &[u8]) -> String {
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&self.key).expect("hmac takes any key length");
        m.update(iv_b64);
        m.update(value);
        hex::encode(m.finalize().into_bytes())
    }

    /// `Crypt::encryptString($plain)`
    pub fn encrypt_string(&self, plain: &[u8]) -> String {
        let iv: [u8; 16] = rand::random();
        let ct = Aes256CbcEnc::new(&self.key.into(), &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(plain);
        let iv_b64 = b64().encode(iv);
        let value = b64().encode(ct);
        let mac = self.mac(iv_b64.as_bytes(), value.as_bytes());
        // json_encode(..., JSON_UNESCAPED_SLASHES); base64 holds nothing else that needs escaping
        let json = format!(r#"{{"iv":"{iv_b64}","value":"{value}","mac":"{mac}","tag":""}}"#);
        b64().encode(json)
    }

    /// `Crypt::decryptString($payload)`; a Fault where Laravel throws a DecryptException.
    pub fn decrypt_string(&self, payload: &[u8]) -> Result<Vec<u8>, Fault> {
        let bad = |m: &str| Fault::Other(format!("decrypt: {m}"));
        let json = base64_decode_lenient(payload);
        let Some(Val::Arr(p)) = php::json_decode(&json, &php::JsonOpts::default()) else { return Err(bad("the payload is invalid")) };
        let field = |k: &str| match p.get_str(k) {
            Some(Val::Str(s)) => Some(s.clone()),
            _ => None,
        };
        let (Some(iv), Some(value), Some(mac)) = (field("iv"), field("value"), field("mac")) else { return Err(bad("the payload is invalid")) };
        match p.get_str("tag") {
            None | Some(Val::Null) | Some(Val::Str(_)) => {}
            _ => return Err(bad("the payload is invalid")),
        }
        if php::base64_decode_strict(&iv).map_or(0, |v| v.len()) != 16 {
            return Err(bad("the payload is invalid"));
        }
        if let Some(Val::Str(t)) = p.get_str("tag") {
            if !(t.is_empty() || t == b"0") {
                return Err(bad("tag with a non-AEAD cipher"));
            }
        }
        let want = self.mac(&iv, &value);
        if !constant_time_eq(want.as_bytes(), &mac) {
            return Err(bad("the MAC is invalid"));
        }
        let iv_raw = base64_decode_lenient(&iv);
        let iv16: [u8; 16] = iv_raw.try_into().map_err(|_| bad("iv"))?;
        let ct = base64_decode_lenient(&value);
        Aes256CbcDec::new(&self.key.into(), &iv16.into()).decrypt_padded_vec_mut::<Pkcs7>(&ct).map_err(|_| bad("could not decrypt the data"))
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// -------------------------------------------------------------------------------------------- timestamps ---

/// A timestamp as Laravel writes it to SQLite (`Y-m-d H:i:s`, the app runs in UTC).
pub fn ts(unix: i64) -> String {
    chrono::DateTime::from_timestamp(unix, 0).map(|d| d.format("%Y-%m-%d %H:%M:%S").to_string()).unwrap_or_default()
}

/// A stored timestamp read back as Eloquent's `asDateTime` would (UTC seconds). None where Carbon would throw.
pub fn parse_ts(v: &Val) -> Option<i64> {
    match v {
        Val::Int(i) => Some(*i),
        Val::Str(s) => {
            let t = std::str::from_utf8(s).ok()?.trim();
            for f in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S%.f"] {
                if let Ok(d) = chrono::NaiveDateTime::parse_from_str(t, f) {
                    return Some(d.and_utc().timestamp());
                }
            }
            if let Ok(d) = chrono::DateTime::parse_from_rfc3339(t) {
                return Some(d.timestamp());
            }
            if let Ok(d) = chrono::NaiveDate::parse_from_str(t, "%Y-%m-%d") {
                return d.and_hms_opt(0, 0, 0).map(|x| x.and_utc().timestamp());
            }
            if php::is_numeric_str(s) {
                return Some(php::str_to_int(s));
            }
            None
        }
        _ => None,
    }
}

/// `(string) Str::uuid()`: a random version-4 UUID.
pub fn uuid4() -> String {
    let mut b: [u8; 16] = rand::random();
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex::encode(b);
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

// --------------------------------------------------------------------------------------- dirty checking ---

/// How a model casts a column, for Eloquent's "did this attribute change" rule (`originalIsEquivalent`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cast {
    Plain,
    Date,
    Json,
    Int,
    Bool,
}

/// True when assigning `new` over `orig` leaves the attribute clean (no UPDATE for it).
pub fn equivalent(cast: Cast, new: &Val, orig: Option<&Val>) -> Result<bool, Fault> {
    let Some(orig) = orig else { return Ok(false) };
    if new == orig {
        return Ok(true);
    }
    if matches!(new, Val::Null) {
        return Ok(false);
    }
    Ok(match cast {
        Cast::Date => {
            if matches!(orig, Val::Null) {
                return Ok(false);
            }
            let a = parse_ts(new).ok_or_else(|| Fault::Other("unparsable timestamp".into()))?;
            let b = parse_ts(orig).ok_or_else(|| Fault::Other("unparsable timestamp".into()))?;
            a == b
        }
        Cast::Json => from_json(new) == from_json(orig),
        Cast::Int => !matches!(orig, Val::Null) && new.to_int() == orig.to_int(),
        Cast::Bool => !matches!(orig, Val::Null) && new.to_bool() == orig.to_bool(),
        Cast::Plain => new.is_numeric() && orig.is_numeric() && new.to_php_string()? == orig.to_php_string()?,
    })
}

/// Eloquent's `fromJson` for an `array` cast: null and "" are null, otherwise `json_decode($v, true)`.
pub fn from_json(v: &Val) -> Val {
    match v {
        Val::Null => Val::Null,
        Val::Str(s) if s.is_empty() => Val::Null,
        Val::Str(s) => php::json_decode(s, &php::JsonOpts::default()).unwrap_or(Val::Null),
        Val::Int(_) | Val::Float(_) => v.to_php_string().ok().and_then(|s| php::json_decode(&s, &php::JsonOpts::default())).unwrap_or(Val::Null),
        _ => Val::Null,
    }
}

/// The key of an `array`-cast map, as PHP holds it after `json_decode`.
pub fn key_str(k: &Key) -> Option<&[u8]> {
    match k {
        Key::Str(s) => Some(s),
        Key::Int(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_merges_json_over_query_and_trims() {
        let i = Input::new("POST", Some("application/json"), Some("id=q&extra=%20x%20"), br#"{"id":"  b  ","n":"","p":null}"#);
        assert_eq!(i.get("id"), Some(&Val::str("b")));
        assert_eq!(i.get("extra"), Some(&Val::str("x")));
        assert_eq!(i.get("n"), Some(&Val::Null));
        assert!(i.has("p"));
        assert!(!i.has("q"));
        // not JSON by Laravel's case-sensitive test: the body is ignored
        let i = Input::new("POST", Some("Application/JSON"), None, br#"{"id":"b"}"#);
        assert_eq!(i.get("id"), None);
        // invalid JSON is an empty bag; a scalar becomes [0 => scalar]
        assert_eq!(Input::new("POST", Some("application/json"), None, b"{").get("id"), None);
        assert_eq!(Input::new("POST", Some("application/json"), None, b"\"x\"").get("0"), Some(&Val::str("x")));
        // form body
        let i = Input::new("POST", Some("application/x-www-form-urlencoded; charset=utf-8"), None, b"id=7&a[]=1");
        assert_eq!(i.get("id"), Some(&Val::str("7")));
        assert!(matches!(i.get("a"), Some(Val::Arr(_))));
    }

    #[test]
    fn client_ip_like_symfony() {
        let t = parse_trusted(DEFAULT_TRUSTED);
        let caddy: IpAddr = "172.18.0.5".parse().unwrap();
        assert_eq!(client_ip(caddy, &["203.0.113.9"], &t), "203.0.113.9");
        assert_eq!(client_ip(caddy, &["1.1.1.1, 203.0.113.9:4444"], &t), "203.0.113.9");
        assert_eq!(client_ip(caddy, &["203.0.113.9, 10.0.0.2"], &t), "203.0.113.9");
        assert_eq!(client_ip(caddy, &["garbage"], &t), "172.18.0.5");
        assert_eq!(client_ip(caddy, &[], &t), "172.18.0.5");
        assert_eq!(client_ip(caddy, &["[2001:db8::1]:80"], &t), "2001:db8::1");
        let public: IpAddr = "198.51.100.1".parse().unwrap();
        assert_eq!(client_ip(public, &["203.0.113.9"], &t), "198.51.100.1");
    }

    #[test]
    fn crypt_round_trip_and_rejects_tampering() {
        let e = Encrypter::from_app_key("base64:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=").unwrap();
        let p = e.encrypt_string(b"secret pw");
        assert_eq!(e.decrypt_string(p.as_bytes()).unwrap(), b"secret pw");
        let other = Encrypter::from_app_key("base64:HwAeHRwbGhkYFxYVFBMSERAPDg0MCwoJCAcGBQQDAgE=").unwrap();
        assert!(other.decrypt_string(p.as_bytes()).is_err());
        assert!(e.decrypt_string(b"garbage").is_err());
        assert!(Encrypter::from_app_key("base64:AAEC").is_err());
    }

    #[test]
    fn decrypts_the_laravel_payload_layout() {
        // Built here by hand in Laravel's layout (no PHP on this machine to make one): base64(json{iv,value,mac,tag}),
        // value = base64(AES-256-CBC/PKCS7), mac = hmac_sha256_hex(iv_b64 . value_b64), with a fixed zero IV.
        // The replay against PHP is what proves the two sides read each other's payloads.
        let e = Encrypter::from_app_key("base64:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=").unwrap();
        let iv_b64 = "AAAAAAAAAAAAAAAAAAAAAA==";
        let ct = Aes256CbcEnc::new(&e.key.into(), &[0u8; 16].into()).encrypt_padded_vec_mut::<Pkcs7>(b"hello");
        let value = b64().encode(ct);
        let mac = e.mac(iv_b64.as_bytes(), value.as_bytes());
        let json = format!(r#"{{"iv":"{iv_b64}","value":"{value}","mac":"{mac}","tag":""}}"#);
        assert_eq!(e.decrypt_string(b64().encode(json).as_bytes()).unwrap(), b"hello");
    }

    #[test]
    fn dirty_rules() {
        assert!(equivalent(Cast::Plain, &Val::Int(0), Some(&Val::str("0"))).unwrap());
        assert!(!equivalent(Cast::Plain, &Val::str(""), Some(&Val::Null)).unwrap());
        assert!(!equivalent(Cast::Plain, &Val::str("5.0"), Some(&Val::Int(5))).unwrap());
        assert!(equivalent(Cast::Date, &Val::str("2026-10-24 10:00:00"), Some(&Val::str("2026-10-24T10:00:00"))).unwrap());
        assert!(!equivalent(Cast::Date, &Val::str("2026-10-24 10:00:01"), Some(&Val::str("2026-10-24 10:00:00"))).unwrap());
        assert!(equivalent(Cast::Json, &Val::str(r#"{"a":"Y"}"#), Some(&Val::str(r#"{"a": "Y"}"#))).unwrap());
        assert!(!equivalent(Cast::Plain, &Val::str("x"), None).unwrap());
    }

    #[test]
    fn timestamps() {
        assert_eq!(ts(0), "1970-01-01 00:00:00");
        assert_eq!(parse_ts(&Val::str("2026-10-24 12:00:00")), Some(1792843200));
        assert_eq!(uuid4().len(), 36);
    }
}
