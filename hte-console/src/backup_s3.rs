//! The previous console's `S3Target`: S3 and S3-compatible storage (MinIO, Backblaze B2, Wasabi, R2, ...) over plain HTTP with
//! Signature Version 4, written against the REST API directly. The payload is signed by its SHA-256, so an upload is
//! streamed from disk and never held in memory.

use crate::backup_remote::Remote;
use hmac::{Hmac, Mac};
use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;
use std::time::Duration;

pub struct S3 {
    pub bucket: String,
    pub region: String,
    pub access_key: String,
    pub secret_key: String,
    pub endpoint: String,
    pub prefix: String,
    pub path_style: bool,
}

type HmacSha256 = Hmac<Sha256>;

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut m = HmacSha256::new_from_slice(key).expect("hmac takes any key length");
    m.update(data);
    m.finalize().into_bytes().to_vec()
}

/// The previous console's `rawurlencode`: everything but `A-Za-z0-9-._~` as %XX.
fn rawurlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn file_sha256(path: &Path) -> Result<String, String> {
    let mut f = std::fs::File::open(path).map_err(|_| format!("Cannot read {}.", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf).map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k_region = hmac(&k_date, region.as_bytes());
    let k_service = hmac(&k_region, service.as_bytes());
    hmac(&k_service, b"aws4_request")
}

/// The `Authorization` value for a request whose (lowercase-named) headers are all signed.
#[allow(clippy::too_many_arguments)]
fn authorization(method: &str, canonical_uri: &str, canonical_query: &str, headers: &BTreeMap<String, String>, payload_hash: &str, amz_date: &str, region: &str, access_key: &str, secret_key: &str) -> String {
    let canonical_headers: String = headers.iter().map(|(k, v)| format!("{k}:{}\n", v.trim())).collect();
    let signed_headers = headers.keys().cloned().collect::<Vec<_>>().join(";");
    let canonical_request = [method, canonical_uri, canonical_query, &canonical_headers, &signed_headers, payload_hash].join("\n");
    let date = &amz_date[..8];
    let scope = format!("{date}/{region}/s3/aws4_request");
    let to_sign = ["AWS4-HMAC-SHA256", amz_date, &scope, &sha256_hex(canonical_request.as_bytes())].join("\n");
    let signature = hex::encode(hmac(&signing_key(secret_key, date, region, "s3"), to_sign.as_bytes()));
    format!("AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed_headers}, Signature={signature}")
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&")
}

/// The text of the first `<tag>` element in `xml`.
fn tag(xml: &str, name: &str) -> Option<String> {
    let re = Regex::new(&format!(r"(?s)<{name}(?:\s[^>]*)?>(.*?)</{name}>")).ok()?;
    re.captures(xml).map(|c| unescape(c[1].trim()))
}

fn looks_like_xml(body: &str) -> bool {
    let t = body.trim();
    t.starts_with('<') && t.ends_with('>')
}

impl S3 {
    fn region(&self) -> String {
        let r = self.region.trim();
        if r.is_empty() { "us-east-1".into() } else { r.into() }
    }

    fn endpoint(&self) -> String {
        let e = self.endpoint.trim();
        let e = if e.is_empty() { format!("https://s3.{}.amazonaws.com", self.region()) } else { e.to_string() };
        e.trim_end_matches('/').to_string()
    }

    fn prefix(&self) -> String {
        let p = self.prefix.trim_matches(|c| c == '/' || c == ' ');
        if p.is_empty() { String::new() } else { format!("{p}/") }
    }

    fn bucket(&self) -> &str {
        self.bucket.trim()
    }

    /// Sign and send; Ok(body text) on 2xx, the previous console's error message otherwise.
    fn request(&self, method: &str, key: &str, query: &[(&str, String)], body_file: Option<&Path>) -> Result<String, String> {
        let endpoint = self.endpoint();
        let url = url::Url::parse(&endpoint).ok().filter(|u| u.host_str().is_some()).ok_or("The S3 endpoint is not a valid URL.")?;
        if self.bucket().is_empty() {
            return Err("The S3 bucket name is empty.".into());
        }
        let mut host = url.host_str().unwrap_or_default().to_string();
        if let Some(p) = url.port() {
            host = format!("{host}:{p}");
        }
        let base_path = url.path().trim_end_matches('/').to_string();
        let path = if self.path_style {
            format!("{base_path}/{}/{key}", self.bucket())
        } else {
            host = format!("{}.{host}", self.bucket());
            format!("{base_path}/{key}")
        };
        // each segment encoded on its own so the slashes survive
        let mut canonical_uri = path.split('/').map(rawurlencode).collect::<Vec<_>>().join("/");
        if canonical_uri.is_empty() {
            canonical_uri = "/".into();
        }
        let mut q: Vec<(String, String)> = query.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
        q.sort();
        let canonical_query = q.iter().map(|(k, v)| format!("{}={}", rawurlencode(k), rawurlencode(v))).collect::<Vec<_>>().join("&");

        let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let payload_hash = match body_file {
            Some(f) => file_sha256(f)?,
            None => sha256_hex(b""),
        };
        let mut headers = BTreeMap::new();
        headers.insert("host".to_string(), host.clone());
        headers.insert("x-amz-content-sha256".to_string(), payload_hash.clone());
        headers.insert("x-amz-date".to_string(), amz_date.clone());
        let auth = authorization(method, &canonical_uri, &canonical_query, &headers, &payload_hash, &amz_date, &self.region(), &self.access_key, &self.secret_key);

        let scheme = url.scheme();
        let full = format!("{scheme}://{host}{canonical_uri}{}", if canonical_query.is_empty() { String::new() } else { format!("?{canonical_query}") });

        let client = reqwest::blocking::Client::builder()
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(if body_file.is_some() { 3600 } else { 60 }))
            .build()
            .map_err(|e| format!("S3 request failed: {e}"))?;
        let m = reqwest::Method::from_bytes(method.as_bytes()).map_err(|e| format!("S3 request failed: {e}"))?;
        let mut req = client.request(m, &full).header("x-amz-content-sha256", &payload_hash).header("x-amz-date", &amz_date).header("Authorization", auth);
        if let Some(f) = body_file {
            let file = std::fs::File::open(f).map_err(|_| format!("Cannot read {}.", f.display()))?;
            let len = file.metadata().map_err(|e| format!("Cannot read {}: {e}", f.display()))?.len();
            req = req.header("Content-Type", "application/x-tar").body(reqwest::blocking::Body::sized(file, len));
        }
        let resp = req.send().map_err(|e| format!("S3 request failed: {e}"))?;
        let status = resp.status();
        let text = resp.text().unwrap_or_default();
        if !status.is_success() {
            return Err(error_message(status.as_u16(), &text));
        }
        Ok(text)
    }
}

fn error_message(status: u16, body: &str) -> String {
    let mut detail = String::new();
    if looks_like_xml(body) {
        let code = tag(body, "Code").unwrap_or_default();
        let message = tag(body, "Message").unwrap_or_default();
        detail = format!("{code}{}", if message.is_empty() { String::new() } else { format!(": {message}") }).trim().to_string();
    }
    format!("S3 returned HTTP {status}{}.", if detail.is_empty() { String::new() } else { format!(" ({detail})") })
}

impl Remote for S3 {
    fn put(&self, local: &Path, name: &str) -> Result<(), String> {
        self.request("PUT", &format!("{}{name}", self.prefix()), &[], Some(local)).map(|_| ())
    }

    fn list(&self) -> Result<Vec<(String, Option<u64>)>, String> {
        let prefix = self.prefix();
        let contents = Regex::new(r"(?s)<Contents>(.*?)</Contents>").expect("static regex");
        let mut names: Vec<(String, Option<u64>)> = vec![];
        let mut token: Option<String> = None;
        loop {
            let mut query = vec![("list-type", "2".to_string()), ("max-keys", "1000".to_string())];
            if !prefix.is_empty() {
                query.push(("prefix", prefix.clone()));
            }
            if let Some(t) = &token {
                query.push(("continuation-token", t.clone()));
            }
            let body = self.request("GET", "", &query, None)?;
            if !looks_like_xml(&body) {
                return Err("S3 returned a response that is not XML.".into());
            }
            for c in contents.captures_iter(&body) {
                let key = tag(&c[1], "Key").unwrap_or_default();
                if !prefix.is_empty() && !key.starts_with(&prefix) {
                    continue;
                }
                let rest = &key[prefix.len()..];
                // only direct children: a key with another slash lives in a sub-directory that is not ours to manage
                if rest.is_empty() || rest.contains('/') {
                    continue;
                }
                let size = tag(&c[1], "Size").map(|s| crate::php::str_to_int(s.as_bytes()).max(0) as u64);
                match names.iter_mut().find(|(n, _)| n == rest) {
                    Some(e) => e.1 = size,
                    None => names.push((rest.to_string(), size)),
                }
            }
            let outside = contents.replace_all(&body, "");
            token = if tag(&outside, "IsTruncated").as_deref() == Some("true") { tag(&outside, "NextContinuationToken") } else { None };
            if token.as_deref().map_or(true, str::is_empty) {
                break;
            }
        }
        Ok(names)
    }

    fn delete(&self, name: &str) -> Result<(), String> {
        self.request("DELETE", &format!("{}{name}", self.prefix()), &[], None).map(|_| ())
    }

    fn test(&self) -> Result<String, String> {
        let mut query = vec![("list-type", "2".to_string()), ("max-keys", "1".to_string())];
        if !self.prefix().is_empty() {
            query.push(("prefix", self.prefix()));
        }
        self.request("GET", "", &query, None)?;
        Ok(format!("Connected to {}.", self.label()))
    }

    fn label(&self) -> String {
        let p = self.prefix();
        format!("S3 bucket {}{}", self.bucket(), if p.is_empty() { String::new() } else { format!("/{}", p.trim_end_matches('/')) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    #[test]
    fn rawurlencode_like_php() {
        assert_eq!(rawurlencode("a b/c~d-e_f.g"), "a%20b%2Fc~d-e_f.g");
        assert_eq!(rawurlencode("é"), "%C3%A9");
    }

    #[test]
    fn signing_key_aws_example() {
        // AWS documentation, "Examples of how to derive a signing key" (iam, 20150830)
        let k = signing_key("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20150830", "us-east-1", "iam");
        assert_eq!(hex::encode(k), "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9");
    }

    #[test]
    fn signature_aws_get_object_example() {
        // AWS S3 documentation, "Signature Calculations: Example: GET Object" (with the Range header signed)
        let mut h = BTreeMap::new();
        h.insert("host".to_string(), "examplebucket.s3.amazonaws.com".to_string());
        h.insert("range".to_string(), "bytes=0-9".to_string());
        h.insert("x-amz-content-sha256".to_string(), sha256_hex(b""));
        h.insert("x-amz-date".to_string(), "20130524T000000Z".to_string());
        let a = authorization("GET", "/test.txt", "", &h, &sha256_hex(b""), "20130524T000000Z", "us-east-1", "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
        assert_eq!(
            a,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    #[test]
    fn labels_and_defaults() {
        let s = S3 { bucket: " bk ".into(), region: "".into(), access_key: "a".into(), secret_key: "s".into(), endpoint: "".into(), prefix: " /cortendesk/ ".into(), path_style: false };
        assert_eq!(s.label(), "S3 bucket bk/cortendesk");
        assert_eq!(s.endpoint(), "https://s3.us-east-1.amazonaws.com");
        assert_eq!(s.prefix(), "cortendesk/");
        let s = S3 { prefix: "".into(), region: "eu-west-1".into(), ..s };
        assert_eq!(s.label(), "S3 bucket bk");
        assert_eq!(s.endpoint(), "https://s3.eu-west-1.amazonaws.com");
    }

    #[test]
    fn error_texts_like_php() {
        assert_eq!(error_message(403, "<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>"), "S3 returned HTTP 403 (AccessDenied: Access Denied).");
        assert_eq!(error_message(500, "oops"), "S3 returned HTTP 500.");
        assert_eq!(error_message(404, "<Error><Code>NoSuchBucket</Code></Error>"), "S3 returned HTTP 404 (NoSuchBucket).");
    }

    /// (method, request target, headers lowercased, body)
    type Seen = Arc<Mutex<Vec<(String, String, BTreeMap<String, String>, Vec<u8>)>>>;

    /// A one-thread fake S3: answers every request with `respond(method, target)` -> (status, body).
    fn fake(respond: impl Fn(&str, &str) -> (u16, String) + Send + 'static) -> (String, Seen) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let seen: Seen = Arc::new(Mutex::new(vec![]));
        let seen2 = seen.clone();
        std::thread::spawn(move || {
            for stream in l.incoming() {
                let Ok(mut s) = stream else { break };
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut line = String::new();
                if r.read_line(&mut line).unwrap_or(0) == 0 {
                    continue;
                }
                let mut parts = line.split_whitespace();
                let (method, target) = (parts.next().unwrap_or("").to_string(), parts.next().unwrap_or("").to_string());
                let mut headers = BTreeMap::new();
                loop {
                    let mut h = String::new();
                    r.read_line(&mut h).unwrap();
                    if h.trim().is_empty() {
                        break;
                    }
                    if let Some((k, v)) = h.split_once(':') {
                        headers.insert(k.trim().to_lowercase(), v.trim().to_string());
                    }
                }
                let len: usize = headers.get("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
                let mut body = vec![0u8; len];
                r.read_exact(&mut body).unwrap();
                let (status, text) = respond(&method, &target);
                seen2.lock().unwrap().push((method, target, headers, body));
                let _ = write!(s, "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}", text.len());
            }
        });
        (format!("http://127.0.0.1:{}", addr.port()), seen)
    }

    fn client(endpoint: &str) -> S3 {
        S3 { bucket: "bk".into(), region: "us-east-1".into(), access_key: "AK".into(), secret_key: "SK".into(), endpoint: endpoint.into(), prefix: "cortendesk".into(), path_style: true }
    }

    #[test]
    fn put_list_delete_test_against_a_fake_server() {
        let (url, seen) = fake(|m, t| match (m, t) {
            ("PUT", _) | ("DELETE", _) => (200, String::new()),
            ("GET", t) if t.contains("continuation-token=NEXT") => (200, "<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>cortendesk/b.tar</Key><Size>7</Size></Contents></ListBucketResult>".into()),
            ("GET", t) if t.contains("max-keys=1000") => (200, "<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>NEXT</NextContinuationToken><Contents><Key>cortendesk/a.tar</Key><Size>5</Size></Contents><Contents><Key>cortendesk/sub/c.tar</Key><Size>1</Size></Contents><Contents><Key>cortendesk/</Key><Size>0</Size></Contents></ListBucketResult>".into()),
            ("GET", _) => (200, "<ListBucketResult></ListBucketResult>".into()),
            _ => (400, String::new()),
        });
        let s3 = client(&url);
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("x.tar");
        std::fs::write(&f, b"hello").unwrap();
        s3.put(&f, "x.tar").unwrap();
        assert_eq!(s3.list().unwrap(), vec![("a.tar".to_string(), Some(5)), ("b.tar".to_string(), Some(7))]);
        s3.delete("a.tar").unwrap();
        assert_eq!(s3.test().unwrap(), "Connected to S3 bucket bk/cortendesk.");
        let seen = seen.lock().unwrap();
        let put = &seen[0];
        assert_eq!((put.0.as_str(), put.1.as_str()), ("PUT", "/bk/cortendesk/x.tar"));
        assert_eq!(put.3, b"hello");
        assert_eq!(put.2["x-amz-content-sha256"], sha256_hex(b"hello"));
        assert_eq!(put.2["content-type"], "application/x-tar");
        assert!(put.2["authorization"].starts_with("AWS4-HMAC-SHA256 Credential=AK/") && put.2["authorization"].contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date"));
        assert_eq!(seen[1].1, "/bk/?list-type=2&max-keys=1000&prefix=cortendesk%2F");
        assert!(seen[2].1.contains("continuation-token=NEXT"));
        assert_eq!((seen[3].0.as_str(), seen[3].1.as_str()), ("DELETE", "/bk/cortendesk/a.tar"));
        assert_eq!(seen[4].1, "/bk/?list-type=2&max-keys=1&prefix=cortendesk%2F");
    }

    #[test]
    fn an_error_response_and_bad_input() {
        let (url, _) = fake(|_, _| (403, "<Error><Code>SignatureDoesNotMatch</Code><Message>no</Message></Error>".into()));
        let s3 = client(&url);
        assert_eq!(s3.test().unwrap_err(), "S3 returned HTTP 403 (SignatureDoesNotMatch: no).");
        assert_eq!(s3.delete("a.tar").unwrap_err(), "S3 returned HTTP 403 (SignatureDoesNotMatch: no).");
        let (url, _) = fake(|_, _| (200, "not xml".into()));
        assert_eq!(client(&url).list().unwrap_err(), "S3 returned a response that is not XML.");
        assert_eq!(S3 { bucket: " ".into(), ..client("http://127.0.0.1:1") }.test().unwrap_err(), "The S3 bucket name is empty.");
        assert_eq!(client("not a url").test().unwrap_err(), "The S3 endpoint is not a valid URL.");
        assert!(client("http://127.0.0.1:1").test().unwrap_err().starts_with("S3 request failed: "));
    }

    #[test]
    fn path_style_without_a_prefix() {
        let (url, seen) = fake(|_, _| (200, "<ListBucketResult></ListBucketResult>".into()));
        let s3 = S3 { path_style: true, prefix: "".into(), ..client(&url) };
        s3.test().unwrap();
        assert_eq!(seen.lock().unwrap()[0].1, "/bk/?list-type=2&max-keys=1");
    }
}
