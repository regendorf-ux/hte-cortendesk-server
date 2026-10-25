//! `multipart/form-data` bodies (the Settings -> Backups upload): the parts, split at the boundary. Text parts fill the
//! request's input like urlencoded fields do (so the CSRF `_token` is found); a part with a filename is a file.

pub struct Part<'a> {
    pub name: String,
    pub filename: Option<String>,
    pub data: &'a [u8],
}

fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() || from > hay.len() - needle.len() {
        return None;
    }
    hay[from..].windows(needle.len()).position(|w| w == needle).map(|i| i + from)
}

pub fn boundary(content_type: &str) -> Option<String> {
    if !content_type.to_ascii_lowercase().trim_start().starts_with("multipart/form-data") {
        return None;
    }
    content_type.split(';').skip(1).find_map(|p| {
        let (k, v) = p.trim().split_once('=')?;
        k.trim().eq_ignore_ascii_case("boundary").then(|| v.trim().trim_matches('"').to_string())
    })
}

fn header_param(headers: &str, param: &str) -> Option<String> {
    let lower = headers.to_ascii_lowercase();
    let key = format!("{param}=\"");
    // the parameter, not the end of another one (`name=` inside `filename=`)
    let mut at = 0;
    while let Some(i) = lower[at..].find(&key) {
        let i = at + i;
        if i == 0 || matches!(lower.as_bytes()[i - 1], b' ' | b';' | b'\t') {
            let rest = &headers[i + key.len()..];
            return rest.find('"').map(|e| rest[..e].to_string());
        }
        at = i + key.len();
    }
    None
}

/// The parts of a body, or None when the content type is not multipart/form-data or the body is not well formed.
pub fn parts<'a>(content_type: &str, body: &'a [u8]) -> Option<Vec<Part<'a>>> {
    let b = boundary(content_type)?;
    let delim = format!("--{b}").into_bytes();
    let mut out = vec![];
    let mut at = find(body, &delim, 0)?;
    loop {
        at += delim.len();
        if body[at..].starts_with(b"--") {
            return Some(out);
        }
        // the rest of the delimiter line
        at = find(body, b"\r\n", at)? + 2;
        let head_end = find(body, b"\r\n\r\n", at)?;
        let headers = String::from_utf8_lossy(&body[at..head_end]).into_owned();
        let data_start = head_end + 4;
        let next = find(body, &[b"\r\n".as_slice(), &delim].concat(), data_start)?;
        out.push(Part { name: header_param(&headers, "name").unwrap_or_default(), filename: header_param(&headers, "filename"), data: &body[data_start..next] });
        at = next + 2;
    }
}

fn pct(b: &[u8]) -> String {
    let mut s = String::new();
    for &c in b {
        if c.is_ascii_alphanumeric() || b"-_.~[]".contains(&c) {
            s.push(c as char);
        } else {
            s.push_str(&format!("%{c:02X}"));
        }
    }
    s
}

/// The text parts as an urlencoded string, for the input bag.
pub fn as_urlencoded(content_type: &str, body: &[u8]) -> Vec<u8> {
    let Some(ps) = parts(content_type, body) else { return vec![] };
    ps.iter().filter(|p| p.filename.is_none()).map(|p| format!("{}={}", pct(p.name.as_bytes()), pct(p.data))).collect::<Vec<_>>().join("&").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_text_and_file() {
        let body = b"--XyZ\r\nContent-Disposition: form-data; name=\"_token\"\r\n\r\nabc\r\n--XyZ\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"b.tar\"\r\nContent-Type: application/x-tar\r\n\r\nDATA\r\n--MORE\r\n--XyZ--\r\n";
        let ps = parts("multipart/form-data; boundary=XyZ", body).unwrap();
        assert_eq!(ps.len(), 2);
        assert_eq!((ps[0].name.as_str(), ps[0].data), ("_token", b"abc".as_slice()));
        assert_eq!((ps[1].name.as_str(), ps[1].filename.as_deref(), ps[1].data), ("upload", Some("b.tar"), b"DATA\r\n--MORE".as_slice()));
        assert_eq!(as_urlencoded("multipart/form-data; boundary=XyZ", body), b"_token=abc");
        assert!(parts("application/json", body).is_none());
    }
}
