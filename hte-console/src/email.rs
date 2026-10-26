//! Laravel's `email` validation rule (RFCValidation, egulias/email-validator), as far as an API that creates console
//! users needs it: a dot-atom local part and a host name (or a bracketed IPv4 literal) as the domain.
//!
//! Deliberately narrower than egulias: quoted local parts, comments, folding whitespace, obsolete forms and
//! non-ASCII characters are refused here and accepted by the previous console. Refusing is the safe direction (an account is not
//! created from an address nobody can mail); everything an ordinary address looks like passes the same in both.

/// `atext` of RFC 5322 section 3.2.3.
fn atext(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+/=?^_`{|}~-".contains(&b)
}

fn label(l: &[u8]) -> bool {
    !l.is_empty() && l[0] != b'-' && l[l.len() - 1] != b'-' && l.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-')
}

fn ipv4_literal(d: &[u8]) -> bool {
    let Some(inner) = d.strip_prefix(b"[").and_then(|d| d.strip_suffix(b"]")) else { return false };
    let Ok(s) = std::str::from_utf8(inner) else { return false };
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()) && p.parse::<u16>().map_or(false, |n| n <= 255))
}

/// `$value` as a string, already known not to contain CR or LF.
pub fn is_valid(s: &[u8]) -> bool {
    if s.iter().any(|b| *b == b'\r' || *b == b'\n') {
        return false;
    }
    let Some(at) = s.iter().rposition(|b| *b == b'@') else { return false };
    let (local, domain) = (&s[..at], &s[at + 1..]);
    if local.is_empty() || domain.is_empty() {
        return false;
    }
    if !local.split(|b| *b == b'.').all(|atom| !atom.is_empty() && atom.iter().all(|b| atext(*b))) {
        return false;
    }
    ipv4_literal(domain) || domain.split(|b| *b == b'.').all(label)
}

#[cfg(test)]
mod tests {
    use super::is_valid;

    #[test]
    fn ordinary_addresses() {
        for ok in ["a@b.co", "first.last+tag@example.com", "x@localhost", "o'neil@example.org", "u@[10.0.0.1]", "a_b@x-y.example"] {
            assert!(is_valid(ok.as_bytes()), "{ok}");
        }
        for bad in ["", "a", "@b.co", "a@", "a@@b.co", "a..b@c.co", ".a@c.co", "a.@c.co", "a@-b.co", "a@b-.co", "a b@c.co", "a@b..co", "a@b.co\n", "a@b_c.co", "ü@b.co", "a@[300.1.1.1]"] {
            assert!(!is_valid(bad.as_bytes()), "{bad}");
        }
    }
}
