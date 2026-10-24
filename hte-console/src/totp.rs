//! `App\Support\TwoFactor` (v1.15.0-hte.1): TOTP as otphp 11.5 computes it with the console's settings
//! (SHA-1, 6 digits, 30-second period, epoch 0), checked with a ±1 step window that returns the HIGHEST matching
//! step, and `consumeTotp`'s replay guard (one conditional UPDATE of `users.totp_last_timestep`).

use crate::php::{self, Fault};
use hmac::{Hmac, Mac};

pub const PERIOD: i64 = 30;

/// The TOTP secret of the replay's and the tests' seeded user (RFC 6238's own test key, base32). Test only.
pub const REPLAY_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

/// RFC 4648 base32 as otphp reads a secret (ParagonIE `Base32::decodeUpper`, no padding required). A character
/// outside the alphabet is an exception in PHP (500); None here.
pub fn base32_decode(s: &[u8]) -> Option<Vec<u8>> {
    let s: Vec<u8> = s.iter().copied().take_while(|&c| c != b'=').collect();
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let (mut buf, mut bits) = (0u64, 0u32);
    for c in s {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        } as u64;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// `$totp->at($timestamp)`: the 6-digit code of the step that holds `timestamp`.
pub fn at(key: &[u8], step: i64) -> String {
    let mut m = <Hmac<sha1::Sha1> as Mac>::new_from_slice(key).expect("hmac takes any key length");
    m.update(&(step as u64).to_be_bytes());
    let h = m.finalize().into_bytes();
    let off = (h[h.len() - 1] & 0x0f) as usize;
    let bin = ((h[off] as u32 & 0x7f) << 24) | ((h[off + 1] as u32) << 16) | ((h[off + 2] as u32) << 8) | h[off + 3] as u32;
    format!("{:06}", bin % 1_000_000)
}

/// `TwoFactor::verify($secret, $code)`: the accepted step, or None. Err where otphp throws (a secret that is not
/// base32).
pub fn verify(secret: &[u8], code: &[u8], now: i64) -> Result<Option<i64>, Fault> {
    let code = php::trim(code);
    if code.len() != 6 || !code.iter().all(u8::is_ascii_digit) {
        return Ok(None);
    }
    let key = base32_decode(secret).ok_or_else(|| Fault::Other("TOTP secret is not base32".into()))?;
    let current = now.div_euclid(PERIOD);
    for offset in [1, 0, -1] {
        let step = current + offset;
        if step < 0 {
            continue;
        }
        if php::hash_equals(at(&key, step).as_bytes(), code) {
            return Ok(Some(step));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_sha1_vectors() {
        // RFC 6238 appendix B, SHA-1 key "12345678901234567890", 8 digits there: the last 6 here.
        let key = b"12345678901234567890";
        assert_eq!(at(key, 59 / PERIOD), "287082");
        assert_eq!(at(key, 1111111109 / PERIOD), "081804");
        assert_eq!(at(key, 1234567890 / PERIOD), "005924");
        assert_eq!(at(key, 2000000000 / PERIOD), "279037");
    }

    #[test]
    fn base32_like_paragonie() {
        assert_eq!(base32_decode(b"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap(), b"12345678901234567890");
        assert_eq!(base32_decode(b"MZXW6===").unwrap(), b"foo");
        assert!(base32_decode(b"mzxw6").is_none(), "decodeUpper: lower case is not the alphabet");
        assert!(base32_decode(b"MZ1W6").is_none());
    }

    #[test]
    fn window_returns_the_highest_step() {
        let secret = b"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let key = base32_decode(secret).unwrap();
        let now = 1_800_000_015;
        let cur = now / PERIOD;
        assert_eq!(verify(secret, at(&key, cur).as_bytes(), now).unwrap(), Some(cur));
        assert_eq!(verify(secret, at(&key, cur + 1).as_bytes(), now).unwrap(), Some(cur + 1));
        assert_eq!(verify(secret, at(&key, cur - 1).as_bytes(), now).unwrap(), Some(cur - 1));
        assert_eq!(verify(secret, at(&key, cur - 2).as_bytes(), now).unwrap(), None);
        assert_eq!(verify(secret, b"12345", now).unwrap(), None);
        assert_eq!(verify(secret, b"12a456", now).unwrap(), None);
        assert!(verify(b"not base32!", b"123456", now).is_err());
    }
}
