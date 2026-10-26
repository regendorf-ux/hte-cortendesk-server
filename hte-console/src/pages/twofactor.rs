//! Phase 8 (0.8.2): Account → Two-Factor Authentication, ported from v1.15.0-hte.1 `TwoFactorSettings` and
//! `App\Support\TwoFactor`: enrol (QR code + manual key, confirmed by a code), recovery codes (10, shown once, bcrypt
//! stored), regenerate them, turn it off (password; refused while it is required).
//!
//!   GET  /account/two-factor
//!   POST /account/two-factor   do=start | cancel | confirm | regenerate | disable | dismiss
//!
//! Deliberate difference: the previous console keeps the candidate secret in the session until it is confirmed; here it travels in the
//! form as `Crypt::encryptString("<user id>|<secret>")` (the app key's AES-256-CBC + HMAC), so the page writes no
//! session state; a blob made for one account does not work for another, and the secret is on the screen anyway.
//! Recovery codes are only ever in the answer to the post that made them.

use super::kit::*;
use super::{Ctx, Reply, Req};
use crate::laravel::{self, Cast};
use crate::php::{Fault, Val};
use crate::sqlite::{self as db, P};
use rusqlite::Connection;
use serde_json::json;

/// `TwoFactor::ISSUER` (the previous console's said CortenDesk; the name in the authenticator app only, codes do not depend on it), `RECOVERY_COUNT`
const ISSUER: &str = "HTE Remote";
const RECOVERY_COUNT: usize = 10;
/// How long a started enrolment can be confirmed (the previous console's lasts as long as the session).
const SETUP_TTL: i64 = 15 * 60;

/// RFC 4648 base32, upper case, no padding (otphp's `Base32::encodeUpper`, trimmed).
pub fn base32(bytes: &[u8]) -> String {
    const A: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in bytes {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(A[((buf >> bits) & 31) as usize] as char);
        }
        buf &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(A[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// `TwoFactor::generateSecret()`: otphp's `TOTP::generate()` (64 random bytes, base32).
pub fn generate_secret() -> String {
    use rand::RngCore;
    let mut b = [0u8; 64];
    rand::rngs::OsRng.fill_bytes(&mut b);
    base32(&b)
}

/// `TwoFactor::provisioningUri($secret, $label)`: what otphp 11 builds (issuer and secret, defaults left out).
pub fn provisioning_uri(secret: &str, label: &str) -> String {
    format!("otpauth://totp/{}?issuer={}&secret={secret}", crate::laravel::urlencode(format!("{ISSUER}:{label}").as_bytes()).replace('+', "%20"), crate::laravel::urlencode(ISSUER.as_bytes()).replace('+', "%20"))
}

/// `TwoFactor::qrSvg()`: the URI as an inline SVG, 200 px, a one-module margin.
pub fn qr_svg(data: &str) -> String {
    use qrcodegen::{QrCode, QrCodeEcc};
    let Ok(qr) = QrCode::encode_text(data, QrCodeEcc::Low) else { return String::new() };
    let n = qr.size();
    let dim = n + 2;
    let mut path = String::new();
    for y in 0..n {
        for x in 0..n {
            if qr.get_module(x, y) {
                path.push_str(&format!("M{},{}h1v1h-1z", x + 1, y + 1));
            }
        }
    }
    format!(r##"<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="200" height="200" viewBox="0 0 {dim} {dim}" shape-rendering="crispEdges"><rect width="100%" height="100%" fill="#ffffff"/><path fill="#000000" d="{path}"/></svg>"##)
}

/// `TwoFactor::generateRecoveryCodes()`: XXXXX-XXXXX from an alphabet without 0/O/1/I.
pub fn recovery_codes() -> Vec<String> {
    use rand::Rng;
    const A: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::rngs::OsRng;
    let block = |rng: &mut rand::rngs::OsRng| (0..5).map(|_| A[rng.gen_range(0..A.len())] as char).collect::<String>();
    (0..RECOVERY_COUNT).map(|_| format!("{}-{}", block(&mut rng), block(&mut rng))).collect()
}

/// `RequireTwoFactor::isRequiredFor($user)`
fn required(ctx: &Ctx, c: &Connection) -> Result<bool, Fault> {
    crate::signin::two_factor_required(c, &ctx.user)
}

fn remaining(c: &Connection, uid: i64) -> Result<i64, Fault> {
    count(c, r#"select count(*) as aggregate from "two_factor_recovery_codes" where "two_factor_recovery_codes"."user_id" = ? and "two_factor_recovery_codes"."user_id" is not null and "used_at" is null"#, &[P(Val::Int(uid))])
}

/// `issueRecoveryCodes()`: the old set deleted, ten new ones stored as bcrypt hashes (created_at only).
fn issue_codes(ctx: &Ctx, c: &Connection) -> Result<Vec<String>, Fault> {
    db::exec(c, r#"delete from "two_factor_recovery_codes" where "two_factor_recovery_codes"."user_id" = ? and "two_factor_recovery_codes"."user_id" is not null"#, &[P(Val::Int(ctx.uid()))])?;
    let codes = recovery_codes();
    for code in &codes {
        db::exec(
            c,
            r#"insert into "two_factor_recovery_codes" ("user_id", "code_hash", "created_at") values (?, ?, ?)"#,
            &[P(Val::Int(ctx.uid())), P(Val::str(&laravel::hash_make(code.as_bytes())?)), P(Val::str(&laravel::ts(ctx.now)))],
        )?;
    }
    Ok(codes)
}

/// What the page shows.
#[derive(Default)]
struct View {
    setup: Option<String>,
    codes: Vec<String>,
    error_field: &'static str,
    error: String,
}

fn render(ctx: &Ctx, c: &Connection, v: View) -> Result<Reply, Fault> {
    let user = find(c, "users", ctx.uid())?.ok_or_else(|| Fault::Other("user vanished".into()))?;
    let enabled = user.val("totp_enabled").to_bool();
    let username = s(&user, "username");
    let (secret, qr, blob) = match &v.setup {
        Some(sec) if !enabled => {
            let blob = ctx.p.n.crypt.encrypt_string(format!("{}|{}|{sec}", ctx.uid(), ctx.now).as_bytes());
            (sec.clone(), qr_svg(&provisioning_uri(sec, &username)), blob)
        }
        _ => (String::new(), String::new(), String::new()),
    };
    let rem = if enabled { remaining(c, ctx.uid())? } else { 0 };
    let layout = ctx.layout(c, "account.two-factor", "Two-Factor Authentication", "Account")?;
    let page = json!({
        "tfa": {
            "enabled": enabled, "confirmed_at": ymd(&user, "totp_confirmed_at"), "remaining": rem, "required": required(ctx, c)?,
            "setting_up": !secret.is_empty(), "secret": secret, "qr": qr, "setup_blob": blob, "codes": v.codes,
            "error_field": v.error_field, "error": v.error,
        },
        "enforced": ctx.flashed.get("twofactor_enforced").and_then(|v| v.as_str()).unwrap_or(""),
    });
    Ok(Reply::Html(200, ctx.render("account/two-factor-page.html", layout, page)?))
}

fn error(field: &'static str, m: &str) -> View {
    View { error_field: field, error: m.to_string(), ..Default::default() }
}

/// `GET|POST /account/two-factor`
pub fn page(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    if req.method != "POST" {
        return render(ctx, c, View::default());
    }
    let body = Body::of(req);
    let mut user = find(c, "users", ctx.uid())?.ok_or_else(|| Fault::Other("user vanished".into()))?;
    let enabled = user.val("totp_enabled").to_bool();
    let username = s(&user, "username");
    match body.get("do").as_str() {
        "start" => render(ctx, c, View { setup: Some(generate_secret()), ..Default::default() }),
        "confirm" => {
            if enabled {
                return render(ctx, c, View::default());
            }
            // the candidate secret, only from a blob made for this account
            let secret = ctx
                .p
                .n
                .crypt
                .decrypt_string(body.get("setup").as_bytes())
                .ok()
                .and_then(|b| String::from_utf8(b).ok())
                // "<user id>|<made at>|<secret>": this account's, and at most SETUP_TTL old
                .and_then(|t| {
                    let mut it = t.splitn(3, '|');
                    let (uid, at, secret) = (it.next()?, it.next()?.parse::<i64>().ok()?, it.next()?);
                    (uid == ctx.uid().to_string() && at + SETUP_TTL >= ctx.now).then(|| secret.to_string())
                })
                .unwrap_or_default();
            let code = body.get("code");
            if code.trim().is_empty() {
                return render(ctx, c, View { setup: (!secret.is_empty()).then(|| secret.clone()), ..error("code", "The confirm code field is required.") });
            }
            let step = if secret.is_empty() { None } else { crate::totp::verify(secret.as_bytes(), code.as_bytes(), ctx.now)? };
            let Some(step) = step else {
                return render(ctx, c, View { setup: (!secret.is_empty()).then(|| secret.clone()), ..error("code", "That code is incorrect or has expired. Try the current one.") });
            };
            update(
                c,
                "users",
                &mut user,
                vec![
                    ("totp_secret", Val::str(&ctx.p.n.crypt.encrypt_string(secret.as_bytes())), Cast::Plain),
                    ("totp_enabled", Val::Bool(true), Cast::Bool),
                    ("totp_confirmed_at", Val::str(&laravel::ts(ctx.now)), Cast::Date),
                    ("totp_last_timestep", Val::Int(step), Cast::Plain),
                ],
                ctx.now,
            )?;
            let codes = issue_codes(ctx, c)?;
            audit(ctx, c, "user.2fa-enable", "Enabled two-factor authentication", Some("user"), Some(&username))?;
            render(ctx, c, View { codes, ..Default::default() })
        }
        "regenerate" | "disable" => {
            if !enabled {
                return render(ctx, c, View::default());
            }
            let disabling = body.get("do") == "disable";
            if disabling && required(ctx, c)? {
                return render(ctx, c, error("password", "Two-factor authentication is required for your account and cannot be disabled."));
            }
            let pw = body.get("password");
            if pw.is_empty() {
                return render(ctx, c, error("password", "The password field is required."));
            }
            if !laravel::hash_check(pw.as_bytes(), &user.val("password"))? {
                return render(ctx, c, error("password", "That password is incorrect."));
            }
            if disabling {
                // `clearTwoFactor()`
                db::exec(c, r#"delete from "two_factor_recovery_codes" where "two_factor_recovery_codes"."user_id" = ? and "two_factor_recovery_codes"."user_id" is not null"#, &[P(Val::Int(ctx.uid()))])?;
                update(
                    c,
                    "users",
                    &mut user,
                    vec![("totp_secret", Val::Null, Cast::Plain), ("totp_enabled", Val::Bool(false), Cast::Bool), ("totp_confirmed_at", Val::Null, Cast::Date), ("totp_last_timestep", Val::Null, Cast::Plain)],
                    ctx.now,
                )?;
                audit(ctx, c, "user.2fa-disable", "Disabled two-factor authentication", Some("user"), Some(&username))?;
                return render(ctx, c, View::default());
            }
            let codes = issue_codes(ctx, c)?;
            audit(ctx, c, "user.2fa-recovery-regenerate", "Regenerated 2FA recovery codes", Some("user"), Some(&username))?;
            render(ctx, c, View { codes, ..Default::default() })
        }
        // cancel, dismiss: the page as it is
        _ => Ok(Reply::Redirect("/account/two-factor".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_uris_and_codes() {
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
        assert_eq!(crate::totp::base32_decode(base32(&[1, 2, 3, 250]).as_bytes()).unwrap(), vec![1, 2, 3, 250]);
        let s = generate_secret();
        assert_eq!(s.len(), 103);
        assert_eq!(provisioning_uri("ABC", "anna"), "otpauth://totp/HTE%20Remote%3Aanna?issuer=HTE%20Remote&secret=ABC");
        let codes = recovery_codes();
        assert_eq!(codes.len(), 10);
        assert!(codes.iter().all(|c| super::super::challenge::looks_like_recovery(c) && !c.contains('0') && !c.contains('O') && !c.contains('1') && !c.contains('I')));
        let svg = qr_svg(&provisioning_uri("ABC", "anna"));
        assert!(svg.starts_with("<svg") && svg.contains("<path"));
    }
}
