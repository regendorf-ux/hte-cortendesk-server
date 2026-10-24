//! `App\Services\OidcUserResolver` (v1.15.0-hte.1): verified claims to a console account. The order is the
//! security core and is kept exactly: (iss, sub) first; the email only for the first link of an existing local
//! account; then just-in-time provisioning under the operator's policy.

use crate::laravel::{self, Cast};
use crate::php::{self, Fault, Val};
use crate::sqlite::{self as db, Row, P};
use rusqlite::Connection;

pub enum Outcome {
    Ok(Row),
    /// 'pending' or 'denied': the message is shown to the person and handed to the client's poll.
    Refused(String),
}

fn claim(claims: &Val, k: &str) -> Option<Val> {
    match claims {
        Val::Arr(a) => a.get_str(k).cloned(),
        _ => None,
    }
}

/// `trim((string) ($claims[$k] ?? ''))`
fn claim_str(claims: &Val, k: &str) -> Result<Vec<u8>, Fault> {
    Ok(php::trim(&claim(claims, k).unwrap_or(Val::Null).to_php_string()?).to_vec())
}

fn deny(m: &str) -> Result<Outcome, Fault> {
    Ok(Outcome::Refused(m.to_string()))
}

#[derive(PartialEq)]
enum Verification {
    Verified,
    Unverified,
    Unknown,
}

fn email_verification(c: &Connection, claims: &Val) -> Result<Verification, Fault> {
    if db::setting(c, "oidc_require_verified_email", "0")? != b"1" {
        return Ok(Verification::Verified);
    }
    let v = match claim(claims, "email_verified") {
        None | Some(Val::Null) => return Ok(Verification::Unknown),
        Some(v) => v,
    };
    let yes = matches!(v, Val::Bool(true) | Val::Int(1)) || matches!(&v, Val::Str(s) if s.eq_ignore_ascii_case(b"true") || s == b"1");
    Ok(if yes { Verification::Verified } else { Verification::Unverified })
}

fn verification_refusal(v: &Verification) -> &'static str {
    if *v == Verification::Unknown {
        "Your identity provider did not say whether this email address is verified, and this console is set to require that. An administrator can turn the requirement off under Settings \u{2192} SSO."
    } else {
        "Your identity provider reports this email address as unverified, and this console is set to require verification. Verify it with the provider, or ask an administrator to turn the requirement off under Settings \u{2192} SSO."
    }
}

/// `domainAllowed($email)`
fn domain_allowed(c: &Connection, email: &[u8]) -> Result<bool, Fault> {
    let configured = php::trim(&db::setting(c, "oidc_allowed_domains", "")?).to_vec();
    if configured.is_empty() {
        return Ok(true);
    }
    // preg_split('/[,\s]+/'), then ltrim(strtolower(trim($d)), '@'), then array_filter (drops '' and '0')
    let domains: Vec<Vec<u8>> = configured
        .split(|b| b",\t\n\x0B\x0C\r ".contains(b))
        .map(|d| {
            let d = php::trim(d).to_ascii_lowercase();
            let start = d.iter().position(|&b| b != b'@').unwrap_or(d.len());
            d[start..].to_vec()
        })
        .filter(|d| !d.is_empty() && d != b"0")
        .collect();
    if domains.is_empty() {
        return Ok(true);
    }
    let Some(at) = email.iter().position(|&b| b == b'@') else { return Ok(false) };
    let domain = &email[at + 1..];
    Ok(domains.iter().any(|d| d == domain))
}

pub fn resolve(c: &Connection, claims: &Val, now: i64) -> Result<Outcome, Fault> {
    let sub = claim_str(claims, "sub")?;
    let iss = claim_str(claims, "iss")?;
    if sub.is_empty() || iss.is_empty() {
        return deny("The identity provider did not identify the user.");
    }
    let email = claim_str(claims, "email")?.to_ascii_lowercase();
    let verification = email_verification(c, claims)?;
    if !domain_allowed(c, &email)? {
        return deny("Your email domain is not permitted to sign in to this console.");
    }
    // 1. Known identity.
    if let Some(u) = db::first(c, r#"select * from "users" where "oidc_iss" = ? and "oidc_sub" = ? limit 1"#, &[P(Val::Str(iss.clone())), P(Val::Str(sub.clone()))])? {
        return admit(c, u, &email, claims, now);
    }
    // 2. First-time linking against an existing local account.
    if !email.is_empty() {
        if let Some(mut existing) = db::first(c, r#"select * from "users" where LOWER(email) = ? limit 1"#, &[P(Val::Str(email.clone()))])? {
            if verification != Verification::Verified {
                return deny(verification_refusal(&verification));
            }
            let linked = existing.val("oidc_sub");
            if linked.to_bool() && linked != Val::Str(sub.clone()) {
                return deny("This account is already linked to a different SSO identity.");
            }
            let status = if existing.val("oidc_status").to_bool() { existing.val("oidc_status") } else { Val::str("active") };
            let ts = laravel::ts(now);
            db::update_dirty(
                c,
                "users",
                &mut existing,
                vec![("oidc_iss", Val::Str(iss), Cast::Plain), ("oidc_sub", Val::Str(sub), Cast::Plain), ("oidc_status", status, Cast::Plain)],
                &ts,
            )?;
            tracing::info!("OIDC: linked an existing account");
            return admit(c, existing, &email, claims, now);
        }
    }
    // 3. Just-in-time provisioning.
    provision(c, iss, sub, email, verification, claims, now)
}

fn admit(c: &Connection, mut user: Row, email: &[u8], claims: &Val, now: i64) -> Result<Outcome, Fault> {
    if user.val("oidc_status") == Val::str("pending") {
        return deny("Your account is waiting for administrator approval.");
    }
    if !user.val("is_active").to_bool() {
        return deny("This account is disabled. Contact your administrator.");
    }
    let mut updates = vec![];
    let name = claim_str(claims, "name")?;
    if !name.is_empty() && Val::Str(name.clone()) != user.val("name") {
        updates.push(("name", Val::Str(name), Cast::Plain));
    }
    if !email.is_empty() && user.val("email").to_php_string()?.to_ascii_lowercase() != email {
        updates.push(("email", Val::Str(email.to_vec()), Cast::Plain));
    }
    if !updates.is_empty() {
        db::update_dirty(c, "users", &mut user, updates, &laravel::ts(now))?;
    }
    Ok(Outcome::Ok(user))
}

fn provision(c: &Connection, iss: Vec<u8>, sub: Vec<u8>, email: Vec<u8>, verification: Verification, claims: &Val, now: i64) -> Result<Outcome, Fault> {
    let policy = db::setting(c, "oidc_new_user_policy", "deny")?;
    if policy != b"pending" && policy != b"active" {
        return deny("No console account matches this sign-in. Contact your administrator.");
    }
    if !email.is_empty() && verification != Verification::Verified {
        return deny(verification_refusal(&verification));
    }
    let pending = policy == b"pending";
    let name = Val::Str(claim_str(claims, "name")?);
    let email_v = Val::Str(email.clone());
    let username = unique_username(c, claims, &email)?;
    let ts = laravel::ts(now);
    let cols = vec![
        ("username", Val::Str(username)),
        ("name", if name.to_bool() { name } else { Val::Null }),
        ("email", if email_v.to_bool() { email_v } else { Val::Null }),
        // unusable by design: a provisioned account has no password to type (the `hashed` cast bcrypts it)
        ("password", Val::str(&laravel::hash_make(laravel::str_random(64).as_bytes())?)),
        ("is_admin", Val::Bool(db::setting(c, "oidc_default_admin", "0")? == b"1")),
        ("is_active", Val::Bool(true)),
        ("auth_provider", Val::str("oidc")),
        ("oidc_iss", Val::Str(iss)),
        ("oidc_sub", Val::Str(sub)),
        ("oidc_status", Val::str(if pending { "pending" } else { "active" })),
    ];
    let id = db::insert(c, "users", cols, &ts)?;
    let group_id = Val::Str(db::setting(c, "oidc_default_group_id", "0")?).to_int();
    if group_id > 0 {
        // syncWithoutDetaching([$groupId]) on a brand-new user: one pivot row (a missing group fails the foreign key)
        db::exec(c, r#"insert into "user_group_user" ("user_group_id", "user_id") values (?, ?)"#, &[P(Val::Int(group_id)), P(Val::Int(id))])?;
    }
    tracing::info!(pending, "OIDC: provisioned an account");
    if pending {
        return deny("Your account has been created and is waiting for administrator approval.");
    }
    Ok(Outcome::Ok(crate::signin::find_user(c, &Val::Int(id))?.ok_or_else(|| Fault::Other("the new user vanished".into()))?))
}

/// `uniqueUsername($claims, $email)`
fn unique_username(c: &Connection, claims: &Val, email: &[u8]) -> Result<Vec<u8>, Fault> {
    let truthy = |v: &[u8]| !(v.is_empty() || v == b"0");
    let before_at = email.split(|&b| b == b'@').next().unwrap_or(b"").to_vec();
    let mut candidate = claim_str(claims, "preferred_username")?;
    if !truthy(&candidate) {
        candidate = claim_str(claims, "name")?;
    }
    if !truthy(&candidate) {
        candidate = before_at;
    }
    if !truthy(&candidate) {
        candidate = b"user".to_vec();
    }
    // preg_replace('/[^a-zA-Z0-9_]/', '_') byte by byte, strtolower, '/_+/' -> '_', trim '_', Str::limit(45, '')
    let replaced: Vec<u8> = candidate.iter().map(|&b| if b.is_ascii_alphanumeric() || b == b'_' { b.to_ascii_lowercase() } else { b'_' }).collect();
    let mut collapsed: Vec<u8> = vec![];
    for b in replaced {
        if b == b'_' && collapsed.last() == Some(&b'_') {
            continue;
        }
        collapsed.push(b);
    }
    let start = collapsed.iter().position(|&b| b != b'_').unwrap_or(collapsed.len());
    let end = collapsed.iter().rposition(|&b| b != b'_').map_or(start, |p| p + 1);
    let mut base = collapsed[start..end.max(start)].to_vec();
    if base.is_empty() {
        base = b"user".to_vec();
    }
    base.truncate(45);
    let mut username = base.clone();
    let mut suffix = 1;
    while db::first(c, r#"select exists(select * from "users" where "username" = ?) as "exists""#, &[P(Val::Str(username.clone()))])?.map_or(false, |r| r.val("exists").to_bool()) {
        username = base.clone();
        username.extend_from_slice(format!("_{suffix}").as_bytes());
        suffix += 1;
    }
    Ok(username)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(
            r#"create table "users" ("id" integer primary key autoincrement not null, "username" varchar not null, "name" varchar, "email" varchar, "password" varchar not null, "is_admin" tinyint(1) not null default '0', "is_active" tinyint(1) not null default '1', "auth_provider" varchar not null default 'local', "oidc_sub" varchar, "oidc_iss" varchar, "oidc_status" varchar, "created_at" datetime, "updated_at" datetime);
               create table "settings" ("key" varchar not null, "value" text, "created_at" datetime, "updated_at" datetime, primary key ("key"));
               insert into users (username, password) values ('anna', 'x'), ('anna_1', 'x');"#,
        )
        .unwrap();
        c
    }

    fn claims(s: &str) -> Val {
        php::json_decode(s.as_bytes(), &Default::default()).unwrap()
    }

    #[test]
    fn usernames_like_php() {
        let c = db();
        assert_eq!(unique_username(&c, &claims(r#"{"preferred_username":"Anna"}"#), b"").unwrap(), b"anna_2");
        assert_eq!(unique_username(&c, &claims(r#"{"preferred_username":"  Jörg  Müller "}"#), b"").unwrap(), b"j_rg_m_ller");
        assert_eq!(unique_username(&c, &claims(r#"{"preferred_username":"0","name":"__Bob__"}"#), b"").unwrap(), b"bob");
        assert_eq!(unique_username(&c, &claims(r#"{}"#), b"carl.d@example.com").unwrap(), b"carl_d");
        assert_eq!(unique_username(&c, &claims(r#"{}"#), b"").unwrap(), b"user");
        assert_eq!(unique_username(&c, &claims(r#"{"name":"!!!"}"#), b"").unwrap(), b"user");
        let long = "x".repeat(60);
        assert_eq!(unique_username(&c, &claims(&format!(r#"{{"name":"{long}"}}"#)), b"").unwrap().len(), 45);
    }

    #[test]
    fn domains_like_php() {
        let c = db();
        assert!(domain_allowed(&c, b"").unwrap());
        c.execute_batch("insert into settings (key, value) values ('oidc_allowed_domains', ' @Example.com, other.org 0')").unwrap();
        assert!(domain_allowed(&c, b"a@example.com").unwrap());
        assert!(domain_allowed(&c, b"a@other.org").unwrap());
        assert!(!domain_allowed(&c, b"a@sub.example.com").unwrap());
        assert!(!domain_allowed(&c, b"noat").unwrap());
        assert!(!domain_allowed(&c, b"").unwrap());
    }

    #[test]
    fn deny_policy_and_link_rules() {
        let c = db();
        let iss = "https://idp.example";
        let out = resolve(&c, &claims(&format!(r#"{{"iss":"{iss}","sub":"s1","email":"new@example.com"}}"#)), 0).unwrap();
        assert!(matches!(out, Outcome::Refused(m) if m.starts_with("No console account")));
        c.execute_batch("update users set email = 'Anna@Example.com' where username = 'anna'").unwrap();
        let out = resolve(&c, &claims(&format!(r#"{{"iss":"{iss}","sub":"s1","email":"ANNA@example.com","name":"Anna A"}}"#)), 0).unwrap();
        let Outcome::Ok(u) = out else { panic!("linked") };
        assert_eq!(u.val("oidc_sub"), Val::str("s1"));
        // strtolower($user->email) === $email: the stored spelling stays
        assert_eq!(u.val("email"), Val::str("Anna@Example.com"));
        assert_eq!(u.val("name"), Val::str("Anna A"));
        // a second identity with the same address is refused
        let out = resolve(&c, &claims(&format!(r#"{{"iss":"{iss}","sub":"s2","email":"anna@example.com"}}"#)), 0).unwrap();
        assert!(matches!(out, Outcome::Refused(m) if m.contains("already linked")));
        // the same identity is found by (iss, sub), whatever the email says now
        let out = resolve(&c, &claims(&format!(r#"{{"iss":"{iss}","sub":"s1","email":""}}"#)), 0).unwrap();
        assert!(matches!(out, Outcome::Ok(_)));
    }
}
