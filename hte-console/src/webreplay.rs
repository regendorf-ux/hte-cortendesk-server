//! `hte-console web-signin-replay <php-url> <rust-url>`: phase 8's comparison of the console's sign-in against PHP's.
//!
//! The same scenario runs against each console with a browser-like cookie jar of its own (from the same address, on
//! the same seeded database copy): the sign-in page; the break-glass password (wrong, unknown, disabled, empty,
//! SSO-created, waiting for approval, no CSRF token, right); the signed-in sign-in page; logout; the per-account
//! throttle; and Microsoft sign-in through the fake identity provider in every mode it has (each broken-token kind,
//! a refusal by the provider, an outsider, a disabled account, linking by e-mail, a known identity, provisioning).
//! For every step it compares the status, where a redirect goes, the text a person reads (digits folded: the seconds
//! of a throttle message and the times inside a token message differ by a second between two runs) and the sequence
//! of CSS classes. The rows both consoles write are compared afterwards by the script (`replay-signin-web.sh`) with
//! `snapshot`.
//!
//! Differences listed as "by design" (never counted): the token kinds phase 2 hardened (no `exp`, several audiences
//! without `azp`), which PHP accepts and hte-console refuses. `HTE_WEBREPLAY_MUTATE=1` changes one of hte-console's
//! answers before the comparison, to prove the comparison can fail.

use crate::pagereplay::shape;
use std::collections::BTreeMap;

pub struct Report {
    pub total: usize,
    pub differences: Vec<String>,
    pub by_design: Vec<String>,
}

/// One step's answer, as compared.
#[derive(Clone, Debug, PartialEq)]
struct Obs {
    status: u16,
    location: String,
    text: Vec<String>,
    classes: Vec<String>,
}

/// The seed's accounts (fixtures/signin's seed and the one added by the script).
const BREAK_GLASS: (&str, &str) = ("user-5eed0002", "tok-5eed00000000b002");
const DISABLED: &str = "user-5eed0003";
const SSO_CREATED: (&str, &str) = ("user-5eed0004", "tok-5eed00000000b004");
const WAITING: &str = "user-5eed0005";
const THROTTLED: &str = "user-5eed0008";
const WRONG: &str = "tok-5eed0000wrongpw1";

/// Modes PHP accepts and hte-console refuses (phase 2's hardening, `README.md` of the crate).
const HARDENED: &[&str] = &["no-exp", "multi-aud"];

struct Browser {
    c: reqwest::Client,
    base: String,
    jar: BTreeMap<String, String>,
}

fn path_of(location: &str) -> String {
    match location.find("://") {
        Some(i) => location[i + 3..].find('/').map(|j| location[i + 3 + j..].to_string()).unwrap_or_else(|| "/".into()),
        None => location.to_string(),
    }
}

fn fold_digits(words: Vec<String>) -> Vec<String> {
    words.into_iter().map(|w| w.chars().map(|c| if c.is_ascii_digit() { '#' } else { c }).collect()).collect()
}

impl Browser {
    fn new(base: &str) -> Browser {
        Browser { c: reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().expect("client"), base: base.trim_end_matches('/').to_string(), jar: BTreeMap::new() }
    }

    fn cookie_header(&self) -> String {
        self.jar.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; ")
    }

    /// A request to this console (path) or anywhere (absolute URL); the jar is sent to this console only.
    async fn go(&mut self, method: &str, url: &str, form: Option<Vec<(&str, String)>>) -> Result<(u16, String, String), String> {
        let ours = !url.starts_with("http");
        let full = if ours { format!("{}{url}", self.base) } else { url.to_string() };
        let mut rq = self.c.request(method.parse().map_err(|_| "method")?, &full).header("x-forwarded-for", "198.18.9.1").header("user-agent", "hte-web-signin-replay");
        if ours || full.starts_with(&self.base) {
            rq = rq.header("cookie", self.cookie_header());
        }
        if let Some(f) = form {
            let pairs: Vec<(&str, &[u8])> = f.iter().map(|(k, v)| (*k, v.as_bytes())).collect();
            rq = rq.header("content-type", "application/x-www-form-urlencoded").body(crate::laravel::http_build_query(&pairs));
        }
        let r = rq.send().await.map_err(|e| format!("{method} {full}: {e}"))?;
        if ours || full.starts_with(&self.base) {
            for v in r.headers().get_all("set-cookie") {
                let Ok(s) = v.to_str() else { continue };
                let first = s.split(';').next().unwrap_or("");
                let Some((k, val)) = first.split_once('=') else { continue };
                let gone = s.to_ascii_lowercase().contains("max-age=0") || val == "deleted";
                if gone {
                    self.jar.remove(k.trim());
                } else {
                    self.jar.insert(k.trim().to_string(), val.to_string());
                }
            }
        }
        let status = r.status().as_u16();
        let location = r.headers().get("location").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        Ok((status, location, r.text().await.map_err(|e| e.to_string())?))
    }

    async fn obs(&mut self, method: &str, path: &str, form: Option<Vec<(&str, String)>>) -> Result<Obs, String> {
        let (status, location, body) = self.go(method, path, form).await?;
        let (text, classes) = if status == 200 { shape(&body) } else { (vec![], vec![]) };
        Ok(Obs { status, location: path_of(&location), text: fold_digits(text), classes })
    }

    /// The CSRF token of the page at `path` (its `csrf-token` meta).
    async fn token(&mut self, path: &str) -> Result<String, String> {
        let (_, _, body) = self.go("GET", path, None).await?;
        let i = body.find("name=\"csrf-token\" content=\"").ok_or_else(|| format!("{path}: no csrf-token"))? + 27;
        Ok(body[i..].split('"').next().unwrap_or("").to_string())
    }

    async fn password(&mut self, user: &str, pw: &str) -> Result<Obs, String> {
        let t = self.token("/login").await?;
        self.obs("POST", "/login", Some(vec![("_token", t), ("username", user.into()), ("password", pw.into()), ("remember", "on".into())])).await
    }

    async fn logout(&mut self) -> Result<Obs, String> {
        let t = self.token("/account").await?;
        self.obs("POST", "/logout", Some(vec![("_token", t)])).await
    }
}

/// The whole scenario on one console: (label, answer) in order.
async fn scenario(base: &str) -> Result<Vec<(String, Obs)>, String> {
    let mut out: Vec<(String, Obs)> = vec![];
    let mut b = Browser::new(base);
    out.push(("sign-in page".into(), b.obs("GET", "/login", None).await?));
    for (label, user, pw) in [
        ("wrong password", BREAK_GLASS.0, WRONG),
        ("unknown account", "user-5eed0999", WRONG),
        ("disabled account", DISABLED, BREAK_GLASS.1),
        ("empty username", "", WRONG),
        ("account made by single sign-on", SSO_CREATED.0, SSO_CREATED.1),
        ("account waiting for approval", WAITING, BREAK_GLASS.1),
    ] {
        out.push((label.into(), b.password(user, pw).await?));
        out.push((format!("{label}: the page after"), b.obs("GET", "/login", None).await?));
    }
    out.push(("no CSRF token".into(), b.obs("POST", "/login", Some(vec![("username", BREAK_GLASS.0.into()), ("password", BREAK_GLASS.1.into())])).await?));
    out.push(("break-glass password".into(), b.password(BREAK_GLASS.0, BREAK_GLASS.1).await?));
    out.push(("signed in: the sign-in page".into(), b.obs("GET", "/login", None).await?));
    out.push(("logout".into(), b.logout().await?));
    out.push(("after logout".into(), b.obs("GET", "/account", None).await?));
    out.push(("logout again (no session)".into(), b.obs("POST", "/logout", Some(vec![])).await?));
    // the per-account throttle: five failures, then even the right password waits (alarm 100, one row)
    let mut t = Browser::new(base);
    for i in 0..5 {
        let o = t.password(THROTTLED, WRONG).await?;
        if i == 4 {
            out.push(("throttle: fifth failure".into(), o));
        }
    }
    out.push(("throttle: sixth attempt".into(), t.password(THROTTLED, BREAK_GLASS.1).await?));
    out.push(("throttle: the page after".into(), t.obs("GET", "/login", None).await?));
    // Microsoft sign-in through the fake provider
    let mut modes: Vec<(&str, &str)> = vec![("ok", "linked"), ("ok", "known"), ("ok", "anna"), ("ok", "outsider"), ("ok", "disabled")];
    modes.extend(crate::fake_idp::MODES.iter().filter(|m| !["ok", "slow-token", "wrong-tid"].contains(m)).map(|m| (*m, "known")));
    for (mode, user) in modes {
        let label = format!("sso {mode} {user}");
        let mut s = Browser::new(base);
        s.go("GET", "/login", None).await?;
        let (status, auth, _) = s.go("GET", "/login/oidc", None).await?;
        let u = url::Url::parse(&auth).map_err(|_| format!("{label}: the start did not redirect to the provider ({status})"))?;
        let mut keys: Vec<String> = u.query_pairs().map(|(k, _)| k.into_owned()).collect();
        keys.sort();
        let q: BTreeMap<String, String> = u.query_pairs().into_owned().collect();
        let start = Obs {
            status,
            location: format!("{} redirect_uri={} method={} challenge={} nonce={}", keys.join(","), path_of(q.get("redirect_uri").map_or("", |s| s)), q.get("code_challenge_method").map_or("", |s| s), q.get("code_challenge").map_or(0, |s| s.len()), q.get("nonce").map_or(0, |s| s.len())),
            text: vec![],
            classes: vec![],
        };
        out.push((format!("{label}: start"), start));
        let (_, back, _) = s.go("GET", &format!("{auth}&hte_fake={mode}&hte_user={user}"), None).await?;
        let cb = path_of(&back);
        let o = s.obs("GET", &cb, None).await?;
        let signed_in = o.location == "/";
        out.push((format!("{label}: callback"), o));
        if signed_in {
            out.push((format!("{label}: logout"), s.logout().await?));
        } else {
            out.push((format!("{label}: the page after"), s.obs("GET", "/login", None).await?));
        }
    }
    Ok(out)
}

pub async fn run(php: &str, rust: &str) -> Result<Report, String> {
    let a = scenario(php).await?;
    let mut b = scenario(rust).await?;
    if std::env::var("HTE_WEBREPLAY_MUTATE").map_or(false, |v| v == "1") {
        if let Some((_, o)) = b.first_mut() {
            o.text.push("mutated".into());
        }
    }
    let (mut differences, mut by_design) = (vec![], vec![]);
    if a.len() != b.len() {
        differences.push(format!("the scenario has {} steps on PHP and {} on hte-console", a.len(), b.len()));
    }
    for ((label, x), (_, y)) in a.iter().zip(b.iter()) {
        if x == y {
            continue;
        }
        let hardened = HARDENED.iter().any(|m| label.starts_with(&format!("sso {m} ")));
        let mut what = vec![];
        if x.status != y.status {
            what.push(format!("status {} / {}", x.status, y.status));
        }
        if x.location != y.location {
            what.push(format!("redirect {:?} / {:?}", x.location, y.location));
        }
        if x.text != y.text {
            what.push(format!("text\n    PHP:         {}\n    hte-console: {}", x.text.join(" "), y.text.join(" ")));
        }
        if x.classes != y.classes {
            let i = x.classes.iter().zip(y.classes.iter()).position(|(p, q)| p != q).unwrap_or(x.classes.len().min(y.classes.len()));
            what.push(format!("classes from #{i}: {:?} / {:?}", x.classes.get(i), y.classes.get(i)));
        }
        let line = format!("{label}: {}", what.join("; "));
        if hardened {
            by_design.push(format!("{label}: PHP signs in, hte-console refuses the token (phase 2 hardening): {}", what.join("; ").lines().next().unwrap_or("")));
        } else {
            differences.push(line);
        }
    }
    Ok(Report { total: a.len().min(b.len()), differences, by_design })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digits_fold_and_locations_lose_their_host() {
        assert_eq!(fold_digits(vec!["in".into(), "59".into(), "seconds.".into()]), vec!["in", "##", "seconds."]);
        assert_eq!(path_of("http://h:8080/login"), "/login");
        assert_eq!(path_of("http://h:8080"), "/");
        assert_eq!(path_of("/x"), "/x");
    }
}
