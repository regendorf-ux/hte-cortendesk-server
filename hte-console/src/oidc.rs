//! `App\Services\OidcService` (v1.15.0-hte.1) for the RustDesk client's sign-in: the settings, discovery and JWKS
//! (cached), the authorization URL with PKCE (S256), the token exchange, and the ID token's checks as
//! firebase/php-jwt 7.1.0 makes them, with the same messages.
//!
//! Stricter than PHP, quietly (the answer for a valid sign-in is the same; the crate's notes list each):
//! - only RS256 is accepted, whatever the provider advertises (PHP accepts any advertised algorithm, HS* with the
//!   client secret as the key);
//! - `exp` and `nonce` must be present (PHP checks `exp` only when there is one);
//! - with more than one audience, `azp` must be this client; for a Microsoft issuer, `tid` must be the issuer's tenant;
//! - an unknown `kid` refetches the key set once (at most once a minute) before failing, for key rotation;
//! - the provider is spoken to over https only (`HTE_CONSOLE_OIDC_ALLOW_HTTP=1` for the replay's fake provider),
//!   no redirects are followed and every answer is read to at most 1 MiB.
//!
//! Nothing here logs a token, a code, a secret or a claim.

use crate::laravel::{self, Encrypter};
use crate::php::{self, Arr, Fault, Key, Val};
use crate::sqlite as db;
use rusqlite::Connection;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Discovery and JWKS cache lifetime (PHP: `DISCOVERY_TTL`).
pub const DISCOVERY_TTL: Duration = Duration::from_secs(300);
/// Clock skew allowed on exp/nbf/iat (PHP: `LEEWAY`).
pub const LEEWAY: i64 = 60;
/// An unknown `kid` refetches the key set at most this often.
pub const JWKS_REFETCH: Duration = Duration::from_secs(60);
/// Largest answer read from the provider.
pub const MAX_PROVIDER_BYTES: usize = 1 << 20;

/// What `OidcService` throws: an `OidcException` (its message is shown to the person) or anything else (a 500).
#[derive(Debug, Clone, PartialEq)]
pub enum OidcError {
    Msg(String),
    Fault(Fault),
}

impl From<Fault> for OidcError {
    fn from(f: Fault) -> Self {
        OidcError::Fault(f)
    }
}

fn msg(s: &str) -> OidcError {
    OidcError::Msg(s.to_string())
}

/// The `oidc_*` settings as `OidcService::setting()` reads them: trimmed text, '' when missing.
#[derive(Clone, Default)]
pub struct Settings {
    pub enabled: String,
    pub discovery_url: String,
    pub client_id: String,
    /// Decrypted (or the stored value when it does not decrypt, as PHP tolerates a legacy plaintext). Never logged.
    pub client_secret: String,
    pub button_label: String,
    pub public_base_url: String,
    pub scopes: String,
    pub disable_local_login: String,
}

impl std::fmt::Debug for Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Settings").field("enabled", &self.enabled).field("discovery_url", &self.discovery_url).finish_non_exhaustive()
    }
}

fn setting(c: &Connection, key: &str) -> Result<String, Fault> {
    let v = db::setting(c, key, "")?;
    Ok(String::from_utf8_lossy(php::trim(&v)).into_owned())
}

impl Settings {
    pub fn load(c: &Connection, crypt: &Encrypter) -> Result<Settings, Fault> {
        let stored = setting(c, "oidc_client_secret")?;
        let client_secret = if stored.is_empty() {
            String::new()
        } else {
            match crypt.decrypt_string(stored.as_bytes()) {
                Ok(p) => String::from_utf8_lossy(&p).into_owned(),
                Err(_) => stored,
            }
        };
        Ok(Settings {
            enabled: setting(c, "oidc_enabled")?,
            discovery_url: setting(c, "oidc_discovery_url")?,
            client_id: setting(c, "oidc_client_id")?,
            client_secret,
            button_label: setting(c, "oidc_button_label")?,
            public_base_url: setting(c, "oidc_public_base_url")?,
            scopes: setting(c, "oidc_scopes")?,
            disable_local_login: setting(c, "oidc_disable_local_login")?,
        })
    }

    pub fn is_configured(&self) -> bool {
        !self.discovery_url.is_empty() && !self.client_id.is_empty() && !self.client_secret.is_empty()
    }

    /// `isEnabled()`: the environment's kill switch first (`CORTENDESK_OIDC_DISABLED`), then the settings.
    pub fn is_enabled(&self, env_disabled: bool) -> bool {
        !env_disabled && self.enabled == "1" && self.is_configured()
    }

    pub fn local_login_disabled(&self, env_disabled: bool) -> bool {
        self.is_enabled(env_disabled) && self.disable_local_login == "1"
    }

    pub fn button_label(&self) -> &str {
        if self.button_label.is_empty() { "Sign in with SSO" } else { &self.button_label }
    }

    /// `clientProviderName()`: the button label without a leading "Sign in with" (and the like).
    pub fn client_provider_name(&self) -> String {
        static LEAD: once_cell::sync::Lazy<regex::bytes::Regex> = once_cell::sync::Lazy::new(|| {
            // PCRE's \s without /u: space, \t, \n, \v, \f, \r
            regex::bytes::Regex::new(r"(?i-u)^[ \t\n\x0B\x0C\r]*(sign[- ]?in|log[- ]?in|login|continue|authenticate)[ \t\n\x0B\x0C\r]+with[ \t\n\x0B\x0C\r]*").unwrap()
        });
        let label = self.button_label().as_bytes();
        let stripped = LEAD.replace(label, &b""[..]);
        let name = php::trim(&stripped);
        if name.is_empty() { "SSO".into() } else { String::from_utf8_lossy(name).into_owned() }
    }

    pub fn scopes(&self) -> &str {
        if self.scopes.is_empty() { "openid email profile" } else { &self.scopes }
    }

    /// `discoveryUrl()`: a bare issuer or a full `.well-known` URL.
    pub fn discovery_document_url(&self) -> String {
        let c = String::from_utf8_lossy(php::trim(self.discovery_url.as_bytes())).trim_end_matches('/').to_string();
        if c.contains("/.well-known/") { c } else { format!("{c}/.well-known/openid-configuration") }
    }
}

/// `CORTENDESK_OIDC_DISABLED` read as `filter_var(..., FILTER_VALIDATE_BOOL)`.
pub fn env_disabled() -> bool {
    std::env::var("CORTENDESK_OIDC_DISABLED").map_or(false, |v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "on" | "yes"))
}

/// PHP's `empty()` of a value.
pub fn empty(v: Option<&Val>) -> bool {
    match v {
        None => true,
        Some(v) => !v.to_bool(),
    }
}

fn get<'a>(a: &'a Val, k: &str) -> Option<&'a Val> {
    match a {
        Val::Arr(a) => a.get_str(k),
        _ => None,
    }
}

/// `(string) ($a[$k] ?? '')`
fn str_of(a: &Val, k: &str) -> Result<String, Fault> {
    Ok(String::from_utf8_lossy(&get(a, k).map_or(Ok(vec![]), |v| v.to_php_string())?).into_owned())
}

// ------------------------------------------------------------------------------------------------ client ---

struct Cached {
    doc: Val,
    at: Instant,
}

/// The provider side: an HTTP client and the discovery/JWKS caches (in memory, one entry per discovery URL).
pub struct Oidc {
    http: reqwest::Client,
    allow_http: bool,
    discovery: Mutex<HashMap<String, Cached>>,
    jwks: Mutex<HashMap<String, Cached>>,
    /// The kill switch, read once at start like PHP's cached config.
    pub env_disabled: bool,
    /// How old the cached key set must be before an unknown kid fetches it again (`JWKS_REFETCH`).
    pub jwks_refetch: Duration,
}

impl Oidc {
    pub fn new(allow_http: bool, env_disabled: bool) -> Oidc {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .user_agent("hte-console")
            .build()
            .expect("http client");
        Oidc { http, allow_http, discovery: Mutex::new(HashMap::new()), jwks: Mutex::new(HashMap::new()), env_disabled, jwks_refetch: JWKS_REFETCH }
    }

    pub fn from_env() -> Oidc {
        Oidc::new(std::env::var("HTE_CONSOLE_OIDC_ALLOW_HTTP").map_or(false, |v| v.trim() == "1"), env_disabled())
    }

    fn url_allowed(&self, u: &str) -> bool {
        match url::Url::parse(u) {
            Ok(p) => p.scheme() == "https" || (self.allow_http && p.scheme() == "http"),
            Err(_) => false,
        }
    }

    /// GET a JSON document; None for anything but a 2xx answer that decodes.
    async fn get_json(&self, u: &str, timeout: Duration, bearer: Option<&str>) -> Option<Val> {
        if !self.url_allowed(u) {
            tracing::warn!("OIDC: a provider URL is not https (or not a URL); not fetched");
            return None;
        }
        let mut rq = self.http.get(u).timeout(timeout).header("accept", "application/json");
        if let Some(t) = bearer {
            rq = rq.bearer_auth(t);
        }
        let resp = rq.send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let body = read_capped(resp, MAX_PROVIDER_BYTES).await?;
        php::json_decode(&body, &php::JsonOpts::default())
    }

    fn cache_get(map: &Mutex<HashMap<String, Cached>>, key: &str) -> Option<(Val, Instant)> {
        let m = map.lock().unwrap_or_else(|e| e.into_inner());
        m.get(key).filter(|c| c.at.elapsed() < DISCOVERY_TTL).map(|c| (c.doc.clone(), c.at))
    }

    fn cache_put(map: &Mutex<HashMap<String, Cached>>, key: &str, doc: Val) {
        let mut m = map.lock().unwrap_or_else(|e| e.into_inner());
        // one provider at a time: a changed discovery URL leaves at most a few stale entries
        if m.len() >= 8 {
            m.clear();
        }
        m.insert(key.to_string(), Cached { doc, at: Instant::now() });
    }

    /// Forget both caches (PHP: `forgetCaches()`, after a settings change; here also for tests).
    pub fn forget(&self) {
        self.discovery.lock().unwrap_or_else(|e| e.into_inner()).clear();
        self.jwks.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    /// `discovery()`: the provider's configuration, cached; failures are not cached.
    pub async fn discovery(&self, s: &Settings) -> Result<Val, OidcError> {
        if s.discovery_url.is_empty() {
            return Err(msg("No identity provider URL is configured."));
        }
        let url = s.discovery_document_url();
        if let Some((d, _)) = Self::cache_get(&self.discovery, &url) {
            return Ok(d);
        }
        let doc = self.get_json(&url, Duration::from_secs(10), None).await.filter(|d| matches!(d, Val::Arr(_)) && !empty(get(d, "issuer")));
        match doc {
            Some(d) => {
                Self::cache_put(&self.discovery, &url, d.clone());
                Ok(d)
            }
            None => {
                tracing::warn!("OIDC: provider configuration unreadable");
                Err(OidcError::Msg(format!("Could not read the provider's configuration from {url}.")))
            }
        }
    }

    /// `jwks()`; `refresh` skips the cache (an unknown kid), at most once per `JWKS_REFETCH`.
    async fn jwks(&self, s: &Settings, discovery: &Val, refresh: bool) -> Result<Val, OidcError> {
        let key = s.discovery_document_url();
        if let Some((d, at)) = Self::cache_get(&self.jwks, &key) {
            if !refresh || at.elapsed() < self.jwks_refetch {
                return Ok(d);
            }
        }
        let u = str_of(discovery, "jwks_uri")?;
        let doc = self.get_json(&u, Duration::from_secs(10), None).await.filter(|d| matches!(d, Val::Arr(_)) && !empty(get(d, "keys")));
        match doc {
            Some(d) => {
                Self::cache_put(&self.jwks, &key, d.clone());
                Ok(d)
            }
            None => Err(msg("Could not read the signing keys from the provider.")),
        }
    }

    /// `buildAuthorizationUrl()`
    pub async fn authorization_url(&self, s: &Settings, redirect_uri: &str, state: &str, nonce: &str, verifier: &str) -> Result<String, OidcError> {
        let d = self.discovery(s).await?;
        let query = laravel::http_build_query(&[
            ("response_type", b"code"),
            ("client_id", s.client_id.as_bytes()),
            ("redirect_uri", redirect_uri.as_bytes()),
            ("scope", s.scopes().as_bytes()),
            ("state", state.as_bytes()),
            ("nonce", nonce.as_bytes()),
            ("code_challenge", code_challenge(verifier).as_bytes()),
            ("code_challenge_method", b"S256"),
        ]);
        let endpoint = browser_facing(&s.public_base_url, &str_of(&d, "authorization_endpoint")?);
        if endpoint.is_empty() {
            return Err(msg("The provider did not advertise an authorization endpoint."));
        }
        Ok(format!("{endpoint}{}{query}", if endpoint.contains('?') { '&' } else { '?' }))
    }

    /// `exchangeCode()`: redeem the code, verify the ID token, merge userinfo under it. `now` is unix seconds.
    pub async fn exchange_code(&self, s: &Settings, code: &str, redirect_uri: &str, verifier: &str, nonce: &str, now: i64) -> Result<Val, OidcError> {
        let d = self.discovery(s).await?;
        let endpoint = str_of(&d, "token_endpoint")?;
        let unreachable = || msg("Could not reach the provider to finish sign-in. Try again.");
        if !self.url_allowed(&endpoint) {
            return Err(unreachable());
        }
        let form = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", s.client_id.as_str()),
            ("client_secret", s.client_secret.as_str()),
            ("code_verifier", verifier),
        ];
        let resp = self.http.post(&endpoint).timeout(Duration::from_secs(15)).header("accept", "application/json").form(&form).send().await.map_err(|_| unreachable())?;
        let status = resp.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(OidcError::Msg(format!("Token exchange failed ({status}). Check the client ID and secret.")));
        }
        let body = read_capped(resp, MAX_PROVIDER_BYTES).await.ok_or_else(unreachable)?;
        let json = php::json_decode(&body, &php::JsonOpts::default()).unwrap_or(Val::Null);
        let id_token = str_of(&json, "id_token")?;
        if id_token.is_empty() {
            return Err(msg("The provider returned no ID token. Ensure the \"openid\" scope is granted."));
        }
        let claims = self.verify_id_token(s, &d, &id_token, nonce, now).await?;
        let access = str_of(&json, "access_token")?;
        let info = self.user_info(&d, &access).await?;
        Ok(array_merge(&info, &claims))
    }

    /// `userInfo()`: best effort, `[]` on any failure.
    async fn user_info(&self, d: &Val, access_token: &str) -> Result<Val, Fault> {
        if access_token.is_empty() {
            return Ok(Val::Arr(Arr::new()));
        }
        let endpoint = str_of(d, "userinfo_endpoint")?;
        if endpoint.is_empty() {
            return Ok(Val::Arr(Arr::new()));
        }
        Ok(match self.get_json(&endpoint, Duration::from_secs(10), Some(access_token)).await {
            Some(v @ Val::Arr(_)) => v,
            _ => Val::Arr(Arr::new()),
        })
    }

    /// `verifyIdToken()` for the client flow (a nonce is always expected).
    pub async fn verify_id_token(&self, s: &Settings, d: &Val, jwt: &str, nonce: &str, now: i64) -> Result<Val, OidcError> {
        let fail = |m: &str| OidcError::Msg(format!("The ID token failed verification: {m}"));

        // decodeSegment(): only to read alg; the header is untrusted.
        let parts: Vec<&str> = jwt.split('.').collect();
        if parts.len() != 3 {
            return Err(msg("The provider returned a malformed ID token."));
        }
        let header = segment_json(parts[0]).filter(|v| matches!(v, Val::Arr(_))).unwrap_or(Val::Arr(Arr::new()));
        let alg = str_of(&header, "alg")?;
        let advertised = accepted_signing_algorithms(d);
        // Hardened: RS256 only, even when the provider also advertises something else.
        if !advertised.iter().any(|a| a == &alg) || alg != "RS256" {
            return Err(OidcError::Msg(format!(
                "The ID token was signed with an algorithm this provider does not advertise{}",
                if alg.is_empty() { ".".to_string() } else { format!(" ({alg}).") }
            )));
        }
        let mut jwks = self.jwks(s, d, false).await?;

        // JWT::decode($jwt, JWK::parseKeySet($jwks, $alg)), step by step with php-jwt's messages; the key set is
        // parsed first (it is the call's argument).
        let mut keys = parse_key_set(&jwks, &alg).map_err(|m| fail(&m))?;
        let payload_raw = laravel::base64_decode_lenient(&b64url_to_b64(parts[1]));
        let payload = match php::json_decode(&payload_raw, &php::JsonOpts { bigint_as_string: true, depth: 512 }) {
            Some(Val::Arr(a)) => a,
            Some(Val::Null) if payload_raw == b"null" => return Err(fail("Invalid claims encoding")),
            Some(_) => return Err(fail("Payload must be a JSON object")),
            None if std::str::from_utf8(&payload_raw).is_err() => return Err(fail("Malformed UTF-8 characters")),
            None => return Err(fail("Syntax error, malformed JSON")),
        };
        for k in ["iat", "nbf", "exp"] {
            if let Some(v) = payload.get_str(k) {
                if !matches!(v, Val::Null) && !v.is_numeric() {
                    return Err(fail(&format!("Payload {k} must be a number")));
                }
            }
        }
        // `empty($kid) && $kid !== '0'`: absent, null, "", 0 and false fail; the string "0" is a kid
        let kid = match get(&header, "kid") {
            Some(v) if !empty(Some(v)) || *v == Val::str("0") => v.to_php_string()?,
            _ => return Err(fail("\"kid\" empty, unable to lookup correct key")),
        };
        if !keys.contains_key(&kid) {
            // Hardened: the provider may have rotated its keys since the cache was filled.
            jwks = self.jwks(s, d, true).await?;
            keys = parse_key_set(&jwks, &alg).map_err(|m| fail(&m))?;
        }
        let Some(key) = keys.get(&kid) else { return Err(fail("\"kid\" invalid, unable to lookup correct key")) };
        if !php::hash_equals(key.alg.as_bytes(), alg.as_bytes()) {
            return Err(fail("Incorrect key for this algorithm"));
        }
        if key.bits < 2048 {
            return Err(fail("Provided key is too short"));
        }
        let sig = laravel::base64_decode_lenient(&b64url_to_b64(parts[2]));
        let signed = format!("{}.{}", parts[0], parts[1]);
        let ok = ring::signature::RsaPublicKeyComponents { n: &key.n, e: &key.e }
            .verify(&ring::signature::RSA_PKCS1_2048_8192_SHA256, signed.as_bytes(), &sig)
            .is_ok();
        if !ok {
            return Err(fail("Signature verification failed"));
        }
        let num = |k: &str| payload.get_str(k).filter(|v| !matches!(v, Val::Null)).map(to_f64);
        if let Some(nbf) = num("nbf") {
            if nbf.floor() > (now + LEEWAY) as f64 {
                return Err(fail(&format!("Cannot handle token with nbf prior to {}", atom(nbf.floor() as i64))));
            }
        } else if let Some(iat) = num("iat") {
            if iat.floor() > (now + LEEWAY) as f64 {
                return Err(fail(&format!("Cannot handle token with iat prior to {}", atom(iat.floor() as i64))));
            }
        }
        match num("exp") {
            Some(exp) if ((now - LEEWAY) as f64) < exp => {}
            // Hardened: a token without exp is refused (php-jwt lets it through).
            _ => return Err(fail("Expired token")),
        }

        let claims = Val::Arr(payload);
        let issuer = str_of(d, "issuer")?;
        if issuer.is_empty() || !php::hash_equals(issuer.as_bytes(), str_of(&claims, "iss")?.as_bytes()) {
            return Err(msg("The ID token was issued by an unexpected issuer."));
        }
        // Hardened: an Entra (Microsoft) token names its tenant; it must be the issuer's.
        if let Some(tenant) = microsoft_tenant(&issuer) {
            let tid = str_of(&claims, "tid")?.to_ascii_lowercase();
            if !php::hash_equals(tenant.as_bytes(), tid.as_bytes()) {
                return Err(msg("The ID token was issued by an unexpected issuer."));
            }
        }
        let audiences: Vec<Val> = match get(&claims, "aud") {
            Some(Val::Arr(a)) => a.iter().map(|(_, v)| v.clone()).collect(),
            other => vec![other.cloned().unwrap_or(Val::Null)],
        };
        let mut aud_ok = false;
        for a in &audiences {
            if a.to_php_string()? == s.client_id.as_bytes() {
                aud_ok = true;
            }
        }
        if !aud_ok {
            return Err(msg("The ID token was not issued for this client."));
        }
        // Hardened: several audiences need the authorized party to be this client (OpenID Connect core 3.1.3.7).
        if audiences.len() > 1 && !php::hash_equals(s.client_id.as_bytes(), str_of(&claims, "azp")?.as_bytes()) {
            return Err(msg("The ID token was not issued for this client."));
        }
        // Hardened: always expected (the client flow always sends one).
        if nonce.is_empty() || !php::hash_equals(nonce.as_bytes(), str_of(&claims, "nonce")?.as_bytes()) {
            return Err(msg("The ID token nonce did not match. Please try signing in again."));
        }
        if empty(get(&claims, "sub")) {
            return Err(msg("The ID token carried no subject claim."));
        }
        Ok(claims)
    }
}

/// A JSON-decoded segment of a JWT, as `decodeSegment()` reads one (non-strict base64).
fn segment_json(seg: &str) -> Option<Val> {
    let raw = laravel::base64_decode_lenient(seg.replace('-', "+").replace('_', "/").as_bytes());
    php::json_decode(&raw, &php::JsonOpts::default())
}

/// php-jwt's `convertBase64UrlToBase64`.
fn b64url_to_b64(s: &str) -> Vec<u8> {
    let mut v = s.replace('-', "+").replace('_', "/");
    let r = v.len() % 4;
    if r != 0 {
        v.push_str(&"=".repeat(4 - r));
    }
    v.into_bytes()
}

/// A numeric claim as PHP compares it.
fn to_f64(v: &Val) -> f64 {
    match v {
        Val::Int(i) => *i as f64,
        Val::Float(f) => *f,
        Val::Str(s) => std::str::from_utf8(s).ok().and_then(|t| t.trim().parse::<f64>().ok()).unwrap_or(0.0),
        Val::Bool(b) => *b as i64 as f64,
        _ => 0.0,
    }
}

/// `date(DateTime::ATOM, $t)` in the console's time zone (UTC).
fn atom(t: i64) -> String {
    chrono::DateTime::from_timestamp(t, 0).map(|d| d.format("%Y-%m-%dT%H:%M:%S+00:00").to_string()).unwrap_or_default()
}

/// `acceptedSigningAlgorithms()`: what the provider advertises, without `none`; RS256 when it says nothing.
pub fn accepted_signing_algorithms(d: &Val) -> Vec<String> {
    let list: Vec<String> = match get(d, "id_token_signing_alg_values_supported") {
        Some(Val::Arr(a)) if !a.is_empty() => a.iter().filter_map(|(_, v)| v.to_php_string().ok()).map(|b| String::from_utf8_lossy(&b).into_owned()).filter(|a| !a.is_empty() && a != "none").collect(),
        _ => return vec!["RS256".into()],
    };
    if list.is_empty() { vec!["RS256".into()] } else { list }
}

/// The tenant of a Microsoft identity platform issuer (`https://login.microsoftonline.com/<tenant guid>/v2.0`).
pub fn microsoft_tenant(issuer: &str) -> Option<String> {
    let u = url::Url::parse(issuer).ok()?;
    let host = u.host_str()?.to_ascii_lowercase();
    let microsoft = ["login.microsoftonline.com", "login.microsoftonline.us", "login.partner.microsoftonline.cn", "login.chinacloudapi.cn", "sts.windows.net"];
    if !microsoft.contains(&host.as_str()) {
        return None;
    }
    let first = u.path_segments()?.next()?.to_ascii_lowercase();
    let guid = first.len() == 36 && first.chars().enumerate().all(|(i, c)| if [8, 13, 18, 23].contains(&i) { c == '-' } else { c.is_ascii_hexdigit() });
    guid.then_some(first)
}

/// One verification key of the provider's set.
pub struct Jwk {
    pub n: Vec<u8>,
    pub e: Vec<u8>,
    pub alg: String,
    pub bits: usize,
}

fn strip_zeros(v: Vec<u8>) -> Vec<u8> {
    let i = v.iter().position(|&b| b != 0).unwrap_or(v.len());
    v[i..].to_vec()
}

/// `JWK::parseKeySet($jwks, $defaultAlg)` for RSA keys (keys of other types are left out; the set's other errors
/// carry php-jwt's messages).
pub fn parse_key_set(jwks: &Val, default_alg: &str) -> Result<HashMap<Vec<u8>, Jwk>, String> {
    let Some(Val::Arr(keys)) = get(jwks, "keys") else { return Err("\"keys\" member must exist in the JWK Set".into()) };
    if keys.is_empty() {
        return Err("JWK Set did not contain any keys".into());
    }
    let mut out = HashMap::new();
    for (idx, v) in keys.iter() {
        let Val::Arr(k) = v else { return Err("JWK must not be empty".into()) };
        if k.is_empty() {
            return Err("JWK must not be empty".into());
        }
        let kid = match k.get_str("kid") {
            Some(x) if !matches!(x, Val::Null) => x.to_php_string().map_err(|_| "JWK kid is not a string".to_string())?,
            _ => idx.as_bytes(),
        };
        let Some(kty) = k.get_str("kty").filter(|x| !matches!(x, Val::Null)) else { return Err("JWK must contain a \"kty\" parameter".into()) };
        let alg = match k.get_str("alg").filter(|x| !matches!(x, Val::Null)) {
            Some(a) => String::from_utf8_lossy(&a.to_php_string().map_err(|_| "JWK alg is not a string".to_string())?).into_owned(),
            None => default_alg.to_string(),
        };
        if kty != &Val::str("RSA") {
            continue;
        }
        if !empty(k.get_str("d")) {
            return Err("RSA private keys are not supported".into());
        }
        let (Some(n), Some(e)) = (k.get_str("n").filter(|x| !matches!(x, Val::Null)), k.get_str("e").filter(|x| !matches!(x, Val::Null))) else {
            return Err("RSA keys must contain values for both \"n\" and \"e\"".into());
        };
        let n = strip_zeros(laravel::base64_decode_lenient(&b64url_to_b64(&String::from_utf8_lossy(&n.to_php_string().unwrap_or_default()))));
        let e = strip_zeros(laravel::base64_decode_lenient(&b64url_to_b64(&String::from_utf8_lossy(&e.to_php_string().unwrap_or_default()))));
        let bits = if n.is_empty() { 0 } else { (n.len() - 1) * 8 + (8 - n[0].leading_zeros() as usize) };
        out.insert(kid, Jwk { n, e, alg, bits });
    }
    if out.is_empty() {
        return Err("No supported algorithms found in JWK Set".into());
    }
    Ok(out)
}

/// RFC 7636 S256: base64url(sha256(verifier)) without padding.
pub fn code_challenge(verifier: &str) -> String {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// `browserFacing()`: the provider URL moved onto `oidc_public_base_url`'s origin and path prefix, when set.
pub fn browser_facing(public: &str, u: &str) -> String {
    let public = public.trim_end_matches('/');
    if public.is_empty() || u.is_empty() {
        return u.to_string();
    }
    let (Ok(parts), Ok(pp)) = (url::Url::parse(u), url::Url::parse(public)) else { return u.to_string() };
    let Some(host) = pp.host_str() else { return u.to_string() };
    let port = pp.port().map(|p| format!(":{p}")).unwrap_or_default();
    let prefix = pp.path().trim_end_matches('/');
    format!("{}://{host}{port}{prefix}{}{}", pp.scheme(), parts.path(), parts.query().map(|q| format!("?{q}")).unwrap_or_default())
}

/// `array_merge($a, $b)`: string keys of `b` win, integer keys are appended and renumbered.
fn array_merge(a: &Val, b: &Val) -> Val {
    let mut out = Arr::new();
    for src in [a, b] {
        if let Val::Arr(x) = src {
            for (k, v) in x.iter() {
                match k {
                    Key::Int(_) => out.push(v.clone()),
                    Key::Str(_) => out.set(k.clone(), v.clone()),
                }
            }
        }
    }
    Val::Arr(out)
}

async fn read_capped(mut resp: reqwest::Response, cap: usize) -> Option<Vec<u8>> {
    if resp.content_length().map_or(false, |l| l as usize > cap) {
        return None;
    }
    let mut out = vec![];
    while let Some(chunk) = resp.chunk().await.ok()? {
        if out.len() + chunk.len() > cap {
            return None;
        }
        out.extend_from_slice(&chunk);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(label: &str) -> Settings {
        Settings { button_label: label.into(), ..Default::default() }
    }

    #[test]
    fn provider_name_like_php() {
        assert_eq!(settings("").client_provider_name(), "SSO");
        assert_eq!(settings("Sign in with Microsoft").client_provider_name(), "Microsoft");
        assert_eq!(settings("  LOG-IN WITH Keycloak ").client_provider_name(), "Keycloak");
        assert_eq!(settings("Continue with").client_provider_name(), "SSO");
        assert_eq!(settings("Microsoft").client_provider_name(), "Microsoft");
        assert_eq!(settings("Signin  with   Entra").client_provider_name(), "Entra");
    }

    #[test]
    fn pkce_rfc7636_vector() {
        assert_eq!(code_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn discovery_url_and_browser_facing() {
        let s = Settings { discovery_url: " https://idp.example/realms/x/ ".into(), ..Default::default() };
        assert_eq!(s.discovery_document_url(), "https://idp.example/realms/x/.well-known/openid-configuration");
        let s = Settings { discovery_url: "https://idp.example/.well-known/openid-configuration".into(), ..Default::default() };
        assert_eq!(s.discovery_document_url(), "https://idp.example/.well-known/openid-configuration");
        assert_eq!(browser_facing("", "http://kc:8080/auth?x=1"), "http://kc:8080/auth?x=1");
        assert_eq!(browser_facing("https://sso.example/kc/", "http://kc:8080/realms/r/auth?x=1"), "https://sso.example/kc/realms/r/auth?x=1");
    }

    #[test]
    fn algorithms_and_tenant() {
        assert_eq!(accepted_signing_algorithms(&Val::Arr(Arr::new())), vec!["RS256"]);
        let d = php::json_decode(br#"{"id_token_signing_alg_values_supported":["none",""]}"#, &Default::default()).unwrap();
        assert_eq!(accepted_signing_algorithms(&d), vec!["RS256"]);
        let d = php::json_decode(br#"{"id_token_signing_alg_values_supported":["RS256","HS256"]}"#, &Default::default()).unwrap();
        assert_eq!(accepted_signing_algorithms(&d), vec!["RS256", "HS256"]);
        assert_eq!(microsoft_tenant("https://login.microsoftonline.com/9188040D-6C67-4C5B-B112-36A304B66DAD/v2.0").as_deref(), Some("9188040d-6c67-4c5b-b112-36a304b66dad"));
        assert_eq!(microsoft_tenant("https://login.microsoftonline.com/common/v2.0"), None);
        assert_eq!(microsoft_tenant("https://idp.example/9188040d-6c67-4c5b-b112-36a304b66dad"), None);
    }

    #[test]
    fn merge_lets_the_token_win() {
        let a = php::json_decode(br#"{"email":"a@x","0":"z","name":"Info"}"#, &Default::default()).unwrap();
        let b = php::json_decode(br#"{"email":"b@x","sub":"1"}"#, &Default::default()).unwrap();
        let m = array_merge(&a, &b);
        assert_eq!(php::json_encode(&m).unwrap(), r#"{"email":"b@x","0":"z","name":"Info","sub":"1"}"#);
    }

    #[test]
    fn key_set_errors_like_php_jwt() {
        let p = |s: &str| parse_key_set(&php::json_decode(s.as_bytes(), &Default::default()).unwrap(), "RS256").err();
        assert_eq!(p(r#"{}"#).as_deref(), Some("\"keys\" member must exist in the JWK Set"));
        assert_eq!(p(r#"{"keys":[{"kid":"a"}]}"#).as_deref(), Some("JWK must contain a \"kty\" parameter"));
        assert_eq!(p(r#"{"keys":[{"kty":"RSA","kid":"a","n":"AQ"}]}"#).as_deref(), Some("RSA keys must contain values for both \"n\" and \"e\""));
        assert_eq!(p(r#"{"keys":[{"kty":"RSA","kid":"a","n":"AQ","e":"AQAB","d":"x"}]}"#).as_deref(), Some("RSA private keys are not supported"));
        assert_eq!(p(r#"{"keys":[{"kty":"EC","kid":"a"}]}"#).as_deref(), Some("No supported algorithms found in JWK Set"));
    }
}
