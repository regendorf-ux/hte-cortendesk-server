//! A fake OpenID Connect provider for the tests and the replay (`hte-console fake-idp`): discovery, JWKS, an
//! authorize endpoint that answers at once (no person, no password), a token endpoint that checks the client
//! secret, the redirect URI and PKCE (S256) and then issues an ID token, and userinfo.
//!
//! The authorize request picks what goes wrong with two extra parameters the replay appends: `hte_fake=<mode>`
//! (`ok`, or one of `MODES`: wrong issuer, audience or nonce, alg none or HS256, expired, a bad signature, an unknown
//! or missing kid, a short key, a key for another algorithm, no exp, several audiences, no subject, the provider
//! refusing, the token endpoint failing, no ID token, a malformed one) and `hte_user=<profile>`.
//!
//! The RSA keys below are TEST KEYS made for this file (openssl, 2026-10-24). Nothing trusts them: the console only
//! accepts a provider its settings name, and the replay's throwaway database is the only one that names this one.

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use base64::Engine;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Signing key "ka" (PKCS#1 DER, 2048 bits). Test only.
const KEY_A: &str = "MIIEogIBAAKCAQEA4UmWnK8w6zeSewdu/B8EMIzDRrjtFuH9+1pkc8qmQHpVsSoqOiHy3IRxjuo8pON1jg2VtDmJYIS1Vz9Unc3sG8ELmyQuWd3a6NIdHLcpxRLqHjPlSStStDntwqNdybdcw96wreub9OM352BJRdH7RqS6qHu4GzlOytFWaHISaN8KQ0qDKIwaDnhQeWxDmqA2sBwmOK7XmtvDYSAUT1ZS+VsMDPtRTHKrGsx/46p7zlarnu2Nesx0JUxziPOj869uZSS/PGpuaYF3b1AkjPXiPWeZLJNxfWk/cCeBfacRSfJDGRg55WO+yzBQdhhgQOMcF/1uxR3ajUxJw6fyoNN0ZwIDAQABAoIBAGaATtB3PTCoFjN3zF1V11gnk2mIFgdFR4OnOvEcEMxhXL/AyXmtnIwMjoZRuMnk28WIFMbtLr4FY2SQ4fTyjiyKhrdNnPEyablob+pyw8RwuKiJQBcsaPKrMKxQHAn9LW3I0mYvPsQK5ZKWUoA767HWnT6vG7L3Pgw1drUKwamIhsfS+cItQyGTeWfnYePnS5sfpCESwjTW7Y3a0GmTFyjlbjir6GHC/Nw74NBLNmKYqaJ48IzB5G5+CAGiHurEHAXAL2OntCqAKu/sAbx71vzHO2JPKHCviYdknM74ZH6N6HfUFjJZ0w0xPjlTsTticKoWE5hcOxFlASamxDT82JECgYEA92DdSH3q0aLk95E/hqAsaWZ0bVfYfGxTetW/unP21peO644wDl15qPqcQEKRX1GShYJaILcPO7JL/l7zfu2y0yfd5nkeKUvjcTtZcraQABB6swekd+GhyqB7PalvJmEtXFxT8ZBGHP3P/x8G1asMQPwQacZVsN5RdrW0zrHb2nsCgYEA6SOgXhR/ItN4mpc5g9tqGsaut5WWTEfrFLu57dCPRBicNfDXcZborGpk/QWq3mHQ8G0ELU3FjimpQoe3yDCy786TF7ZpESetMN8qfB92qfhUSIC0+5E8hnRxazSNvfcNRIJzJm75j62kWoWIlPtJkua1As+QRtNdOc7HaoH5kAUCgYB5Pcg2V0BXLnb5vv5bhPU/Uy+Mx5kaohzn/wrQ3zUDR5SMbkuvPrD52JnsBLQq+1fMh26UyiN1JpWIPhEpDGawhsGCy6m0o7T9MhFM350D6w+33u8EslkRbkX4mqoXLVmGAtpBcmxqmRrv9szqu8Jttxx0OviUjuFuRPAwvYr7MQKBgFseT3k1rZLg78wLurDsOoYIjRS3ZCygFyLdVAe8caH9tF/op2t/vaRVWO8DHgsYU98D3JQQR1wOsFaOUKfvUKAlLpwf8OSBi1EEh8hHS8uWgOptU07XLr6mGAX8XkGWoxrZmUO2L9eV2ByBACaqJ9FAVhKpKQxlY5RKWuonrnA5AoGAFuf99PWWjD1sUoxckIEA41Vxr1bs28su5sgbVCW3/taW/xPfD4zmDBJ0mN4iNDUUw7vZs/adPGusYA/E0LcZliVnNe8P4a/ZD/BQKPd7tLSYMub4g2DAOcVFXMXQPvXCDjUQ4Z/ioBGHgoqryEDJLbNFAtUOEMnL20mt7pNyVt0=";
/// A second key, never published under "ka": a token it signs as "ka" has a bad signature. Published as "kalg"
/// with alg RS384 (a key for another algorithm). Test only.
const KEY_B: &str = "MIIEogIBAAKCAQEAmU2C0L7zDjKGt+TTvglAShMoiZSQR97Sx8Opa54wh6WqLrqlZ7trlua6YFyWIcrck2g9N1x62x6F9XE1MTBCOzGLlydPR4FioL71r1ssqhw0l8AOOJyseAIJ7u5vuRrhP0UqJOc1FJ8wjnduMAl2DGXzIc6KoAf9IWwYeGcdI48lJhOcKKKe4ColcV1efbJAeP7CvhglTrZfCsZk/RYiss12Y851f+bfugEYi+H4+zt3QdVjLjl4GEr8exMNfRDrVSOojaKGqXBPA/aDF677JSoEx6ceaP4KTZYdDV5ch5dkO9nsnSAvGcQm4PTsq31vEt5Go+v3dGqUlszYKT2DFwIDAQABAoIBACYlt4uiOHEr+YIBGv+K5ciJA+lYYp6/v8ud0KbK8mCOxM5j+4zYgmlGeNJJt8Io7MJxieogxSGJcuQki4v16kU4ivfN/FhaxeQiIJjGI1MhOaUZUXCc6/3g4//krUBug+Zum5IbRoYfJsIMzgp+EDX9mIatEqnH0yFh+KTdY87ZCVAJM+RzmdBzv4IoIfpsosTCln+qgQq1pK6V1hp0fb5wMquVLG/O8LR0rdgG4NywWgdM0QboBNYamMG1zRtZKoQVb8lz/flOOgHx+31til/Wt3vkg5SRYvQktYHv8BLmKjbGzPEp+RoxbVYZNPZG7U6jM4Pr5pzsfL5r0ghQneECgYEAy6crZk8xmAWiEvqlQM4ifCLNwIwgYlKWJVNCB3j5ZP2JLLk0nRHrWOGQFHKm3OLH3pCu/LuTkA+CUqcjr7eekMD71a9bg8ii3Y1N0q/IqbOMR2E9XLdOxFrIFH5+9U3Gtc+8tDoaJOT0HfB7tqvu0UIBMa6QwzUW55yn1FGWvQ0CgYEAwLUumbltCQztq0SN+xxGaHN+YQmTyW7t0ElniIYEoEaZGfLQOOykbVyYaa8KHlzf/ot+TYYo5Jw6BP74PQn6pPd9+bDR6h41j9oOw+FidacY4lfYd0T6UPnHqmR3Q4QP5QkztDY1KRjUsFkrXVBO8+DN+mlXRXBxmdfJ9eaN37MCgYB02kLIvYATXogUo8TWXnDjEYVFiiG6yPBmElO8vek7zU48XziVN4b2xNZLJU4hR+6vAg2l7mtJKdz5V/XeCVnubQ0TGz9Daogo379buIlG9kLzYhQ3cua7O+u59qsaTbpK8BuyvfPqX4TC+Q3DTvwFDf5pZ2Sg3YF6/CRAa2A2sQKBgBL1wI//Xmr1iqy/IfkC3yqHsnd5qcC32U4U6srT5MCgMZAMA9CV99eKtLQxNJ2oJaG1t8eI250igdLcAzB+OtrgPtTCQOT38+0jVzCOjFFnD1u1qOaTMs2kxbBOEi3iYG34ac3hR3mzp7lyDIIx1JLKG3n3w05hscuhH43CEVNhAoGAMLJv4bS24p4e/nTlNpPW23bx+BWpi+TnlEJOZDczKbBof92zqWhNagfrbQuKCVBSN7fWHn37PtNYsXorM7mO0ZsDJHhVDR2BTMbZTY3pGuxMUDR0uXwiKOSnB9HWnMEdFr/0v/bzM5D9gcNrEWOCx/aysFtSBOEPHUME/gPMnvM=";
/// The modulus of a 1024-bit key, published as "kshort" (too short for php-jwt and for us). Test only.
const SHORT_N_HEX: &str = "EEFBB525E0DCDD09DFD6FBC008AC74493AFFA82A78A516C2D67D0929A3058EDBD654C0E628CBFE93F93C394B15AEA3A1245D3A82C9DAB87584D6A458AE110F94AD804739A03DA84756960C047AF36F77F324FCC4097D7C658E8610CC3B562EC5F44770CCA31CCD6B970656C0B16F79C840A6C1BD9198E2EFFB3415CC29DA45DB";

pub const MODES: &[&str] = &[
    "ok", "wrong-iss", "wrong-aud", "wrong-nonce", "alg-none", "alg-hs256", "expired", "nbf-future", "bad-signature",
    "unknown-kid", "no-kid", "short-key", "wrong-alg-key", "no-exp", "multi-aud", "multi-aud-azp", "no-sub", "deny",
    "token-500", "no-id-token", "malformed", "wrong-tid", "iat-future", "slow-token",
];

/// The people this provider knows. Names, addresses and usernames are placeholder-shaped, so fixtures that show
/// them pass the leftover scan.
pub fn profile(name: &str) -> Option<Value> {
    Some(match name {
        // a new person: provisioned under the `active` policy
        "anna" => json!({"sub": "sub-5eed-anna", "preferred_username": "990005001", "name": "text-5eed0a01", "email": "user-5eed00a001@example.invalid"}),
        // an existing local account by email: linked on first sign-in
        "linked" => json!({"sub": "sub-5eed-linked", "name": "text-5eed0a08", "email": "user-5eed000008@example.invalid"}),
        // an account already linked by (iss, sub)
        "known" => json!({"sub": "sub-5eed-known", "name": "text-5eed0a09", "email": "user-5eed000009@example.invalid"}),
        // a linked account that is disabled
        "disabled" => json!({"sub": "sub-5eed-disabled", "email": "user-5eed00000a@example.invalid"}),
        // an address outside the allowed domains
        "outsider" => json!({"sub": "sub-5eed-outsider", "name": "text-5eed0aff", "email": "user-5eed00a0ff@elsewhere.invalid"}),
        _ => return None,
    })
}

pub struct Config {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    /// The tenant a `wrong-tid` token claims (and `tid` for every token).
    pub tenant: Option<String>,
    pub clock: Arc<dyn Fn() -> i64 + Send + Sync>,
}

struct Grant {
    client_id: String,
    redirect_uri: String,
    challenge: String,
    nonce: String,
    mode: String,
    user: String,
    used: bool,
}

pub struct FakeIdp {
    cfg: Config,
    grants: Mutex<HashMap<String, Grant>>,
    jwks_fetches: std::sync::atomic::AtomicUsize,
}

fn b64u(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn key(der_b64: &str) -> ring::rsa::KeyPair {
    let der = base64::engine::general_purpose::STANDARD.decode(der_b64).expect("test key");
    ring::rsa::KeyPair::from_der(&der).expect("test key")
}

fn public_jwk(k: &ring::rsa::KeyPair, kid: &str, alg: Option<&str>) -> Value {
    let c: ring::rsa::PublicKeyComponents<Vec<u8>> = k.public().into();
    let mut j = json!({"kty": "RSA", "use": "sig", "kid": kid, "n": b64u(&c.n), "e": b64u(&c.e)});
    if let Some(a) = alg {
        j["alg"] = json!(a);
    }
    j
}

/// Sign `header.payload` with a key: RS256.
fn rs256(k: &ring::rsa::KeyPair, input: &str) -> Vec<u8> {
    let mut sig = vec![0u8; k.public().modulus_len()];
    k.sign(&ring::signature::RSA_PKCS1_SHA256, &ring::rand::SystemRandom::new(), input.as_bytes(), &mut sig).expect("sign");
    sig
}

impl FakeIdp {
    pub fn new(cfg: Config) -> Arc<FakeIdp> {
        Arc::new(FakeIdp { cfg, grants: Mutex::new(HashMap::new()), jwks_fetches: Default::default() })
    }

    /// How often the key set was fetched (the console's cache is bounded and refetches for rotation).
    pub fn jwks_fetches(&self) -> usize {
        self.jwks_fetches.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn router(self: &Arc<Self>) -> Router {
        Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks", get(jwks))
            .route("/authorize", get(authorize))
            .route("/token", post(token))
            .route("/userinfo", get(userinfo))
            .with_state(self.clone())
    }

    /// An ID token for a grant, broken the way its mode says.
    pub fn id_token(&self, mode: &str, user: &str, nonce: &str) -> String {
        let now = (self.cfg.clock)();
        let mut claims = profile(user).unwrap_or_else(|| profile("anna").unwrap());
        let c = claims.as_object_mut().unwrap();
        c.insert("iss".into(), json!(if mode == "wrong-iss" { format!("{}/other", self.cfg.issuer) } else { self.cfg.issuer.clone() }));
        c.insert("aud".into(), match mode {
            "wrong-aud" => json!("another-client"),
            "multi-aud" => json!([self.cfg.client_id, "another-client"]),
            "multi-aud-azp" => json!([self.cfg.client_id, "another-client"]),
            _ => json!(self.cfg.client_id),
        });
        if mode == "multi-aud-azp" {
            c.insert("azp".into(), json!(self.cfg.client_id));
        }
        c.insert("nonce".into(), json!(if mode == "wrong-nonce" { "not-the-nonce" } else { nonce }));
        c.insert("iat".into(), json!(match mode {
            "expired" => now - 7200,
            "iat-future" => now + 600,
            _ => now,
        }));
        if mode != "no-exp" {
            c.insert("exp".into(), json!(if mode == "expired" { now - 3600 } else { now + 3600 }));
        }
        if mode == "nbf-future" {
            c.insert("nbf".into(), json!(now + 600));
        }
        if mode == "no-sub" {
            c.remove("sub");
        }
        if let Some(t) = &self.cfg.tenant {
            c.insert("tid".into(), json!(if mode == "wrong-tid" { "00000000-0000-0000-0000-000000000000" } else { t.as_str() }));
        }
        let (alg, kid) = match mode {
            "alg-none" => ("none", Some("ka")),
            "alg-hs256" => ("HS256", Some("ka")),
            "unknown-kid" => ("RS256", Some("kzz")),
            "no-kid" => ("RS256", None),
            "short-key" => ("RS256", Some("kshort")),
            "wrong-alg-key" => ("RS256", Some("kalg")),
            _ => ("RS256", Some("ka")),
        };
        let mut h = json!({"typ": "JWT", "alg": alg});
        if let Some(k) = kid {
            h["kid"] = json!(k);
        }
        let input = format!("{}.{}", b64u(h.to_string().as_bytes()), b64u(claims.to_string().as_bytes()));
        let sig = match mode {
            "alg-none" => vec![],
            "alg-hs256" => {
                use hmac::{Hmac, Mac};
                let mut m = <Hmac<sha2::Sha256> as Mac>::new_from_slice(self.cfg.client_secret.as_bytes()).unwrap();
                m.update(input.as_bytes());
                m.finalize().into_bytes().to_vec()
            }
            "bad-signature" => rs256(&key(KEY_B), &input),
            _ => rs256(&key(KEY_A), &input),
        };
        format!("{input}.{}", b64u(&sig))
    }
}

async fn discovery(State(s): State<Arc<FakeIdp>>) -> Json<Value> {
    let i = &s.cfg.issuer;
    Json(json!({
        "issuer": i,
        "authorization_endpoint": format!("{i}/authorize"),
        "token_endpoint": format!("{i}/token"),
        "jwks_uri": format!("{i}/jwks"),
        "userinfo_endpoint": format!("{i}/userinfo"),
        "response_types_supported": ["code"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "code_challenge_methods_supported": ["S256"],
    }))
}

async fn jwks(State(s): State<Arc<FakeIdp>>) -> Json<Value> {
    s.jwks_fetches.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let short_n = hex::decode(SHORT_N_HEX).unwrap();
    Json(json!({"keys": [
        public_jwk(&key(KEY_A), "ka", None),
        public_jwk(&key(KEY_B), "kalg", Some("RS384")),
        {"kty": "RSA", "use": "sig", "kid": "kshort", "n": b64u(&short_n), "e": "AQAB"},
    ]}))
}

fn bad(m: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({"error": m}))).into_response()
}

async fn authorize(State(s): State<Arc<FakeIdp>>, Query(q): Query<HashMap<String, String>>) -> Response {
    let p = |k: &str| q.get(k).cloned().unwrap_or_default();
    if p("response_type") != "code" || p("client_id") != s.cfg.client_id || p("code_challenge_method") != "S256" {
        return bad("invalid_request");
    }
    let (redirect, state, nonce, challenge) = (p("redirect_uri"), p("state"), p("nonce"), p("code_challenge"));
    if redirect.is_empty() || state.is_empty() || nonce.is_empty() || challenge.len() != 43 || !p("scope").split(' ').any(|x| x == "openid") {
        return bad("invalid_request");
    }
    let mode = q.get("hte_fake").cloned().unwrap_or_else(|| "ok".into());
    let user = q.get("hte_user").cloned().unwrap_or_else(|| "anna".into());
    let sep = if redirect.contains('?') { '&' } else { '?' };
    let enc = crate::laravel::urlencode;
    let location = if mode == "deny" {
        format!("{redirect}{sep}error=access_denied&error_description=denied&state={}", enc(state.as_bytes()))
    } else {
        let code = crate::laravel::str_random(32);
        s.grants.lock().unwrap().insert(code.clone(), Grant { client_id: s.cfg.client_id.clone(), redirect_uri: redirect.clone(), challenge, nonce, mode, user, used: false });
        format!("{redirect}{sep}code={code}&state={}", enc(state.as_bytes()))
    };
    (StatusCode::FOUND, [(header::LOCATION, location)]).into_response()
}

async fn token(State(s): State<Arc<FakeIdp>>, Form(f): Form<HashMap<String, String>>) -> Response {
    let p = |k: &str| f.get(k).cloned().unwrap_or_default();
    if p("grant_type") != "authorization_code" || p("client_id") != s.cfg.client_id || p("client_secret") != s.cfg.client_secret {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid_client"}))).into_response();
    }
    let (mode, user, nonce) = {
        let mut grants = s.grants.lock().unwrap();
        let Some(g) = grants.get_mut(&p("code")) else { return bad("invalid_grant") };
        if g.used || g.redirect_uri != p("redirect_uri") || g.client_id != p("client_id") || crate::oidc::code_challenge(&p("code_verifier")) != g.challenge {
            return bad("invalid_grant");
        }
        g.used = true;
        (g.mode.clone(), g.user.clone(), g.nonce.clone())
    };
    let access = format!("at-{}", crate::laravel::str_random(24));
    if mode == "slow-token" {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    match mode.as_str() {
        "token-500" => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "server_error"}))).into_response(),
        "no-id-token" => Json(json!({"access_token": access, "token_type": "Bearer"})).into_response(),
        "malformed" => Json(json!({"access_token": access, "token_type": "Bearer", "id_token": "abc.def"})).into_response(),
        _ => {
            s.grants.lock().unwrap().insert(access.clone(), Grant { client_id: String::new(), redirect_uri: String::new(), challenge: String::new(), nonce: String::new(), mode: String::new(), user: user.clone(), used: true });
            Json(json!({"access_token": access, "token_type": "Bearer", "expires_in": 3600, "id_token": s.id_token(&mode, &user, &nonce)})).into_response()
        }
    }
}

async fn userinfo(State(s): State<Arc<FakeIdp>>, h: HeaderMap) -> Response {
    let bearer = h.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")).unwrap_or("");
    let user = s.grants.lock().unwrap().get(bearer).map(|g| g.user.clone());
    match user.and_then(|u| profile(&u)) {
        // userinfo carries one claim the token does not, and loses to the token on the rest
        Some(p) => Json(json!({"sub": p["sub"], "name": "text-5eed0bad", "locale": "en"})).into_response(),
        None => (StatusCode::UNAUTHORIZED, "").into_response(),
    }
}

/// `hte-console fake-idp`: HTE_FAKE_IDP_LISTEN (default 0.0.0.0:8080), HTE_FAKE_IDP_ISSUER (its own base URL as the
/// console reaches it), HTE_FAKE_IDP_CLIENT_ID and HTE_FAKE_IDP_CLIENT_SECRET (what the console's settings hold).
pub async fn serve_from_env() -> Result<(), String> {
    let issuer = std::env::var("HTE_FAKE_IDP_ISSUER").map_err(|_| "set HTE_FAKE_IDP_ISSUER".to_string())?.trim_end_matches('/').to_string();
    let cfg = Config {
        issuer,
        client_id: std::env::var("HTE_FAKE_IDP_CLIENT_ID").unwrap_or_else(|_| "client-seed".into()),
        client_secret: std::env::var("HTE_FAKE_IDP_CLIENT_SECRET").map_err(|_| "set HTE_FAKE_IDP_CLIENT_SECRET".to_string())?,
        tenant: None,
        clock: Arc::new(|| chrono::Utc::now().timestamp()),
    };
    let listen = std::env::var("HTE_FAKE_IDP_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let l = tokio::net::TcpListener::bind(&listen).await.map_err(|e| format!("cannot listen on {listen}: {e}"))?;
    tracing::info!("fake identity provider (TEST ONLY) on {listen}");
    let app = FakeIdp::new(cfg).router().route("/__fake-idp/health", get(|| async { "ok" }));
    axum::serve(l, app).await.map_err(|e| e.to_string())
}
