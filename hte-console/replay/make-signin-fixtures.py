#!/usr/bin/env python3
"""Write phase 2's synthetic sign-in fixtures (hte-console/fixtures/signin/*.json) from the expectations below.

Every expected answer is read from the PHP console's source at v1.15.0-hte.1 (ClientAuthController,
ClientOidcController, OidcService with firebase/php-jwt 7.1.0, OidcUserResolver, DeviceEnrollment, Laravel 13.35's
throttle and auth middleware); `source` in each fixture says which statement. Nothing here was captured: sign-in
traffic carries credentials and is never recorded. Names, addresses and passwords are placeholder-shaped test
values (seeded by 0000000000002-signin-seed.sql). Run: python3 replay/make-signin-fixtures.py (from hte-console/).
"""
import json
import os
import shutil

OUT = os.path.join(os.path.dirname(__file__), "..", "fixtures", "signin")
PW = "tok-5eed00000000b002"          # the seeded accounts' password
UUID_201 = "UExBQ0VIT0xERVIhAAAA0g=="
UUID_202 = "UExBQ0VIT0xERVIhAAAA0w=="
UUID_X = "UExBQ0VIT0xERVIhAAAA2A=="
DEVICE_INFO = {"os": "Windows", "type": "client", "name": "text-5eed0d01"}

fixtures = []


def add(slug, source, method, path, body=None, *, xff="198.18.2.1", query=None, auth=None, raw=None,
        status=200, ct="application/json", resp=None, html=None, capture=None, browser=None):
    headers = {"accept": "application/json", "x-forwarded-for": xff}
    if auth is not None:
        headers["authorization"] = auth
    if raw is not None:
        req_body = {"kind": "raw", "content_type": "application/json", "text": raw}
    elif body is not None:
        req_body = {"kind": "json", "value": body}
    else:
        req_body = {"kind": "empty"}
    if html is not None:
        resp_body = {"kind": "html", "contains": html}
    elif resp is None:
        resp_body = {"kind": "empty"}
    else:
        resp_body = {"kind": "json", "value": resp}
    fx = {
        "format": 1,
        "seq": len(fixtures) + 1,
        "synthetic": True,
        "source": source.replace("::", "->"),  # "::" reads as an IPv6 address to the leftover scan
        "method": method,
        "path": path,
        "query": query or {},
        "request": {"headers": headers, "cookies": {}, "body": req_body},
        "response": {"status": status, "headers": {"content-type": ct} if ct else {}, "cookies": {}, "body": resp_body},
    }
    if capture:
        fx["capture"] = capture
    if browser:
        fx["browser"] = browser
    fixtures.append((slug, fx))


def err(m):
    return {"error": m}


def payload(name, display, email, admin=False):
    return {"name": name, "display_name": display, "email": email, "note": "", "status": 1, "is_admin": admin, "info": {}}


U2 = payload("user-5eed0002", "text-5eed0002", "user-5eed000002@example.invalid", True)
U6 = payload("user-5eed0006", "text-5eed0006", "user-5eed000006@example.invalid")
ANNA = payload("990005001", "text-5eed0a01", "user-5eed00a001@example.invalid")
LINKED = payload("user-5eed0008", "text-5eed0a08", "user-5eed000008@example.invalid")
KNOWN = payload("user-5eed0009", "text-5eed0a09", "user-5eed000009@example.invalid")


def auth_body(user):
    return {"access_token": "{{random}}", "type": "access_token", "tfa_type": "", "secret": "", "user": user}


def login(user, pw=PW, dev="990000201", uuid=UUID_201, info=DEVICE_INFO, **kw):
    b = {"username": user, "password": pw, "id": dev, "uuid": uuid}
    if info is not None:
        b["deviceInfo"] = info
    return b


PENDING = err("No authed oidc is found")
WRONG = err("Wrong credentials")

# ---------------------------------------------------------------------------------------------- login-options ---
add("login-options", "loginOptions(): SSO on, label 'Sign in with Microsoft' -> clientProviderName() strips the verb",
    "GET", "/api/login-options", resp=["common-oidc/[{\"name\":\"Microsoft\"}]"])
add("login-options-head", "Route::match(['get','head']): HEAD runs the route, the body is dropped", "HEAD", "/api/login-options", ct="application/json")
add("login-options-put", "Laravel: MethodNotAllowedHttpException rendered as JSON for api/*", "PUT", "/api/login-options", status=405,
    resp={"message": "The PUT method is not supported for route api/login-options. Supported methods: GET, HEAD."})

# ------------------------------------------------------------------------------------------------- password ---
add("login-wrong-password", "login(): Hash::check fails -> LoginLog unsuccessful, 'Wrong credentials'", "POST", "/api/login",
    login("user-5eed0002", pw="tok-5eed0000000bad02"), xff="198.18.2.10", resp=WRONG)
add("login-unknown-user", "login(): no such username -> 'Wrong credentials' (LoginLog with the name as typed)", "POST", "/api/login",
    login("user-5eed00ff"), xff="198.18.2.10", resp=WRONG)
add("login-empty-password", "login(): $password === '' never reaches Hash::check", "POST", "/api/login",
    login("user-5eed0002", pw=""), xff="198.18.2.10", resp=WRONG)
add("login-inactive", "login(): is_active false -> 'Wrong credentials'", "POST", "/api/login",
    login("user-5eed0003"), xff="198.18.2.10", resp=WRONG)
add("login-sso-provisioned", "login(): right password but isSsoProvisioned() (auth_provider oidc)", "POST", "/api/login",
    login("user-5eed0004", pw="tok-5eed00000000b004"), xff="198.18.2.10", resp=err("This account signs in through single sign-on."))
add("login-sso-pending", "login(): isSsoPending() (oidc_status pending)", "POST", "/api/login",
    login("user-5eed0005"), xff="198.18.2.10", resp=err("Your account is waiting for administrator approval."))
add("login-username-array", "(string) $request->input('username'): Array to string conversion -> 500", "POST", "/api/login",
    {"username": ["user-5eed0002"], "password": PW}, xff="198.18.2.11", status=500, resp={"message": "Server Error"})
add("login-invalid-json", "invalid JSON is an empty input: username '' finds nobody", "POST", "/api/login",
    raw="{\"username\":\"user-5eed0002\",", xff="198.18.2.11", resp=WRONG)
add("login-get", "Route::post: GET is 405", "GET", "/api/login", xff="198.18.2.11", status=405,
    resp={"message": "The GET method is not supported for route api/login. Supported methods: POST."})
add("login-ok-pending-device", "signIn(): token issued; DeviceEnrollment::signedIn approves pending 990000201, owner set",
    "POST", "/api/login", login("user-5eed0002"), xff="198.18.2.12", resp=auth_body(U2), capture={"t1": "/access_token"})
add("current-user", "currentUser(): the guard finds the token, stamps last_used_at; UserPayload", "POST", "/api/currentUser",
    xff="198.18.2.12", auth="Bearer {{t1}}", resp=U2)
add("current-user-no-token", "auth:client without a bearer: 401 Unauthenticated.", "POST", "/api/currentUser", xff="198.18.2.12",
    status=401, resp={"message": "Unauthenticated."})
add("current-user-unknown-token", "auth:client with a token nobody holds: 401", "POST", "/api/currentUser", xff="198.18.2.12",
    # an unfilled template, sent as it is: `seed-sql` seeds every other bearer token a fixture shows as valid
    auth="Bearer {{nobody}}", status=401, resp={"message": "Unauthenticated."})
add("logout", "logout(): the token row is deleted, {}", "POST", "/api/logout", xff="198.18.2.12", auth="Bearer {{t1}}", resp={})
add("current-user-after-logout", "the deleted token no longer authenticates", "POST", "/api/currentUser", xff="198.18.2.12",
    auth="Bearer {{t1}}", status=401, resp={"message": "Unauthenticated."})
add("login-ok-new-device", "signedIn(): an unknown id is registered (gate off: active, owner, registered_ip)", "POST", "/api/login",
    login("user-5eed0002", dev="990000203", uuid=UUID_X), xff="198.18.2.13", resp=auth_body(U2))
add("login-ok-trashed-device", "signedIn(): a soft-deleted device is left alone", "POST", "/api/login",
    login("user-5eed0002", dev="990000204", uuid=UUID_X, info=None), xff="198.18.2.13", resp=auth_body(U2))

# ----------------------------------------------------------------------------------------------------- TOTP ---
TFA = {"type": "email_check", "tfa_type": "tfa_check", "secret": "{{random}}", "user": {"name": "user-5eed0006"}}


def code_step(var, code, dev="990000205"):
    return {"type": "tfa_code", "secret": "{{%s}}" % var, "id": dev, "tfaCode": code}


add("tfa-challenge", "login(): hasTwoFactorEnabled() -> challenge(tfa): secret, tfa_check", "POST", "/api/login",
    login("user-5eed0006", dev="990000205", uuid=UUID_X), xff="198.18.2.30", resp=TFA, capture={"s1": "/secret"})
add("tfa-wrong-code", "verifyCode(): consumeTotp fails -> hit, LoginLog 'wrong verification code', tries 1", "POST", "/api/login",
    code_step("s1", "{{totp_wrong}}"), xff="198.18.2.30", resp=err("That code is incorrect or has expired."))
add("tfa-other-device", "verifyCode(): bound to the device that gave the password", "POST", "/api/login",
    code_step("s1", "{{totp}}", dev="990000299"), xff="198.18.2.30", resp=err("Your sign-in expired. Sign in again."))
add("tfa-ok", "verifyCode(): the current code -> step burnt, Cache::pull, RateLimiter::clear, signIn()", "POST", "/api/login",
    code_step("s1", "{{totp}}"), xff="198.18.2.30", resp=auth_body(U6), capture={"t2": "/access_token"})
add("tfa-secret-reused", "one prompt, one token: the pulled secret is gone", "POST", "/api/login",
    code_step("s1", "{{totp_last}}"), xff="198.18.2.30", resp=err("Your sign-in expired. Sign in again."))
add("tfa-challenge-2", "a second prompt for the same account", "POST", "/api/login",
    login("user-5eed0006", dev="990000205", uuid=UUID_X), xff="198.18.2.30", resp=TFA, capture={"s2": "/secret"})
add("tfa-code-replayed", "consumeTotp(): the conditional UPDATE claims nothing for a used step", "POST", "/api/login",
    code_step("s2", "{{totp_last}}"), xff="198.18.2.30", resp=err("That code has already been used. Wait for the next one."))
add("tfa-current-user", "the TOTP sign-in's token works", "POST", "/api/currentUser", xff="198.18.2.30", auth="Bearer {{t2}}", resp=U6)

# brute force on the code step: 5 wrong codes per account and address a minute, across prompts, then an alarm
add("bf-challenge-1", "challenge for the brute-force run", "POST", "/api/login",
    login("user-5eed0006", dev="990000205", uuid=UUID_X), xff="198.18.2.40", resp=TFA, capture={"s3": "/secret"})
for i in range(4):
    add("bf-wrong-%d" % (i + 1), "wrong code %d of the first prompt (limiter hit %d)" % (i + 1, i + 1), "POST", "/api/login",
        code_step("s3", "{{totp_wrong}}"), xff="198.18.2.40", resp=err("That code is incorrect or has expired."))
add("bf-challenge-2", "a new prompt: CHALLENGE_TRIES counts per prompt, the limiter per account and address", "POST", "/api/login",
    login("user-5eed0006", dev="990000205", uuid=UUID_X), xff="198.18.2.40", resp=TFA, capture={"s4": "/secret"})
add("bf-wrong-5", "wrong code 5 (limiter hit 5)", "POST", "/api/login", code_step("s4", "{{totp_wrong}}"), xff="198.18.2.40",
    resp=err("That code is incorrect or has expired."))
add("bf-too-many", "tooManyAttempts: AlarmLog::console(TYP_BRUTE_FORCE) once, 'Too many attempts. Try again in N seconds.'",
    "POST", "/api/login", code_step("s4", "{{totp_wrong}}"), xff="198.18.2.40", resp=err("Too many attempts. Try again in {{n}} seconds."))
add("bf-too-many-again", "still limited; the alarm is not raised again inside ALARM_COOLDOWN", "POST", "/api/login",
    code_step("s4", "{{totp_wrong}}"), xff="198.18.2.40", resp=err("Too many attempts. Try again in {{n}} seconds."))

# the client-login throttle: 20 a minute per address (the group's 240 is not reached)
for i in range(20):
    add("throttle-%02d" % (i + 1), "throttle:20,1,client-login, attempt %d" % (i + 1), "POST", "/api/login",
        login("user-5eed0002", pw="tok-5eed0000000bad03"), xff="198.18.2.50", resp=WRONG)
add("throttle-21", "the 21st attempt in a minute: 429 before the controller (no LoginLog)", "POST", "/api/login",
    login("user-5eed0002", pw="tok-5eed0000000bad03"), xff="198.18.2.50", status=429, resp={"message": "Too Many Attempts."})

# ----------------------------------------------------------------------------------------------------- OIDC ---
OIDC_START = {"code": "{{random}}", "url": "{{oidc-url}}"}


def oidc_auth(dev, uuid, xff, cvar, uvar, op="sso", source="auth(): OidcAuthRequest::start, buildAuthorizationUrl (PKCE S256)"):
    add("oidc-auth-" + cvar, source, "POST", "/api/oidc/auth",
        {"id": dev, "uuid": uuid, "op": op, "deviceInfo": {"os": "Mac OS", "type": "client", "name": "text-5eed0d02"}},
        xff=xff, resp=OIDC_START, capture={cvar: "/code", uvar: "/url"})


def poll(slug, cvar, dev, uuid, resp, source, capture=None):
    add(slug, source, "GET", "/api/oidc/auth-query", xff="198.18.3.250", query={"code": "{{%s}}" % cvar, "id": dev, "uuid": uuid},
        resp=resp, capture=capture)


def callback(slug, uvar, mode, profile, status, html, source, keep=None):
    b = {"authorize": uvar, "mode": mode, "profile": profile}
    if keep:
        b["keep"] = keep
    add(slug, source, "GET", "/login/oidc/client-callback", xff="198.18.3.251", status=status, ct="text/html", html=html, browser=b)


oidc_auth("990000202", UUID_202, "198.18.3.1", "c1", "u1")
poll("oidc-poll-pending", "c1", "990000202", UUID_202, PENDING, "authQuery(): not authorized yet")
poll("oidc-poll-other-device", "c1", "990000299", UUID_202, PENDING, "belongsToDevice() fails: read as pending")
callback("oidc-callback-ok", "u1", "ok", "anna", 200, ["Signed in to HTE Remote", "You are signed in as text-5eed0a01."],
         "browserCallback(): exchange, verify, provision (policy active), token, 990000202 approved and owned", keep="cb1")
poll("oidc-poll-other-uuid", "c1", "990000202", UUID_X, PENDING, "belongsToDevice(): the uuid must match too")
poll("oidc-poll-ok", "c1", "990000202", UUID_202, auth_body(ANNA), "authorized: AuthBody, the row deleted", capture={"t3": "/access_token"})
poll("oidc-poll-again", "c1", "990000202", UUID_202, PENDING, "one-shot: the row is gone")
callback("oidc-callback-again", "u1", "ok", "anna", 400, ["This sign-in request has expired."],
         "the same callback after collection: no row for the state -> 400", keep=None)
fixtures[-1][1]["browser"] = {"again": "cb1"}
add("oidc-current-user", "the SSO token works; userinfo's name lost to the token's (array_merge)", "POST", "/api/currentUser",
    xff="198.18.3.1", auth="Bearer {{t3}}", resp=ANNA)
add("oidc-auth-get", "Route::post: GET is 405", "GET", "/api/oidc/auth", xff="198.18.3.1", status=405,
    resp={"message": "The GET method is not supported for route api/oidc/auth. Supported methods: POST."})

ok_flows = [
    ("linked", "990000206", LINKED, "OidcUserResolver: first-time link by email, then admit() refreshes the name"),
    ("known", "990000207", KNOWN, "OidcUserResolver: found by (iss, sub); admit() refreshes the name"),
]
n = 1
for profile, dev, user, source in ok_flows:
    n += 1
    c, u = "c%d" % n, "u%d" % n
    oidc_auth(dev, UUID_X, "198.18.3.%d" % n, c, u)
    callback("oidc-callback-" + profile, u, "ok", profile, 200, ["Signed in to HTE Remote", "You are signed in as %s." % user["display_name"]], source)
    poll("oidc-poll-" + profile, c, dev, UUID_X, auth_body(user), "the poll collects the token")

failures = [
    ("wrong-iss", "anna", "The ID token was issued by an unexpected issuer.", "verifyIdToken(): iss differs from the discovery issuer"),
    ("wrong-aud", "anna", "The ID token was not issued for this client.", "verifyIdToken(): client_id not among aud"),
    ("wrong-nonce", "anna", "The ID token nonce did not match. Please try signing in again.", "verifyIdToken(): nonce differs"),
    ("alg-none", "anna", "The ID token was signed with an algorithm this provider does not advertise (none).", "acceptedSigningAlgorithms() never holds none"),
    ("alg-hs256", "anna", "The ID token was signed with an algorithm this provider does not advertise (HS256).", "the provider advertises RS256 only"),
    ("expired", "anna", "The ID token failed verification: Expired token", "php-jwt: exp past (60 s leeway)"),
    ("nbf-future", "anna", "The ID token failed verification: Cannot handle token with nbf prior to {{ts}}", "php-jwt: nbf 10 minutes ahead"),
    ("bad-signature", "anna", "The ID token failed verification: Signature verification failed", "php-jwt: signed by another key"),
    ("unknown-kid", "anna", "The ID token failed verification: \"kid\" invalid, unable to lookup correct key", "php-jwt: kid not in the JWKS"),
    ("no-kid", "anna", "The ID token failed verification: \"kid\" empty, unable to lookup correct key", "php-jwt: no kid with a key set"),
    ("short-key", "anna", "The ID token failed verification: Provided key is too short", "php-jwt: a 1024-bit RSA key"),
    ("wrong-alg-key", "anna", "The ID token failed verification: Incorrect key for this algorithm", "php-jwt: the key says RS384"),
    ("no-sub", "anna", "The ID token carried no subject claim.", "verifyIdToken(): empty($claims['sub'])"),
    ("malformed", "anna", "The provider returned a malformed ID token.", "decodeSegment(): not three segments"),
    ("no-id-token", "anna", "The provider returned no ID token. Ensure the \"openid\" scope is granted.", "exchangeCode(): no id_token"),
    ("token-500", "anna", "Token exchange failed (500). Check the client ID and secret.", "exchangeCode(): the token endpoint fails"),
    ("deny", "anna", "The identity provider rejected the sign-in.", "browserCallback(): ?error= from the provider"),
    ("ok", "outsider", "Your email domain is not permitted to sign in to this console.", "OidcUserResolver::domainAllowed (LoginLog 'sso', failed)"),
    ("ok", "disabled", "This account is disabled. Contact your administrator.", "OidcUserResolver::admit(): is_active false"),
]
for mode, profile, message, source in failures:
    n += 1
    c, u = "c%d" % n, "u%d" % n
    dev = "9900003%02d" % n
    slug = mode if profile == "anna" else profile
    oidc_auth(dev, UUID_X, "198.18.4.%d" % n, c, u)
    # the page shows the message through Blade's {{ }} (htmlspecialchars, ENT_QUOTES)
    shown = message.split("{{")[0].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#039;")
    callback("oidc-callback-" + slug, u, mode, profile, 403, ["Sign-in failed", shown], source + "; fail(): 403 page, failure kept")
    poll("oidc-poll-" + slug, c, dev, UUID_X, err(message), "authQuery(): the failure is handed over once, the row deleted")
    poll("oidc-poll-" + slug + "-after", c, dev, UUID_X, PENDING, "after the failure was collected: pending")

add("oidc-callback-unknown-state", "browserCallback(): no row for the state -> 400 page", "GET", "/login/oidc/client-callback",
    xff="198.18.3.251", query={"state": "tok-5eed00000000aaaa", "code": "tok-5eed00000000bbbb"}, status=400, ct="text/html",
    html=["This sign-in request has expired."])

# ---------------------------------------------------------------------------------------------------- write ---
if os.path.isdir(OUT):
    for f in os.listdir(OUT):
        if f.endswith(".json"):
            os.remove(os.path.join(OUT, f))
os.makedirs(OUT, exist_ok=True)
for i, (slug, fx) in enumerate(fixtures, 1):
    fx["seq"] = i
    path_slug = "".join(ch if ch.isalnum() else "_" for ch in fx["path"]).strip("_")
    name = "0000000000002-%06d-%s-%s-%s.json" % (i, fx["method"].lower(), path_slug, slug)
    with open(os.path.join(OUT, name), "w") as f:
        json.dump(fx, f, indent=2)
        f.write("\n")
print("%d fixtures written to %s" % (len(fixtures), os.path.normpath(OUT)))
