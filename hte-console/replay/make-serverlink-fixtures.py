#!/usr/bin/env python3
"""Write phase 3's synthetic server-link fixtures (hte-console/fixtures/serverlink/*.json).

Every expected answer is read from the PHP console's source at v1.15.0-hte.1 (VerifyServerSecret,
ServerLinkController, App\\Hte\\RefusalsController and Reach::recordRefusals, Laravel 13.35's validator, throttle,
HandleCors and router); `source` in each fixture says which statement. Nothing here was captured: the ID server's
calls carry the server link secret and are never recorded. Ids, names and addresses are placeholders seeded by
0000000000003-serverlink-seed.sql; the secret is a placeholder-shaped test value that replay.sh gives both consoles.

The policy's body depends on everything else in the replay database (captured devices, sign-in tokens minted at
random), so its fixtures compare status and type only; replay.sh compares PHP's and hte-console's policy bodies with
each other, and the Rust tests pin the body for this seed exactly. Run: python3 replay/make-serverlink-fixtures.py
(from hte-console/).
"""
import hashlib
import json
import os

OUT = os.path.join(os.path.dirname(__file__), "..", "fixtures", "serverlink")
SECRET = "tok-5eed00000003c0de"
BEARER = "Bearer " + SECRET
AGENT = "cortendesk-server/1.1.1-hte.2"

fixtures = []


def php_json(v):
    """json_encode with PHP's default flags (slashes and non-ASCII escaped)."""
    return json.dumps(v, separators=(",", ":"), ensure_ascii=True).replace("/", "\\/")


def add(slug, source, method, path, body=None, *, auth=BEARER, raw=None, form=None, status=200, ct="application/json",
        resp=None, omitted=False, capture_header=None, inm=None, digest=False):
    headers = {"x-forwarded-for": "198.18.3.1", "user-agent": AGENT}
    if auth is not None:
        headers["authorization"] = auth
    if inm is not None:
        headers["if-none-match"] = inm
    if raw is not None:
        req_body = {"kind": "raw", "content_type": "application/json", "text": raw}
    elif form is not None:
        req_body = {"kind": "form", "fields": form}
    elif body is not None:
        req_body = {"kind": "json", "value": body}
    else:
        req_body = {"kind": "empty"}
    if omitted:
        resp_body = {"kind": "omitted"}
    elif digest:
        # Laravel names nested attributes "addrs.0.id": the leftover scan reads that as a host name, so the fixture
        # holds the digest of the exact body and this script the text
        resp_body = {"kind": "sha256", "prefix": hashlib.sha256(php_json(resp).encode()).hexdigest()[:16]}
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
        "query": {},
        "request": {"headers": headers, "cookies": {}, "body": req_body},
        "response": {"status": status, "headers": {"content-type": ct} if ct else {}, "cookies": {}, "body": resp_body},
    }
    if capture_header:
        fx["capture_header"] = capture_header
    fixtures.append((slug, fx))


def err(m):
    return {"error": m}


def invalid(errors):
    """Laravel's 422 for api/*: the first message, '(and N more errors)', and every message by attribute."""
    msgs = [m for v in errors.values() for m in v]
    message = msgs[0]
    if len(msgs) > 1:
        n = len(msgs) - 1
        message += f" (and {n} more {'error' if n == 1 else 'errors'})"
    return {"message": message, "errors": errors}


POLICY, ADDRS, REFUSALS = "/api/server/policy", "/api/server/local-addrs", "/api/server/refusals"

# ---- VerifyServerSecret, the router -------------------------------------------------------------------------------
add("policy-no-token", "VerifyServerSecret: hash_equals(secret, (string) bearerToken()) fails -> 401", "GET", POLICY,
    auth=None, status=401, resp=err("Invalid server secret."))
add("policy-wrong-token", "VerifyServerSecret: a wrong bearer -> 401", "GET", POLICY,
    auth="Bearer tok-5eed00000003bad0", status=401, resp=err("Invalid server secret."))
add("policy-post", "routes/api.php: Route::get -> MethodNotAllowedHttpException, rendered as JSON on api/*", "POST", POLICY,
    body={}, status=405, resp={"message": "The POST method is not supported for route api/server/policy. Supported methods: GET, HEAD."})

# ---- the policy ---------------------------------------------------------------------------------------------------
add("policy", "ServerLinkController->policy: ServerLink->policy() with Reach->policyBlock(); ETag sha256 of the body; recordPull",
    "GET", POLICY, omitted=True, capture_header={"e1": "etag"})
add("policy-not-modified", "the same body: isNotModified(If-None-Match) -> 304, no body, no content type", "GET", POLICY,
    inm="{{e1}}", status=304, ct=None)
add("policy-weak-etag", "Symfony compares ETags weakly: W/ on the request's tag still matches", "GET", POLICY,
    inm="W/{{e1}}", status=304, ct=None)
add("policy-other-etag", "an ETag that is not the current one: the full policy", "GET", POLICY,
    inm='"tok-5eed00000003e7a9"', omitted=True)
add("policy-head", "HEAD on a GET route: headers only", "HEAD", POLICY, status=200)

# ---- local addresses ----------------------------------------------------------------------------------------------
add("local-addrs-update", "localAddrs: a known device, seen_at in the past -> lan_ip, lan_ip_seen_at", "POST", ADDRS,
    {"addrs": [{"id": "990003001", "ip": "198.18.3.21", "seen_at": 1700000000}]}, resp={"updated": 1})
add("local-addrs-older", "localAddrs: an older seen_at must not roll the address back", "POST", ADDRS,
    {"addrs": [{"id": "990003001", "ip": "198.18.3.22", "seen_at": 1690000000}]}, resp={"updated": 0})
add("local-addrs-unknown-and-pending", "localAddrs: an unknown id is skipped; a pending device is not trashed, so it is updated",
    "POST", ADDRS, {"addrs": [{"id": "990003999", "ip": "198.18.3.30"}, {"id": "990003003", "ip": "198.18.3.31"}]}, resp={"updated": 1})
add("local-addrs-ipv6-no-seen-at", "localAddrs: no seen_at is now; an IPv6 address passes the ip rule", "POST", ADDRS,
    {"addrs": [{"id": "990003002", "ip": "2001:db8::3:22"}]}, resp={"updated": 1})
add("local-addrs-future", "localAddrs: a seen_at in the future is now", "POST", ADDRS,
    {"addrs": [{"id": "990003004", "ip": "198.18.3.40", "seen_at": 4102444800}]}, resp={"updated": 1})
add("local-addrs-twice-in-a-batch", "localAddrs: the same device twice; the older one is skipped (not counted)", "POST", ADDRS,
    {"addrs": [{"id": "990003002", "ip": "198.18.3.23"}, {"id": "990003002", "ip": "198.18.3.24", "seen_at": 1700000001}]}, resp={"updated": 1})
add("local-addrs-seen-at-string", "integer rule: filter_var accepts a numeric string; Carbon reads it", "POST", ADDRS,
    {"addrs": [{"id": "990003001", "ip": "198.18.3.26", "seen_at": "1700000500"}]}, resp={"updated": 1})
add("local-addrs-form", "a form body is read into input() the same way", "POST", ADDRS,
    form={"addrs[0][id]": "990003001", "addrs[0][ip]": "198.18.3.25"}, resp={"updated": 1})
add("local-addrs-missing", "validate: addrs required", "POST", ADDRS, {}, status=422,
    resp=invalid({"addrs": ["The addrs field is required."]}))
add("local-addrs-empty-list", "validate: an empty array fails required", "POST", ADDRS, {"addrs": []}, status=422,
    resp=invalid({"addrs": ["The addrs field is required."]}))
add("local-addrs-not-array", "validate: addrs must be an array (no wildcard keys then)", "POST", ADDRS, {"addrs": "198.18.3.1"},
    status=422, resp=invalid({"addrs": ["The addrs field must be an array."]}))
add("local-addrs-bad-entries", "validate: rules per entry, in rule order (all ids, then all ips, then all seen_at)", "POST", ADDRS,
    {"addrs": [{"id": 990003001, "ip": "198.18.3.300", "seen_at": -1}, {"ip": "198.18.3.2"}, "x",
               {"id": "990003002", "ip": "198.18.3.2", "seen_at": "soon"}]},
    status=422, digest=True, resp=invalid({
        "addrs.0.id": ["The addrs.0.id field must be a string."],
        "addrs.1.id": ["The addrs.1.id field is required."],
        "addrs.2.id": ["The addrs.2.id field is required."],
        "addrs.0.ip": ["The addrs.0.ip field must be a valid IP address."],
        "addrs.2.ip": ["The addrs.2.ip field is required."],
        "addrs.0.seen_at": ["The addrs.0.seen_at field must be at least 0."],
        # min on a non-numeric string measures its length (4 >= 0): only the integer rule fails
        "addrs.3.seen_at": ["The addrs.3.seen_at field must be an integer."],
    }))
add("local-addrs-long-id", "validate: max:100 counts characters", "POST", ADDRS,
    {"addrs": [{"id": "x" + " x" * 50, "ip": "198.18.3.2"}]}, status=422, digest=True,
    resp=invalid({"addrs.0.id": ["The addrs.0.id field must not be greater than 100 characters."]}))
add("local-addrs-invalid-json", "a body that is not JSON reads as no input", "POST", ADDRS, raw="{", status=422,
    resp=invalid({"addrs": ["The addrs field is required."]}))
add("local-addrs-no-token", "VerifyServerSecret before validation: 401", "POST", ADDRS, {"addrs": []}, auth=None, status=401,
    resp=err("Invalid server secret."))
add("local-addrs-get", "a POST route: 405", "GET", ADDRS, status=405,
    resp={"message": "The GET method is not supported for route api/server/local-addrs. Supported methods: POST."})

# ---- refusals (alarm 102) -----------------------------------------------------------------------------------------
add("refusals-one", "RefusalsController->store: Reach->recordRefusals, one admin-only alarm 102 with both names", "POST", REFUSALS,
    {"refusals": [{"user_id": "7", "user_name": "user-5eed3004", "from": "990003004", "to": "990003001",
                   "ip": "198.18.3.9", "reason": "outside scope", "at": 1700000000}]}, resp={"recorded": 1})
add("refusals-nobody", "an empty user_name (null after ConvertEmptyStringsToNull) is 'nobody signed in'; unknown from", "POST", REFUSALS,
    {"refusals": [{"user_id": "", "user_name": "", "from": "990003999", "to": "990003002", "ip": "198.18.3.10",
                   "reason": "not signed in", "at": 1700000000}]}, resp={"recorded": 1})
add("refusals-batch", "two at once; only `to` is required; at as a numeric string", "POST", REFUSALS,
    {"refusals": [{"to": "990003002"}, {"user_name": "user-5eed3003", "from": "990003004", "to": "990003003", "at": "1700000001"}]},
    resp={"recorded": 2})
add("refusals-missing-to", "validate: refusals.*.to required", "POST", REFUSALS,
    {"refusals": [{"user_name": "user-5eed3004", "from": "990003004"}]}, status=422, digest=True,
    resp=invalid({"refusals.0.to": ["The refusals.0.to field is required."]}))
add("refusals-bad-fields", "validate: lengths, types and min", "POST", REFUSALS,
    {"refusals": [{"user_id": "text text text text text text text text x", "from": ["990003004"], "to": "990003001", "at": -5}]},
    status=422, digest=True, resp=invalid({
        "refusals.0.user_id": ["The refusals.0.user_id field must not be greater than 40 characters."],
        # max on an array counts its items (1 <= 100): only the string rule fails
        "refusals.0.from": ["The refusals.0.from field must be a string."],
        "refusals.0.at": ["The refusals.0.at field must be at least 0."],
    }))
add("refusals-empty", "validate: an empty list fails required", "POST", REFUSALS, {"refusals": []}, status=422,
    resp=invalid({"refusals": ["The refusals field is required."]}))
add("refusals-wrong-token", "VerifyServerSecret: 401", "POST", REFUSALS, {"refusals": [{"to": "990003001"}]},
    auth="Bearer tok-5eed00000003bad0", status=401, resp=err("Invalid server secret."))

if __name__ == "__main__":
    for f in os.listdir(OUT):
        if f.endswith(".json"):
            os.remove(os.path.join(OUT, f))
    for i, (slug, fx) in enumerate(fixtures, 1):
        method = fx["method"].lower()
        path = fx["path"].strip("/").replace("/", "_").replace("-", "_")
        name = f"0000000000003-{i:06d}-{method}-{path}-{slug}.json"
        with open(os.path.join(OUT, name), "w") as fh:
            json.dump(fx, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
    print(f"{len(fixtures)} fixtures in {os.path.normpath(OUT)}")
