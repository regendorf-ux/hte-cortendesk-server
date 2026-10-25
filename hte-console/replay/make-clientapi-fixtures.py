#!/usr/bin/env python3
"""Write phase 4's synthetic client-API fixtures (hte-console/fixtures/clientapi/*.json) from the expectations below.

Every expected answer is read from the PHP console's source at v1.15.0-hte.1 (AddressBookController, GroupTabController,
WebClientController, AuditController, AddressBook/Device/User models, App\\Hte\\Passwords::hiddenBookFor, Laravel 13.35's
router and auth middleware); `source` in each fixture says which statement. Nothing here was captured: the people,
computers, books and sessions are placeholders seeded by 0000000000004-clientapi-seed.sql. The fixtures run in file
order against one database, so the mutating ones come after the reads they must not disturb.
Run: python3 replay/make-clientapi-fixtures.py (from hte-console/).
"""
import json
import os
import re

OUT = os.path.join(os.path.dirname(__file__), "..", "fixtures", "clientapi")

TOK = {
    "adm": "tok-5eed000000004a01", "anna": "tok-5eed000000004a02", "ben": "tok-5eed000000004a03",
    "none": "tok-5eed000000004a04", "off": "tok-5eed000000004a05", "exp": "tok-5eed000000004a06",
    "nodev": "tok-5eed000000004a07",
}
G = lambda n: "00000000-0000-4000-8000-0000000004%s" % n
PERSONAL, ORPHAN = G("a1"), G("a2")          # anna's personal book; a personal book whose owner is gone
C1, C2, C3, C4, C5, C6 = G("c1"), G("c2"), G("c3"), G("c4"), G("c5"), G("c6")
GONE = G("ff")
fixtures = []


def add(slug, source, method, path, who=None, body=None, *, query=None, raw=None, status=200, ct="application/json",
        resp=None, html=None, xff="198.18.5.1"):
    headers = {"accept": "application/json", "x-forwarded-for": xff}
    if who:
        headers["authorization"] = "Bearer " + TOK.get(who, who)
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
    # a guid in a path would be mistaken for a long token by the sanitiser: the path carries {{g<suffix>}}, "vars" the guid
    guids = re.findall(r"00000000-0000-4000-8000-0000000004([0-9a-f]{2})", path)
    vars_ = {"g" + g: "00000000-0000-4000-8000-0000000004" + g for g in guids}
    for g in guids:
        path = path.replace("00000000-0000-4000-8000-0000000004" + g, "{{g%s}}" % g)
    fixtures.append((slug, {
        "format": 1, "seq": 0, "synthetic": True,
        "source": source.replace("::", "->"),
        **({"vars": vars_} if vars_ else {}),
        "method": method, "path": path, "query": query or {},
        "request": {"headers": headers, "cookies": {}, "body": req_body},
        "response": {"status": status, "headers": {"content-type": ct} if ct else {}, "cookies": {}, "body": resp_body},
    }))


def err(m):
    return {"error": m}


UNAUTH = {"message": "Unauthenticated."}
NOBOOK, DENIED = err("Address book not found"), err("Permission denied")
EMPTY = None   # `response('', 200)`: an empty body (the content type is not compared)


def ok(slug, source, method, path, who, body=None, **kw):
    add(slug, source, method, path, who, body, ct=None, resp=EMPTY, **kw)


def not_allowed(slug, method, path, allowed):
    add(slug, "Laravel: MethodNotAllowedHttpException, the verbs of the other routes on this URI, in Router verb order",
        method, path, status=405,
        resp={"message": "The %s method is not supported for route %s. Supported methods: %s." % (method, path.lstrip("/"), allowed)})


# ------------------------------------------------------------------------------------------------ the guard ---
add("no-token", "auth:client without a bearer: 401 Unauthenticated.", "POST", "/api/ab/personal", status=401, resp=UNAUTH)
add("unknown-token", "auth:client with a token nobody holds", "POST", "/api/ab/personal", "{{nobody}}", status=401, resp=UNAUTH)
add("disabled-user", "the client-token guard: the owner must be active", "POST", "/api/ab/personal", "off", status=401, resp=UNAUTH)
add("expired-token", "the client-token guard: expires_at in the past", "POST", "/api/ab/personal", "exp", status=401, resp=UNAUTH)
add("get-without-token", "auth:client covers the GET routes too", "GET", "/api/users", status=401, resp=UNAUTH)

# ------------------------------------------------------------------------------------------ routing errors ---
not_allowed("put-ab", "PUT", "/api/ab", "GET, HEAD, POST")
not_allowed("get-ab-personal", "GET", "/api/ab/personal", "POST")
not_allowed("post-ab-tag-rename", "POST", "/api/ab/tag/rename/x", "PUT")
not_allowed("post-ab-peer-delete", "POST", "/api/ab/peer/x", "DELETE")
not_allowed("put-server-config", "PUT", "/api/server-config", "GET, HEAD, POST")
not_allowed("post-users", "POST", "/api/users", "GET, HEAD")
add("tags-two-segments", "{guid} is one path segment: NotFoundHttpException rendered as JSON", "POST", "/api/ab/tags/a/b", "anna",
    status=404, resp={"message": "The route api/ab/tags/a/b could not be found."})

# ----------------------------------------------------------------------------- settings, personal, legacy ---
add("settings", "settings(): max_peer_one_ab 0", "POST", "/api/ab/settings", "anna", resp={"max_peer_one_ab": 0})
add("personal-anna", "personal(): AddressBook::personalFor finds her book", "POST", "/api/ab/personal", "anna", resp={"guid": PERSONAL})
add("personal-ben-creates", "personalFor(): firstOrCreate makes the missing personal book, a random guid", "POST", "/api/ab/personal",
    "ben", resp={"guid": "{{random}}"})
add("personal-ben-again", "personalFor(): the second call finds the same book (a single row, see the database)", "POST", "/api/ab/personal",
    "ben", resp={"guid": "{{random}}"})

ANNA_PEERS = [
    {"id": "990000421", "username": "user-5eed0421", "hostname": "host-5eed0421", "platform": "Windows", "alias": "text-5eed0421",
     "tags": ["text-5eed04d1"], "hash": "tok-5eed000000000421"},
    {"id": "990000422", "username": "", "hostname": "host-5eed0422", "platform": "Mac OS", "alias": "",
     "tags": ["text-5eed04d1", "text-5eed04d2"], "hash": "tok-5eed000000000422"},
]
ANNA_DATA = {"tags": ["text-5eed04d1", "text-5eed04d2"], "peers": ANNA_PEERS,
             "tag_colors": json.dumps({"text-5eed04d1": 4278190080, "text-5eed04d2": 5}, separators=(",", ":"))}


def packed(d):
    return json.dumps(d, separators=(",", ":"))


add("legacy-get", "legacyGet(): triple-encoded pull, tags by id, tag_colors a string inside the data string", "GET", "/api/ab", "anna",
    resp={"data": packed(ANNA_DATA), "licensed_devices": 0})
add("legacy-get-post-alias", "Route::post('/ab/get'): the same pull; Ben's book exists and is empty (tag_colors: json_encode([]))",
    "POST", "/api/ab/get", "ben", resp={"data": packed({"tags": [], "peers": [], "tag_colors": "[]"}), "licensed_devices": 0})
add("legacy-get-admin", "legacyGet(): an administrator has a personal book of their own too (made on first use)", "GET", "/api/ab", "adm",
    resp={"data": packed({"tags": [], "peers": [], "tag_colors": "[]"}), "licensed_devices": 0})

# ------------------------------------------------------------------------------------------- shared profiles ---
def prof(g, n, owner, note, rule):
    return {"guid": g, "name": "text-5eed04c%d" % n, "owner": owner, "note": note, "rule": rule}


A, AN = "user-5eed0401", "user-5eed0402"
BE = "user-5eed0403"
add("shared-admin", "sharedProfiles(): an administrator has full control of every shared book; another person's automatic book "
    "(hte_auto_books) is hidden even from them", "POST", "/api/ab/shared/profiles", "adm",
    resp={"total": 4, "data": [prof(C1, 1, A, "", 3), prof(C2, 2, AN, "text-5eed04ca", 3), prof(C3, 3, A, "", 3), prof(C4, 4, A, "", 3)]})
add("shared-anna", "sharedProfiles(): everyone->1, owner->3, group 1->3, no rule->hidden, her own automatic book shown, Ben's hidden",
    "POST", "/api/ab/shared/profiles", "anna",
    resp={"total": 4, "data": [prof(C1, 1, A, "", 1), prof(C2, 2, AN, "text-5eed04ca", 3), prof(C3, 3, A, "", 3), prof(C5, 5, AN, "", 3)]})
add("shared-ben", "sharedProfiles(): the highest permission of every rule that matches (user rule 2 beats group rule 1)",
    "POST", "/api/ab/shared/profiles", "ben",
    resp={"total": 4, "data": [prof(C1, 1, A, "", 1), prof(C2, 2, AN, "text-5eed04ca", 2), prof(C3, 3, A, "", 3), prof(C6, 6, BE, "", 3)]})
add("shared-none", "sharedProfiles(): somebody in no group sees the books granted to everyone only", "POST", "/api/ab/shared/profiles", "none",
    resp={"total": 1, "data": [prof(C1, 1, A, "", 1)]})
add("shared-page-2", "pagination(): current=2&pageSize=2 slices the sorted list, total is all of it", "POST", "/api/ab/shared/profiles", "anna",
    query={"current": "2", "pageSize": "2"},
    resp={"total": 4, "data": [prof(C3, 3, A, "", 3), prof(C5, 5, AN, "", 3)]})
add("shared-page-nonsense", "pagination(): (int) 'abc' is 0, max(1, 0) = 1 per page; a negative page is page 1", "POST", "/api/ab/shared/profiles",
    "anna", query={"current": "-4", "pageSize": "abc"}, resp={"total": 4, "data": [prof(C1, 1, A, "", 1)]})
add("shared-page-empty-value", "TrimStrings and ConvertEmptyStringsToNull: an empty pageSize is null, the default 100 applies", "POST",
    "/api/ab/shared/profiles", "none", query={"pageSize": "", "current": ""}, resp={"total": 1, "data": [prof(C1, 1, A, "", 1)]})

# --------------------------------------------------------------------------------------------- reading books ---
def peer(i, host, plat, alias, tags, user="", relay="false", rdp="", rdpu="", login="", **extra):
    p = {"id": i, "username": user, "hostname": host, "platform": plat, "alias": alias, "tags": tags,
         "forceAlwaysRelay": relay, "rdpPort": rdp, "rdpUsername": rdpu, "loginName": login}
    p.update(extra)
    return p


PEER421 = peer("990000421", "host-5eed0421", "Windows", "text-5eed0421", ["text-5eed04d1"], "user-5eed0421", hash="tok-5eed000000000421")
PEER422 = peer("990000422", "host-5eed0422", "Mac OS", "", ["text-5eed04d1", "text-5eed04d2"], "", "true", "3389", "user-5eed0422",
               "user-5eed0922", hash="tok-5eed000000000422")
PEER431 = peer("990000431", "host-5eed0431", "Linux", "text-5eed0431", ["text-5eed04e1"], "user-5eed0431", password="tok-5eed000000000431")
PEER432 = peer("990000432", "host-5eed0432", "Windows", "", [])
add("peers-personal", "peers(): her personal book: peerJson with hash, forceAlwaysRelay a string", "POST", "/api/ab/peers", "anna",
    query={"ab": PERSONAL}, resp={"total": 2, "data": [PEER421, PEER422]})
add("peers-shared-password", "peers(): a shared book gives the decrypted password where there is one, no hash", "POST", "/api/ab/peers", "anna",
    query={"ab": C3}, resp={"total": 2, "data": [PEER431, PEER432]})
add("peers-page", "peers(): forPage(2, 1)", "POST", "/api/ab/peers", "anna", query={"ab": C3, "current": "2", "pageSize": "1"},
    resp={"total": 2, "data": [PEER432]})
add("peers-not-found", "bookOrFail(): no such guid", "POST", "/api/ab/peers", "anna", query={"ab": GONE}, resp=NOBOOK)
add("peers-no-guid", "peers(): (string) query('ab', '') is empty, so no book", "POST", "/api/ab/peers", "anna", resp=NOBOOK)
add("peers-denied", "bookOrFail(): no rule gives Anna the book", "POST", "/api/ab/peers", "anna", query={"ab": C4}, resp=DENIED)
add("peers-other-personal", "permissionFor(): a personal book is private to its owner", "POST", "/api/ab/peers", "ben", query={"ab": PERSONAL}, resp=DENIED)
add("peers-orphan-admin", "permissionFor(): an administrator may reach a personal book whose owner is gone", "POST", "/api/ab/peers", "adm",
    query={"ab": ORPHAN}, resp={"total": 0, "data": []})
add("peers-orphan-other", "permissionFor(): not anyone else", "POST", "/api/ab/peers", "anna", query={"ab": ORPHAN}, resp=DENIED)
add("tags-personal", "tags(): ordered by name, color an int", "POST", "/api/ab/tags/" + PERSONAL, "anna",
    resp=[{"name": "text-5eed04d1", "color": 4278190080}, {"name": "text-5eed04d2", "color": 5}])
add("tags-shared", "tags(): READ is enough", "POST", "/api/ab/tags/" + C3, "ben",
    resp=[{"name": "text-5eed04e1", "color": 1}, {"name": "text-5eed04e2", "color": 0}])
add("tags-not-found", "bookOrFail(): no such guid", "POST", "/api/ab/tags/" + GONE, "ben", resp=NOBOOK)
add("tags-denied", "bookOrFail(): no rule", "POST", "/api/ab/tags/" + C4, "ben", resp=DENIED)

# ------------------------------------------------------------------------------------ web client bootstrap ---
def card(i, user, host, plat, hh):
    return {"view-style": "shrink", "tm": 0, "info": {"username": user, "hostname": host, "platform": plat, "hash": hh, "id": i}, "tmppwd": ""}


SC = {"id_server": "host-5eed0401.example.invalid:21116", "key": "tok-5eed00000000a1b2"}
add("server-config", "serverConfig(): id_server and key from the settings, peers from her personal book keyed by id (tm is masked)",
    "POST", "/api/server-config", "anna",
    resp={"code": 0, "message": "success", "data": dict(SC, peers={
        "990000421": card("990000421", "user-5eed0421", "host-5eed0421", "Windows", "tok-5eed000000000421"),
        "990000422": card("990000422", "", "host-5eed0422", "Mac OS", "tok-5eed000000000422")})})
add("server-config-get", "Route::match(['get','post']); Ben's book is empty: (object) [] encodes as {}", "GET", "/api/server-config", "ben",
    resp={"code": 0, "message": "success", "data": dict(SC, peers={})})
add("webclient-config", "configJs(): the bootstrap script, application/javascript, built from the request's own address; no login",
    "GET", "/webclient-config/index.js", ct="application/javascript",
    html=["('api-server', 'http", "const ws2_prefix = 'wc-';", "(ws2_prefix + 'api-server', 'http", "webclient_magic_queryonline = 0;"])

# --------------------------------------------------------------------------------------------------- group tab ---
add("device-groups-anna", "deviceGroups(): accessibleDeviceGroupIds() = her user group's folder", "GET", "/api/device-group/accessible", "anna",
    resp={"total": 1, "data": [{"name": "text-5eed04b1"}]})
add("device-groups-ben", "accessibleDeviceGroupIds(): direct grant + user group grants + group_accesses, sorted by name", "GET",
    "/api/device-group/accessible", "ben",
    resp={"total": 3, "data": [{"name": "text-5eed04b1"}, {"name": "text-5eed04b2"}, {"name": "text-5eed04b3"}]})
add("device-groups-none", "accessibleDeviceGroupIds(): a group_accesses grant to the person alone", "GET", "/api/device-group/accessible", "none",
    resp={"total": 1, "data": [{"name": "text-5eed04b3"}]})
add("device-groups-admin", "seesAllDevices(): an administrator sees every folder", "GET", "/api/device-group/accessible", "adm",
    query={"current": "2", "pageSize": "2"}, resp={"total": 3, "data": [{"name": "text-5eed04b3"}]})


def uj(name, display, email, note, status):
    return {"name": name, "display_name": display, "email": email, "note": note, "status": status, "is_admin": False, "info": {}}


U2 = uj("user-5eed0402", "text-5eed0402", "user-5eed040002@example.invalid", "text-5eed0902", 1)
U3 = uj("user-5eed0403", "user-5eed0403", "user-5eed040003@example.invalid", "", 1)
U4 = uj("user-5eed0404", "user-5eed0404", "", "", 1)
U5 = uj("user-5eed0405", "text-5eed0405", "user-5eed040005@example.invalid", "", 0)
add("users-anna", "users(): herself, her group-mates, and the members of a group her group may access (visibleUserIds)", "GET", "/api/users", "anna",
    resp={"total": 3, "data": [U2, U3, U5]})
add("users-anna-active", "users(): status=1 keeps the active ones; display_name falls back to the username", "GET", "/api/users", "anna",
    query={"status": "1"}, resp={"total": 2, "data": [U2, U3]})
add("users-none", "users(): access granted to the person alone; an empty name and no email read as ''", "GET", "/api/users", "none",
    resp={"total": 3, "data": [U3, U4, U5]})
add("users-page", "users(): forPage", "GET", "/api/users", "none", query={"current": "3", "pageSize": "1"}, resp={"total": 3, "data": [U5]})


def dev(i, os_, host, status, user, group, uname="", note=""):
    return {"id": i, "info": {"username": uname, "os": os_, "device_name": host}, "status": status, "user": user, "user_name": user,
            "device_group_name": group, "note": note}


D411 = dev("990000411", "windows", "host-5eed0411", 1, "user-5eed0402", "", "user-5eed0411", "text-5eed0911")
D412 = dev("990000412", "macos", "host-5eed0412", 0, "user-5eed0403", "text-5eed04b1")
D413 = dev("990000413", "windows", "host-5eed0413", 0, "", "text-5eed04b2")
D414 = dev("990000414", "linux", "host-5eed0414", 1, "", "text-5eed04b3")
D417 = dev("990000417", "windows", "host-5eed0417", 0, "", "")
add("peers-anna-devices", "peers(): her own approved computers plus those in her folder; pending and deleted ones never", "GET", "/api/peers",
    "anna", resp={"total": 2, "data": [D411, D412]})
add("peers-ben-devices", "scopeOwnershipVisibleTo(): own + every accessible folder", "GET", "/api/peers", "ben",
    resp={"total": 3, "data": [D412, D413, D414]})
add("peers-none-devices", "scopeOwnershipVisibleTo(): only the folder granted to the person", "GET", "/api/peers", "none",
    resp={"total": 1, "data": [D414]})
add("peers-admin-devices", "seesAllDevices(): every approved computer, in rustdesk_id order; status = online within the window", "GET",
    "/api/peers", "adm", resp={"total": 5, "data": [D411, D412, D413, D414, D417]})
add("peers-page-devices", "peers(): forPage(2, 2)", "GET", "/api/peers", "adm", query={"current": "2", "pageSize": "2"},
    resp={"total": 5, "data": [D413, D414]})

# ---------------------------------------------------------------------------------------------------- audit ---
F1, F3, F4, F5 = G("f1"), G("f3"), G("f4"), G("f5")
S1, S2 = "tok-5eed000000007001", "tok-5eed000000007002"
add("audit-note-ok", "note(): her own session (from_peer = her token's device), nobody wrote a note: stored, trimmed (TrimStrings)", "PUT",
    "/api/audit", "anna", raw='{"guid":"%s","note":"  text-5eed0a01  "}' % F1, resp={})
add("audit-note-not-yours", "note(): the row's from_peer is another computer", "PUT", "/api/audit", "ben",
    {"guid": F1, "note": "text-5eed0a02"}, status=403, resp=err("Not your session"))
add("audit-note-no-device", "note(): a token without a device_id has no sessions", "PUT", "/api/audit", "nodev",
    {"guid": F1, "note": "text-5eed0a02"}, status=403, resp=err("Not your session"))
add("audit-note-another-user", "note(): another user already left a note", "PUT", "/api/audit", "anna",
    {"guid": F5, "note": "text-5eed0a02"}, status=409, resp=err("Another user already left a note"))
add("audit-note-own-again", "note(): the same user may rewrite their note", "PUT", "/api/audit", "ben",
    {"guid": F3, "note": "text-5eed0a03"}, resp={})
add("audit-note-unknown", "note(): no such guid", "PUT", "/api/audit", "anna", {"guid": GONE, "note": "text-5eed0a02"}, status=404,
    resp=err("Unknown session"))
add("audit-note-empty", "note(): a blank note is null (TrimStrings, ConvertEmptyStringsToNull), nothing happens: {}", "PUT", "/api/audit", "anna",
    raw='{"guid":"%s","note":"   "}' % F1, resp={})
add("audit-note-number", "cleanNote(): only a string counts", "PUT", "/api/audit", "anna", {"guid": F1, "note": 5}, resp={})
add("audit-note-no-guid", "note(): guid '' gives {}", "PUT", "/api/audit", "anna", {"note": "text-5eed0a02"}, resp={})
add("audit-active-latest", "activeConnection(): the latest row of that session from her device (conn_type free)", "GET",
    "/api/audit/conn/active", "anna", query={"id": "990000451", "session_id": S1}, resp=F4)
add("audit-active-type", "activeConnection(): conn_type=0 narrows it", "GET", "/api/audit/conn/active", "anna",
    query={"id": "990000451", "session_id": S1, "conn_type": "0"}, resp=F1)
add("audit-active-type-text", "activeConnection(): a conn_type that is not numeric is ignored", "GET", "/api/audit/conn/active", "anna",
    query={"id": "990000451", "session_id": S1, "conn_type": "abc"}, resp=F4)
add("audit-active-guid-assigned", "activeConnection(): a row from before guids gets one on first request", "GET", "/api/audit/conn/active",
    "anna", query={"id": "990000451", "session_id": S2}, resp="{{random}}")
add("audit-active-other-device", "activeConnection(): rows of another computer do not match", "GET", "/api/audit/conn/active", "ben",
    query={"id": "990000451", "session_id": S1}, resp="")
add("audit-active-no-session", "activeConnection(): session_id '0' is no session", "GET", "/api/audit/conn/active", "anna",
    query={"id": "990000451", "session_id": "0"}, resp="")
add("audit-active-no-id", "activeConnection(): no id", "GET", "/api/audit/conn/active", "anna", query={"session_id": S1}, resp="")
add("audit-active-no-device", "activeConnection(): a token without a device", "GET", "/api/audit/conn/active", "nodev",
    query={"id": "990000451", "session_id": S1}, resp="")

# ------------------------------------------------------------------------------------------ peer add/update ---
ok("peer-add-personal", "peerAdd(): a personal book keeps the hash, drops the password; tags map by name, unknown names vanish", "POST",
   "/api/ab/peer/add/" + PERSONAL, "anna",
   {"id": "990000423", "username": "user-5eed0423", "hostname": "host-5eed0423", "platform": "Linux", "alias": "text-5eed0423",
    "hash": "tok-5eed000000000423", "password": "tok-5eed000000000433", "tags": ["text-5eed04d2", "text-5eed04d8"]})
add("peer-add-duplicate", "peerAdd(): the book already has that peer", "POST", "/api/ab/peer/add/" + PERSONAL, "anna", {"id": "990000423"},
    resp=err("Peer already exists"))
add("peer-add-no-id", "peerAdd(): id is required", "POST", "/api/ab/peer/add/" + PERSONAL, "anna", {"alias": "text-5eed0423"},
    resp=err("id is required"))
add("peer-add-read-only", "peerAdd(): READ_WRITE needed, a read rule is not enough", "POST", "/api/ab/peer/add/" + C1, "anna",
    {"id": "990000424"}, resp=DENIED)
add("peer-add-not-found", "peerAdd(): no such book", "POST", "/api/ab/peer/add/" + GONE, "anna", {"id": "990000424"}, resp=NOBOOK)
ok("peer-add-alias-from-fleet", "peerAdd(): a blank alias is filled from a computer she may see (Device::visibleTo); the password is encrypted",
   "POST", "/api/ab/peer/add/" + C3, "anna", {"id": "990000411", "password": "tok-5eed000000000451", "tags": ["text-5eed04e2"]})
ok("peer-add-alias-not-visible", "peerAdd(): not from a computer she may not see: the alias stays blank", "POST", "/api/ab/peer/add/" + C2, "ben",
   {"id": "990000411", "hostname": "host-5eed0451"})
add("peers-after-add-c3", "peers(): what the two adds left in the shared book", "POST", "/api/ab/peers", "anna", query={"ab": C3},
    resp={"total": 3, "data": [PEER431, PEER432,
                               peer("990000411", "", "", "text-5eed0411", ["text-5eed04e2"], password="tok-5eed000000000451")]})
ok("peer-update-fields", "peerUpdate(): present fields only; tags replaced by names", "PUT", "/api/ab/peer/update/" + C3, "anna",
   {"id": "990000431", "alias": "text-5eed0461", "tags": ["text-5eed04e2", "text-5eed04e1"]})
ok("peer-update-password", "peerUpdate(): a shared book re-encrypts the password; a hash is ignored", "PUT", "/api/ab/peer/update/" + C3, "anna",
   {"id": "990000432", "password": "tok-5eed000000000452", "hash": "tok-5eed000000000453"})
ok("peer-update-personal", "peerUpdate(): a personal book takes the hash and ignores the password", "PUT", "/api/ab/peer/update/" + PERSONAL,
   "anna", {"id": "990000422", "hash": "tok-5eed000000000462", "password": "tok-5eed000000000463", "platform": "Linux"})
add("peer-update-not-found", "peerUpdate(): no such peer in the book", "PUT", "/api/ab/peer/update/" + C3, "anna", {"id": "990000499"},
    resp=err("Peer not found"))
add("peer-update-denied", "peerUpdate(): a read rule", "PUT", "/api/ab/peer/update/" + C1, "anna", {"id": "990000499"}, resp=DENIED)
ok("peer-update-own-add", "peerUpdate(): READ_WRITE may update the entry he added (alias set)", "PUT", "/api/ab/peer/update/" + C2, "ben",
   {"id": "990000411", "alias": "text-5eed0471"})
add("peers-after-update-c3", "peers(): the updates", "POST", "/api/ab/peers", "anna", query={"ab": C3},
    resp={"total": 3, "data": [
        peer("990000431", "host-5eed0431", "Linux", "text-5eed0461", ["text-5eed04e1", "text-5eed04e2"], "user-5eed0431",
             password="tok-5eed000000000431"),
        peer("990000432", "host-5eed0432", "Windows", "", [], password="tok-5eed000000000452"),
        peer("990000411", "", "", "text-5eed0411", ["text-5eed04e2"], password="tok-5eed000000000451")]})
add("peers-after-update-personal", "peers(): the personal book after add and update", "POST", "/api/ab/peers", "anna", query={"ab": PERSONAL},
    resp={"total": 3, "data": [
        PEER421,
        peer("990000422", "host-5eed0422", "Linux", "", ["text-5eed04d1", "text-5eed04d2"], "", "true", "3389", "user-5eed0422",
             "user-5eed0922", hash="tok-5eed000000000462"),
        peer("990000423", "host-5eed0423", "Linux", "text-5eed0423", ["text-5eed04d2"], "user-5eed0423",
             hash="tok-5eed000000000423")]})
ok("peer-delete", "peerDelete(): the ids in the body, blanks dropped by array_filter", "DELETE", "/api/ab/peer/" + PERSONAL, "anna",
   ["990000423", "", "990000499"])
ok("peer-delete-nothing", "peerDelete(): an empty list deletes nothing", "DELETE", "/api/ab/peer/" + C2, "ben", [])
ok("peer-delete-shared", "peerDelete(): READ_WRITE is enough on a shared book", "DELETE", "/api/ab/peer/" + C2, "ben", ["990000411"])
add("peer-delete-denied", "peerDelete(): read only", "DELETE", "/api/ab/peer/" + C1, "ben", ["990000411"], resp=DENIED)
add("peer-delete-not-found", "peerDelete(): no such book", "DELETE", "/api/ab/peer/" + GONE, "ben", ["990000411"], resp=NOBOOK)
add("peers-after-delete", "peers(): the personal book without the deleted peer", "POST", "/api/ab/peers", "anna", query={"ab": PERSONAL},
    resp={"total": 2, "data": [
        PEER421,
        peer("990000422", "host-5eed0422", "Linux", "", ["text-5eed04d1", "text-5eed04d2"], "", "true", "3389", "user-5eed0422",
             "user-5eed0922", hash="tok-5eed000000000462")]})

# --------------------------------------------------------------------------------------------------- tags ---
add("tag-add-needs-full", "tagAdd(): FULL needed; READ_WRITE (Ben on book 2) is not enough", "POST", "/api/ab/tag/add/" + C2, "ben",
    {"name": "text-5eed04e9"}, resp=DENIED)
ok("tag-add", "tagAdd(): firstOrCreate with the color", "POST", "/api/ab/tag/add/" + C3, "anna", {"name": "text-5eed04e3", "color": 42})
ok("tag-add-again", "tagAdd(): the name exists: firstOrCreate changes nothing", "POST", "/api/ab/tag/add/" + C3, "anna",
   {"name": "text-5eed04e3", "color": 43})
ok("tag-add-default-color", "tagAdd(): no color is 0", "POST", "/api/ab/tag/add/" + C3, "anna", {"name": "text-5eed04e4"})
ok("tag-add-string-color", "tagAdd(): (int) '7'", "POST", "/api/ab/tag/add/" + PERSONAL, "anna", {"name": "text-5eed04d9", "color": "7"})
add("tag-add-no-name", "tagAdd(): name is required", "POST", "/api/ab/tag/add/" + C3, "anna", {"color": 1}, resp=err("name is required"))
add("tags-after-add", "tags(): sorted by name", "POST", "/api/ab/tags/" + C3, "anna",
    resp=[{"name": "text-5eed04e1", "color": 1}, {"name": "text-5eed04e2", "color": 0}, {"name": "text-5eed04e3", "color": 42},
          {"name": "text-5eed04e4", "color": 0}])
ok("tag-rename", "tagRename(): {old, new}", "PUT", "/api/ab/tag/rename/" + C3, "anna", {"old": "text-5eed04e3", "new": "text-5eed04e5"})
add("tag-rename-not-found", "tagRename(): no such tag", "PUT", "/api/ab/tag/rename/" + C3, "anna", {"old": "text-5eed04e3", "new": "text-5eed04e6"},
    resp=err("Tag not found"))
add("tag-rename-taken", "tagRename(): the unique index (address_book_id, name) throws: 500", "PUT", "/api/ab/tag/rename/" + C3, "anna",
    {"old": "text-5eed04e5", "new": "text-5eed04e1"}, status=500, resp={"message": "Server Error"})
ok("tag-update", "tagUpdate(): the color of the named tag", "PUT", "/api/ab/tag/update/" + C3, "anna", {"name": "text-5eed04e5", "color": 9})
ok("tag-update-missing", "tagUpdate(): no such name updates nothing", "PUT", "/api/ab/tag/update/" + C3, "anna", {"name": "text-5eed04ee", "color": 9})
add("tag-update-denied", "tagUpdate(): FULL needed", "PUT", "/api/ab/tag/update/" + C2, "ben", {"name": "text-5eed04ef", "color": 1}, resp=DENIED)
add("tag-rename-denied", "tagRename(): FULL needed", "PUT", "/api/ab/tag/rename/" + C1, "anna", {"old": "text-5eed04ef", "new": "text-5eed04f0"}, resp=DENIED)
ok("tag-delete", "tagDelete(): the tags go, and leave the entries' tag_ids", "DELETE", "/api/ab/tag/" + C3, "anna", ["text-5eed04e5", "text-5eed04e1", ""])
add("tag-delete-denied", "tagDelete(): FULL needed", "DELETE", "/api/ab/tag/" + C2, "ben", ["text-5eed04ef"], resp=DENIED)
add("tags-after-delete", "tags(): what is left", "POST", "/api/ab/tags/" + C3, "anna",
    resp=[{"name": "text-5eed04e2", "color": 0}, {"name": "text-5eed04e4", "color": 0}])
add("peers-after-tag-delete", "peers(): the deleted tag is gone from the peers that carried it", "POST", "/api/ab/peers", "anna", query={"ab": C3},
    resp={"total": 3, "data": [
        peer("990000431", "host-5eed0431", "Linux", "text-5eed0461", ["text-5eed04e2"], "user-5eed0431", password="tok-5eed000000000431"),
        peer("990000432", "host-5eed0432", "Windows", "", [], password="tok-5eed000000000452"),
        peer("990000411", "", "", "text-5eed0411", ["text-5eed04e2"], password="tok-5eed000000000451")]})

# ------------------------------------------------------------------------------------------- legacy push ---
PUSH = {"tags": ["text-5eed04d3", "text-5eed04d4"],
        "peers": [{"id": "990000425", "username": "user-5eed0425", "hostname": "host-5eed0425", "platform": "Windows", "alias": "text-5eed0425",
                   "hash": "tok-5eed000000000425", "tags": ["text-5eed04d3"]},
                  {"id": "", "username": "text-5eed0426"},
                  "not-a-peer",
                  {"id": "990000427", "tags": ["text-5eed04d3", "text-5eed04d4", "text-5eed04d7"]}],
        "tag_colors": json.dumps({"text-5eed04d3": 7}, separators=(",", ":"))}
add("legacy-push-malformed", "legacyPush(): data that is not JSON: an error, nothing changes", "POST", "/api/ab", "anna",
    {"data": "{not json"}, resp=err("Malformed address book payload"))
add("legacy-push-scalar", "legacyPush(): JSON that is not an array: the same error", "POST", "/api/ab", "anna", {"data": "42"},
    resp=err("Malformed address book payload"))
add("legacy-push-array-data", "(string) $request->input('data'): Array to string conversion -> 500", "POST", "/api/ab", "anna",
    {"data": ["x"]}, status=500, resp={"message": "Server Error"})
add("legacy-push", "legacyPush(): tags and entries rebuilt; blank ids and non-peers skipped; unknown tag names dropped", "POST", "/api/ab",
    "anna", {"data": packed(PUSH)}, resp={})
add("legacy-get-after-push", "legacyGet(): the pushed book, tag colors by name (a missing one is 0)", "GET", "/api/ab", "anna",
    resp={"data": packed({"tags": ["text-5eed04d3", "text-5eed04d4"], "peers": [
        {"id": "990000425", "username": "user-5eed0425", "hostname": "host-5eed0425", "platform": "Windows", "alias": "text-5eed0425",
         "tags": ["text-5eed04d3"], "hash": "tok-5eed000000000425"},
        {"id": "990000427", "username": "", "hostname": "", "platform": "", "alias": "", "tags": ["text-5eed04d3", "text-5eed04d4"], "hash": ""}],
        "tag_colors": json.dumps({"text-5eed04d3": 7, "text-5eed04d4": 0}, separators=(",", ":"))}), "licensed_devices": 0})
add("legacy-push-empty", "legacyPush(): an empty book empties it (tag_colors '' decodes to nothing)", "POST", "/api/ab", "ben",
    {"data": packed({"tags": [], "peers": [], "tag_colors": ""})}, resp={})

# ---------------------------------------------------------------------------------------------------- write ---
os.makedirs(OUT, exist_ok=True)
for f in os.listdir(OUT):
    if f.endswith(".json"):
        os.remove(os.path.join(OUT, f))
for i, (slug, fx) in enumerate(fixtures, 1):
    fx["seq"] = i
    path_slug = "".join(ch if ch.isalnum() else "_" for ch in fx["path"]).strip("_")
    path_slug = path_slug.replace("_", "-") if False else path_slug
    name = "0000000000004-%06d-%s-%s-%s.json" % (i, fx["method"].lower(), path_slug, slug)
    with open(os.path.join(OUT, name), "w") as f:
        json.dump(fx, f, indent=2)
        f.write("\n")
print("%d fixtures written to %s" % (len(fixtures), os.path.normpath(OUT)))
