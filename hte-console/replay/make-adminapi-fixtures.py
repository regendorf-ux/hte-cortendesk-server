#!/usr/bin/env python3
"""Write phase 5's synthetic admin-API fixtures (hte-console/fixtures/adminapi/*.json and the seed) from the
expectations below.

Every expected answer is read from the PHP console's source at v1.15.0-hte.1 (routes/api.php, routes/client-cli.php,
AdminApi/*Controller, Api/DeviceCliController, ApiTokenCan, the api-token guard in AppServiceProvider, ApiToken, User,
Device, AddressBook*, DuplicateDevices, DeviceAddressBooks, Laravel 13.35's router, validator and exception handler);
`source` in each fixture says which statement. Nothing here was captured: the people, computers, books, logs and API
tokens are placeholders seeded by 0000000000005-adminapi-seed.sql (the tokens' sha256 is computed here). The fixtures
run in file order against one database, so reads come first, then the mutating ones family by family, then the reads
that show their effect (the console audit trail lists every API change).
Run: python3 replay/make-adminapi-fixtures.py (from hte-console/).
"""
import hashlib
import json
import os
import re

OUT = os.path.join(os.path.dirname(__file__), "..", "fixtures", "adminapi")
TS = "2026-01-01T00:00:00+00:00"   # any ISO time: the comparison masks every *_at

TOK = {
    "full": "tok-5eed000000005a01", "ro": "tok-5eed000000005a02", "none": "tok-5eed000000005a03",
    "expired": "tok-5eed000000005a04", "off": "tok-5eed000000005a05", "disabled-owner": "tok-5eed000000005a06",
    "no-perm-owner": "tok-5eed000000005a07", "ben": "tok-5eed000000005a08", "orphan": "tok-5eed000000005a09",
    "odd": "tok-5eed000000005a0a", "short": "tok-5eed000000005a0b", "ab": "tok-5eed000000005a0c",
    "strat": "tok-5eed000000005a0d",
}
# who owns which token (the audit trail names the operator)
OWNER = {"full": "user-5eed0501", "ben": "user-5eed0503", "ab": "user-5eed0501", "strat": "user-5eed0501",
         "short": "user-5eed0501"}
fixtures = []
AUDITS = []   # (operator, action, target_type, target_id, summary), in the order written
GUID_A1, GUID_A2, GUID_A3 = ("00000000-0000-4000-8000-00000000050%d" % n for n in (1, 2, 3))


def add(slug, source, method, path, who=None, body=None, *, query=None, raw=None, status=200, ct="application/json",
        resp=None, text=False, auth=None, xff="198.18.5.1", audit=None, ignore=()):
    headers = {"accept": "application/json", "x-forwarded-for": xff}
    if auth is not None:
        headers["authorization"] = auth
    elif who:
        headers["authorization"] = "Bearer " + TOK.get(who, who)
    if raw is not None:
        req_body = {"kind": "raw", "content_type": "application/json", "text": raw}
    elif body is not None:
        req_body = {"kind": "json", "value": body}
    else:
        req_body = {"kind": "empty"}
    if text:
        resp_body = {"kind": "omitted"}          # plain text the client prints: status and type are compared
    elif resp is None:
        resp_body = {"kind": "empty"}
    else:
        resp_body = {"kind": "json", "value": resp}
    skip = list(ignore)
    if isinstance(resp, dict) and "errors" in resp:
        skip.append("/response/errors")        # Laravel's validation messages are vocabulary, not captured text
    if isinstance(resp, dict) and isinstance(resp.get("data"), list) and any(isinstance(x, dict) and "action" in x for x in resp["data"]):
        skip.append("/response/data/action")   # `user.delete`, `address-book.peer-add`: names of actions
    if auth is not None:
        skip.append("/request/headers/authorization")
    fixtures.append((slug, {
        "format": 1, "seq": 0, "synthetic": True, "sanitise_expected": True, "scan_ignore": skip, "source": source.replace("::", "->"),
        "method": method, "path": path, "query": query or {},
        "request": {"headers": headers, "cookies": {}, "body": req_body},
        "response": {"status": status, "headers": {"content-type": ct} if ct else {}, "cookies": {}, "body": resp_body},
    }))
    if audit:
        actor = OWNER.get(who, "?")
        for a in (audit if isinstance(audit, list) else [audit]):
            AUDITS.append((actor,) + a)


def env(data=None, message="", code=0):
    return {"code": code, "data": data, "message": message}


def page(items, total, current=1, pages=1):
    return {"code": 0, "data": items, "total": total, "current": current, "total_pages": pages, "message": ""}


def bad(message, status=422, code=1):
    return {"code": code, "data": None, "message": message}


UNAUTH = {"message": "Unauthenticated."}
ENV401 = {"code": 401, "data": None, "message": "Unauthenticated."}
SERVER_ERROR = {"message": "Server Error"}


def lacks(level, resource):
    return {"code": 403, "data": None, "message": "Token lacks '%s' permission on '%s'." % (level, resource)}


def invalid(first, errors):
    n = sum(len(v) for v in errors.values())
    more = "" if n == 1 else " (and %d more error%s)" % (n - 1, "" if n == 2 else "s")
    return {"message": first + more, "errors": errors}


def not_found(model, ident):
    return {"message": "No query results for model [App\\Models\\%s] %s" % (model, ident)}


# ----------------------------------------------------------------------------------------- the world (seed) ---
def user(i, uname, name, email, note, admin, active, groups=()):
    return {"id": 950000 + i, "username": uname, "name": name, "email": email, "note": note, "is_admin": admin,
            "is_active": active, "groups": [{"id": g, "name": n} for g, n in groups], "created_at": TS}


UG1, UG2, UG3 = (950401, "text-5eed0801"), (950402, "text-5eed0802"), (950403, "text-5eed0803")
U = {
    1: user(1, "user-5eed0501", "text-5eed0501", "user-5eed050001@example.invalid", None, True, True),
    2: user(2, "user-5eed0502", None, None, None, False, True),
    3: user(3, "user-5eed0503", "text-5eed0503", "user-5eed050003@example.invalid", None, False, True),
    4: user(4, "user-5eed0504", "text-5eed0504", None, None, False, False),
    5: user(5, "user-5eed0505", "text-5eed0505", "user-5eed050005@example.invalid", "text-5eed0605", False, True, [UG1]),
    6: user(6, "user-5eed0506", "text-5eed0506", "user-5eed050006@example.invalid", None, False, True, [UG1]),
    7: user(7, "user-5eed0507", "text-5eed0507", None, None, False, True, [UG3]),
    8: user(8, "user-5eed0508", None, None, None, False, True),
    9: user(9, "user-5eed0509", "text-5eed0509", None, None, False, False),
}
SEEDUSER = {"id": 900001, "username": "user-5eed0599", "name": "text-5eed0599", "email": "user-5eed059999@example.invalid",
            "note": None, "is_admin": True, "is_active": True, "groups": [], "created_at": TS}
ALL_USERS = [U[i] for i in range(1, 10)] + [SEEDUSER]


def nogroups(u, **kw):
    return {**u, "groups": [], **kw}


def dev(n, rid, uuid, alias, host, os_, platform, user_, group, online, status="active", disabled=False, dups=(),
        cpu=None, memory=None, version=None, username=None, lip=None, rip=None, note=None):
    return {"id": 950700 + n, "rustdesk_id": rid, "uuid": uuid, "alias": alias, "hostname": host, "os": os_,
            "platform": platform, "cpu": cpu, "memory": memory, "version": version, "username": username,
            "note": note, "status": status, "online": bool(online), "last_online_at": TS if online is not None else None,
            "last_online_ip": lip, "registered_ip": rip, "created_at": TS, "updated_at": TS,
            "user": ({"id": 950000 + user_, "username": U[user_]["username"]} if user_ else None),
            "device_group": ({"id": group[0], "name": group[1]} if group else None), "disabled": disabled,
            "possible_duplicates": list(dups)}


DG1, DG2, DG3 = (950501, "text-5eed0a01"), (950502, "text-5eed0a02"), (950503, "text-5eed0a03")
D = {
    11: dev(11, "990000511", "00000000-0000-4000-8000-000000000511", "text-5eed0b11", "host-5eed0511", "Linux / Ubuntu 22.04", "linux", 5, DG1, True,
            dups=["990000513"], cpu="cpu-5eed", memory="8", version="1.4.0", username="user-5eed0e11", lip="198.18.5.11", rip="198.18.5.11"),
    12: dev(12, "990000512", "00000000-0000-4000-8000-000000000512", None, "host-5eed0512", "Windows / Windows 11", "windows", 6, None, False),
    13: dev(13, "990000513", "00000000-0000-4000-8000-000000000511", None, "host-5eed0513", "Mac OS / macOS 14", "macos", None, DG1, None, dups=["990000511"]),
    14: dev(14, "990000514", "00000000-0000-4000-8000-000000000514", None, None, None, "unknown", 5, None, None, status="pending"),
    16: dev(16, "990000516", "00000000-0000-4000-8000-000000000516", None, "host-5eed0516", "Android / Android 13", "android", None, None, True),
    17: dev(17, "990000517", "00000000-0000-4000-8000-000000000517", None, None, "Windows 10", "windows", 6, DG2, False),
    18: dev(18, "990000518", "00000000-0000-4000-8000-000000000518", None, "host-5eed0518", "Linux / Debian 12", "linux", 8, None, False),
}


def devp(n, **kw):
    d = dict(D[n])
    d.update(kw)
    return d


def ug(i, name, note, n, members=None):
    d = {"id": 950400 + i, "name": name, "note": note, "users_count": n}
    if members is not None:
        d["members"] = [{"id": 950000 + m, "username": U[m]["username"]} for m in members]
    return d


def dgrp(i, name, note, n, devices=None):
    d = {"id": 950500 + i, "name": name, "note": note, "devices_count": n}
    if devices is not None:
        d["devices"] = [{"id": 950700 + k, "rustdesk_id": "9900005%02d" % k, "alias": a, "hostname": h} for k, a, h in devices]
    return d


def book(i, guid, name, personal, owner, note, peers, tags, rules):
    return {"id": 950200 + i, "guid": guid, "name": name, "is_personal": personal,
            "owner": ({"id": 950000 + owner, "username": U[owner]["username"]} if owner else None), "note": note,
            "peers_count": peers, "tags_count": tags, "rules_count": rules}


def peer(i, rid, alias=None, host=None, plat=None, uname=None, login=None, relay=False, port=None, rdpu=None, tags=()):
    return {"id": 950200 + i, "rustdesk_id": rid, "alias": alias, "hostname": host, "platform": plat, "username": uname,
            "login_name": login, "force_always_relay": relay, "rdp_port": port, "rdp_username": rdpu, "tags": list(tags)}


# =========================================================================== A. the guard, routing, reads ===
U_PATH = "/api/v1/users"
add("no-token", "auth:api-token: no bearer, 401 Unauthenticated.", "GET", U_PATH, status=401, resp=UNAUTH)
add("empty-bearer", "AppServiceProvider guard: `if (! $bearer)` an empty token is no token", "GET", U_PATH, auth="Bearer ", status=401, resp=UNAUTH)
add("zero-bearer", "the guard's `! $bearer`: the string \"0\" is falsy too", "GET", U_PATH, auth="Bearer 0", status=401, resp=UNAUTH)
add("basic-scheme", "Request::bearerToken reads only `Bearer `: a Basic header is no token", "GET", U_PATH, auth="Basic " + TOK["full"], status=401, resp=UNAUTH)
add("unknown-token", "ApiToken::findValid: no row for the hash", "GET", U_PATH, "{{nobody}}", status=401, resp=UNAUTH)
add("expired-token", "ApiToken::isValid: expires_at in the past", "GET", U_PATH, "expired", status=401, resp=UNAUTH)
add("inactive-token", "ApiToken::isValid: is_active false", "GET", U_PATH, "off", status=401, resp=UNAUTH)
add("owner-disabled", "the guard: the owner must be active", "GET", U_PATH, "disabled-owner", status=401, resp=UNAUTH)
add("owner-without-token-right", "the guard: the owner must still hold 'manage API tokens' (consoleAllows token rw)", "GET", U_PATH, "no-perm-owner", status=401, resp=UNAUTH)
add("owner-deleted", "the guard: ApiToken->user is null once the owner is deleted (nullOnDelete)", "GET", U_PATH, "orphan", status=401, resp=UNAUTH)
add("none-matrix-read", "ApiTokenCan: level none on user cannot read", "GET", U_PATH, "none", status=403, resp=lacks("r", "user"))
add("readonly-cannot-write", "ApiTokenCan: user r cannot rw", "POST", U_PATH, "ro", {"username": "user-5eed0599", "password": "tok-5eed00000000c001"}, status=403, resp=lacks("rw", "user"))
add("odd-level-reads-as-none", "Permissions::rank((string) 5) is 0: the level 5 grants nothing", "GET", U_PATH, "odd", status=403, resp=lacks("r", "user"))
add("odd-level-array-is-a-type-error", "Permissions::rank(array): TypeError, rendered as a 500", "GET", "/api/v1/audits/conn", "odd", status=500, resp=SERVER_ERROR)
add("role-holder-token", "an owner with a role holding token rw: the token works on what its matrix grants", "GET", "/api/v1/user-groups", "ben",
    resp=page([ug(1, UG1[1], "text-5eed0901", 2), ug(2, UG2[1], None, 0), ug(3, UG3[1], None, 1)], 3))
add("role-holder-without-ab", "ApiTokenCan: address_book none on Ben's token", "GET", "/api/v1/address-books", "ben", status=403, resp=lacks("r", "address_book"))
add("no-route", "Router: no route matches, NotFoundHttpException (before any middleware)", "GET", "/api/v1/nope", status=404,
    resp={"message": "The route api/v1/nope could not be found."})
add("no-route-with-token", "the same, even with a token", "GET", "/api/v1/users/5/nope", "full", status=404,
    resp={"message": "The route api/v1/users/5/nope could not be found."})
add("not-allowed", "Router: the URI exists, the verb does not; the verbs of the other routes, in Router verb order", "PUT", U_PATH, "full",
    status=405, resp={"message": "The PUT method is not supported for route api/v1/users. Supported methods: GET, HEAD, POST."})
add("not-allowed-nested", "same, a route with a parameter", "PATCH", "/api/v1/devices/950711", "full", status=405,
    resp={"message": "The PATCH method is not supported for route api/v1/devices/950711. Supported methods: GET, HEAD, DELETE."})
add("binding-needs-auth", "auth:api-token runs before the model binding: no token, 401, not 404", "GET", "/api/v1/users/999999", status=401, resp=UNAUTH)
add("binding-not-found", "SubstituteBindings: ModelNotFoundException names the model and the value", "GET", "/api/v1/users/999999", "full",
    status=404, resp=not_found("User", "999999"))
add("binding-text-id", "an id that is no number is a value like any other", "GET", "/api/v1/users/abc", "full", status=404, resp=not_found("User", "abc"))
add("binding-before-ability", "the binding runs before api-token-can: a token without the right gets the 404 for a missing row", "GET",
    "/api/v1/users/999999", "none", status=404, resp=not_found("User", "999999"))
add("ability-after-binding", "...and the 403 for a row that exists", "GET", "/api/v1/users/950005", "none", status=403, resp=lacks("r", "user"))

# ---------------------------------------------------------------------------------------------------- users ---
add("users-list", "UsersController::index: every user by username, with groups; 10 incl. the seed administrator", "GET", U_PATH, "full",
    resp=page(ALL_USERS, 10))
add("users-page", "paginate(page_size=3): page 2", "GET", U_PATH, "full", query={"page_size": "3", "page": "2"},
    resp=page([U[4], U[5], U[6]], 10, 2, 4))
add("users-per-page-alias", "perPage(): per_page when page_size is absent; the last page", "GET", U_PATH, "full",
    query={"per_page": "2", "page": "5"}, resp=page([U[9], SEEDUSER], 10, 5, 5))
add("users-page-size-zero", "perPage(): max(1, min(n, 200)): 0 becomes 1", "GET", U_PATH, "full", query={"page_size": "0"},
    resp=page([U[1]], 10, 1, 10))
add("users-bad-page", "the paginator's page resolver: a page that is no integer >= 1 is page 1", "GET", U_PATH, "full",
    query={"page_size": "1", "page": "abc"}, resp=page([U[1]], 10, 1, 10))
add("users-negative-page", "page -3 is page 1", "GET", U_PATH, "full", query={"page_size": "1", "page": "-3"}, resp=page([U[1]], 10, 1, 10))
add("users-page-past-end", "a page past the end: no items, the page asked for", "GET", U_PATH, "full", query={"page_size": "5", "page": "9"},
    resp=page([], 10, 9, 2))
add("users-name", "when(filled(name)): username, name or email LIKE", "GET", U_PATH, "full", query={"name": "user-5eed0505"}, resp=page([U[5]], 1))
add("users-name-email", "...case-insensitive, on the email too", "GET", U_PATH, "full", query={"name": "user-5eed059999@example.invalid"}, resp=page([SEEDUSER], 1))
add("users-group-id", "whereHas(groups): a numeric group is an id", "GET", U_PATH, "full", query={"group": "950401"}, resp=page([U[5], U[6]], 2), ignore=("/query/group",))
add("users-group-name", "...a non-numeric one a name", "GET", U_PATH, "full", query={"group": UG3[1]}, resp=page([U[7]], 1))
add("users-group-none", "...an unknown one nothing", "GET", U_PATH, "full", query={"group": "text-5eed0899"}, resp=page([], 0))
add("users-status-inactive", "status: is_active = (status === 'active')", "GET", U_PATH, "full", query={"status": "inactive"}, resp=page([U[4], U[9]], 2))
add("users-status-active", "...active", "GET", U_PATH, "full", query={"status": "active"},
    resp=page([U[i] for i in (1, 2, 3, 5, 6, 7, 8)] + [SEEDUSER], 8))
add("users-status-case", "...strict: ACTIVE is not active", "GET", U_PATH, "full", query={"status": "ACTIVE"}, resp=page([U[4], U[9]], 2))
add("users-show", "UsersController::show: one user, groups loaded", "GET", "/api/v1/users/950005", "full", resp=env(U[5]))
add("users-show-no-groups", "...a user with no groups", "GET", "/api/v1/users/950002", "full", resp=env(U[2]))

# --------------------------------------------------------------------------------------------------- devices ---
DEVICES_ALL = [D[11], D[12], D[13], D[14], D[16], D[17], D[18]]
add("devices-list", "DevicesController::index: every non-deleted device by RustDesk id, pending included, twins named", "GET", "/api/v1/devices", "full",
    resp=page(DEVICES_ALL, 7))
add("devices-id", "when(filled(id)): rustdesk_id LIKE", "GET", "/api/v1/devices", "full", query={"id": "0511"}, resp=page([D[11]], 1))
add("devices-name", "alias or hostname LIKE", "GET", "/api/v1/devices", "full", query={"name": "host-5eed0513"}, resp=page([D[13]], 1))
add("devices-alias", "...the alias", "GET", "/api/v1/devices", "full", query={"name": "text-5eed0b11"}, resp=page([D[11]], 1))
add("devices-user", "whereHas(user): username or name LIKE", "GET", "/api/v1/devices", "full", query={"user": "user-5eed0505"}, resp=page([D[11], D[14]], 2))
add("devices-user-group-id", "whereHas(user groups): a numeric group is an id", "GET", "/api/v1/devices", "full", query={"group": "950401"},
    resp=page([D[11], D[12], D[14], D[17]], 4), ignore=("/query/group",))
add("devices-user-group-name", "...a name (Fay owns no device)", "GET", "/api/v1/devices", "full", query={"group": UG3[1]}, resp=page([], 0))
add("devices-device-group-id", "device_group: numeric is device_group_id", "GET", "/api/v1/devices", "full", query={"device_group": "950501"}, resp=page([D[11], D[13]], 2))
add("devices-device-group-name", "...non-numeric is the folder's name", "GET", "/api/v1/devices", "full", query={"device_group": DG2[1]}, resp=page([D[17]], 1))
add("devices-offline-days", "offline_days: never seen or last seen before the cutoff", "GET", "/api/v1/devices", "full", query={"offline_days": "2"},
    resp=page([D[13], D[14], D[17]], 3))
add("devices-show", "DevicesController::show", "GET", "/api/v1/devices/950711", "full", resp=env(D[11]))
add("devices-show-pending", "...a pending one, no twins (twins are looked for among approved devices)", "GET", "/api/v1/devices/950714", "full", resp=env(D[14]))
add("devices-show-deleted", "the binding without withTrashed: a disabled device is not found", "GET", "/api/v1/devices/950715", "full",
    status=404, resp=not_found("Device", "950715"))

# ------------------------------------------------------------------------------------------------ groups ---
add("user-groups-list", "UserGroupsController::index: by name, with member counts", "GET", "/api/v1/user-groups", "full",
    resp=page([ug(1, UG1[1], "text-5eed0901", 2), ug(2, UG2[1], None, 0), ug(3, UG3[1], None, 1)], 3))
add("user-groups-name", "name LIKE", "GET", "/api/v1/user-groups", "full", query={"name": "text-5eed0802"}, resp=page([ug(2, UG2[1], None, 0)], 1))
add("user-groups-show", "show(): members by username", "GET", "/api/v1/user-groups/950401", "full", resp=env(ug(1, UG1[1], "text-5eed0901", 2, [5, 6])))
add("device-groups-list", "DeviceGroupsController::index: counts leave out disabled devices", "GET", "/api/v1/device-groups", "full",
    resp=page([dgrp(1, DG1[1], None, 2), dgrp(2, DG2[1], None, 1), dgrp(3, DG3[1], None, 0)], 3))
add("device-groups-show", "show(): the folder's devices by RustDesk id", "GET", "/api/v1/device-groups/950501", "full",
    resp=env(dgrp(1, DG1[1], None, 2, [(11, "text-5eed0b11", "host-5eed0511"), (13, None, "host-5eed0513")])))
add("device-groups-show-deleted-device", "...a disabled device is not listed or counted", "GET", "/api/v1/device-groups/950503", "full",
    resp=env(dgrp(3, DG3[1], None, 0, [])))

# ---------------------------------------------------------------------------------------------- address books ---
B1 = book(1, GUID_A1, "text-5eed0c01", False, 1, "text-5eed0d01", 3, 2, 2)
B2 = book(2, GUID_A2, "text-5eed0c02", True, 6, None, 1, 1, 1)
B3 = book(3, GUID_A3, "text-5eed0c03", False, 6, None, 1, 0, 0)
add("books-list", "AddressBooksController::index: by name, owner and counts", "GET", "/api/v1/address-books", "full", resp=page([B1, B2, B3], 3))
add("books-name", "name LIKE", "GET", "/api/v1/address-books", "full", query={"name": "text-5eed0c03"}, resp=page([B3], 1))
add("books-show", "show()", "GET", "/api/v1/address-books/950201", "full", resp=env(B1))
P11 = peer(11, "990000511", "text-5eed0e11", "host-5eed0511", "linux", "user-5eed0e11", None, True, "3389", "user-5eed0f11", [950231, 950232])
P12 = peer(12, "990000512")
P15 = peer(15, "990000518")
add("peers-list", "peers(): by RustDesk id; relay is a boolean, the port a string, no tags is []", "GET", "/api/v1/address-books/950201/peers", "full",
    resp=env([P11, P12, P15]))
add("tags-list", "tags(): by name", "GET", "/api/v1/address-books/950201/tags", "full",
    resp=env([{"id": 950231, "name": "text-5eed1001", "color": 0}, {"id": 950232, "name": "text-5eed1002", "color": 5}]))
add("rules-list", "rules(): in id order, permission an int", "GET", "/api/v1/address-books/950201/rules", "full",
    resp=env([{"id": 950241, "subject_type": "everyone", "subject_id": None, "permission": 1},
              {"id": 950242, "subject_type": "user", "subject_id": 950006, "permission": 3}]))

# ----------------------------------------------------------------------------------------------------- audits ---
C1 = {"id": 950601, "action": "new", "rustdesk_id": "990000511", "from_peer": "990000601", "from_name": "text-5eed1201", "conn_type": 0,
      "ip": "198.18.5.60", "session_id": "tok-5eed000000006001", "created_at": TS, "closed_at": TS, "note": "text-5eed1301",
      "note_by": "user-5eed0501", "noted_at": TS}
C2 = {"id": 950602, "action": "close", "rustdesk_id": "990000512", "from_peer": "990000602", "from_name": None, "conn_type": 1,
      "ip": None, "session_id": None, "created_at": TS, "closed_at": None, "note": None, "note_by": None, "noted_at": None}
add("audits-conn", "AuditsController::connection: newest first, the note's author by username", "GET", "/api/v1/audits/conn", "full", resp=page([C2, C1], 2))
add("audits-conn-id", "id LIKE", "GET", "/api/v1/audits/conn", "full", query={"id": "0512"}, resp=page([C2], 1))
add("audits-conn-peer", "from_peer or from_name LIKE", "GET", "/api/v1/audits/conn", "full", query={"peer": "text-5eed1201"}, resp=page([C1], 1))
add("audits-conn-action", "action is an equality", "GET", "/api/v1/audits/conn", "full", query={"action": "close"}, resp=page([C2], 1))
add("audits-conn-from", "whereDate >= date_from", "GET", "/api/v1/audits/conn", "full", query={"date_from": "2026-02-01"}, resp=page([C2], 1))
add("audits-conn-to", "whereDate <= date_to", "GET", "/api/v1/audits/conn", "full", query={"date_to": "2026-01-31"}, resp=page([C1], 1))
add("audits-conn-day", "...both bounds inclusive: one day", "GET", "/api/v1/audits/conn", "full", query={"date_from": "2026-01-10", "date_to": "2026-01-10"}, resp=page([C1], 1))
F1 = {"id": 950611, "rustdesk_id": "990000511", "from_peer": "990000603", "from_name": None, "path": "path-5eed0001", "direction": 0, "is_file": True,
      "file_count": 2, "ip": None, "created_at": TS, "files": [{"name": "text-5eed0f01", "size": 1024}, {"name": "text-5eed0f02", "size": 7}, {"name": "text-5eed0f03", "size": 0}],
      "clipboard": False}
F2 = {"id": 950612, "rustdesk_id": "990000512", "from_peer": None, "from_name": "text-5eed1202", "path": None, "direction": 1, "is_file": False,
      "file_count": 1, "ip": "198.18.5.61", "created_at": TS, "files": [{"name": "text-5eed0f04", "size": 5}], "clipboard": True}
F3 = {"id": 950613, "rustdesk_id": "990000512", "from_peer": None, "from_name": None, "path": None, "direction": 1, "is_file": True,
      "file_count": 0, "ip": None, "created_at": TS, "files": [], "clipboard": False}
add("audits-file", "AuditsController::file: the files named in the JSON info (bad entries skipped), clipboard = no path and some file", "GET",
    "/api/v1/audits/file", "full", resp=page([F3, F2, F1], 3))
add("audits-file-direction", "direction is an equality", "GET", "/api/v1/audits/file", "full", query={"direction": "1"}, resp=page([F3, F2], 2))
A1 = {"id": 950621, "rustdesk_id": "990000511", "typ": 0, "type_label": "IP whitelist block", "info": '{"a":1}', "created_at": TS}
A2 = {"id": 950622, "rustdesk_id": "990000513", "typ": 102, "type_label": "Session refused: outside the person's access", "info": "{}", "created_at": TS}
A3 = {"id": 950623, "rustdesk_id": "990000512", "typ": 55, "type_label": "Type 55", "info": None, "created_at": TS}
add("audits-alarm", "AuditsController::alarm: the type's label, or 'Type n'", "GET", "/api/v1/audits/alarm", "full", resp=page([A3, A2, A1], 3))
add("audits-alarm-typ", "typ = (int) typ", "GET", "/api/v1/audits/alarm", "full", query={"typ": "102"}, resp=page([A2], 1))
K1 = {"id": 950631, "username": "user-5eed0501", "action": "user.create", "target_type": "user", "target_id": "user-5eed0510", "summary": "text-5eed1401",
      "ip": "198.18.5.70", "created_at": TS}
K2 = {"id": 950632, "username": "user-5eed0502", "action": "device.enable", "target_type": "device", "target_id": "990000511", "summary": "text-5eed1402",
      "ip": None, "created_at": TS}
add("audits-console", "AuditsController::console: newest first", "GET", "/api/v1/audits/console", "full", resp=page([K2, K1], 2))
add("audits-console-action", "action LIKE", "GET", "/api/v1/audits/console", "full", query={"action": "device"}, resp=page([K2], 1))
add("audits-console-operator", "operator: username or summary LIKE", "GET", "/api/v1/audits/console", "full", query={"operator": "text-5eed1401"}, resp=page([K1], 1))

# =========================================================================================== B. the writes ===
# ----------------------------------------------------------------------------------------------- user groups ---
add("ug-store", "UserGroupsController::store (Ben's token: the operator is Ben)", "POST", "/api/v1/user-groups", "ben",
    {"name": "text-5eed0804", "note": "text-5eed0904", "id": 5, "users_count": 9}, status=201,
    resp=env(ug(4, "text-5eed0804", "text-5eed0904", 0), "User group created."),
    audit=("group.create", "group", "text-5eed0804", "Created user group text-5eed0804 (API)"))
add("ug-store-empty", "validate(): name required", "POST", "/api/v1/user-groups", "full", {}, status=422,
    resp=invalid("The name field is required.", {"name": ["The name field is required."]}))
add("ug-store-duplicate", "Rule::unique", "POST", "/api/v1/user-groups", "full", {"name": UG1[1]}, status=422,
    resp=invalid("The name has already been taken.", {"name": ["The name has already been taken."]}))
add("ug-store-not-a-string", "the string rule", "POST", "/api/v1/user-groups", "full", {"name": 5}, status=422,
    resp=invalid("The name field must be a string.", {"name": ["The name field must be a string."]}))
add("ug-store-too-long", "max:255", "POST", "/api/v1/user-groups", "full", {"name": ("text " * 52).strip()}, status=422, ignore=("/request/name",),
    resp=invalid("The name field must not be greater than 255 characters.", {"name": ["The name field must not be greater than 255 characters."]}))
add("ug-store-blank-note", "an empty string is null (ConvertEmptyStringsToNull), the note stays null", "POST", "/api/v1/user-groups", "full",
    {"name": "text-5eed0805", "note": ""}, status=201, resp=env(ug(5, "text-5eed0805", None, 0), "User group created."),
    audit=("group.create", "group", "text-5eed0805", "Created user group text-5eed0805 (API)"))
add("ug-update", "UserGroupsController::update: the audit names the new name", "PUT", "/api/v1/user-groups/950402", "full",
    {"name": "text-5eed0806", "note": "text-5eed0906"}, resp=env(ug(2, "text-5eed0806", "text-5eed0906", 0), "User group updated."),
    audit=("group.update", "group", "text-5eed0806", "Updated user group text-5eed0806 (API)"))
add("ug-update-own-name", "unique()->ignore(own id): the same name is fine", "PUT", "/api/v1/user-groups/950402", "full", {"name": "text-5eed0806"},
    resp=env(ug(2, "text-5eed0806", "text-5eed0906", 0), "User group updated."),
    audit=("group.update", "group", "text-5eed0806", "Updated user group text-5eed0806 (API)"))
add("ug-update-taken", "...another group's name is not", "PUT", "/api/v1/user-groups/950402", "full", {"name": UG1[1]}, status=422,
    resp=invalid("The name has already been taken.", {"name": ["The name has already been taken."]}))
add("ug-update-null-name", "sometimes|required: a name that is present but null fails", "PUT", "/api/v1/user-groups/950402", "full", {"name": None}, status=422,
    resp=invalid("The name field is required.", {"name": ["The name field is required."]}))
add("ug-update-note-null", "nullable note: set to null", "PUT", "/api/v1/user-groups/950402", "full", {"note": None},
    resp=env(ug(2, "text-5eed0806", None, 0), "User group updated."),
    audit=("group.update", "group", "text-5eed0806", "Updated user group text-5eed0806 (API)"))
add("ug-update-nothing", "no field, no change, the same audit line", "PUT", "/api/v1/user-groups/950402", "full", {},
    resp=env(ug(2, "text-5eed0806", None, 0), "User group updated."),
    audit=("group.update", "group", "text-5eed0806", "Updated user group text-5eed0806 (API)"))
add("ug-add-member-name", "addMember(): by user_name; syncWithoutDetaching", "POST", "/api/v1/user-groups/950402/members", "full",
    {"user_name": "user-5eed0508"}, resp=env(ug(2, "text-5eed0806", None, 1, [8]), "Member added."),
    audit=("group.update", "group", "text-5eed0806", "Added user-5eed0508 to user group text-5eed0806 (API)"))
add("ug-add-member-again", "...already a member: nothing to attach, the same answer and a new audit line", "POST", "/api/v1/user-groups/950402/members", "full",
    {"user_name": "user-5eed0508"}, resp=env(ug(2, "text-5eed0806", None, 1, [8]), "Member added."),
    audit=("group.update", "group", "text-5eed0806", "Added user-5eed0508 to user group text-5eed0806 (API)"))
add("ug-add-member-id", "...by user_id (user_id wins when both are given)", "POST", "/api/v1/user-groups/950402/members", "full",
    {"user_id": 950005, "user_name": "user-5eed0508"}, resp=env(ug(2, "text-5eed0806", None, 2, [5, 8]), "Member added."),
    audit=("group.update", "group", "text-5eed0806", "Added user-5eed0505 to user group text-5eed0806 (API)"))
add("ug-add-member-none", "resolveUser(): neither field, no user", "POST", "/api/v1/user-groups/950402/members", "full", {}, status=404, resp=bad("User not found."))
add("ug-add-member-unknown", "...an id nobody has", "POST", "/api/v1/user-groups/950402/members", "full", {"user_id": 999999}, status=404, resp=bad("User not found."))
add("ug-add-member-array", "User::find(array) is a collection: ->id on it throws, a 500", "POST", "/api/v1/user-groups/950402/members", "full",
    {"user_id": [950005]}, status=500, resp=SERVER_ERROR)
add("ug-remove-member", "removeMember(): detach", "DELETE", "/api/v1/user-groups/950402/members", "full", {"user_name": "user-5eed0508"},
    resp=env(None, "Member removed."), audit=("group.update", "group", "text-5eed0806", "Removed user-5eed0508 from user group text-5eed0806 (API)"))
add("ug-remove-member-unknown", "...unknown user", "DELETE", "/api/v1/user-groups/950402/members", "full", {"user_name": "user-5eed0598"}, status=404, resp=bad("User not found."))
add("ug-destroy", "destroy(): members detached, group deleted", "DELETE", "/api/v1/user-groups/950403", "full", resp=env(None, "User group deleted."),
    audit=("group.delete", "group", "text-5eed0803", "Deleted user group text-5eed0803 (API)"))

# --------------------------------------------------------------------------------------------- device groups ---
add("dg-store", "DeviceGroupsController::store", "POST", "/api/v1/device-groups", "full", {"name": "text-5eed0a04", "note": "text-5eed0b04"}, status=201,
    resp=env(dgrp(4, "text-5eed0a04", "text-5eed0b04", 0), "Device group created."),
    audit=("group.create", "group", "text-5eed0a04", "Created device group text-5eed0a04 (API)"))
add("dg-store-duplicate", "Rule::unique", "POST", "/api/v1/device-groups", "full", {"name": DG1[1]}, status=422,
    resp=invalid("The name has already been taken.", {"name": ["The name has already been taken."]}))
add("dg-update", "update()", "PUT", "/api/v1/device-groups/950504", "full", {"name": "text-5eed0a05"},
    resp=env(dgrp(4, "text-5eed0a05", "text-5eed0b04", 0), "Device group updated."),
    audit=("group.update", "group", "text-5eed0a05", "Updated device group text-5eed0a05 (API)"))
add("dg-add-member-rid", "addMember(): by rustdesk_id; the device's folder is set and its policy re-resolved", "POST", "/api/v1/device-groups/950502/members", "full",
    {"rustdesk_id": "990000516"}, resp=env(dgrp(2, DG2[1], None, 2, [(16, None, "host-5eed0516"), (17, None, None)]), "Device added."),
    audit=("group.update", "group", DG2[1], "Added device 990000516 to text-5eed0a02 (API)"))
add("dg-add-member-id", "...by device_id", "POST", "/api/v1/device-groups/950504/members", "full", {"device_id": 950712},
    resp=env(dgrp(4, "text-5eed0a05", "text-5eed0b04", 1, [(12, None, "host-5eed0512")]), "Device added."),
    audit=("group.update", "group", "text-5eed0a05", "Added device 990000512 to text-5eed0a05 (API)"))
add("dg-add-member-deleted", "Device::find leaves out disabled devices", "POST", "/api/v1/device-groups/950504/members", "full", {"device_id": 950715}, status=404,
    resp=bad("Device not found."))
add("dg-add-member-none", "resolveDevice(): neither field", "POST", "/api/v1/device-groups/950504/members", "full", {}, status=404, resp=bad("Device not found."))
add("dg-remove-member", "removeMember(): only a device that is in this folder is moved out", "DELETE", "/api/v1/device-groups/950502/members", "full",
    {"rustdesk_id": "990000516"}, resp=env(None, "Device removed."),
    audit=("group.update", "group", DG2[1], "Removed device 990000516 from text-5eed0a02 (API)"))
add("dg-remove-member-elsewhere", "...a device in another folder stays where it is, the audit line is still written", "DELETE", "/api/v1/device-groups/950502/members", "full",
    {"device_id": 950711}, resp=env(None, "Device removed."),
    audit=("group.update", "group", DG2[1], "Removed device 990000511 from text-5eed0a02 (API)"))
add("dg-destroy", "destroy(): the folder's active devices keep no folder (a disabled device keeps its dangling id), every device's policy is re-resolved",
    "DELETE", "/api/v1/device-groups/950503", "full", resp=env(None, "Device group deleted."),
    audit=("group.delete", "group", DG3[1], "Deleted device group text-5eed0a03 (API)"))

# ----------------------------------------------------------------------------------------- address books ---
NEWB = book(4, "{{random}}", "text-5eed0c04", False, 1, None, 0, 0, 0)
add("book-store", "AddressBooksController::store: the owner defaults to the token's owner, the guid is made", "POST", "/api/v1/address-books", "full",
    {"name": "text-5eed0c04"}, status=201, resp=env(NEWB, "Address book created."),
    audit=("address-book.create", "address_book", "{{random}}", "Created address book text-5eed0c04 (API)"))
add("book-store-owner", "...a named owner, personal flag and note", "POST", "/api/v1/address-books", "full",
    {"name": "text-5eed0c05", "owner_user_id": 950005, "is_personal": True, "note": "text-5eed0d05"}, status=201,
    resp=env(book(5, "{{random}}", "text-5eed0c05", True, 5, "text-5eed0d05", 0, 0, 0), "Address book created."),
    audit=("address-book.create", "address_book", "{{random}}", "Created address book text-5eed0c05 (API)"))
add("book-store-invalid", "validate(): a missing name, an owner that is no user, is_personal that is no boolean", "POST", "/api/v1/address-books", "full",
    {"owner_user_id": 999999, "is_personal": "maybe"}, status=422,
    resp=invalid("The name field is required.", {"name": ["The name field is required."], "owner_user_id": ["The selected owner user id is invalid."],
                                                 "is_personal": ["The is personal field must be true or false."]}))
add("book-store-owner-text", "an owner that is no integer fails both the integer and the exists rule", "POST", "/api/v1/address-books", "full",
    {"name": "text-5eed0c06", "owner_user_id": "abc"}, status=422,
    resp=invalid("The owner user id field must be an integer.",
                 {"owner_user_id": ["The owner user id field must be an integer.", "The selected owner user id is invalid."]}))
add("book-update", "update(): the audit names the book's guid", "PUT", "/api/v1/address-books/950203", "full", {"name": "text-5eed0c07", "note": "text-5eed0d07"},
    resp=env(book(3, GUID_A3, "text-5eed0c07", False, 6, "text-5eed0d07", 1, 0, 0), "Address book updated."),
    audit=("address-book.update", "address_book", GUID_A3, "Updated address book text-5eed0c07 (API)"))
add("book-update-owner-null", "a null owner: NOT NULL constraint, a 500, nothing written", "PUT", "/api/v1/address-books/950203", "full", {"owner_user_id": None},
    status=500, resp=SERVER_ERROR)
add("book-update-owner", "a new owner", "PUT", "/api/v1/address-books/950203", "full", {"owner_user_id": 950008},
    resp=env(book(3, GUID_A3, "text-5eed0c07", False, 8, "text-5eed0d07", 1, 0, 0), "Address book updated."),
    audit=("address-book.update", "address_book", GUID_A3, "Updated address book text-5eed0c07 (API)"))

PNEW = peer(0, "990000530", "text-5eed1501", None, None, None, None, True, 3389, None, [950231])
PNEW["id"] = 0
add("peer-store", "storePeer(): the answer is the model as built (relay true, port an int), the row is read back as a string later", "POST",
    "/api/v1/address-books/950201/peers", "full",
    {"rustdesk_id": "990000530", "alias": "text-5eed1501", "force_always_relay": True, "rdp_port": 3389, "tag_ids": [950231]}, status=201,
    resp=env(PNEW, "Peer added."), audit=("address-book.peer-add", "address_book", GUID_A1, "Added peer 990000530 to text-5eed0c01 (API)"))
add("peer-store-invalid", "validatePeer(): required id, tag_ids an array, relay a boolean, port an integer, platform max 64", "POST",
    "/api/v1/address-books/950201/peers", "full",
    {"tag_ids": "x", "force_always_relay": 2, "rdp_port": "abc", "platform": "p" * 65}, status=422,
    resp=invalid("The rustdesk id field is required.",
                 {"rustdesk_id": ["The rustdesk id field is required."], "platform": ["The platform field must not be greater than 64 characters."],
                  "force_always_relay": ["The force always relay field must be true or false."], "rdp_port": ["The rdp port field must be an integer."],
                  "tag_ids": ["The tag ids field must be an array."]}))
add("peer-store-duplicate", "the unique (book, RustDesk id) index: a QueryException, a 500", "POST", "/api/v1/address-books/950201/peers", "full",
    {"rustdesk_id": "990000530"}, status=500, resp=SERVER_ERROR)
add("peer-update", "updatePeer(): partial validation (sometimes), dirty-only update", "PUT", "/api/v1/address-books/950201/peers/950211", "full",
    {"alias": "text-5eed1502", "tag_ids": [950232], "force_always_relay": False},
    resp=env(peer(11, "990000511", "text-5eed1502", "host-5eed0511", "linux", "user-5eed0e11", None, False, "3389", "user-5eed0f11", [950232]), "Peer updated."),
    audit=("address-book.peer-update", "address_book", GUID_A1, "Updated peer 990000511 (API)"))
add("peer-update-null-id", "sometimes|string: a present null fails the string rule", "PUT", "/api/v1/address-books/950201/peers/950211", "full",
    {"rustdesk_id": None}, status=422, resp=invalid("The rustdesk id field must be a string.", {"rustdesk_id": ["The rustdesk id field must be a string."]}))
add("peer-update-other-book", "abort_unless(address_book_id matches, 404): an empty message", "PUT", "/api/v1/address-books/950202/peers/950211", "full",
    {"alias": "text-5eed1503"}, status=404, resp={"message": ""})
add("peer-destroy-other-book", "the same on delete", "DELETE", "/api/v1/address-books/950202/peers/950211", "full", status=404, resp={"message": ""})
add("peer-destroy", "destroyPeer()", "DELETE", "/api/v1/address-books/950201/peers/950212", "full", resp=env(None, "Peer deleted."),
    audit=("address-book.peer-delete", "address_book", GUID_A1, "Deleted peer 990000512 (API)"))
add("tag-store", "storeTag(): a tag with no color answers null (the column default 0 is not read back)", "POST", "/api/v1/address-books/950201/tags", "full",
    {"name": "text-5eed1004"}, status=201, resp=env({"id": 0, "name": "text-5eed1004", "color": None}, "Tag added."),
    audit=("address-book.tag-add", "address_book", GUID_A1, "Added tag text-5eed1004 (API)"))
add("tag-store-color", "...a color is kept as sent (a string), the integer column reads back as 255", "POST", "/api/v1/address-books/950201/tags", "full",
    {"name": "text-5eed1005", "color": "255"}, status=201, resp=env({"id": 0, "name": "text-5eed1005", "color": "255"}, "Tag added."),
    audit=("address-book.tag-add", "address_book", GUID_A1, "Added tag text-5eed1005 (API)"))
add("tag-store-null-color", "an explicit null color: NOT NULL constraint, a 500", "POST", "/api/v1/address-books/950201/tags", "full",
    {"name": "text-5eed1006", "color": None}, status=500, resp=SERVER_ERROR)
add("tag-store-duplicate", "the unique (book, name) index: a 500", "POST", "/api/v1/address-books/950201/tags", "full", {"name": "text-5eed1001"}, status=500, resp=SERVER_ERROR)
add("tag-store-invalid", "validate(): name required, color max 32", "POST", "/api/v1/address-books/950201/tags", "full", {"color": "c" * 33}, status=422,
    resp=invalid("The name field is required.", {"name": ["The name field is required."], "color": ["The color field must not be greater than 32 characters."]}))
add("tag-update", "updateTag()", "PUT", "/api/v1/address-books/950201/tags/950231", "full", {"name": "text-5eed1007", "color": "7"},
    resp=env({"id": 950231, "name": "text-5eed1007", "color": "7"}, "Tag updated."),
    audit=("address-book.tag-update", "address_book", GUID_A1, "Updated tag text-5eed1007 (API)"))
add("tag-update-other-book", "abort_unless: 404", "PUT", "/api/v1/address-books/950202/tags/950231", "full", {"name": "text-5eed1008"}, status=404, resp={"message": ""})
add("tag-destroy-other-book", "...on delete too", "DELETE", "/api/v1/address-books/950202/tags/950231", "full", status=404, resp={"message": ""})
add("tag-destroy", "destroyTag(): the audit names the tag", "DELETE", "/api/v1/address-books/950201/tags/950232", "full", resp=env(None, "Tag deleted."),
    audit=("address-book.tag-delete", "address_book", GUID_A1, "Deleted tag text-5eed1002 (API)"))
add("rule-store", "storeRule(): a group rule", "POST", "/api/v1/address-books/950201/rules", "full",
    {"subject_type": "group", "subject_id": 950401, "permission": 2}, status=201,
    resp=env({"id": 0, "subject_type": "group", "subject_id": 950401, "permission": 2}, "Rule added."),
    audit=("address-book.rule-add", "address_book", GUID_A1, "Added AB rule (API)"))
add("rule-store-everyone", "...everyone forces subject_id to null; permission as a string is cast to int in the answer", "POST", "/api/v1/address-books/950201/rules", "full",
    {"subject_type": "everyone", "subject_id": 5, "permission": "3"}, status=201,
    resp=env({"id": 0, "subject_type": "everyone", "subject_id": None, "permission": 3}, "Rule added."),
    audit=("address-book.rule-add", "address_book", GUID_A1, "Added AB rule (API)"))
add("rule-store-invalid", "Rule::in on the subject and the permission", "POST", "/api/v1/address-books/950201/rules", "full",
    {"subject_type": "nobody", "permission": "x"}, status=422,
    resp=invalid("The selected subject type is invalid.",
                 {"subject_type": ["The selected subject type is invalid."],
                  "permission": ["The permission field must be an integer.", "The selected permission is invalid."]}))
add("rule-store-permission-9", "...a permission that is not 1, 2 or 3", "POST", "/api/v1/address-books/950201/rules", "full",
    {"subject_type": "user", "subject_id": 950006, "permission": 9}, status=422,
    resp=invalid("The selected permission is invalid.", {"permission": ["The selected permission is invalid."]}))
add("rule-update", "updateRule(): sometimes|required", "PUT", "/api/v1/address-books/950201/rules/950242", "full", {"permission": 1},
    resp=env({"id": 950242, "subject_type": "user", "subject_id": 950006, "permission": 1}, "Rule updated."),
    audit=("address-book.rule-update", "address_book", GUID_A1, "Updated AB rule (API)"))
add("rule-update-everyone", "...changing the type to everyone does not clear subject_id on update", "PUT", "/api/v1/address-books/950201/rules/950242", "full",
    {"subject_type": "everyone"}, resp=env({"id": 950242, "subject_type": "everyone", "subject_id": 950006, "permission": 1}, "Rule updated."),
    audit=("address-book.rule-update", "address_book", GUID_A1, "Updated AB rule (API)"))
add("rule-update-other-book", "abort_unless: 404", "PUT", "/api/v1/address-books/950202/rules/950242", "full", {"permission": 1}, status=404, resp={"message": ""})
add("rule-destroy", "destroyRule()", "DELETE", "/api/v1/address-books/950201/rules/950241", "full", resp=env(None, "Rule deleted."),
    audit=("address-book.rule-delete", "address_book", GUID_A1, "Deleted AB rule (API)"))
add("book-destroy", "destroy(): entries, tags and rules go with the book", "DELETE", "/api/v1/address-books/950203", "full", resp=env(None, "Address book deleted."),
    audit=("address-book.delete", "address_book", GUID_A3, "Deleted address book text-5eed0c07 (API)"))

# ------------------------------------------------------------------------------------------ --assign ---
CLI = "/api/devices/cli"
add("cli-no-token", "auth:api-token on the client route", "POST", CLI, body={"id": "990000540", "uuid": "00000000-0000-4000-8000-000000000540", "note": "text-5eed1601"}, status=401, resp=UNAUTH)
add("cli-readonly", "api-token-can:device,rw", "POST", CLI, "ro", {"id": "990000540", "uuid": "00000000-0000-4000-8000-000000000540", "note": "text-5eed1601"}, status=403, resp=lacks("rw", "device"))
add("cli-not-allowed", "the route is POST only", "GET", CLI, "full", status=405,
    resp={"message": "The GET method is not supported for route api/devices/cli. Supported methods: POST."})
add("cli-missing-uuid", "assign(): id and uuid are required (plain text for the client)", "POST", CLI, "full", {"id": "990000540"}, status=400, ct="text/plain", text=True)
add("cli-nothing", "assign(): at least one recognized flag (a tag alone is no assignment)", "POST", CLI, "full", {"id": "990000540", "uuid": "00000000-0000-4000-8000-000000000540", "address_book_tag": "text-5eed1801"},
    status=400, ct="text/plain", text=True)
add("cli-flagless", "...none at all", "POST", CLI, "full", {"id": "990000540", "uuid": "00000000-0000-4000-8000-000000000540"}, status=400, ct="text/plain", text=True)
add("cli-ab-needs-ab-right", "an address_book_* field needs address_book rw on the token itself", "POST", CLI, "strat",
    {"id": "990000540", "uuid": "00000000-0000-4000-8000-000000000540", "address_book_name": "text-5eed0c01"}, status=403, ct="text/plain", text=True)
add("cli-strategy-needs-right", "strategy_name needs strategy rw on the token", "POST", CLI, "ab",
    {"id": "990000540", "uuid": "00000000-0000-4000-8000-000000000540", "strategy_name": "text-5eed1101"}, status=403, ct="text/plain", text=True)
add("cli-unknown-user", "a named user that does not exist fails before anything is written", "POST", CLI, "full",
    {"id": "990000540", "uuid": "00000000-0000-4000-8000-000000000540", "user_name": "user-5eed0598"}, status=404, ct="text/plain", text=True)
add("cli-unknown-group", "...a device group", "POST", CLI, "full", {"id": "990000540", "uuid": "00000000-0000-4000-8000-000000000540", "device_group_name": "text-5eed0899"}, status=404, ct="text/plain", text=True)
add("cli-deleted-strategy", "...a strategy (a deleted one does not count)", "POST", CLI, "full", {"id": "990000540", "uuid": "00000000-0000-4000-8000-000000000540", "strategy_name": "text-5eed1102"},
    status=404, ct="text/plain", text=True)
add("cli-unknown-book", "...an address book", "POST", CLI, "full", {"id": "990000540", "uuid": "00000000-0000-4000-8000-000000000540", "address_book_name": "text-5eed0899"}, status=404, ct="text/plain", text=True)
add("cli-new-device", "a device the table has not seen: registered ACTIVE with the named owner, the default folder, its strategy assigned, the book entry upserted with a tag "
    "and an encrypted password (an empty 200 is 'Done!')", "POST", CLI, "full",
    {"id": "990000540", "uuid": "00000000-0000-4000-8000-000000000540", "user_name": "user-5eed0507", "device_name": "host-5eed0540", "device_username": "user-5eed0e40",
     "note": "text-5eed1601", "strategy_name": "text-5eed1101", "address_book_name": "text-5eed0c01", "address_book_alias": "text-5eed1701",
     "address_book_tag": "text-5eed1801", "address_book_password": "tok-5eed00000000c0ff", "address_book_note": "ignored"}, ct=None,
    audit=("device.assign", "device", "990000540", "Registered and assigned device 990000540 via --assign (API)"))
add("cli-existing-device", "a device that exists: only what is sent changes (uuid refreshed, folder moved, policy re-resolved); the entry is updated, the tag reused", "POST", CLI, "full",
    {"id": "990000511", "uuid": "00000000-0000-4000-8000-000000000511", "device_group_name": "text-5eed0a02", "address_book_name": "text-5eed0c01", "address_book_tag": "text-5eed1801"}, ct=None,
    audit=("device.assign", "device", "990000511", "Assigned device 990000511 via --assign (API)"))
add("cli-pending-device", "a pending device is approved by a deploy/assign carrying a device rw token", "POST", CLI, "full",
    {"id": "990000514", "uuid": "00000000-0000-4000-8000-000000000514", "note": "text-5eed1602"}, ct=None,
    audit=("device.assign", "device", "990000514", "Assigned device 990000514 via --assign (API)"))
add("cli-disabled-twin", "a disabled device with the same RustDesk id: the insert hits the unique index, a 500 (JSON, as every api/* error)", "POST", CLI, "full",
    {"id": "990000519", "uuid": "00000000-0000-4000-8000-000000000519", "note": "text-5eed1603"}, status=500, resp=SERVER_ERROR)

# ---------------------------------------------------------------------------------------------------- devices ---
add("dev-assign-both", "assign(): user_name and device_group_name; the answer is read back (fresh)", "POST", "/api/v1/devices/950711/assign", "full",
    {"user_name": "user-5eed0506", "device_group_name": DG2[1]},
    resp=env({**D[11], "user": {"id": 950006, "username": "user-5eed0506"}, "device_group": {"id": 950502, "name": DG2[1]}, "possible_duplicates": ["990000513"],
              "uuid": "00000000-0000-4000-8000-000000000511"}, "Device assigned."),
    audit=("device.assign", "device", "990000511", "Reassigned device 990000511 (API)"))
add("dev-assign-unassign", "an empty user_id is an explicit unassign", "POST", "/api/v1/devices/950711/assign", "full", {"user_id": ""},
    resp=env({**D[11], "user": None, "device_group": {"id": 950502, "name": DG2[1]}}, "Device assigned."),
    audit=("device.assign", "device", "990000511", "Reassigned device 990000511 (API)"))
add("dev-assign-unknown-user", "a user that is named but not found", "POST", "/api/v1/devices/950711/assign", "full", {"user_id": 999999}, status=404, resp=bad("User not found."))
add("dev-assign-unknown-group", "...a folder", "POST", "/api/v1/devices/950711/assign", "full", {"device_group_id": 999999}, status=404, resp=bad("Device group not found."))
add("dev-assign-nothing", "nothing to assign", "POST", "/api/v1/devices/950711/assign", "full", {}, status=422,
    resp=bad("Nothing to assign; provide user_(id|name) or device_group_(id|name)."))
add("dev-disable", "disable(): a soft delete", "POST", "/api/v1/devices/950716/disable", "full", resp=env(None, "Device disabled."),
    audit=("device.disable", "device", "990000516", "Disabled device 990000516 (API)"))
add("dev-enable", "enable(): withTrashed binding, restore, the serialised device", "POST", "/api/v1/devices/950715/enable", "full",
    resp=env(dev(15, "990000515", "00000000-0000-4000-8000-000000000515", None, None, "Android 13", "android", 5, None, None), "Device enabled."),
    audit=("device.enable", "device", "990000515", "Enabled device 990000515 (API)"))
add("dev-enable-active", "...an active device is only audited", "POST", "/api/v1/devices/950712/enable", "full",
    resp=env({**D[12], "device_group": {"id": 950504, "name": "text-5eed0a05"}}, "Device enabled."),
    audit=("device.enable", "device", "990000512", "Enabled device 990000512 (API)"))
add("dev-destroy-books-forbidden", "destroy(remove_from_address_books) needs address_book rw on the token", "DELETE", "/api/v1/devices/950718", "strat",
    {"remove_from_address_books": True}, status=403, resp=lacks("rw", "address_book") | {"code": 403})
add("dev-destroy-books", "...with it: the device's entries leave every book, one audit line per book", "DELETE", "/api/v1/devices/950718", "full",
    {"remove_from_address_books": "yes"}, resp=env({"address_book_entries_removed": 1}, "Device deleted."),
    audit=[("device.destroy", "device", "990000518", "Destroyed device 990000518 (API)"),
           ("address-book.peer-delete", "address-book", "text-5eed0c01", "Removed 1 entry (990000518) from address book text-5eed0c01 after device delete (API)")])
add("dev-destroy-trashed", "destroy(): a disabled device can be destroyed (withTrashed)", "DELETE", "/api/v1/devices/950719", "full", resp=env(None, "Device deleted."),
    audit=("device.destroy", "device", "990000519", "Destroyed device 990000519 (API)"))

# ----------------------------------------------------------------------------------------------------- users ---
NEWU = {"id": 0, "username": "user-5eed0510", "name": "text-5eed0510", "email": "user-5eed050010@example.invalid", "note": "text-5eed0610",
        "is_admin": False, "is_active": False, "groups": [], "created_at": TS}
add("user-store", "UsersController::store: admin and role are never taken from the request; is_active false kept", "POST", U_PATH, "full",
    {"username": "user-5eed0510", "name": "text-5eed0510", "email": "user-5eed050010@example.invalid", "password": "tok-5eed00000000c002", "is_active": False,
     "note": "text-5eed0610", "is_admin": True, "role_id": 950101}, status=201, resp=env(NEWU, "User created."),
    audit=("user.create", "user", "user-5eed0510", "Created user user-5eed0510 (API)"))
add("user-store-minimal", "...only the required fields: active by the model's default", "POST", U_PATH, "full",
    {"username": "user-5eed0511", "password": "tok-5eed00000000c003"}, status=201,
    resp=env({"id": 0, "username": "user-5eed0511", "name": None, "email": None, "note": None, "is_admin": False, "is_active": True, "groups": [], "created_at": TS}, "User created."),
    audit=("user.create", "user", "user-5eed0511", "Created user user-5eed0511 (API)"))
add("user-store-empty", "validate(): username and password required", "POST", U_PATH, "full", {}, status=422,
    resp=invalid("The username field is required.", {"username": ["The username field is required."], "password": ["The password field is required."]}))
add("user-store-invalid", "validate(): email, min:8, boolean (errors in the rules' order)", "POST", U_PATH, "full",
    {"username": "user-5eed0512", "email": "not-an-email", "password": "short", "is_active": "maybe"}, status=422,
    ignore=("/request/email", "/request/password"),
    resp=invalid("The email field must be a valid email address.",
                 {"email": ["The email field must be a valid email address."], "password": ["The password field must be at least 8 characters."],
                  "is_active": ["The is active field must be true or false."]}))
add("user-store-taken", "Rule::unique on the username and the email", "POST", U_PATH, "full",
    {"username": "user-5eed0501", "email": "user-5eed050005@example.invalid", "password": "tok-5eed00000000c004"}, status=422,
    resp=invalid("The username has already been taken.",
                 {"username": ["The username has already been taken."], "email": ["The email has already been taken."]}))
add("user-enable", "enable(): active already is a no-op; the answer has no groups (the relation is not loaded)", "POST", "/api/v1/users/950005/enable", "full",
    resp=env(nogroups(U[5]), "User enabled."), audit=("user.enable", "user", "user-5eed0505", "Enabled user user-5eed0505 (API)"))
add("user-enable-inactive", "...an inactive one becomes active", "POST", "/api/v1/users/950009/enable", "full",
    resp=env({**U[9], "is_active": True}, "User enabled."), audit=("user.enable", "user", "user-5eed0509", "Enabled user user-5eed0509 (API)"))
add("user-disable-self", "disable(): not the token owner", "POST", "/api/v1/users/950001/disable", "full", status=422, resp=bad("You cannot disable the token owner account."))
add("user-disable", "...another user: inactive, client tokens, sessions and trusted browsers gone, remember token rotated", "POST", "/api/v1/users/950007/disable", "full",
    resp=env({**U[7], "groups": [], "is_active": False}, "User disabled."), audit=("user.disable", "user", "user-5eed0507", "Disabled user user-5eed0507 (API)"))
add("user-force-logout", "forceLogout(): the same revocation, the account stays active", "POST", "/api/v1/users/950008/force-logout", "full",
    resp=env(None, "User logged out everywhere."), audit=("user.force-logout", "user", "user-5eed0508", "Forced logout of user-5eed0508 (API)"))
add("user-destroy-self", "destroy(): not the token owner", "DELETE", "/api/v1/users/950001", "full", status=422, resp=bad("You cannot delete the token owner account."))
add("user-destroy", "...another user: devices released (active ones only), personal books deleted, every device's policy re-resolved", "DELETE",
    "/api/v1/users/950006", "full", resp=env(None, "User deleted."), audit=("user.delete", "user", "user-5eed0506", "Deleted user user-5eed0506 (API)"))
add("user-destroy-token-owner-elsewhere", "a deleted user's token stops working (the owner is gone)", "GET", U_PATH, "orphan", status=401, resp=UNAUTH)

# ==================================================================================== C. the effects ===
add("after-console-audit", "every change above is a console-audit line by the token's owner, from the request's address, newest first", "GET",
    "/api/v1/audits/console", "full", query={"operator": "(API)", "page_size": "200"}, ignore=("/query/operator",),
    resp=page([{"id": 0, "username": a[0], "action": a[1], "target_type": a[2], "target_id": a[3], "summary": a[4], "ip": "198.18.5.1", "created_at": TS}
               for a in reversed(AUDITS)], len(AUDITS), 1, 1))

# ------------------------------------------------------------------------------------------------- write ---
os.makedirs(OUT, exist_ok=True)
for f in os.listdir(OUT):
    if f.endswith(".json"):
        os.remove(os.path.join(OUT, f))
fixtures = [f for f in fixtures if f]
for i, (slug, fx) in enumerate(fixtures, 1):
    fx["seq"] = i
    orig = fx["path"]
    if max(map(len, re.findall(r"[A-Za-z0-9+/_-]+", fx["path"])), default=0) >= 30:
        # the sanitiser takes a 32-character run for a token: the ids ride as replay variables
        ids = sorted(set(re.findall(r"/(95\d{4})(?=/|$)", fx["path"])))
        fx["vars"] = {"i" + i: i for i in ids}
        fx["path"] = re.sub(r"/(95\d{4})(?=/|$)", lambda m: "/{{i%s}}" % m.group(1), fx["path"])
    path_slug = "".join(ch if ch.isalnum() else "_" for ch in orig).strip("_")
    name = "0000000000005-%06d-%s-%s-%s.json" % (i, fx["method"].lower(), path_slug, slug)
    with open(os.path.join(OUT, name), "w") as f:
        json.dump(fx, f, indent=2)
        f.write("\n")
print("%d fixtures written to %s" % (len(fixtures), os.path.normpath(OUT)))

# ---------------------------------------------------------------------------------------------------- seed ---
def sha(t):
    return hashlib.sha256(t.encode()).hexdigest()


def tok(key, name, owner, perms, extra="", active=1):
    plain = TOK[key]
    return "(%s, '%s', '%s', '%s', %s, '%s', %s, %d, datetime('now'), datetime('now'))" % (
        "NULL", name, sha(plain), plain[:12], owner, json.dumps(perms, separators=(",", ":")), extra or "NULL", active)


ALL_RW = {k: "rw" for k in ("device", "user", "group", "strategy", "address_book", "audit")}
ALL_R = {k: "r" for k in ALL_RW}
ALL_NONE = {k: "none" for k in ALL_RW}
tokens = [
    ("full", "text-5eed0001", "950001", ALL_RW, ""),
    ("ro", "text-5eed0002", "950001", ALL_R, ""),
    ("none", "text-5eed0003", "950001", ALL_NONE, ""),
    ("expired", "text-5eed0004", "950001", ALL_RW, "datetime('now', '-1 day')"),
    ("off", "text-5eed0005", "950001", ALL_RW, ""),
    ("disabled-owner", "text-5eed0006", "950004", ALL_RW, ""),
    ("no-perm-owner", "text-5eed0007", "950002", ALL_RW, ""),
    ("ben", "text-5eed0008", "950003", {"device": "rw", "user": "rw", "group": "rw", "strategy": "none", "address_book": "none", "audit": "r"}, ""),
    ("orphan", "text-5eed0009", "NULL", ALL_RW, ""),
    ("odd", "text-5eed000a", "950001", {"device": "rw", "user": 5, "group": "x", "address_book": None, "audit": ["r"]}, ""),
    ("short", "text-5eed000b", "950001", {"device": "rw", "user": "none", "group": "none", "strategy": "none", "address_book": "none", "audit": "none"}, "datetime('now', '+30 days')"),
    ("ab", "text-5eed000c", "950001", {"device": "rw", "user": "none", "group": "none", "strategy": "none", "address_book": "rw", "audit": "none"}, ""),
    ("strat", "text-5eed000d", "950001", {"device": "rw", "user": "none", "group": "none", "strategy": "rw", "address_book": "none", "audit": "none"}, ""),
]
SEED = r"""-- Phase 5 (the admin automation API): the people, API tokens, groups, computers, address books, logs and policy the
-- synthetic fixtures in this directory expect. SYNTHETIC: placeholders only, no real name, address, key or password.
-- Generated by replay/make-adminapi-fixtures.py (the tokens' sha256 is computed there). Applied after `hte-console seed-sql`.
--
-- people (ids 95000x): 1 administrator, 2 no role (a token it owns is refused), 3 holds a role with "manage API tokens",
--   4 disabled (a token it owns is refused), 5 and 6 in user group 1, 7 in user group 3 (has client tokens, a web session and
--   a trusted browser), 8 (has a web session), 9 disabled
-- API tokens: tok-5eed000000005a01 .. 0d (see TOK in the generator): full, read-only, none, expired, inactive, owner
--   disabled, owner without the right, Ben's, owner gone, odd matrix, device-only, address-book, strategy
-- user groups 950401 {5, 6}, 950402 {}, 950403 {7}; device groups 950501 (granted to user group 1), 950502, 950503
-- computers (ids 9507xx, RustDesk ids 9900005xx): 11 online (Linux, 5), 12 offline (Windows, 6), 13 twin of 11 by uuid,
--   14 pending (5), 15 disabled (5), 16 online and nobody's, 17 offline (6, folder 2), 18 (8), 19 disabled in folder 3
-- address books 950201 (shared, administrator's), 950202 (eve's personal), 950203 (shared, eve's); strategy 950301 (enabled)
--   assigned to device group 2; 950302 deleted

INSERT OR IGNORE INTO users (id, username, name, email, password, is_admin, is_active, created_at, updated_at) VALUES (900001, 'user-seed0001', 'text-seed0001', 'user-seed0001@example.invalid', 'x', 1, 1, datetime('now'), datetime('now'));
-- the replay's scan wants every value placeholder-shaped hex, so the administrator `seed-sql` makes is renamed
UPDATE users SET username = 'user-5eed0599', name = 'text-5eed0599', email = 'user-5eed059999@example.invalid' WHERE id = 900001;

-- the image's first start made an administrator of its own (random name): the lists here hold only this world
DELETE FROM users WHERE id < 900000;

INSERT INTO roles (id, name, description, permissions, created_at, updated_at) VALUES (950101, 'text-5eed0701', NULL, '{"token":"rw","device":"r"}', datetime('now'), datetime('now'));

INSERT INTO users (id, username, name, email, note, password, is_admin, is_active, role_id, remember_token, created_at, updated_at) VALUES
 (950001, 'user-5eed0501', 'text-5eed0501', 'user-5eed050001@example.invalid', NULL, 'x', 1, 1, NULL, NULL, datetime('now'), datetime('now')),
 (950002, 'user-5eed0502', NULL, NULL, NULL, 'x', 0, 1, NULL, NULL, datetime('now'), datetime('now')),
 (950003, 'user-5eed0503', 'text-5eed0503', 'user-5eed050003@example.invalid', NULL, 'x', 0, 1, 950101, NULL, datetime('now'), datetime('now')),
 (950004, 'user-5eed0504', 'text-5eed0504', NULL, NULL, 'x', 0, 0, NULL, NULL, datetime('now'), datetime('now')),
 (950005, 'user-5eed0505', 'text-5eed0505', 'user-5eed050005@example.invalid', 'text-5eed0605', 'x', 0, 1, NULL, NULL, datetime('now'), datetime('now')),
 (950006, 'user-5eed0506', 'text-5eed0506', 'user-5eed050006@example.invalid', NULL, 'x', 0, 1, NULL, NULL, datetime('now'), datetime('now')),
 (950007, 'user-5eed0507', 'text-5eed0507', NULL, NULL, 'x', 0, 1, NULL, 'tok-5eed00000000b001', datetime('now'), datetime('now')),
 (950008, 'user-5eed0508', NULL, NULL, NULL, 'x', 0, 1, NULL, 'tok-5eed00000000b002', datetime('now'), datetime('now')),
 (950009, 'user-5eed0509', 'text-5eed0509', NULL, NULL, 'x', 0, 0, NULL, NULL, datetime('now'), datetime('now'));

INSERT INTO api_tokens (id, name, token_hash, token_prefix, user_id, permissions, expires_at, is_active, created_at, updated_at) VALUES
""" + ",\n".join(
    " (%d, '%s', '%s', '%s', %s, '%s', %s, %d, datetime('now'), datetime('now'))" % (
        950800 + i, name, sha(TOK[key]), TOK[key][:12], owner, json.dumps(perms, separators=(",", ":")), exp or "NULL", 0 if key == "off" else 1)
    for i, (key, name, owner, perms, exp) in enumerate(tokens, 1)) + r""";

INSERT INTO client_tokens (user_id, token, created_at, updated_at) VALUES (950007, 'tok-5eed00000000b101', datetime('now'), datetime('now')), (950007, 'tok-5eed00000000b102', datetime('now'), datetime('now')), (950008, 'tok-5eed00000000b103', datetime('now'), datetime('now'));
INSERT INTO sessions (id, user_id, ip_address, user_agent, payload, last_activity) VALUES ('sess-5eed00000001', 950007, '198.18.5.80', 'agent-5eed', 'payload', 1), ('sess-5eed00000002', 950008, '198.18.5.81', 'agent-5eed', 'payload', 1), ('sess-5eed00000003', 950005, '198.18.5.82', 'agent-5eed', 'payload', 1);
INSERT INTO trusted_devices (user_id, token_hash, label, ip, expires_at, created_at, updated_at) VALUES (950007, '""" + sha("seed-trusted-1") + r"""', 'text-5eed1901', '198.18.5.83', datetime('now', '+30 days'), datetime('now'), datetime('now')), (950005, '""" + sha("seed-trusted-2") + r"""', 'text-5eed1902', '198.18.5.84', datetime('now', '+30 days'), datetime('now'), datetime('now'));

INSERT INTO user_groups (id, name, note, created_at, updated_at) VALUES (950401, 'text-5eed0801', 'text-5eed0901', datetime('now'), datetime('now')), (950402, 'text-5eed0802', NULL, datetime('now'), datetime('now')), (950403, 'text-5eed0803', NULL, datetime('now'), datetime('now'));
INSERT INTO user_group_user (user_id, user_group_id) VALUES (950005, 950401), (950006, 950401), (950007, 950403);
INSERT INTO device_groups (id, name, note, created_at, updated_at) VALUES (950501, 'text-5eed0a01', NULL, datetime('now'), datetime('now')), (950502, 'text-5eed0a02', NULL, datetime('now'), datetime('now')), (950503, 'text-5eed0a03', NULL, datetime('now'), datetime('now'));
INSERT INTO device_group_user_group (device_group_id, user_group_id) VALUES (950501, 950401), (950503, 950402);

INSERT INTO strategies (id, name, enabled, is_default, created_at, updated_at, deleted_at) VALUES (950301, 'text-5eed1101', 1, 0, datetime('now'), datetime('now'), NULL), (950302, 'text-5eed1102', 1, 0, datetime('now'), datetime('now'), datetime('now'));
INSERT INTO device_group_strategy (device_group_id, strategy_id) VALUES (950502, 950301);

INSERT INTO settings (key, value, created_at, updated_at) VALUES ('default_device_group_id', '950502', datetime('now'), datetime('now')), ('online_window', '3600', datetime('now'), datetime('now'));

INSERT INTO devices (id, rustdesk_id, uuid, status, alias, hostname, os, cpu, memory, version, username, user_id, device_group_id, last_online_at, last_online_ip, registered_ip, deleted_at, created_at, updated_at) VALUES
 (950711, '990000511', '00000000-0000-4000-8000-000000000511', 'active', 'text-5eed0b11', 'host-5eed0511', 'Linux / Ubuntu 22.04', 'cpu-5eed', '8', '1.4.0', 'user-5eed0e11', 950005, 950501, datetime('now', '-10 seconds'), '198.18.5.11', '198.18.5.11', NULL, datetime('now'), datetime('now')),
 (950712, '990000512', '00000000-0000-4000-8000-000000000512', 'active', NULL, 'host-5eed0512', 'Windows / Windows 11', NULL, NULL, NULL, NULL, 950006, NULL, datetime('now', '-1 day'), NULL, NULL, NULL, datetime('now'), datetime('now')),
 (950713, '990000513', '00000000-0000-4000-8000-000000000511', 'active', NULL, 'host-5eed0513', 'Mac OS / macOS 14', NULL, NULL, NULL, NULL, NULL, 950501, NULL, NULL, NULL, NULL, datetime('now'), datetime('now')),
 (950714, '990000514', '00000000-0000-4000-8000-000000000514', 'pending', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 950005, NULL, NULL, NULL, NULL, NULL, datetime('now'), datetime('now')),
 (950715, '990000515', '00000000-0000-4000-8000-000000000515', 'active', NULL, NULL, 'Android 13', NULL, NULL, NULL, NULL, 950005, NULL, NULL, NULL, NULL, datetime('now', '-1 hour'), datetime('now'), datetime('now')),
 (950716, '990000516', '00000000-0000-4000-8000-000000000516', 'active', NULL, 'host-5eed0516', 'Android / Android 13', NULL, NULL, NULL, NULL, NULL, NULL, datetime('now', '-30 seconds'), NULL, NULL, NULL, datetime('now'), datetime('now')),
 (950717, '990000517', '00000000-0000-4000-8000-000000000517', 'active', NULL, NULL, 'Windows 10', NULL, NULL, NULL, NULL, 950006, 950502, datetime('now', '-3 days'), NULL, NULL, NULL, datetime('now'), datetime('now')),
 (950718, '990000518', '00000000-0000-4000-8000-000000000518', 'active', NULL, 'host-5eed0518', 'Linux / Debian 12', NULL, NULL, NULL, NULL, 950008, NULL, datetime('now', '-2 hours'), NULL, NULL, NULL, datetime('now'), datetime('now')),
 (950719, '990000519', '00000000-0000-4000-8000-000000000519', 'active', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 950503, NULL, NULL, NULL, datetime('now', '-2 hours'), datetime('now'), datetime('now'));

INSERT INTO address_books (id, guid, name, owner_user_id, is_personal, note, created_at, updated_at) VALUES
 (950201, '""" + GUID_A1 + r"""', 'text-5eed0c01', 950001, 0, 'text-5eed0d01', datetime('now'), datetime('now')),
 (950202, '""" + GUID_A2 + r"""', 'text-5eed0c02', 950006, 1, NULL, datetime('now'), datetime('now')),
 (950203, '""" + GUID_A3 + r"""', 'text-5eed0c03', 950006, 0, NULL, datetime('now'), datetime('now'));
INSERT INTO tags (id, address_book_id, name, color, created_at, updated_at) VALUES (950231, 950201, 'text-5eed1001', 0, datetime('now'), datetime('now')), (950232, 950201, 'text-5eed1002', 5, datetime('now'), datetime('now')), (950233, 950202, 'text-5eed1003', 0, datetime('now'), datetime('now'));
INSERT INTO address_book_rules (id, address_book_id, subject_type, subject_id, permission, created_at, updated_at) VALUES (950241, 950201, 'everyone', NULL, 1, datetime('now'), datetime('now')), (950242, 950201, 'user', 950006, 3, datetime('now'), datetime('now')), (950243, 950202, 'group', 950401, 2, datetime('now'), datetime('now'));
INSERT INTO address_book_entries (id, address_book_id, rustdesk_id, alias, hostname, platform, username, login_name, force_always_relay, rdp_port, rdp_username, tag_ids, created_at, updated_at) VALUES
 (950211, 950201, '990000511', 'text-5eed0e11', 'host-5eed0511', 'linux', 'user-5eed0e11', NULL, 1, '3389', 'user-5eed0f11', '[950231,950232]', datetime('now'), datetime('now')),
 (950212, 950201, '990000512', NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, datetime('now'), datetime('now')),
 (950213, 950202, '990000517', NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, '[950233]', datetime('now'), datetime('now')),
 (950214, 950203, '990000511', NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, datetime('now'), datetime('now')),
 (950215, 950201, '990000518', NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, datetime('now'), datetime('now'));

INSERT INTO audit_connections (id, action, conn_id, rustdesk_id, from_peer, from_name, ip, session_id, conn_type, note, note_user_id, noted_at, closed_at, created_at, updated_at) VALUES
 (950601, 'new', 1, '990000511', '990000601', 'text-5eed1201', '198.18.5.60', 'tok-5eed000000006001', 0, 'text-5eed1301', 950001, '2026-01-10 11:30:00', '2026-01-10 11:00:00', '2026-01-10 10:00:00', '2026-01-10 10:00:00'),
 (950602, 'close', 2, '990000512', '990000602', NULL, NULL, NULL, 1, NULL, NULL, NULL, NULL, '2026-02-10 10:00:00', '2026-02-10 10:00:00');
INSERT INTO audit_file_transfers (id, rustdesk_id, from_peer, from_name, path, info, is_file, direction, file_count, ip, created_at, updated_at) VALUES
 (950611, '990000511', '990000603', NULL, 'path-5eed0001', '{"files":[["text-5eed0f01",1024],["text-5eed0f02","7"],[""],"str",["text-5eed0f03"]]}', 1, 0, 2, NULL, '2026-01-11 10:00:00', '2026-01-11 10:00:00'),
 (950612, '990000512', NULL, 'text-5eed1202', NULL, '{"files":[["text-5eed0f04",5]]}', 0, 1, 1, '198.18.5.61', '2026-01-12 10:00:00', '2026-01-12 10:00:00'),
 (950613, '990000512', NULL, NULL, NULL, 'not json', 1, 1, 0, NULL, '2026-01-13 10:00:00', '2026-01-13 10:00:00');
INSERT INTO alarm_logs (id, rustdesk_id, typ, info, created_at, updated_at) VALUES (950621, '990000511', 0, '{"a":1}', '2026-01-14 10:00:00', '2026-01-14 10:00:00'), (950622, '990000513', 102, '{}', '2026-01-15 10:00:00', '2026-01-15 10:00:00'), (950623, '990000512', 55, NULL, '2026-01-16 10:00:00', '2026-01-16 10:00:00');
INSERT INTO console_audits (id, user_id, username, action, target_type, target_id, summary, ip, created_at) VALUES
 (950631, 950001, 'user-5eed0501', 'user.create', 'user', 'user-5eed0510', 'text-5eed1401', '198.18.5.70', '2026-03-01 10:00:00'),
 (950632, 950002, 'user-5eed0502', 'device.enable', 'device', '990000511', 'text-5eed1402', NULL, '2026-03-02 10:00:00');
"""
with open(os.path.join(OUT, "0000000000005-adminapi-seed.sql"), "w") as f:
    f.write(SEED)
