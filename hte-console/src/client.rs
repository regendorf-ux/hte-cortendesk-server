//! Phase 4: the bearer-token client endpoints, answered natively. Each handler is a port of the PHP console's
//! (v1.15.0-hte.1), statement by statement:
//!
//!   GET /api/ab, POST /api/ab/get, POST /api/ab            legacy address book      AddressBookController
//!   POST /api/ab/personal, /settings, /shared/profiles,
//!        /peers, /tags/{guid}, /peer/add/{guid}, /tag/...  new multi-book API       AddressBookController
//!   PUT /api/ab/peer/update/{guid}, DELETE /api/ab/peer/{guid}, PUT /api/ab/tag/rename|update/{guid}, DELETE /api/ab/tag/{guid}
//!   GET|POST /api/server-config                            web client bootstrap     WebClientController
//!   GET /api/device-group/accessible, /api/users, /api/peers   group tab            GroupTabController
//!   PUT /api/audit, GET /api/audit/conn/active             end-of-session note      AuditController
//!   GET /webclient-config/index.js                         web client pre-login     WebClientController
//!
//! All but the last sit behind `auth:client`: the bearer token and its user are checked by phase 2's guard
//! (`signin::authenticate`), and every list is scoped to that person exactly as PHP scopes it (`Device::visibleTo`,
//! `User::accessibleDeviceGroupIds`, `AddressBook::permissionFor`, HTE's one `reject` of other people's automatic
//! books). Same tables, same rows, no schema change. Laravel's routing is reproduced where a client could see it:
//! trailing slashes and percent-decoding before matching, 404 and 405 texts, HEAD for GET, OPTIONS and CORS.
//!
//! PHP writes without a transaction (the legacy push deletes, then inserts); so does this, statement for statement,
//! and a failure part way leaves what PHP would leave. Not ported: `/webclient` (a page behind the console's session)
//! and `/rdclient/*` (static files): they stay PHP's.

use crate::api::{blocking, fail, header_str, json_message, request_root, respond, Native, Reply};
use crate::laravel::{self, Cast, Input};
use crate::php::{self, Arr, Fault, JsonOpts, Key, Val};
use crate::sqlite::{self as db, Row, P};
use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, Method, Request, Response, StatusCode};
use axum::routing::any;
use axum::Router;
use rusqlite::Connection;
use std::net::SocketAddr;
use std::sync::Arc;

const PERM_READ: i64 = 1;
const PERM_READ_WRITE: i64 = 2;
const PERM_FULL: i64 = 3;

// -------------------------------------------------------------------------------------------------- routes ---

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum R {
    AbGet,
    AbPush,
    AbPersonal,
    AbSettings,
    AbShared,
    AbPeers,
    AbTags,
    PeerAdd,
    PeerUpdate,
    PeerDelete,
    TagAdd,
    TagRename,
    TagUpdate,
    TagDelete,
    ServerConfig,
    DeviceGroups,
    Users,
    Peers,
    AuditNote,
    AuditActive,
    ConfigJs,
}

/// routes/api.php (the `auth:client` group) and routes/web.php, in file order. `{}` is a `{guid}` segment.
const ROUTES: &[(&str, &str, R)] = &[
    ("PUT", "/api/audit", R::AuditNote),
    ("GET", "/api/audit/conn/active", R::AuditActive),
    ("GET", "/api/ab", R::AbGet),
    ("POST", "/api/ab/get", R::AbGet),
    ("POST", "/api/ab", R::AbPush),
    ("POST", "/api/ab/personal", R::AbPersonal),
    ("POST", "/api/ab/settings", R::AbSettings),
    ("POST", "/api/ab/shared/profiles", R::AbShared),
    ("POST", "/api/ab/peers", R::AbPeers),
    ("POST", "/api/ab/tags/{}", R::AbTags),
    ("POST", "/api/ab/peer/add/{}", R::PeerAdd),
    ("PUT", "/api/ab/peer/update/{}", R::PeerUpdate),
    ("DELETE", "/api/ab/peer/{}", R::PeerDelete),
    ("POST", "/api/ab/tag/add/{}", R::TagAdd),
    ("PUT", "/api/ab/tag/rename/{}", R::TagRename),
    ("PUT", "/api/ab/tag/update/{}", R::TagUpdate),
    ("DELETE", "/api/ab/tag/{}", R::TagDelete),
    ("GET", "/api/server-config", R::ServerConfig),
    ("POST", "/api/server-config", R::ServerConfig),
    ("GET", "/api/device-group/accessible", R::DeviceGroups),
    ("GET", "/api/users", R::Users),
    ("GET", "/api/peers", R::Peers),
    ("GET", "/webclient-config/index.js", R::ConfigJs),
];

/// Laravel's `Router::$verbs` order, which the 405 message lists in.
const VERBS: &[&str] = &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"];

#[derive(Debug, PartialEq, Eq)]
enum Lookup {
    Found(R, Vec<u8>),
    /// the URI exists, the method does not: the methods that do
    NotAllowed(Vec<&'static str>),
    NoRoute,
}

/// `rawurldecode`: `%XX` only (a `+` stays a plus).
fn rawurldecode(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'%' && i + 2 < s.len() {
            let hex = |c: u8| (c as char).to_digit(16);
            if let (Some(h), Some(l)) = (hex(s[i + 1]), hex(s[i + 2])) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(s[i]);
        i += 1;
    }
    out
}

/// Laravel's `UriValidator`: `rtrim($path, '/') ?: '/'`, decoded, against each route's pattern; the first route that
/// matches the URI and the method wins; with none for the method, the methods of the routes that match the URI.
fn lookup(method: &str, raw_path: &[u8]) -> Lookup {
    let decoded = rawurldecode(raw_path);
    let end = decoded.iter().rposition(|&c| c != b'/').map_or(0, |i| i + 1);
    let path: &[u8] = if end == 0 { b"/" } else { &decoded[..end] };
    let segs: Vec<&[u8]> = path.split(|&c| c == b'/').collect();
    let mut allowed: Vec<&'static str> = vec![];
    for (m, pattern, r) in ROUTES {
        let pat: Vec<&str> = pattern.split('/').collect();
        if pat.len() != segs.len() {
            continue;
        }
        let mut param = vec![];
        let ok = pat.iter().zip(&segs).all(|(p, s)| {
            if *p == "{}" {
                param = s.to_vec();
                !s.is_empty()
            } else {
                p.as_bytes() == *s
            }
        });
        if !ok {
            continue;
        }
        if *m == method || (method == "HEAD" && *m == "GET") {
            return Lookup::Found(*r, param);
        }
        for v in VERBS {
            if (*v == *m || (*v == "HEAD" && *m == "GET")) && !allowed.contains(v) {
                allowed.push(*v);
            }
        }
    }
    if allowed.is_empty() {
        return Lookup::NoRoute;
    }
    allowed.sort_by_key(|v| VERBS.iter().position(|x| x == v));
    Lookup::NotAllowed(allowed)
}

/// Registers the paths; the handler decides the rest from `lookup`. A path that is not canonical (a trailing slash,
/// a different case) matches no route here and goes to the fallback (PHP), which answers it as it always did.
pub fn mount(r: Router<Arc<Native>>) -> Router<Arc<Native>> {
    let mut r = r;
    let mut seen: Vec<&str> = Vec::new();
    for (_, path, _) in ROUTES {
        if !path.contains("{}") && !seen.contains(path) {
            seen.push(path);
            r = r.route(path, any(handle));
        }
    }
    for prefix in ["/api/ab/tags", "/api/ab/peer", "/api/ab/tag"] {
        r = r.route(&format!("{prefix}/*rest"), any(handle));
    }
    r
}

/// The largest body a client endpoint reads (`HTE_CONSOLE_CLIENT_MAX_BODY_BYTES`, default 8 MiB: a whole legacy
/// address book is pushed at once).
fn max_body() -> usize {
    std::env::var("HTE_CONSOLE_CLIENT_MAX_BODY_BYTES").ok().and_then(|v| v.trim().parse().ok()).unwrap_or(8 * 1024 * 1024)
}

fn page(status: u16, html: String, head: bool) -> Response<Body> {
    Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
        .header(header::CONTENT_TYPE, "text/html; charset=UTF-8")
        .header(header::CACHE_CONTROL, "no-cache, private")
        .header("x-content-type-options", "nosniff")
        .header("referrer-policy", "no-referrer")
        .body(if head { Body::empty() } else { Body::from(html) })
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

async fn handle(State(n): State<Arc<Native>>, ConnectInfo(peer): ConnectInfo<SocketAddr>, req: Request<Body>) -> Response<Body> {
    let (parts, body) = req.into_parts();
    let method = parts.method.as_str().to_string();
    let head = parts.method == Method::HEAD;
    let raw_path = parts.uri.path().to_string();
    let web = raw_path == "/webclient-config/index.js";

    // HandleCors (api/* only): a preflight never reaches the route.
    if !web && parts.method == Method::OPTIONS && parts.headers.contains_key("access-control-request-method") {
        let mut extra = vec![
            ("access-control-allow-methods", header_str(&parts.headers, "access-control-request-method").unwrap_or("").to_ascii_uppercase()),
            ("access-control-max-age", "0".to_string()),
            ("vary", "Access-Control-Request-Method, Access-Control-Request-Headers".to_string()),
        ];
        if let Some(h) = header_str(&parts.headers, "access-control-request-headers") {
            extra.push(("access-control-allow-headers", h.to_string()));
        }
        return respond(Reply::Text(204, vec![]), extra, false);
    }

    // `$request->path()`: the raw path without surrounding slashes
    let shown = {
        let t = raw_path.trim_matches('/');
        if t.is_empty() { "/" } else { t }.to_string()
    };
    let lookup_method = if parts.method == Method::OPTIONS { "OPTIONS" } else { method.as_str() };
    let (route, guid) = match lookup(lookup_method, raw_path.as_bytes()) {
        Lookup::Found(r, g) => (r, g),
        Lookup::NoRoute => {
            return if web {
                page(404, crate::signin::error_page(404, "Not Found"), head)
            } else {
                respond(json_message(404, &format!("The route {shown} could not be found.")), vec![], head)
            };
        }
        Lookup::NotAllowed(allowed) => {
            if parts.method == Method::OPTIONS {
                // the router answers OPTIONS for a known path itself
                let mut resp = respond(Reply::Text(200, vec![]), vec![("allow", allowed.join(",")), ("vary", "Access-Control-Request-Method".into())], false);
                if web {
                    resp.headers_mut().remove("access-control-allow-origin");
                }
                return resp;
            }
            if web {
                return page(405, crate::signin::error_page(405, "Method Not Allowed"), head);
            }
            let msg = format!("The {method} method is not supported for route {shown}. Supported methods: {}.", allowed.join(", "));
            return respond(json_message(405, &msg), vec![("allow", allowed.join(", "))], head);
        }
    };

    if route == R::ConfigJs {
        return config_js(&n, &parts.headers, peer.ip(), head);
    }

    // ValidatePostSize, bounded here far below PHP's limit
    let max = max_body();
    let declared = header_str(&parts.headers, "content-length").and_then(|v| v.trim().parse::<u64>().ok());
    if declared.map_or(false, |l| l > max as u64) {
        return respond(json_message(413, "The POST data is too large."), vec![], false);
    }
    let body = match axum::body::to_bytes(body, max).await {
        Ok(b) => b,
        Err(_) => return respond(json_message(413, "The POST data is too large."), vec![], false),
    };
    let input = Input::new(&method, header_str(&parts.headers, header::CONTENT_TYPE.as_str()), parts.uri.query(), &body);
    let bearer = laravel::bearer_token(parts.headers.get(header::AUTHORIZATION).map(|v| v.as_bytes()));
    let now = n.now();
    let reply = blocking(&n, move |n, c| run(n, c, route, guid, bearer, &input, now)).await;
    respond(reply.unwrap_or_else(Reply::server_error), vec![], head)
}

/// GET /webclient-config/index.js: the web client's pre-login bootstrap, pointing its API calls back at this console.
/// PHP builds the origin with `getSchemeAndHttpHost()`; here `HTE_CONSOLE_PUBLIC_URL` when set (the Host header then
/// decides nothing), else the same request-derived origin as the sign-in pages.
fn config_js(n: &Native, h: &HeaderMap, peer: std::net::IpAddr, head: bool) -> Response<Body> {
    let Some(root) = request_root(n, h, peer) else { return page(404, crate::signin::error_page(404, "Not Found"), head) };
    let js = format!(
        "localStorage.setItem('api-server', '{root}');\nconst ws2_prefix = 'wc-';\nlocalStorage.setItem(ws2_prefix + 'api-server', '{root}');\nwindow.webclient_magic_queryonline = 0;\n"
    );
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/javascript")
        .header(header::CACHE_CONTROL, "no-cache, private")
        .body(if head { Body::empty() } else { Body::from(js) })
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

// ------------------------------------------------------------------------------------------------ dispatch ---

fn run(n: &Native, c: &Connection, r: R, guid: Vec<u8>, bearer: Option<Vec<u8>>, input: &Input, now: i64) -> Reply {
    let (token, user) = match crate::signin::authenticate(c, bearer.as_deref(), now) {
        Ok(Some(x)) => x,
        Ok(None) => return json_message(401, "Unauthenticated."),
        Err(f) => return fail("client-token guard", &f),
    };
    let cx = Cx { n, c, token, user, input, guid, now };
    let out = match r {
        R::AbGet => cx.legacy_get(),
        R::AbPush => cx.legacy_push(),
        R::AbPersonal => cx.personal(),
        R::AbSettings => Ok(Reply::Json(200, r#"{"max_peer_one_ab":0}"#.into())),
        R::AbShared => cx.shared_profiles(),
        R::AbPeers => cx.ab_peers(),
        R::AbTags => cx.tags(),
        R::PeerAdd => cx.peer_add(),
        R::PeerUpdate => cx.peer_update(),
        R::PeerDelete => cx.peer_delete(),
        R::TagAdd => cx.tag_add(),
        R::TagRename => cx.tag_rename(),
        R::TagUpdate => cx.tag_update(),
        R::TagDelete => cx.tag_delete(),
        R::ServerConfig => cx.server_config(),
        R::DeviceGroups => cx.device_groups(),
        R::Users => cx.users(),
        R::Peers => cx.peers(),
        R::AuditNote => cx.audit_note(),
        R::AuditActive => cx.audit_active(),
        R::ConfigJs => Ok(Reply::server_error()), // answered before the guard (config_js)
    };
    out.unwrap_or_else(|f| fail(&format!("client api {r:?}"), &f))
}

struct Cx<'a> {
    n: &'a Native,
    c: &'a Connection,
    token: Row,
    user: Row,
    input: &'a Input,
    /// the `{guid}` segment of the route, when it has one
    guid: Vec<u8>,
    now: i64,
}

// ------------------------------------------------------------------------------------------------ helpers ---

fn enc(v: &Val) -> Result<String, Fault> {
    php::json_encode(v).ok_or_else(|| Fault::Other("json_encode failed (invalid UTF-8)".into()))
}

fn jstr(b: &[u8]) -> Result<String, Fault> {
    let mut o = String::new();
    php::enc_str(b, &mut o).ok_or_else(|| Fault::Other("json_encode failed (invalid UTF-8)".into()))?;
    Ok(o)
}

fn error(m: &str) -> Result<Reply, Fault> {
    Ok(Reply::Json(200, format!(r#"{{"error":{}}}"#, jstr(m.as_bytes())?)))
}

fn list(items: Vec<Val>) -> Val {
    let mut a = Arr::new();
    for i in items {
        a.push(i);
    }
    Val::Arr(a)
}

fn obj(pairs: Vec<(&str, Val)>) -> Val {
    php::assoc(pairs.into_iter().map(|(k, v)| (k.to_string(), v)))
}

/// `(string) $row->col`
fn sv(r: &Row, col: &str) -> Result<Val, Fault> {
    Ok(Val::Str(r.val(col).to_php_string()?))
}

fn ids(v: &[i64]) -> Vec<P> {
    v.iter().map(|i| P(Val::Int(*i))).collect()
}

fn marks(n: usize) -> String {
    vec!["?"; n].join(", ")
}

/// PHP's loose `==` of a tag id against an element of a stored `tag_ids` array (`Collection::whereIn`, not strict).
fn loose_eq(id: i64, v: &Val) -> bool {
    match v {
        Val::Int(i) => *i == id,
        Val::Float(f) => *f == id as f64,
        Val::Bool(b) => *b == (id != 0),
        Val::Null => id == 0,
        Val::Str(s) => php::is_numeric_str(s) && std::str::from_utf8(s).ok().and_then(|t| t.trim().parse::<f64>().ok()).map_or(false, |f| f == id as f64),
        Val::Arr(_) => false,
    }
}

/// `$e->tag_ids ?? []` (the `array` cast): the decoded JSON, an empty array for null.
fn tag_ids_of(r: &Row) -> Result<Arr, Fault> {
    match laravel::from_json(&r.val("tag_ids")) {
        Val::Null => Ok(Arr::new()),
        Val::Arr(a) => Ok(a),
        _ => Err(Fault::Other("tag_ids is not an array".into())),
    }
}

/// An array key as PHP derives it from a value used as an offset.
fn key_of(v: &Val) -> Result<Key, Fault> {
    Ok(match v {
        Val::Null => Key::Str(vec![]),
        Val::Bool(b) => Key::Int(*b as i64),
        Val::Int(i) => Key::Int(*i),
        Val::Float(f) if f.fract() == 0.0 && f.is_finite() => Key::Int(*f as i64),
        Val::Float(_) => return Err(Fault::Other("float offset with a fraction".into())),
        Val::Str(s) => Key::from_bytes(s),
        Val::Arr(_) => return Err(Fault::Other("illegal offset type".into())),
    })
}

/// `array_filter(array_map('strval', (array) $request->json()->all()))`: the request's JSON body whatever its
/// content type; `json_decode(trim($content) === '' ? '[]' : $content)`, cast to array, cleaned like the input bag when the request is JSON.
fn json_strings(input: &Input) -> Result<Vec<Vec<u8>>, Fault> {
    let raw: &[u8] = if php::trim(&input.raw).is_empty() { b"[]" } else { &input.raw };
    let mut arr = php::json_decode(raw, &JsonOpts::default()).unwrap_or(Val::Null).to_array();
    if input.is_json {
        laravel::clean(&mut arr, b"");
    }
    let mut out = vec![];
    for (_, v) in arr.iter() {
        let s = v.to_php_string()?;
        if !(s.is_empty() || s == b"0") {
            out.push(s);
        }
    }
    Ok(out)
}

/// `$request->filled($key)`: present and not an empty string (arrays and booleans always count).
fn filled(input: &Input, key: &str) -> Result<bool, Fault> {
    Ok(match input.get(key) {
        None | Some(Val::Null) => false,
        Some(Val::Bool(_)) | Some(Val::Arr(_)) => true,
        Some(v) => !php::trim(&v.to_php_string()?).is_empty(),
    })
}

fn env_trim(name: &str) -> String {
    std::env::var(name).map(|v| String::from_utf8_lossy(php::trim(v.as_bytes())).into_owned()).unwrap_or_default()
}

impl Cx<'_> {
    fn ts(&self) -> String {
        laravel::ts(self.now)
    }
    fn uid(&self) -> i64 {
        self.user.id()
    }
    fn admin(&self) -> bool {
        self.user.val("is_admin").to_bool()
    }

    /// `[current, pageSize]`: `max(1, (int) query('current', 1))`, `min(500, max(1, (int) query('pageSize', 100)))`.
    fn pagination(&self) -> (i64, i64) {
        // `$request->query($key, $default)` is `all()[$key] ?? $default`: a present but empty value is the default too
        let q = |k: &str, d: i64| self.input.query(k).filter(|v| !matches!(v, Val::Null)).map_or(d, |v| v.to_int());
        let (cur, size) = (q("current", 1), q("pageSize", 100));
        (cur.max(1), size.max(1).min(500))
    }

    /// `forPage`: Eloquent embeds the two integers in the SQL.
    fn page_sql(&self) -> String {
        let (page, size) = self.pagination();
        format!(" limit {size} offset {}", (page - 1).saturating_mul(size))
    }

    // ---------------------------------------------------------------------------------- the person's reach ---

    /// `$user->groups()->pluck('user_groups.id')`
    fn user_group_ids(&self) -> Result<Vec<i64>, Fault> {
        let rows = db::rows(
            self.c,
            r#"select "user_groups"."id" from "user_groups" inner join "user_group_user" on "user_groups"."id" = "user_group_user"."user_group_id" where "user_group_user"."user_id" = ?"#,
            &[P(Val::Int(self.uid()))],
        )?;
        Ok(rows.iter().map(|r| r.val("id").to_int()).collect())
    }

    /// `User::groupAccessTargetIds($type)`
    fn group_access_targets(&self, target_type: &str) -> Result<Vec<i64>, Fault> {
        let groups = self.user_group_ids()?;
        let mut sql = String::from(r#"select "target_id" from "group_accesses" where "target_type" = ? and (("accessor_type" = ? and "accessor_id" = ?)"#);
        let mut params = vec![P(Val::str(target_type)), P(Val::str("user")), P(Val::Int(self.uid()))];
        if !groups.is_empty() {
            sql += &format!(r#" or ("accessor_type" = ? and "accessor_id" in ({}))"#, marks(groups.len()));
            params.push(P(Val::str("user_group")));
            params.extend(ids(&groups));
        }
        sql += ")";
        Ok(db::rows(self.c, &sql, &params)?.iter().map(|r| r.val("target_id").to_int()).collect())
    }

    /// `User::accessibleDeviceGroupIds()`: per-user grants, grants of the person's user groups, and group accesses.
    fn accessible_device_group_ids(&self) -> Result<Vec<i64>, Fault> {
        let uid = P(Val::Int(self.uid()));
        let direct = db::rows(
            self.c,
            r#"select "device_groups"."id" from "device_groups" inner join "device_group_user" on "device_groups"."id" = "device_group_user"."device_group_id" where "device_group_user"."user_id" = ?"#,
            &[uid],
        )?;
        let via_groups = db::rows(
            self.c,
            r#"select "device_group_user_group"."device_group_id" from "device_group_user_group" inner join "user_group_user" on "user_group_user"."user_group_id" = "device_group_user_group"."user_group_id" where "user_group_user"."user_id" = ?"#,
            &[P(Val::Int(self.uid()))],
        )?;
        let mut out: Vec<i64> = vec![];
        let all = direct
            .iter()
            .map(|r| r.val("id").to_int())
            .chain(via_groups.iter().map(|r| r.val("device_group_id").to_int()))
            .chain(self.group_access_targets("device_group")?);
        for i in all {
            if !out.contains(&i) {
                out.push(i);
            }
        }
        Ok(out)
    }

    /// `User::visibleUserIds()`: the person, the members of their user groups and of the groups accessed from them.
    fn visible_user_ids(&self) -> Result<Vec<i64>, Fault> {
        let mut groups = self.user_group_ids()?;
        for g in self.group_access_targets("user_group")? {
            if !groups.contains(&g) {
                groups.push(g);
            }
        }
        let mut out = vec![self.uid()];
        if !groups.is_empty() {
            let rows = db::rows(self.c, &format!(r#"select "user_id" from "user_group_user" where "user_group_id" in ({})"#, marks(groups.len())), &ids(&groups))?;
            for r in rows {
                let i = r.val("user_id").to_int();
                if !out.contains(&i) {
                    out.push(i);
                }
            }
        }
        Ok(out)
    }

    /// `Device::scopeVisibleTo`: the SQL after `from "devices"` and its parameters.
    fn visible_devices(&self) -> Result<(String, Vec<P>), Fault> {
        let mut sql = String::new();
        let mut params = vec![];
        if !self.admin() {
            let groups = self.accessible_device_group_ids()?;
            if groups.is_empty() {
                sql += r#"("user_id" = ?)"#;
                params.push(P(Val::Int(self.uid())));
            } else {
                sql += &format!(r#"("user_id" = ? or "device_group_id" in ({}))"#, marks(groups.len()));
                params.push(P(Val::Int(self.uid())));
                params.extend(ids(&groups));
            }
            sql += " and ";
        }
        sql += r#""status" = ? and "devices"."deleted_at" is null"#;
        params.push(P(Val::str("active")));
        Ok((sql, params))
    }

    // ------------------------------------------------------------------------------------------ address books ---

    /// `AddressBook::personalFor($user)`: `firstOrCreate`.
    fn personal_for(&self) -> Result<Row, Fault> {
        let owner = Val::Int(self.uid());
        if let Some(b) = db::first(self.c, r#"select * from "address_books" where "owner_user_id" = ? and "is_personal" = ? limit 1"#, &[P(owner.clone()), P(Val::Bool(true))])? {
            return Ok(b);
        }
        let id = db::insert(
            self.c,
            "address_books",
            vec![("owner_user_id", owner), ("is_personal", Val::Bool(true)), ("name", Val::str("My address book")), ("guid", Val::str(&laravel::uuid4()))],
            &self.ts(),
        )?;
        db::first(self.c, r#"select * from "address_books" where "id" = ? limit 1"#, &[P(Val::Int(id))])?.ok_or_else(|| Fault::Other("inserted address book vanished".into()))
    }

    /// `AddressBook::permissionFor($user, $groupIds)`: 0 none, 1 read, 2 read/write, 3 full.
    fn permission(&self, book: &Row, groups: Option<&[i64]>) -> Result<i64, Fault> {
        let owner = book.val("owner_user_id").to_int() == self.uid();
        if book.val("is_personal").to_bool() {
            if owner {
                return Ok(PERM_FULL);
            }
            if !self.admin() {
                return Ok(0);
            }
            // an orphaned book (its owner is gone) is the administrators' to clean up
            let owner_row = db::first(self.c, r#"select * from "users" where "id" = ? limit 1"#, &[P(book.val("owner_user_id"))])?;
            return Ok(if owner_row.is_none() { PERM_FULL } else { 0 });
        }
        if owner || self.admin() {
            return Ok(PERM_FULL);
        }
        let groups = match groups {
            Some(g) => g.to_vec(),
            None => self.user_group_ids()?,
        };
        let rules = db::rows(self.c, r#"select * from "address_book_rules" where "address_book_rules"."address_book_id" = ? and "address_book_rules"."address_book_id" is not null"#, &[P(book.val("id"))])?;
        let mut best = 0;
        for rule in rules {
            let hit = match rule.val("subject_type").to_php_string()?.as_slice() {
                b"everyone" => true,
                b"user" => rule.val("subject_id").to_int() == self.uid(),
                b"group" => groups.contains(&rule.val("subject_id").to_int()),
                _ => false,
            };
            if hit {
                best = best.max(rule.val("permission").to_int());
            }
        }
        Ok(best)
    }

    /// `bookOrFail`: the book, or the answer to send instead.
    fn book_or_fail(&self, guid: &[u8], required: i64) -> Result<Result<Row, Reply>, Fault> {
        let Some(book) = db::first(self.c, r#"select * from "address_books" where "guid" = ? limit 1"#, &[P(Val::Str(guid.to_vec()))])? else {
            return Ok(Err(error("Address book not found")?));
        };
        if self.permission(&book, None)? < required {
            return Ok(Err(error("Permission denied")?));
        }
        Ok(Ok(book))
    }

    fn book_tags(&self, book: &Row) -> Result<Vec<Row>, Fault> {
        db::rows(self.c, r#"select * from "tags" where "tags"."address_book_id" = ? and "tags"."address_book_id" is not null"#, &[P(book.val("id"))])
    }

    /// `tagNamesToIds`: ids of the book's tags with those names.
    fn tag_names_to_ids(&self, book: &Row, names: &Arr) -> Result<Vec<i64>, Fault> {
        let mut want = vec![];
        for (_, v) in names.iter() {
            want.push(P(Val::Str(v.to_php_string()?)));
        }
        if want.is_empty() {
            return Ok(vec![]);
        }
        let sql = format!(r#"select "id" from "tags" where "tags"."address_book_id" = ? and "tags"."address_book_id" is not null and "name" in ({})"#, marks(want.len()));
        let mut params = vec![P(book.val("id"))];
        params.append(&mut want);
        Ok(db::rows(self.c, &sql, &params)?.iter().map(|r| r.val("id").to_int()).collect())
    }

    /// `$tags->whereIn('id', $e->tag_ids ?? [])->pluck('name')->values()`
    fn names_of(tags: &[Row], entry: &Row) -> Result<Vec<Val>, Fault> {
        let wanted = tag_ids_of(entry)?;
        Ok(tags.iter().filter(|t| wanted.iter().any(|(_, v)| loose_eq(t.id(), v))).map(|t| t.val("name")).collect())
    }

    fn tag_ids_json(ids: &[i64]) -> String {
        format!("[{}]", ids.iter().map(i64::to_string).collect::<Vec<_>>().join(","))
    }

    /// POST /api/ab/personal
    fn personal(&self) -> Result<Reply, Fault> {
        let book = self.personal_for()?;
        Ok(Reply::Json(200, enc(&obj(vec![("guid", book.val("guid"))]))?))
    }

    /// `accessibleSharedBooks`: shared books with a permission, minus other people's automatic books, by name.
    fn accessible_shared_books(&self) -> Result<Vec<(Row, i64)>, Fault> {
        let groups = if self.admin() { vec![] } else { self.user_group_ids()? };
        let books = db::rows(self.c, r#"select * from "address_books" where "is_personal" = ?"#, &[P(Val::Bool(false))])?;
        let mut out = vec![];
        for b in books {
            let rule = self.permission(&b, Some(&groups))?;
            if rule <= 0 {
                continue;
            }
            // HTE: someone else's automatic (per-computer password) book is never listed, administrators included
            let auto = db::first(self.c, r#"select "user_id" from "hte_auto_books" where "address_book_id" = ? limit 1"#, &[P(b.val("id"))])?;
            if let Some(a) = auto {
                if !matches!(a.val("user_id"), Val::Null) && a.val("user_id").to_int() != self.uid() {
                    continue;
                }
            }
            out.push((b, rule));
        }
        // sortBy(name): PHP 8's stable asort with SORT_REGULAR
        let mut keyed: Vec<(Vec<u8>, (Row, i64))> = vec![];
        for x in out {
            keyed.push((x.0.val("name").to_php_string()?, x));
        }
        keyed.sort_by(|a, b| php::smart_strcmp(&a.0, &b.0));
        Ok(keyed.into_iter().map(|(_, x)| x).collect())
    }

    /// POST /api/ab/shared/profiles
    fn shared_profiles(&self) -> Result<Reply, Fault> {
        let books = self.accessible_shared_books()?;
        let (page, size) = self.pagination();
        let skip = ((page - 1) as i128 * size as i128).min(books.len() as i128) as usize;
        let mut data = vec![];
        for (b, rule) in books.iter().skip(skip).take(size as usize) {
            let owner = db::first(self.c, r#"select * from "users" where "id" = ? limit 1"#, &[P(b.val("owner_user_id"))])?;
            let owner_name = match owner.map(|o| o.val("username")) {
                None | Some(Val::Null) => Val::str(""),
                Some(v) => v,
            };
            data.push(obj(vec![("guid", b.val("guid")), ("name", b.val("name")), ("owner", owner_name), ("note", sv(b, "note")?), ("rule", Val::Int(*rule))]));
        }
        Ok(Reply::Json(200, enc(&obj(vec![("total", Val::Int(books.len() as i64)), ("data", list(data))]))?))
    }

    /// `peerJson`: forceAlwaysRelay is a STRING.
    fn peer_json(&self, e: &Row, book: &Row, tags: &[Row]) -> Result<Val, Fault> {
        let mut pairs = vec![
            ("id", e.val("rustdesk_id")),
            ("username", sv(e, "username")?),
            ("hostname", sv(e, "hostname")?),
            ("platform", sv(e, "platform")?),
            ("alias", sv(e, "alias")?),
            ("tags", list(Self::names_of(tags, e)?)),
            ("forceAlwaysRelay", Val::str(if e.val("force_always_relay").to_bool() { "true" } else { "false" })),
            ("rdpPort", sv(e, "rdp_port")?),
            ("rdpUsername", sv(e, "rdp_username")?),
            ("loginName", sv(e, "login_name")?),
        ];
        if book.val("is_personal").to_bool() {
            pairs.push(("hash", sv(e, "hash")?));
        } else if !matches!(e.val("password_enc"), Val::Null) {
            pairs.push(("password", Val::Str(self.n.crypt.decrypt_string(&e.val("password_enc").to_php_string()?)?)));
        }
        Ok(obj(pairs))
    }

    /// POST /api/ab/peers?current&pageSize&ab=<guid>
    fn ab_peers(&self) -> Result<Reply, Fault> {
        let guid = self.input.query_string("ab")?;
        let book = match self.book_or_fail(&guid, PERM_READ)? {
            Ok(b) => b,
            Err(r) => return Ok(r),
        };
        let total = db::first(self.c, r#"select count(*) as "aggregate" from "address_book_entries" where "address_book_entries"."address_book_id" = ? and "address_book_entries"."address_book_id" is not null"#, &[P(book.val("id"))])?
            .map_or(0, |r| r.val("aggregate").to_int());
        let entries = db::rows(
            self.c,
            &format!(r#"select * from "address_book_entries" where "address_book_entries"."address_book_id" = ? and "address_book_entries"."address_book_id" is not null order by "id" asc{}"#, self.page_sql()),
            &[P(book.val("id"))],
        )?;
        let tags = self.book_tags(&book)?;
        let mut data = vec![];
        for e in &entries {
            data.push(self.peer_json(e, &book, &tags)?);
        }
        Ok(Reply::Json(200, enc(&obj(vec![("total", Val::Int(total)), ("data", list(data))]))?))
    }

    /// POST /api/ab/tags/{guid}: a bare array, color an int.
    fn tags(&self) -> Result<Reply, Fault> {
        let book = match self.book_or_fail(&self.guid, PERM_READ)? {
            Ok(b) => b,
            Err(r) => return Ok(r),
        };
        let rows = db::rows(self.c, r#"select * from "tags" where "tags"."address_book_id" = ? and "tags"."address_book_id" is not null order by "name" asc"#, &[P(book.val("id"))])?;
        Ok(Reply::Json(200, enc(&list(rows.iter().map(|t| obj(vec![("name", t.val("name")), ("color", Val::Int(t.val("color").to_int()))])).collect()))?))
    }

    /// POST /api/ab/peer/add/{guid}: success is 200 with an empty body.
    fn peer_add(&self) -> Result<Reply, Fault> {
        let book = match self.book_or_fail(&self.guid, PERM_READ_WRITE)? {
            Ok(b) => b,
            Err(r) => return Ok(r),
        };
        let id = self.input.string("id")?;
        if id.is_empty() {
            return error("id is required");
        }
        let exists = db::first(
            self.c,
            r#"select * from "address_book_entries" where "address_book_entries"."address_book_id" = ? and "address_book_entries"."address_book_id" is not null and "rustdesk_id" = ? limit 1"#,
            &[P(book.val("id")), P(Val::Str(id.clone()))],
        )?;
        if exists.is_some() {
            return error("Peer already exists");
        }
        // an add from the client arrives without an alias: fill it from the fleet, but only a device this person may see
        let mut alias = self.input.string("alias")?;
        if alias.is_empty() {
            let (cond, mut params) = self.visible_devices()?;
            params.push(P(Val::Str(id.clone())));
            let d = db::first(self.c, &format!(r#"select "alias" from "devices" where {cond} and "rustdesk_id" = ? limit 1"#), &params)?;
            alias = match d.map(|d| d.val("alias")) {
                None | Some(Val::Null) => vec![],
                Some(v) => v.to_php_string()?,
            };
        }
        let personal = book.val("is_personal").to_bool();
        let username = self.input.string("username")?;
        let hostname = self.input.string("hostname")?;
        let platform = self.input.string("platform")?;
        let hash = if personal { Val::Str(self.input.string("hash")?) } else { Val::Null };
        let password_enc = if !personal && filled(self.input, "password")? { Val::str(&self.n.crypt.encrypt_string(&self.input.string("password")?)) } else { Val::Null };
        let empty = Arr::new();
        let names = self.input.get("tags").map_or(empty.clone(), |v| v.to_array());
        let tag_ids = self.tag_names_to_ids(&book, &names)?;
        db::insert(
            self.c,
            "address_book_entries",
            vec![
                ("rustdesk_id", Val::Str(id)),
                ("alias", Val::Str(alias)),
                ("username", Val::Str(username)),
                ("hostname", Val::Str(hostname)),
                ("platform", Val::Str(platform)),
                ("hash", hash),
                ("password_enc", password_enc),
                ("tag_ids", Val::str(&Self::tag_ids_json(&tag_ids))),
                ("address_book_id", book.val("id")),
            ],
            &self.ts(),
        )?;
        Ok(Reply::stored())
    }

    /// PUT /api/ab/peer/update/{guid}: partial; an absent field is unchanged.
    fn peer_update(&self) -> Result<Reply, Fault> {
        let book = match self.book_or_fail(&self.guid, PERM_READ_WRITE)? {
            Ok(b) => b,
            Err(r) => return Ok(r),
        };
        let id = self.input.string("id")?;
        let entry = db::first(
            self.c,
            r#"select * from "address_book_entries" where "address_book_entries"."address_book_id" = ? and "address_book_entries"."address_book_id" is not null and "rustdesk_id" = ? limit 1"#,
            &[P(book.val("id")), P(Val::Str(id))],
        )?;
        let Some(mut entry) = entry else { return error("Peer not found") };
        let personal = book.val("is_personal").to_bool();
        let mut updates: Vec<(&str, Val, Cast)> = vec![];
        for field in ["alias", "username", "hostname", "platform"] {
            if self.input.has(field) {
                updates.push((field, Val::Str(self.input.string(field)?), Cast::Plain));
            }
        }
        if self.input.has("tags") {
            let names = self.input.get("tags").map_or(Arr::new(), |v| v.to_array());
            let t = self.tag_names_to_ids(&book, &names)?;
            updates.push(("tag_ids", Val::str(&Self::tag_ids_json(&t)), Cast::Json));
        }
        if self.input.has("hash") && personal {
            updates.push(("hash", Val::Str(self.input.string("hash")?), Cast::Plain));
        }
        if self.input.has("password") && !personal {
            updates.push(("password_enc", Val::str(&self.n.crypt.encrypt_string(&self.input.string("password")?)), Cast::Plain));
        }
        db::update_dirty(self.c, "address_book_entries", &mut entry, updates, &self.ts())?;
        Ok(Reply::stored())
    }

    /// DELETE /api/ab/peer/{guid}: the body is a JSON array of ids.
    fn peer_delete(&self) -> Result<Reply, Fault> {
        let book = match self.book_or_fail(&self.guid, PERM_READ_WRITE)? {
            Ok(b) => b,
            Err(r) => return Ok(r),
        };
        let wanted = json_strings(self.input)?;
        if !wanted.is_empty() {
            let sql = format!(
                r#"delete from "address_book_entries" where "address_book_entries"."address_book_id" = ? and "address_book_entries"."address_book_id" is not null and "rustdesk_id" in ({})"#,
                marks(wanted.len())
            );
            let mut params = vec![P(book.val("id"))];
            params.extend(wanted.into_iter().map(|w| P(Val::Str(w))));
            db::exec(self.c, &sql, &params)?;
        }
        Ok(Reply::stored())
    }

    /// POST /api/ab/tag/add/{guid}: managing tags needs full control.
    fn tag_add(&self) -> Result<Reply, Fault> {
        let book = match self.book_or_fail(&self.guid, PERM_FULL)? {
            Ok(b) => b,
            Err(r) => return Ok(r),
        };
        let name = self.input.string("name")?;
        if name.is_empty() {
            return error("name is required");
        }
        let found = db::first(
            self.c,
            r#"select * from "tags" where "tags"."address_book_id" = ? and "tags"."address_book_id" is not null and "name" = ? limit 1"#,
            &[P(book.val("id")), P(Val::Str(name.clone()))],
        )?;
        if found.is_none() {
            let color = self.input.get("color").map_or(0, |v| v.to_int());
            db::insert(self.c, "tags", vec![("name", Val::Str(name)), ("color", Val::Int(color)), ("address_book_id", book.val("id"))], &self.ts())?;
        }
        Ok(Reply::stored())
    }

    /// PUT /api/ab/tag/rename/{guid}: `{"old","new"}`. Entries refer to tags by id, so the rename follows by itself.
    fn tag_rename(&self) -> Result<Reply, Fault> {
        let book = match self.book_or_fail(&self.guid, PERM_FULL)? {
            Ok(b) => b,
            Err(r) => return Ok(r),
        };
        let old = self.input.string("old")?;
        let tag = db::first(
            self.c,
            r#"select * from "tags" where "tags"."address_book_id" = ? and "tags"."address_book_id" is not null and "name" = ? limit 1"#,
            &[P(book.val("id")), P(Val::Str(old))],
        )?;
        let Some(mut tag) = tag else { return error("Tag not found") };
        let new = Val::Str(self.input.string("new")?);
        db::update_dirty(self.c, "tags", &mut tag, vec![("name", new, Cast::Plain)], &self.ts())?;
        Ok(Reply::stored())
    }

    /// PUT /api/ab/tag/update/{guid}: a colour change (a mass update: `updated_at` moves on every match).
    fn tag_update(&self) -> Result<Reply, Fault> {
        let book = match self.book_or_fail(&self.guid, PERM_FULL)? {
            Ok(b) => b,
            Err(r) => return Ok(r),
        };
        let name = self.input.string("name")?;
        let color = self.input.get("color").map_or(0, |v| v.to_int());
        db::exec(
            self.c,
            r#"update "tags" set "color" = ?, "updated_at" = ? where "tags"."address_book_id" = ? and "tags"."address_book_id" is not null and "name" = ?"#,
            &[P(Val::Int(color)), P(Val::str(&self.ts())), P(book.val("id")), P(Val::Str(name))],
        )?;
        Ok(Reply::stored())
    }

    /// DELETE /api/ab/tag/{guid}: the body is a JSON array of names; detached from the entries first.
    fn tag_delete(&self) -> Result<Reply, Fault> {
        let book = match self.book_or_fail(&self.guid, PERM_FULL)? {
            Ok(b) => b,
            Err(r) => return Ok(r),
        };
        let names = json_strings(self.input)?;
        let tag_ids: Vec<i64> = if names.is_empty() {
            vec![]
        } else {
            let sql = format!(r#"select "id" from "tags" where "tags"."address_book_id" = ? and "tags"."address_book_id" is not null and "name" in ({})"#, marks(names.len()));
            let mut params = vec![P(book.val("id"))];
            params.extend(names.into_iter().map(|w| P(Val::Str(w))));
            db::rows(self.c, &sql, &params)?.iter().map(|r| r.val("id").to_int()).collect()
        };
        if !tag_ids.is_empty() {
            let entries = db::rows(self.c, r#"select * from "address_book_entries" where "address_book_entries"."address_book_id" = ? and "address_book_entries"."address_book_id" is not null"#, &[P(book.val("id"))])?;
            for mut e in entries {
                let current = tag_ids_of(&e)?;
                let mut kept = Arr::new();
                for (_, v) in current.iter() {
                    // array_diff compares string forms
                    let s = v.to_php_string()?;
                    if !tag_ids.iter().any(|t| t.to_string().as_bytes() == s.as_slice()) {
                        kept.push(v.clone());
                    }
                }
                // `$kept !== ($e->tag_ids ?? [])`
                if Val::Arr(kept.clone()) != Val::Arr(current) {
                    let json = enc(&Val::Arr(kept))?;
                    db::update_dirty(self.c, "address_book_entries", &mut e, vec![("tag_ids", Val::str(&json), Cast::Json)], &self.ts())?;
                }
            }
            let sql = format!(r#"delete from "tags" where "id" in ({})"#, marks(tag_ids.len()));
            db::exec(self.c, &sql, &ids(&tag_ids))?;
        }
        Ok(Reply::stored())
    }

    // ------------------------------------------------------------------------------------- legacy address book ---

    /// GET /api/ab (and POST /api/ab/get): the triple-encoded pull of the personal book.
    fn legacy_get(&self) -> Result<Reply, Fault> {
        let book = self.personal_for()?;
        let tags = db::rows(self.c, r#"select * from "tags" where "tags"."address_book_id" = ? and "tags"."address_book_id" is not null"#, &[P(book.val("id"))])?;
        let entries = db::rows(self.c, r#"select * from "address_book_entries" where "address_book_entries"."address_book_id" = ? and "address_book_entries"."address_book_id" is not null"#, &[P(book.val("id"))])?;
        let mut peers = vec![];
        for e in &entries {
            peers.push(obj(vec![
                ("id", e.val("rustdesk_id")),
                ("username", sv(e, "username")?),
                ("hostname", sv(e, "hostname")?),
                ("platform", sv(e, "platform")?),
                ("alias", sv(e, "alias")?),
                ("tags", list(Self::names_of(&tags, e)?)),
                ("hash", sv(e, "hash")?),
            ]));
        }
        // tag_colors is a JSON string INSIDE the JSON-string data field
        let mut colors = Arr::new();
        for t in &tags {
            colors.set(key_of(&t.val("name"))?, Val::Int(t.val("color").to_int()));
        }
        let tag_colors = php::json_encode(&Val::Arr(colors)).map_or(Val::Bool(false), |s| Val::str(&s));
        let payload = obj(vec![("tags", list(tags.iter().map(|t| t.val("name")).collect())), ("peers", list(peers)), ("tag_colors", tag_colors)]);
        let data = php::json_encode(&payload).map_or(Val::Bool(false), |s| Val::str(&s));
        Ok(Reply::Json(200, enc(&obj(vec![("data", data), ("licensed_devices", Val::Int(0))]))?))
    }

    /// POST /api/ab: a full replace of the personal book.
    fn legacy_push(&self) -> Result<Reply, Fault> {
        let book = self.personal_for()?;
        let data = self.input.string("data")?;
        let decoded = match php::json_decode(&data, &JsonOpts::default()) {
            Some(Val::Arr(a)) => a,
            _ => return error("Malformed address book payload"),
        };
        let colors_src = match decoded.get_str("tag_colors") {
            None | Some(Val::Null) => vec![],
            Some(v) => v.to_php_string()?,
        };
        // `json_decode(...) ?: []`
        let tag_colors = match php::json_decode(&colors_src, &JsonOpts::default()) {
            Some(Val::Arr(a)) => a,
            _ => Arr::new(),
        };
        let ts = self.ts();
        let book_id = book.val("id");

        // rebuild the tags
        db::exec(self.c, r#"delete from "tags" where "tags"."address_book_id" = ? and "tags"."address_book_id" is not null"#, &[P(book_id.clone())])?;
        let mut id_by_name = Arr::new();
        let tag_list = decoded.get_str("tags").map_or(Arr::new(), |v| v.to_array());
        for (_, name) in tag_list.iter() {
            let name_s = name.to_php_string()?;
            let color = match tag_colors.get(&key_of(name)?) {
                Some(v) => v.to_int(),
                None => 0,
            };
            let id = db::insert(self.c, "tags", vec![("name", Val::Str(name_s)), ("color", Val::Int(color)), ("address_book_id", book_id.clone())], &ts)?;
            id_by_name.set(key_of(name)?, Val::Int(id));
        }

        // rebuild the entries
        db::exec(self.c, r#"delete from "address_book_entries" where "address_book_entries"."address_book_id" = ? and "address_book_entries"."address_book_id" is not null"#, &[P(book_id.clone())])?;
        let peers = decoded.get_str("peers").map_or(Arr::new(), |v| v.to_array());
        for (_, peer) in peers.iter() {
            let Val::Arr(p) = peer else { continue };
            let id = match p.get_str("id") {
                None | Some(Val::Null) => continue,
                Some(Val::Str(s)) if s.is_empty() => continue,
                Some(v) => v.to_php_string()?,
            };
            let field = |k: &str| -> Result<Val, Fault> {
                Ok(Val::Str(match p.get_str(k) {
                    None | Some(Val::Null) => vec![],
                    Some(v) => v.to_php_string()?,
                }))
            };
            let mut tag_ids: Vec<i64> = vec![];
            let peer_tags = p.get_str("tags").map_or(Arr::new(), |v| v.to_array());
            for (_, n) in peer_tags.iter() {
                if let Some(Val::Int(i)) = id_by_name.get(&key_of(n)?) {
                    tag_ids.push(*i);
                }
            }
            db::insert(
                self.c,
                "address_book_entries",
                vec![
                    ("rustdesk_id", Val::Str(id)),
                    ("username", field("username")?),
                    ("hostname", field("hostname")?),
                    ("platform", field("platform")?),
                    ("alias", field("alias")?),
                    ("hash", field("hash")?),
                    ("tag_ids", Val::str(&Self::tag_ids_json(&tag_ids))),
                    ("address_book_id", book_id.clone()),
                ],
                &ts,
            )?;
        }
        Ok(Reply::Json(200, "{}".into()))
    }

    // ------------------------------------------------------------------------------------------- server-config ---

    /// `Setting::server($name)`: the saved setting, else the environment's value (as `config('cortendesk.*')` has it).
    fn server_value(&self, name: &str, env: &[&str]) -> Result<String, Fault> {
        let saved = db::setting(self.c, name, "")?;
        let saved = String::from_utf8_lossy(php::trim(&saved)).into_owned();
        if !saved.is_empty() {
            return Ok(saved);
        }
        Ok(env.iter().map(|e| env_trim(e)).find(|v| !v.is_empty()).unwrap_or_default())
    }

    /// GET|POST /api/server-config: `{code, message, data: {id_server, key, peers}}`, the peers being the first 100
    /// entries of the personal book as peer cards.
    fn server_config(&self) -> Result<Reply, Fault> {
        let book = self.personal_for()?;
        let entries = db::rows(self.c, r#"select * from "address_book_entries" where "address_book_entries"."address_book_id" = ? and "address_book_entries"."address_book_id" is not null limit 100"#, &[P(book.val("id"))])?;
        // `now()->subDay()->getPreciseTimestamp(0)` is whole seconds here; the microseconds PHP rounds with are not known
        let tm = (self.now - 86_400).saturating_mul(1_000_000_000);
        let mut peers = String::from("{");
        for (i, e) in entries.iter().enumerate() {
            let card = obj(vec![
                ("view-style", Val::str("shrink")),
                ("tm", Val::Int(tm)),
                (
                    "info",
                    obj(vec![("username", sv(e, "username")?), ("hostname", sv(e, "hostname")?), ("platform", sv(e, "platform")?), ("hash", sv(e, "hash")?), ("id", sv(e, "rustdesk_id")?)]),
                ),
                ("tmppwd", Val::str("")),
            ]);
            if i > 0 {
                peers.push(',');
            }
            // `(object) $peers`: always an object, keyed by the id as text
            peers += &format!("{}:{}", jstr(&e.val("rustdesk_id").to_php_string()?)?, enc(&card)?);
        }
        peers.push('}');
        let id_server = jstr(self.server_value("id_server", &["HTE_CONSOLE_ID_SERVER", "CORTENDESK_ID_SERVER"])?.as_bytes())?;
        let key = jstr(self.server_value("public_key", &["HTE_CONSOLE_PUBLIC_KEY", "CORTENDESK_PUBLIC_KEY"])?.as_bytes())?;
        Ok(Reply::Json(200, format!(r#"{{"code":0,"message":"success","data":{{"id_server":{id_server},"key":{key},"peers":{peers}}}}}"#)))
    }

    // ------------------------------------------------------------------------------------------------ group tab ---

    /// GET /api/device-group/accessible: only `name` is read by the client.
    fn device_groups(&self) -> Result<Reply, Fault> {
        let mut cond = String::new();
        let mut params = vec![];
        if !self.admin() {
            let g = self.accessible_device_group_ids()?;
            if g.is_empty() {
                cond = " where 0 = 1".into();
            } else {
                cond = format!(r#" where "id" in ({})"#, marks(g.len()));
                params = ids(&g);
            }
        }
        let total = db::first(self.c, &format!(r#"select count(*) as "aggregate" from "device_groups"{cond}"#), &params)?.map_or(0, |r| r.val("aggregate").to_int());
        let rows = db::rows(self.c, &format!(r#"select * from "device_groups"{cond} order by "name" asc{}"#, self.page_sql()), &params)?;
        let data = rows.iter().map(|g| obj(vec![("name", g.val("name"))])).collect();
        Ok(Reply::Json(200, enc(&obj(vec![("total", Val::Int(total)), ("data", list(data))]))?))
    }

    /// GET /api/users: group-mates and groups accessed from the person's own; `status=1` filters to active.
    fn users(&self) -> Result<Reply, Fault> {
        let mut cond = vec![];
        let mut params = vec![];
        if !self.admin() {
            let v = self.visible_user_ids()?;
            cond.push(format!(r#""id" in ({})"#, marks(v.len())));
            params.extend(ids(&v));
        }
        if self.input.query_string("status")? == b"1" {
            cond.push(r#""is_active" = ?"#.to_string());
            params.push(P(Val::Bool(true)));
        }
        let wh = if cond.is_empty() { String::new() } else { format!(" where {}", cond.join(" and ")) };
        let total = db::first(self.c, &format!(r#"select count(*) as "aggregate" from "users"{wh}"#), &params)?.map_or(0, |r| r.val("aggregate").to_int());
        let rows = db::rows(self.c, &format!(r#"select * from "users"{wh} order by "username" asc{}"#, self.page_sql()), &params)?;
        let mut data = vec![];
        for u in &rows {
            data.push(crate::signin::user_payload(u)?);
        }
        Ok(Reply::Json(200, format!(r#"{{"total":{total},"data":[{}]}}"#, data.join(","))))
    }

    /// `Device::onlineWindow()`: the `online_window` setting, else `CORTENDESK_ONLINE_WINDOW`, else 60; 0 means 60.
    fn online_window(&self) -> Result<i64, Fault> {
        let default = std::env::var("CORTENDESK_ONLINE_WINDOW").ok().filter(|v| !v.is_empty()).unwrap_or_else(|| "60".into());
        let v = db::setting(self.c, "online_window", &default)?;
        Ok(if v.is_empty() || v == b"0" { 60 } else { php::str_to_int(&v) })
    }

    /// GET /api/peers: PeerPayload with `info` as an object, the devices the person may see.
    fn peers(&self) -> Result<Reply, Fault> {
        let (cond, params) = self.visible_devices()?;
        let total = db::first(self.c, &format!(r#"select count(*) as "aggregate" from "devices" where {cond}"#), &params)?.map_or(0, |r| r.val("aggregate").to_int());
        let rows = db::rows(self.c, &format!(r#"select * from "devices" where {cond} order by "rustdesk_id" asc{}"#, self.page_sql()), &params)?;
        let window = self.online_window()?;
        let mut data = vec![];
        for d in &rows {
            let owner = match d.val("user_id") {
                Val::Null => None,
                v => db::first(self.c, r#"select "id", "username" from "users" where "id" = ? limit 1"#, &[P(v)])?,
            };
            let group = match d.val("device_group_id") {
                Val::Null => None,
                v => db::first(self.c, r#"select "id", "name" from "device_groups" where "id" = ? limit 1"#, &[P(v)])?,
            };
            let owner_name = match &owner {
                Some(o) => Val::Str(o.val("username").to_php_string()?),
                None => Val::str(""),
            };
            let online = match d.val("last_online_at") {
                Val::Null => false,
                v => laravel::parse_ts(&v).ok_or_else(|| Fault::Other("unparsable devices.last_online_at".into()))? > self.now - window,
            };
            data.push(obj(vec![
                ("id", d.val("rustdesk_id")),
                ("info", obj(vec![("username", sv(d, "username")?), ("os", sv(d, "os")?), ("device_name", sv(d, "hostname")?)])),
                ("status", Val::Int(online as i64)),
                ("user", owner_name.clone()),
                ("user_name", owner_name),
                ("device_group_name", match &group {
                    Some(g) => Val::Str(g.val("name").to_php_string()?),
                    None => Val::str(""),
                }),
                ("note", sv(d, "note")?),
            ]));
        }
        Ok(Reply::Json(200, enc(&obj(vec![("total", Val::Int(total)), ("data", list(data))]))?))
    }

    // ---------------------------------------------------------------------------------------------- audit ---

    /// `tokenDevice()`: the device the bearer token was issued to.
    fn token_device(&self) -> Result<Vec<u8>, Fault> {
        self.token.val("device_id").to_php_string()
    }

    /// GET /api/audit/conn/active?id&session_id&conn_type: the guid of the session this token's device opened.
    fn audit_active(&self) -> Result<Reply, Fault> {
        let id = self.input.query_string("id")?;
        let session = self.input.query_string("session_id")?;
        let device = self.token_device()?;
        if id.is_empty() || session.is_empty() || session == b"0" || device.is_empty() {
            return Ok(Reply::Json(200, r#""""#.into()));
        }
        let mut sql = String::from(r#"select * from "audit_connections" where "rustdesk_id" = ? and "session_id" = ? and "from_peer" = ?"#);
        let mut params = vec![P(Val::Str(id)), P(Val::Str(session)), P(Val::Str(device))];
        if let Some(t) = self.input.query("conn_type").filter(|t| t.is_numeric()) {
            sql += r#" and "conn_type" = ?"#;
            params.push(P(Val::Int(t.to_int())));
        }
        sql += r#" order by "id" desc limit 1"#;
        let Some(mut row) = db::first(self.c, &sql, &params)? else { return Ok(Reply::Json(200, r#""""#.into())) };
        // rows recorded before guids existed get one on first request
        if matches!(row.val("guid"), Val::Null) {
            db::update_dirty(self.c, "audit_connections", &mut row, vec![("guid", Val::str(&laravel::uuid4()), Cast::Plain)], &self.ts())?;
        }
        Ok(Reply::Json(200, jstr(&row.val("guid").to_php_string()?)?))
    }

    /// PUT /api/audit {guid, note}: the end-of-session note of the person who opened the session.
    fn audit_note(&self) -> Result<Reply, Fault> {
        let guid = self.input.string("guid")?;
        let note = crate::audit::clean_note(self.input.get("note"));
        let Some(note) = note.filter(|_| !guid.is_empty()) else { return Ok(Reply::Json(200, "{}".into())) };
        let row = db::first(self.c, r#"select * from "audit_connections" where "guid" = ? limit 1"#, &[P(Val::Str(guid))])?;
        let Some(mut row) = row else { return Ok(Reply::Json(404, r#"{"error":"Unknown session"}"#.into())) };
        let device = self.token_device()?;
        if device.is_empty() || row.val("from_peer") != Val::Str(device) {
            return Ok(Reply::Json(403, r#"{"error":"Not your session"}"#.into()));
        }
        let uid = self.uid();
        if !matches!(row.val("note_user_id"), Val::Null) && row.val("note_user_id") != Val::Int(uid) {
            return Ok(Reply::Json(409, r#"{"error":"Another user already left a note"}"#.into()));
        }
        let ts = self.ts();
        db::update_dirty(
            self.c,
            "audit_connections",
            &mut row,
            vec![("note", Val::Str(note), Cast::Plain), ("note_user_id", Val::Int(uid), Cast::Int), ("noted_at", Val::str(&ts), Cast::Date)],
            &ts,
        )?;
        Ok(Reply::Json(200, "{}".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_follows_laravel() {
        assert_eq!(lookup("GET", b"/api/ab"), Lookup::Found(R::AbGet, vec![]));
        assert_eq!(lookup("HEAD", b"/api/ab"), Lookup::Found(R::AbGet, vec![]));
        assert_eq!(lookup("POST", b"/api/ab"), Lookup::Found(R::AbPush, vec![]));
        // the methods of the other routes of the URI, in Laravel's verb order
        assert_eq!(lookup("PUT", b"/api/ab"), Lookup::NotAllowed(vec!["GET", "HEAD", "POST"]));
        assert_eq!(lookup("DELETE", b"/api/server-config"), Lookup::NotAllowed(vec!["GET", "HEAD", "POST"]));
        assert_eq!(lookup("GET", b"/api/audit"), Lookup::NotAllowed(vec!["PUT"]));
        // trailing slashes are ignored, a guid is one non-empty segment, decoded
        assert_eq!(lookup("POST", b"/api/ab/tags/abc/"), Lookup::Found(R::AbTags, b"abc".to_vec()));
        assert_eq!(lookup("POST", b"/api/ab/tags/a%62c"), Lookup::Found(R::AbTags, b"abc".to_vec()));
        assert_eq!(lookup("POST", b"/api/ab/tags/"), Lookup::NoRoute);
        assert_eq!(lookup("POST", b"/api/ab/tags/a%2Fb"), Lookup::NoRoute);
        // `add` is a legal guid for the DELETE route
        assert_eq!(lookup("DELETE", b"/api/ab/peer/add"), Lookup::Found(R::PeerDelete, b"add".to_vec()));
        assert_eq!(lookup("DELETE", b"/api/ab/peer/add/xyz"), Lookup::NotAllowed(vec!["POST"]));
        assert_eq!(lookup("GET", b"/api/ab/nothing"), Lookup::NoRoute);
        assert_eq!(lookup("GET", b"/webclient-config/index.js"), Lookup::Found(R::ConfigJs, vec![]));
    }

    #[test]
    fn loose_equality_of_tag_ids() {
        assert!(loose_eq(5, &Val::Int(5)));
        assert!(loose_eq(5, &Val::str("5")));
        assert!(loose_eq(5, &Val::str("5.0")));
        assert!(!loose_eq(5, &Val::str("5abc")));
        assert!(!loose_eq(5, &Val::str("abc")));
        assert!(!loose_eq(5, &Val::Null));
    }

    #[test]
    fn decoding_is_rawurldecode() {
        assert_eq!(rawurldecode(b"a%20b+c%zz%4"), b"a b+c%zz%4");
    }
}
