//! Settings -> API tokens (Livewire `ApiTokenManager`): create a scoped bearer token for the automation API, list
//! them, revoke. Only the sha256 is stored; the plaintext is shown once, in the answer to the create post itself (it
//! is never put in the session, a flash or a log).

use super::kit::*;
use super::{Ctx, Reply, Req};
use crate::php::{self, Fault, Val};
use crate::sqlite::{self as db, P};
use rusqlite::Connection;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const RESOURCES: &[(&str, &str)] = &[("device", "Devices"), ("user", "Users"), ("group", "Groups"), ("strategy", "Strategies"), ("address_book", "Address books"), ("audit", "Audit logs")];
const LEVELS: &[&str] = &["none", "r", "rw"];

struct Form {
    name: String,
    days: String,
    perms: Vec<(String, String)>,
    error: String,
    plaintext: String,
    status: u16,
}

fn blank() -> Form {
    Form { name: String::new(), days: String::new(), perms: RESOURCES.iter().map(|(k, _)| (k.to_string(), "none".to_string())).collect(), error: String::new(), plaintext: String::new(), status: 200 }
}

fn render(ctx: &Ctx, c: &Connection, f: Form) -> Result<Reply, Fault> {
    let tokens = db::rows(c, r#"select "api_tokens".*, "users"."username" as "creator" from "api_tokens" left join "users" on "users"."id" = "api_tokens"."user_id" order by "api_tokens"."created_at" desc"#, &[])?;
    let items: Vec<Value> = tokens
        .iter()
        .map(|t| {
            let perms: Vec<Value> = match serde_json::from_slice::<Value>(&t.val("permissions").to_php_string().unwrap_or_default()) {
                Ok(Value::Object(m)) => RESOURCES
                    .iter()
                    .filter_map(|(k, label)| {
                        let l = m.get(*k).and_then(|v| v.as_str()).unwrap_or("none");
                        (l != "none").then(|| json!({"label": label, "level": l.to_uppercase(), "rw": l == "rw"}))
                    })
                    .collect(),
                _ => vec![],
            };
            let expires = ts_of(t, "expires_at");
            json!({
                "id": t.id(), "name": s(t, "name"), "prefix": s(t, "token_prefix"), "perms": perms, "creator": opt(t, "creator").unwrap_or_else(|| "—".into()),
                "last_used": human(t, "last_used_at", ctx.now, false), "last_used_title": ts_of(t, "last_used_at").map(crate::laravel::ts).unwrap_or_default(),
                "expires": ymd(t, "expires_at"), "expired": expires.map_or(false, |e| e <= ctx.now),
            })
        })
        .collect();
    let can_write = ctx.allows("token", "rw");
    let resources: Vec<Value> = RESOURCES.iter().map(|(k, l)| json!({"key": k, "label": l, "level": f.perms.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str()).unwrap_or("none")})).collect();
    let layout = ctx.layout(c, "api-tokens", "API tokens", "System")?;
    let page = json!({"tokens": items, "can_write": can_write, "resources": resources, "name": f.name, "days": f.days, "error": f.error, "plaintext": f.plaintext});
    Ok(Reply::Html(f.status, ctx.render("api-tokens/index.html", layout, page)?))
}

/// GET /api-tokens
pub fn index(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    if req.method == "POST" {
        return create(ctx, c, req);
    }
    render(ctx, c, blank())
}

/// What the person holds on a resource caps what a token they make may hold (`clampToCreator`).
fn ceiling(ctx: &Ctx, resource: &str) -> &'static str {
    if ctx.allows(resource, "rw") {
        "rw"
    } else if ctx.allows(resource, "r") {
        "r"
    } else {
        "none"
    }
}

fn rank(l: &str) -> u8 {
    match l {
        "rw" => 2,
        "r" => 1,
        _ => 0,
    }
}

/// POST /api-tokens
fn create(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    if !ctx.allows("token", "rw") {
        return Ok(abort(403));
    }
    let body = Body::of(req);
    let mut f = blank();
    f.name = body.get("name");
    f.days = body.get("expires_days");
    for (k, _) in RESOURCES {
        let v = body.get(&format!("perm_{k}"));
        let v = if v.is_empty() { "none".to_string() } else { v };
        if let Some(slot) = f.perms.iter_mut().find(|(n, _)| n == k) {
            slot.1 = v;
        }
    }
    let fail = |mut f: Form, msg: &str| -> Form {
        f.error = msg.to_string();
        f.status = 422;
        f
    };
    if f.name.trim().is_empty() {
        return render(ctx, c, fail(f, "A name is needed."));
    }
    if f.name.chars().count() > 255 {
        return render(ctx, c, fail(f, "The name may not be greater than 255 characters."));
    }
    let days: Option<i64> = if f.days.trim().is_empty() {
        None
    } else {
        match f.days.trim().parse::<i64>() {
            Ok(n) if (1..=3650).contains(&n) => Some(n),
            _ => return render(ctx, c, fail(f, "Expires after must be a whole number of days from 1 to 3650.")),
        }
    };
    if f.perms.iter().any(|(_, v)| !LEVELS.contains(&v.as_str())) {
        return render(ctx, c, fail(f, "A permission level is not valid."));
    }
    if f.perms.iter().all(|(_, v)| v == "none") {
        return render(ctx, c, fail(f, "Grant at least one resource permission."));
    }
    let clamped: Vec<(String, Val)> = f.perms.iter().map(|(k, v)| (k.clone(), Val::str(if rank(v) > rank(ceiling(ctx, k)) { ceiling(ctx, k) } else { v }))).collect();
    let plain = format!("cdk_{}", crate::laravel::str_random(40));
    let now = crate::laravel::ts(ctx.now);
    let expires = days.map_or(Val::Null, |d| Val::str(&crate::laravel::ts(ctx.now + d * 86_400)));
    let id = db::insert(
        c,
        "api_tokens",
        vec![
            ("name", Val::str(f.name.trim_end())),
            ("token_hash", Val::str(&hex::encode(Sha256::digest(plain.as_bytes())))),
            ("token_prefix", Val::str(&plain[..12])),
            ("user_id", Val::Int(ctx.uid())),
            ("permissions", Val::str(&php::json_encode(&php::assoc(clamped)).unwrap_or_else(|| "{}".into()))),
            ("expires_at", expires),
            ("is_active", Val::Int(1)),
        ],
        &now,
    )?;
    audit(ctx, c, "api-token.create", &format!("Created API token {}", f.name.trim_end()), Some("api_token"), Some(&id.to_string()))?;
    let mut out = blank();
    out.plaintext = plain;
    render(ctx, c, out)
}

/// POST /api-tokens/revoke
pub fn revoke(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    if !ctx.allows("token", "rw") {
        return Ok(abort(403));
    }
    let id = Body::of(req).int("id");
    if let Some(t) = find(c, "api_tokens", id)? {
        db::exec(c, r#"delete from "api_tokens" where "id" = ?"#, &[P(Val::Int(id))])?;
        audit(ctx, c, "api-token.revoke", &format!("Revoked API token {}", s(&t, "name")), Some("api_token"), Some(&id.to_string()))?;
    }
    Ok(Reply::Redirect("/api-tokens".into()))
}
