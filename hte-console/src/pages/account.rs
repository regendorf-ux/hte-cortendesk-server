//! "My Account" (`AccountProfile` + the two-factor card): the signed-in person's own name, email, password and theme.
//!
//! The Livewire component's three actions are plain form posts here (`/account/profile`, `/account/password`); a
//! success redirects to the page with a one-request flash ("Profile saved."), a validation error renders the page
//! again (422) with the messages and what was typed, as the component did in place. Each form carries `_token`; htmx
//! swaps the result into `#account-cards` so the page does not reload. The theme radios post `/account/theme`
//! (`AccountThemeController`), exactly as the top bar's switch does.
//!
//! What it writes is what PHP writes: `users.name`/`email` (dirty attributes only, then `updated_at`), `password`
//! (a `$2y$` bcrypt hash), the person's `trusted_devices`, a regenerated session, and `console_audits` rows
//! (`account.update`, `account.password`).

use super::{row_json, session, Ctx, Reply, Req};
use crate::laravel::Cast;
use crate::php::{self, Arr, Fault, Val};
use crate::sqlite::{self as db, P};
use crate::validate::{self, Rule};
use rusqlite::Connection;
use serde_json::{json, Map, Value};

fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn text(v: Option<&Val>) -> String {
    match v {
        Some(Val::Str(b)) => lossy(b),
        _ => String::new(),
    }
}

fn truthy(s: &str) -> bool {
    !s.is_empty() && s != "0"
}

/// What the cards show besides the person's row: what was typed and the messages, per form.
#[derive(Default)]
struct Form {
    name: Option<String>,
    email: Option<String>,
    errors: Map<String, Value>,
}

impl Form {
    fn error(&mut self, field: &str, message: &str) {
        self.errors.entry(field.to_string()).or_insert_with(|| json!(message));
    }
}

fn page(ctx: &Ctx, c: &Connection, status: u16, form: Form) -> Result<Reply, Fault> {
    let user = &ctx.user;
    let s = |col: &str| lossy(&user.val(col).to_php_string().unwrap_or_default());
    let (username, name, email) = (s("username"), s("name"), s("email"));
    let sso_provisioned = s("auth_provider") == "oidc";
    let sso_linked = !s("oidc_sub").is_empty();
    let enabled = user.val("totp_enabled").to_bool();
    let remaining = if enabled {
        db::first(c, r#"select count(*) as aggregate from "two_factor_recovery_codes" where "user_id" = ? and "used_at" is null"#, &[P(Val::Int(ctx.uid()))])?.map(|r| r.val("aggregate").to_int()).unwrap_or(0)
    } else {
        0
    };
    let required = {
        let flag = |k: &str| -> Result<bool, Fault> { Ok(db::setting(c, k, "0")? == b"1") };
        flag("two_factor_required")? || (ctx.is_admin() && flag("two_factor_required_admins")?) || ctx.role.as_ref().map_or(false, |r| r.val("require_two_factor").to_bool())
    };
    let confirmed_at = crate::laravel::parse_ts(&user.val("totp_confirmed_at")).map(|t| crate::laravel::ts(t)[..10].to_string()).unwrap_or_default();
    let flash = |k: &str| ctx.flashed.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let layout = ctx.layout(c, "account", "My Account", "Account")?;
    let errors: Map<String, Value> = ["name", "email", "currentPassword", "password", "passwordConfirmation"].iter().map(|k| (k.to_string(), form.errors.get(*k).cloned().unwrap_or_else(|| json!("")))).collect();
    let page = json!({
        "profile": {
            "username": username,
            "initial": username.chars().next().map(|c| c.to_uppercase().collect::<String>()).unwrap_or_default(),
            "title": if truthy(&name) { name.clone() } else { username.clone() },
            "email_line": if truthy(&email) { email.clone() } else { "no email on file".to_string() },
            "is_admin": ctx.is_admin(),
            "sso_linked": sso_linked,
            "sso_provisioned": sso_provisioned,
            "name": form.name.clone().unwrap_or(name.clone()),
            "email": form.email.clone().unwrap_or(email.clone()),
        },
        "errors": errors,
        "profile_saved": flash("profile_saved") == "1",
        "password_saved": flash("password_saved") == "1",
        "email_required": flash("email_required"),
        "twofactor_warning": flash("twofactor_warning"),
        "email_overdue": email.trim().is_empty() && !sso_provisioned,
        "tfa": {"enabled": enabled, "required": required, "remaining": remaining, "confirmed_at": confirmed_at},
        "my_theme": ctx.theme(),
    });
    Ok(Reply::Html(status, ctx.render("account/index.html", layout, page)?))
}

pub fn show(ctx: &Ctx, c: &Connection, _req: &Req) -> Result<Reply, Fault> {
    page(ctx, c, 200, Form::default())
}

/// The messages of a failed `validate_db`, first per field.
fn first_messages(body: &str, form: &mut Form) {
    let Ok(v) = serde_json::from_str::<Value>(body) else { return };
    if let Some(errors) = v.get("errors").and_then(|e| e.as_object()) {
        for (k, list) in errors {
            if let Some(m) = list.get(0).and_then(|m| m.as_str()) {
                form.error(k, m);
            }
        }
    }
}

/// `Rule::unique('users', 'email')->ignore($id)`.
fn unique_probe(c: &Connection, rule: &validate::Rule, v: &Val) -> Result<bool, Fault> {
    match rule {
        Rule::Unique(table, col, ignore) => {
            let mut sql = format!(r#"select count(*) as aggregate from "{table}" where "{col}" = ?"#);
            let mut p = vec![P(v.clone())];
            if let Some(id) = ignore {
                sql.push_str(r#" and "id" <> ?"#);
                p.push(P(Val::Int(*id)));
            }
            Ok(db::first(c, &sql, &p)?.map(|r| r.val("aggregate").to_int()).unwrap_or(0) == 0)
        }
        _ => Ok(true),
    }
}

/// `ConsoleAudit::record(...)` for the signed-in person.
fn audit(ctx: &Ctx, c: &Connection, action: &str, summary: &str) -> Result<(), Fault> {
    db::exec(
        c,
        r#"insert into "console_audits" ("user_id", "username", "action", "target_type", "target_id", "summary", "ip", "created_at") values (?, ?, ?, ?, ?, ?, ?, ?)"#,
        &[
            P(ctx.user.val("id")),
            P(ctx.user.val("username")),
            P(Val::str(action)),
            P(Val::str("user")),
            P(Val::str(&ctx.uid().to_string())),
            P(Val::str(&validate::str_limit(summary, 250, "..."))),
            P(Val::str(&ctx.ip)),
            P(Val::str(&crate::laravel::ts(ctx.now))),
        ],
    )?;
    Ok(())
}

/// The form body as Livewire's properties would hold it: no trimming, no empty-to-null.
fn form_body(req: &Req) -> Arr {
    php::parse_str(&req.input.raw)
}

pub fn save_profile(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    let body = form_body(req);
    let mut data = Arr::new();
    for k in ["name", "email"] {
        data.set(php::Key::Str(k.as_bytes().to_vec()), Val::str(&text(body.get_str(k))));
    }
    let uid = ctx.uid();
    let rules: [(&str, &[Rule]); 2] = [
        ("name", &[Rule::Nullable, Rule::String, Rule::Max(255)]),
        ("email", &[Rule::Nullable, Rule::Email, Rule::Max(255), Rule::Unique("users", "email", Some(uid))]),
    ];
    let probe = |rule: &Rule, v: &Val| unique_probe(c, rule, v);
    match validate::validate_db(&data, &rules, &probe)? {
        Err(json) => {
            let mut form = Form { name: Some(text(data.get_str("name"))), email: Some(text(data.get_str("email"))), ..Form::default() };
            first_messages(&json, &mut form);
            page(ctx, c, 422, form)
        }
        Ok(valid) => {
            let (name, email) = (text(valid.get_str("name")), text(valid.get_str("email")));
            let nullable = |s: &str| if s.is_empty() { Val::Null } else { Val::str(s) };
            let mut row = ctx.user.clone();
            db::update_dirty(c, "users", &mut row, vec![("name", nullable(&name), Cast::Plain), ("email", nullable(&email), Cast::Plain)], &crate::laravel::ts(ctx.now))?;
            audit(ctx, c, "account.update", "Updated own profile")?;
            ctx.flash("profile_saved", json!("1"));
            Ok(Reply::Redirect("/account".into()))
        }
    }
}

pub fn update_password(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    let sso = lossy(&ctx.user.val("auth_provider").to_php_string().unwrap_or_default()) == "oidc";
    let mut form = Form::default();
    if sso {
        form.error("currentPassword", "This account signs in through single sign-on.");
        return page(ctx, c, 422, form);
    }
    let body = form_body(req);
    let current = body.get_str("current_password").map(|v| v.to_php_string().unwrap_or_default()).unwrap_or_default();
    let new = body.get_str("password").map(|v| v.to_php_string().unwrap_or_default()).unwrap_or_default();
    let confirm = body.get_str("password_confirmation").map(|v| v.to_php_string().unwrap_or_default()).unwrap_or_default();
    // required: a value that is not blank once trimmed; string: always true for form input
    let blank = |b: &[u8]| php::trim(b).is_empty();
    if blank(&current) {
        form.error("currentPassword", "The current password field is required.");
    }
    if blank(&new) {
        form.error("password", "The password field is required.");
    } else {
        if crate::validate::mb_strlen(&new) < 8 {
            form.error("password", "The password field must be at least 8 characters.");
        }
        if new != confirm {
            form.error("password", "The new passwords do not match.");
        }
    }
    if blank(&confirm) {
        form.error("passwordConfirmation", "Please confirm the new password.");
    }
    if !form.errors.is_empty() {
        return page(ctx, c, 422, form);
    }
    // proving the current password is what stops a hijacked session from locking the owner out
    if !crate::laravel::hash_check(&current, &ctx.user.val("password"))? {
        form.error("currentPassword", "That is not your current password.");
        return page(ctx, c, 422, form);
    }
    let hash = crate::laravel::hash_make(&new)?;
    let mut row = ctx.user.clone();
    db::update_dirty(c, "users", &mut row, vec![("password", Val::str(&hash), Cast::Plain)], &crate::laravel::ts(ctx.now))?;
    // every browser trusted to skip the emailed sign-in code has to earn that trust again
    db::exec(c, r#"delete from "trusted_devices" where "user_id" = ?"#, &[P(Val::Int(ctx.uid()))])?;
    let id = session::regenerate(c, &ctx.session, ctx.now)?;
    *ctx.new_session_id.borrow_mut() = Some(id);
    audit(ctx, c, "account.password", "Changed own password")?;
    ctx.flash("password_saved", json!("1"));
    Ok(Reply::Redirect("/account".into()))
}

/// `POST /account/theme`: `{theme}` validated against the three themes, saved on the person, 204.
pub fn theme(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    let rules: [(&str, &[Rule]); 1] = [("theme", &[Rule::Required, Rule::String, Rule::In(&["dark", "light", "system"])])];
    match validate::validate_db(req.input.all(), &rules, &|_, _| Ok(true))? {
        Err(body) => Ok(Reply::Json(422, body)),
        Ok(valid) => {
            let mut row = ctx.user.clone();
            db::update_dirty(c, "users", &mut row, vec![("theme", Val::str(&text(valid.get_str("theme"))), Cast::Plain)], &crate::laravel::ts(ctx.now))?;
            let _ = row_json;
            Ok(Reply::NoContent)
        }
    }
}
