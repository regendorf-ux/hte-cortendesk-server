//! Phase 8 (0.8.2): Settings → Email → "Send a test email" (`SettingsPage::sendTestEmail`): the saved relay, whether
//! or not mail is switched on, the relay's own words on failure, and the `settings.mail-test` audit row.

use super::kit::*;
use super::{Ctx, Reply, Req};
use crate::php::Fault;
use rusqlite::Connection;
use serde_json::json;

/// `POST /settings/mail-test` (`setting: rw`)
pub fn send(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    if !ctx.allows("setting", "rw") {
        return Ok(abort(403));
    }
    let to = Body::of(req).get("smtp_test_to").trim().to_string();
    let cfg = crate::mail::MailConfig::load(c, &ctx.p.n.crypt)?;
    let (ok, message) = if !cfg.is_configured() {
        (false, "Save the SMTP settings first.".to_string())
    } else if to.is_empty() || !crate::email::is_valid(to.as_bytes()) {
        (false, "Enter a valid address to send the test to.".to_string())
    } else {
        let p = ctx.p;
        let html = p.view.render("mail/test.html", json!({"app_name": p.n.signin.app_name, "root": ctx.root})).map_err(Fault::Other)?;
        let msg = crate::mail::Message { to: to.clone(), subject: format!("{} \u{2014} test message", p.n.signin.app_name), html };
        let domain = url::Url::parse(&ctx.root).ok().and_then(|u| u.host_str().map(str::to_string)).unwrap_or_default();
        let r = crate::mail::test(c, &p.n.crypt, &p.n.signin.app_name, &domain, &msg, ctx.now)?;
        audit(ctx, c, "settings.mail-test", &format!("Sent a test email to {to}"), Some("settings"), None)?;
        r
    };
    ctx.flash("mail_test", json!({"ok": ok, "message": message, "to": to}));
    Ok(Reply::Redirect("/settings?tab=email".into()))
}
