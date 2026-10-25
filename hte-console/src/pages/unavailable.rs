//! Areas HTE does not use (roles, API tokens, invitations, client downloads, setup, off-site backups): the Rust console
//! has no port of them. The page says so and points at the previous console, where they still work on the same data.

use super::{Ctx, Reply, Req};
use crate::php::Fault;
use rusqlite::Connection;
use serde_json::json;

fn show(ctx: &Ctx, c: &Connection, route: &str, title: &str, subtitle: &str) -> Result<Reply, Fault> {
    let layout = ctx.layout(c, route, title, subtitle)?;
    Ok(Reply::Html(200, ctx.render("unavailable.html", layout, json!({"what": title}))?))
}

pub fn roles(ctx: &Ctx, c: &Connection, _: &Req) -> Result<Reply, Fault> {
    if !ctx.is_admin() {
        return Ok(super::kit::abort(403));
    }
    show(ctx, c, "roles", "Roles", "Manage")
}

pub fn client_downloads(ctx: &Ctx, c: &Connection, _: &Req) -> Result<Reply, Fault> {
    show(ctx, c, "client-downloads", "Client Downloads", "System")
}

pub fn setup(ctx: &Ctx, c: &Connection, _: &Req) -> Result<Reply, Fault> {
    show(ctx, c, "setup", "Setup", "System")
}

pub fn invitations(ctx: &Ctx, c: &Connection, _: &Req) -> Result<Reply, Fault> {
    show(ctx, c, "users", "Invitations", "Manage")
}
