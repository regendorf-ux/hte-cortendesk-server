//! Areas HTE does not use (invitations, client downloads, the setup wizard): the Rust console has no port of them. The page says so and points at the previous console, where they still work on the same data.

use super::{Ctx, Reply, Req};
use crate::php::Fault;
use rusqlite::Connection;
use serde_json::json;

fn show(ctx: &Ctx, c: &Connection, route: &str, title: &str, subtitle: &str) -> Result<Reply, Fault> {
    let layout = ctx.layout(c, route, title, subtitle)?;
    Ok(Reply::Html(200, ctx.render("unavailable.html", layout, json!({"what": title}))?))
}

pub fn client_downloads(ctx: &Ctx, c: &Connection, _: &Req) -> Result<Reply, Fault> {
    show(ctx, c, "client-downloads", "Client Downloads", "System")
}

pub fn setup(ctx: &Ctx, c: &Connection, _: &Req) -> Result<Reply, Fault> {
    show(ctx, c, "setup", "Setup", "System")
}

