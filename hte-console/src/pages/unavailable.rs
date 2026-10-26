//! Areas of the previous console HTE Remote does not carry (client downloads, the setup wizard): HTE Remote has no port of them, and the page says so. Their data is untouched.

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

