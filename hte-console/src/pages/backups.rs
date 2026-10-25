//! Settings -> Backups (Livewire `BackupManager`) and the Maintenance tab's "Prune now" (`SettingsPage::pruneNow`).
//!
//! Local only: the list, Back up now, download, delete, restore from a stored archive, and the schedule and retention
//! (`backup_enabled`, `backup_keep_*`). Not here: the off-site FTP and S3 copy, its Test connection button, and restore
//! from an uploaded file. A stored `backup_target` is left as it is and shown as read-only text.
//!
//! The work is the same code the nightly job runs (`housekeeping::backup_command`, `backup::restore`,
//! `prune::prune_logs`); each opens its own database connection, which is fine because a handler holds the shared one
//! outside any transaction.

use super::kit::*;
use super::{Ctx, Reply, Req};
use crate::backup;
use crate::housekeeping::{self, Setup};
use crate::php::Fault;
use crate::sqlite as db;
use rusqlite::Connection;
use serde_json::{json, Value};

fn setup() -> Result<Setup, Fault> {
    Setup::from_env().map_err(Fault::Other)
}

fn notice(ctx: &Ctx, tone: &str, text: &str) {
    ctx.flash("backup_notice", json!({"tone": tone, "text": text}));
}

fn back() -> Reply {
    Reply::Redirect("/settings?tab=backups".into())
}

/// The data the Backups pane renders (empty unless the tab is the one showing).
pub fn pane(ctx: &Ctx, c: &Connection, tab: &str) -> Result<Value, Fault> {
    let mut out = json!({
        "notice": ctx.flashed.get("backup_notice").cloned().filter(|v| !v.is_null()).unwrap_or(Value::Null),
        "prune": ctx.flashed.get("prune_result").and_then(|v| v.as_str()).unwrap_or(""),
        "saved": !ctx.flashed.get("backup_saved").map_or(true, |v| v.is_null()),
        "items": [], "error": "", "dir": "", "last": Value::Null,
        "enabled": true, "keep_daily": 7, "keep_weekly": 8, "keep_monthly": 6, "target": "none", "server_files": false,
    });
    if tab != "backups" {
        return Ok(out);
    }
    let s = backup::settings(c).map_err(Fault::Other)?;
    out["enabled"] = json!(s.enabled);
    out["keep_daily"] = json!(s.keep.daily);
    out["keep_weekly"] = json!(s.keep.weekly);
    out["keep_monthly"] = json!(s.keep.monthly);
    out["target"] = json!(s.target);
    match setup() {
        Err(Fault::Other(e)) => out["error"] = json!(e),
        Err(f) => return Err(f),
        Ok(setup) => {
            out["dir"] = json!(setup.env.backups_dir.display().to_string());
            out["server_files"] = json!(setup.env.rustdesk_dir.as_ref().map_or(false, |d| d.is_dir()));
            match backup::list(&setup.env) {
                Ok(list) => {
                    out["items"] = Value::Array(
                        list.iter()
                            .map(|b| {
                                let m = |k: &str| b.manifest.as_ref().and_then(|m| m.get(k)).and_then(|v| v.as_str()).map(str::to_string);
                                json!({"name": b.name, "taken": b.created_at.format("%Y-%m-%d %H:%M").to_string(), "size": backup::human_size(b.size),
                                       "version": m("app_version").unwrap_or_else(|| "—".into()), "trigger": m("trigger").unwrap_or_else(|| "unknown".into())})
                            })
                            .collect(),
                    )
                }
                Err(e) => out["error"] = json!(e),
            }
        }
    }
    // `backup_last_result`: the outcome of the last run, as the command recorded it
    let raw = String::from_utf8_lossy(&db::setting(c, "backup_last_result", "")?).into_owned();
    if let Ok(Value::Object(m)) = serde_json::from_str::<Value>(&raw) {
        out["last"] = Value::Object(m);
    }
    Ok(out)
}

fn writer(ctx: &Ctx) -> Option<Reply> {
    (!ctx.allows("setting", "rw")).then(|| abort(403))
}

/// POST /settings/backups/run: `cortendesk:backup` (manual).
pub fn run(ctx: &Ctx, c: &Connection, _: &Req) -> Result<Reply, Fault> {
    if let Some(r) = writer(ctx) {
        return Ok(r);
    }
    let _ = c;
    let setup = setup()?;
    match housekeeping::backup_command(&setup.env, false, ctx.now) {
        Ok(o) => notice(ctx, if o.ok { "success" } else { "danger" }, &o.lines.join("\n")),
        Err(e) => notice(ctx, "danger", &e),
    }
    Ok(back())
}

/// POST /settings/backups/save: schedule and retention.
pub fn save(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    if let Some(r) = writer(ctx) {
        return Ok(r);
    }
    let body = Body::of(req);
    let mut keep = [0i64; 3];
    for (i, k) in ["keep_daily", "keep_weekly", "keep_monthly"].iter().enumerate() {
        let v = body.get(k);
        match v.trim().parse::<i64>() {
            Ok(n) if (0..=backup::MAX_KEEP).contains(&n) && !v.trim().starts_with('+') => keep[i] = n,
            _ => {
                notice(ctx, "danger", &format!("Backup settings were not saved: keep counts are whole numbers from 0 to {}.", backup::MAX_KEEP));
                return Ok(back());
            }
        }
    }
    let enabled = body.get("enabled") == "1";
    let target = backup::settings(c).map_err(Fault::Other)?.target;
    let put = |k: &str, v: &str| backup::put_setting(c, k, v, ctx.now).map_err(Fault::Other);
    put("backup_enabled", if enabled { "1" } else { "0" })?;
    put("backup_keep_daily", &keep[0].to_string())?;
    put("backup_keep_weekly", &keep[1].to_string())?;
    put("backup_keep_monthly", &keep[2].to_string())?;
    // BackupManager::save() writes the off-site fields too (as they are: this page does not edit them)
    for (k, default) in [
        ("backup_target", "none"), ("backup_ftp_host", ""), ("backup_ftp_port", "21"), ("backup_ftp_username", ""), ("backup_ftp_path", ""), ("backup_ftp_tls", "0"),
        ("backup_s3_endpoint", ""), ("backup_s3_region", ""), ("backup_s3_bucket", ""), ("backup_s3_prefix", ""), ("backup_s3_access_key", ""), ("backup_s3_path_style", "0"),
    ] {
        let now_value = String::from_utf8_lossy(&db::setting(c, k, default)?).trim().to_string();
        put(k, &now_value)?;
    }
    audit(ctx, c, "backup.settings", &format!("Updated backup settings ({}, keep {}/{}/{}, copy: {})", if enabled { "daily" } else { "off" }, keep[0], keep[1], keep[2], target), Some("settings"), None)?;
    ctx.flash("backup_saved", json!(true));
    Ok(back())
}

fn named(req: &Req) -> String {
    Body::of(req).get("name")
}

/// POST /settings/backups/delete
pub fn delete(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    if let Some(r) = writer(ctx) {
        return Ok(r);
    }
    let name = named(req);
    let setup = setup()?;
    match backup::delete(&setup.env, &name) {
        Ok(()) => {
            audit(ctx, c, "backup.delete", &format!("Deleted backup {name}"), Some("backup"), Some(&name))?;
            notice(ctx, "info", &format!("Deleted {name}."));
        }
        Err(e) => notice(ctx, "danger", &e),
    }
    Ok(back())
}

/// POST /settings/backups/restore: from a stored archive.
pub fn restore(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    if let Some(r) = writer(ctx) {
        return Ok(r);
    }
    let name = named(req);
    let setup = setup()?;
    let path = match backup::path_of(&setup.env, &name) {
        Ok(Some(p)) => p,
        Ok(None) => {
            notice(ctx, "danger", &format!("No backup named {name}."));
            return Ok(back());
        }
        Err(e) => {
            notice(ctx, "danger", &e);
            return Ok(back());
        }
    };
    match backup::restore(&setup.env, &path, ctx.now, &|_| Ok(())) {
        Err(e) => {
            audit(ctx, c, "backup.restore", &format!("Restore of {name} failed: {e}"), Some("backup"), Some(&name))?;
            notice(ctx, "danger", &format!("Restore failed, nothing was changed: {e}"));
        }
        Ok(r) => {
            audit(ctx, c, "backup.restore", &format!("Restored backup {name}"), Some("backup"), Some(&name))?;
            let mut text = format!("Restored {name}: {} rows across {} tables.", r.rows, r.tables);
            if r.rekeyed {
                text.push_str(" Encrypted values were re-keyed to this install.");
            }
            for (table, cols) in &r.dropped_columns {
                text.push_str(&format!(" Ignored in {table}: {}.", cols.join(", ")));
            }
            if r.restart_needed {
                text.push_str(&format!(" Server files ({}) are staged; restart the container to adopt them.", r.files.join(", ")));
            }
            text.push_str(" Reload the page: the settings you see may be stale.");
            notice(ctx, "success", &text);
        }
    }
    Ok(back())
}

/// GET /settings/backups/download
pub fn download(ctx: &Ctx, _: &Connection, req: &Req) -> Result<Reply, Fault> {
    let _ = ctx;
    let name = q(req, "name");
    let setup = setup()?;
    match backup::path_of(&setup.env, &name) {
        Ok(Some(p)) => match std::fs::read(&p) {
            Ok(body) => Ok(Reply::Bytes { filename: name, body }),
            Err(_) => Ok(abort(404)),
        },
        _ => Ok(abort(404)),
    }
}

/// POST /settings/prune: `SettingsPage::pruneNow()`: the retention in the form is saved, then the pruner runs.
pub fn prune(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    if let Some(r) = writer(ctx) {
        return Ok(r);
    }
    let setup = setup()?;
    // `$logRetentionDays` is an int property: a value that is not a whole number leaves the saved one in force
    if let Ok(n) = Body::of(req).get("log_retention_days").trim().parse::<i64>() {
        if (0..=3650).contains(&n) {
            backup::put_setting(c, "log_retention_days", &n.to_string(), ctx.now).map_err(Fault::Other)?;
        }
    }
    let days = crate::prune::retention_days(c, &setup.retention_default).map_err(Fault::Other)?;
    let out = crate::prune::prune_logs(c, ctx.now, None, &setup.retention_default).map_err(Fault::Other)?;
    audit(ctx, c, "logs.prune", &format!("Pruned logs older than {days} days"), Some("logs"), None)?;
    ctx.flash("prune_result", json!(out.lines.join("\n")));
    Ok(Reply::Redirect("/settings?tab=maintenance".into()))
}
