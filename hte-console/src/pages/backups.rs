//! Settings -> Backups (Livewire `BackupManager`) and the Maintenance tab's "Prune now" (`SettingsPage::pruneNow`).
//!
//! The list, Back up now, download, delete, restore from a stored archive or an uploaded file, the schedule and
//! retention (`backup_enabled`, `backup_keep_*`) and the off-site copy (`backup_target`, FTP / FTPS and S3 with its Test
//! connection button; the clients are `backup_ftp` and `backup_s3`).
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

/// Every field's message, empty where there is none (a template may not name a key that is missing).
fn errors_of(ctx: &Ctx) -> Value {
    let mut m = serde_json::Map::new();
    for k in ["target", "ftp_host", "ftp_port", "ftp_username", "ftp_password", "ftp_path", "s3_endpoint", "s3_region", "s3_bucket", "s3_prefix", "s3_access_key", "s3_secret_key", "upload"] {
        m.insert(k.into(), json!(""));
    }
    if let Some(Value::Object(e)) = ctx.flashed.get("backup_errors") {
        for (k, v) in e {
            m.insert(k.clone(), v.clone());
        }
    }
    Value::Object(m)
}

/// The data the Backups pane renders (empty unless the tab is the one showing).
pub fn pane(ctx: &Ctx, c: &Connection, tab: &str) -> Result<Value, Fault> {
    let mut out = json!({
        "notice": ctx.flashed.get("backup_notice").cloned().filter(|v| !v.is_null()).unwrap_or(Value::Null),
        "prune": ctx.flashed.get("prune_result").and_then(|v| v.as_str()).unwrap_or(""),
        "saved": !ctx.flashed.get("backup_saved").map_or(true, |v| v.is_null()),
        "items": [], "error": "", "dir": "", "last": Value::Null,
        "enabled": true, "keep_daily": 7, "keep_weekly": 8, "keep_monthly": 6, "target": "none", "server_files": false,
        "errors": errors_of(ctx),
        "test": ctx.flashed.get("backup_test").cloned().filter(|v| v.is_object()).unwrap_or(Value::Null),
        "f": json!({"ftp_host": "", "ftp_port": "21", "ftp_username": "", "ftp_path": "", "ftp_tls": false, "s3_endpoint": "", "s3_region": "", "s3_bucket": "", "s3_prefix": "", "s3_access_key": "", "s3_path_style": false}), "ftp_password_set": false, "s3_secret_set": false,
    });
    // PHP prints `config('cortendesk.backups_path')` whether or not the directory works, and on every tab
    out["dir"] = json!(std::env::var("HTE_CONSOLE_BACKUPS_DIR").ok().or_else(|| std::env::var("CORTENDESK_BACKUPS_PATH").ok()).filter(|v| !v.is_empty()).unwrap_or_else(|| "/data/backups".into()));
    if tab != "backups" {
        return Ok(out);
    }
    let s = backup::settings(c).map_err(Fault::Other)?;
    out["enabled"] = json!(s.enabled);
    out["keep_daily"] = json!(s.keep.daily);
    out["keep_weekly"] = json!(s.keep.weekly);
    out["keep_monthly"] = json!(s.keep.monthly);
    out["target"] = json!(s.target);
    let get = |k: &str, d: &str| -> Result<String, Fault> { Ok(String::from_utf8_lossy(&db::setting(c, k, d)?).into_owned()) };
    let stored = json!({
        "ftp_host": get("backup_ftp_host", "")?, "ftp_port": get("backup_ftp_port", "21")?, "ftp_username": get("backup_ftp_username", "")?,
        "ftp_path": get("backup_ftp_path", "")?, "ftp_tls": get("backup_ftp_tls", "0")? == "1",
        "s3_endpoint": get("backup_s3_endpoint", "")?, "s3_region": get("backup_s3_region", "")?, "s3_bucket": get("backup_s3_bucket", "")?,
        "s3_prefix": get("backup_s3_prefix", "")?, "s3_access_key": get("backup_s3_access_key", "")?, "s3_path_style": get("backup_s3_path_style", "0")? == "1",
    });
    out["ftp_password_set"] = json!(!get("backup_ftp_password", "")?.is_empty());
    out["s3_secret_set"] = json!(!get("backup_s3_secret_key", "")?.is_empty());
    out["f"] = stored;
    // a refused save shows what was typed (the password fields are never sent back)
    if let Some(Value::Object(form)) = ctx.flashed.get("backup_form") {
        for (k, v) in form {
            if k == "enabled" || k == "keep_daily" || k == "keep_weekly" || k == "keep_monthly" || k == "target" {
                out[k.as_str()] = v.clone();
            } else {
                out["f"][k.as_str()] = v.clone();
            }
        }
    }
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
    // a field the form did not send keeps what is stored (a request that carries only part of the form)
    let stored = |k: &str, default: &str| -> String { String::from_utf8_lossy(&db::setting(c, &format!("backup_{k}"), default).unwrap_or_default()).trim().to_string() };
    let t = |k: &str| if body.has(k) { body.get(k).trim().to_string() } else { stored(k, if k == "ftp_port" { "21" } else { "" }) };
    let target = if body.has("target") { t("target") } else { backup::settings(c).map_err(Fault::Other)?.target };
    let form = json!({
        "enabled": enabled, "keep_daily": keep[0], "keep_weekly": keep[1], "keep_monthly": keep[2], "target": target,
        "ftp_host": t("ftp_host"), "ftp_port": t("ftp_port"), "ftp_username": t("ftp_username"), "ftp_path": t("ftp_path"), "ftp_tls": body.get("ftp_tls") == "1",
        "s3_endpoint": t("s3_endpoint"), "s3_region": t("s3_region"), "s3_bucket": t("s3_bucket"), "s3_prefix": t("s3_prefix"),
        "s3_access_key": t("s3_access_key"), "s3_path_style": body.get("s3_path_style") == "1",
    });
    // the Livewire component's rules, in its order
    let mut errors = serde_json::Map::new();
    fn bad(errors: &mut serde_json::Map<String, Value>, k: &str, msg: &str) {
        errors.entry(k.to_string()).or_insert_with(|| json!(msg));
    }
    if !["none", "ftp", "s3"].contains(&target.as_str()) {
        bad(&mut errors, "target", "The selected target is invalid.");
    }
    for (k, label) in [("ftp_host", "ftp host"), ("ftp_username", "ftp username"), ("ftp_path", "ftp path"), ("s3_endpoint", "s3 endpoint"), ("s3_bucket", "s3 bucket"), ("s3_prefix", "s3 prefix"), ("s3_access_key", "s3 access key")] {
        let max = if k == "ftp_path" { 512 } else { 255 };
        if t(k).chars().count() > max {
            bad(&mut errors, k, &format!("The {label} field must not be greater than {max} characters."));
        }
    }
    if t("s3_region").chars().count() > 64 {
        bad(&mut errors, "s3_region", "The s3 region field must not be greater than 64 characters.");
    }
    match t("ftp_port").parse::<i64>() {
        Ok(n) if (1..=65535).contains(&n) => {}
        Ok(n) if n < 1 => bad(&mut errors, "ftp_port", "The ftp port field must be at least 1."),
        Ok(_) => bad(&mut errors, "ftp_port", "The ftp port field must not be greater than 65535."),
        Err(_) if t("ftp_port").is_empty() => bad(&mut errors, "ftp_port", "The ftp port field is required."),
        Err(_) => bad(&mut errors, "ftp_port", "The ftp port field must be an integer."),
    }
    let endpoint = t("s3_endpoint");
    if !endpoint.is_empty() && !(url::Url::parse(&endpoint).map_or(false, |u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some())) {
        bad(&mut errors, "s3_endpoint", "The s3 endpoint field must be a valid URL.");
    }
    if body.get("ftp_password").chars().count() > 512 {
        bad(&mut errors, "ftp_password", "The ftp password field must not be greater than 512 characters.");
    }
    if body.get("s3_secret_key").chars().count() > 512 {
        bad(&mut errors, "s3_secret_key", "The s3 secret key field must not be greater than 512 characters.");
    }
    if errors.is_empty() && target == "ftp" && t("ftp_host").is_empty() {
        bad(&mut errors, "ftp_host", "An FTP host is needed to copy backups there.");
    }
    if errors.is_empty() && target == "s3" && t("s3_bucket").is_empty() {
        bad(&mut errors, "s3_bucket", "A bucket name is needed to copy backups there.");
    }
    if !errors.is_empty() {
        ctx.flash("backup_errors", Value::Object(errors));
        ctx.flash("backup_form", form);
        return Ok(back());
    }
    let put = |k: &str, v: &str| backup::put_setting(c, k, v, ctx.now).map_err(Fault::Other);
    put("backup_enabled", if enabled { "1" } else { "0" })?;
    put("backup_keep_daily", &keep[0].to_string())?;
    put("backup_keep_weekly", &keep[1].to_string())?;
    put("backup_keep_monthly", &keep[2].to_string())?;
    put("backup_target", &target)?;
    put("backup_ftp_host", &t("ftp_host"))?;
    put("backup_ftp_port", &t("ftp_port"))?;
    put("backup_ftp_username", &t("ftp_username"))?;
    put("backup_ftp_path", &t("ftp_path"))?;
    put("backup_ftp_tls", if body.get("ftp_tls") == "1" { "1" } else { "0" })?;
    let pw = body.get("ftp_password");
    if !pw.is_empty() {
        put("backup_ftp_password", &ctx.p.n.crypt.encrypt_string(pw.as_bytes()))?;
    }
    put("backup_s3_endpoint", &endpoint)?;
    put("backup_s3_region", &t("s3_region"))?;
    put("backup_s3_bucket", &t("s3_bucket"))?;
    put("backup_s3_prefix", &t("s3_prefix"))?;
    put("backup_s3_access_key", &t("s3_access_key"))?;
    put("backup_s3_path_style", if body.get("s3_path_style") == "1" { "1" } else { "0" })?;
    let sk = body.get("s3_secret_key");
    if !sk.is_empty() {
        put("backup_s3_secret_key", &ctx.p.n.crypt.encrypt_string(sk.as_bytes()))?;
    }
    audit(ctx, c, "backup.settings", &format!("Updated backup settings ({}, keep {}/{}/{}, copy: {})", if enabled { "daily" } else { "off" }, keep[0], keep[1], keep[2], target), Some("settings"), None)?;
    ctx.flash("backup_saved", json!(true));
    Ok(back())
}

/// POST /settings/backups/test: `testTarget()`: save, then prove the saved target works.
pub fn test(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    if let Some(r) = writer(ctx) {
        return Ok(r);
    }
    let reply = save(ctx, c, req)?;
    if ctx.flash_out.borrow().iter().any(|(k, _)| k == "backup_errors") {
        return Ok(reply);
    }
    // what is tested is what the scheduler will use; the "saved" note is for Save only
    ctx.flash("backup_saved", Value::Null);
    let setup = setup()?;
    let result = match crate::backup_remote::target(&setup.env, c) {
        Ok(None) => json!({"tone": "info", "text": "Saved. No off-site copy is configured."}),
        Ok(Some(t)) => match t.test() {
            Ok(m) => json!({"tone": "success", "text": format!("Saved. {m}")}),
            Err(e) => json!({"tone": "danger", "text": format!("Saved, but the test failed: {e}")}),
        },
        Err(e) => json!({"tone": "danger", "text": format!("Saved, but the test failed: {e}")}),
    };
    ctx.flash("backup_test", result);
    Ok(reply)
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
            // the off-site copy mirrors this list; take the file down there too. If that fails the next run's sync removes it.
            match crate::backup_remote::target(&setup.env, c) {
                Ok(Some(t)) => match t.list().and_then(|l| if l.iter().any(|(n, _)| n == &name) { t.delete(&name) } else { Ok(()) }) {
                    Ok(()) => notice(ctx, "info", &format!("Deleted {name} here and at {}.", t.label())),
                    Err(e) => notice(ctx, "warning", &format!("Deleted {name}. The copy at {} could not be removed ({e}); the next run removes it.", t.label())),
                },
                _ => notice(ctx, "info", &format!("Deleted {name}.")),
            }
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
    run_restore(ctx, c, &setup, &path, &name)?;
    Ok(back())
}

fn run_restore(ctx: &Ctx, c: &Connection, setup: &Setup, path: &std::path::Path, name: &str) -> Result<(), Fault> {
    match backup::restore(&setup.env, path, ctx.now, &|_| Ok(())) {
        Err(e) => {
            audit(ctx, c, "backup.restore", &format!("Restore of {name} failed: {e}"), Some("backup"), Some(name))?;
            notice(ctx, "danger", &format!("Restore failed, nothing was changed: {e}"));
        }
        Ok(r) => {
            audit(ctx, c, "backup.restore", &format!("Restored backup {name}"), Some("backup"), Some(name))?;
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
    Ok(())
}

/// POST /settings/backups/upload: `restoreUpload()`: the file is checked and stored like any backup, then restored.
pub fn upload(ctx: &Ctx, c: &Connection, req: &Req) -> Result<Reply, Fault> {
    if let Some(r) = writer(ctx) {
        return Ok(r);
    }
    let ct = req.headers.get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("");
    let file = crate::multipart::parts(ct, &req.input.raw).and_then(|ps| ps.into_iter().find(|p| p.name == "upload" && p.filename.is_some()));
    let Some(file) = file.filter(|f| !f.data.is_empty()) else {
        ctx.flash("backup_errors", json!({"upload": "Pick a backup archive first."}));
        return Ok(back());
    };
    let setup = setup()?;
    let original = file.filename.clone().unwrap_or_default();
    let original = original.rsplit(['/', '\\']).next().unwrap_or("").to_string();
    let tmp = setup.env.backups_dir.join(format!(".upload-{:016x}.tmp", rand::random::<u64>()));
    let stored = std::fs::write(&tmp, file.data).map_err(|e| format!("Could not store the uploaded backup: {e}")).and_then(|_| backup::import(&setup.env, &tmp, &original, ctx.now));
    let _ = std::fs::remove_file(&tmp);
    match stored {
        Err(e) => notice(ctx, "danger", &e),
        Ok(name) => {
            let path = setup.env.backups_dir.join(&name);
            run_restore(ctx, c, &setup, &path, &name)?;
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
