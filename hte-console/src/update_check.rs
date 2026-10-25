//! The sidebar's release check (phase 9). PHP read `cortendesk.latest_version`, which its own pages filled from upstream
//! CortenDesk's releases; HTE Remote is its own program now, so hte-console asks HTE's repository instead: the public GitHub
//! API's tag list (no token, nothing of HTE's sent but the request itself), about once a day, and caches the newest
//! `hte-rd-server-v<x.y.z>` tag where the pages read it. `HTE_REMOTE_UPDATE_CHECK=0` turns it off (old name:
//! `CORTENDESK_UPDATE_CHECK`); `HTE_REMOTE_UPDATE_REPO` points it at another `owner/name`.

use std::sync::Arc;

use crate::api::Native;
use crate::php::Val;

/// Where the pages read the newest release (a serialized string, as PHP cached it).
pub const CACHE_KEY: &str = "hte_remote.latest_version";
/// The git tag that builds the image `hte-rd-server:<x.y.z>`.
pub const TAG_PREFIX: &str = "hte-rd-server-v";
pub const DEFAULT_REPO: &str = "regendorf-ux/hte-cortendesk-server";
const EVERY: u64 = 24 * 3600;
const RETRY: u64 = 3600;
/// Kept a little over two days, so one failed day does not turn the line to "unknown".
const KEEP: i64 = 50 * 3600;

/// `filter_var(..., FILTER_VALIDATE_BOOL)` with true as the default, as PHP read `cortendesk.update_check`.
pub fn enabled() -> bool {
    match crate::envvar::var("HTE_REMOTE_UPDATE_CHECK") {
        Ok(v) if !v.trim().is_empty() => matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "on" | "yes"),
        _ => true,
    }
}

/// `owner/name` of the repository whose tags are read; anything else falls back to HTE's.
pub fn repo() -> String {
    let r = crate::envvar::var("HTE_REMOTE_UPDATE_REPO").unwrap_or_default().trim().to_string();
    let ok = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)) && s != "." && s != "..";
    match r.split_once('/') {
        Some((o, n)) if ok(o) && ok(n) => r,
        _ => DEFAULT_REPO.to_string(),
    }
}

/// The newest stable `hte-rd-server-v<x.y.z>` in a GitHub tag list (`[{"name": ...}, ...]`); pre-releases and other tags are ignored.
pub fn latest_from_tags(body: &[u8]) -> Option<String> {
    let list: serde_json::Value = serde_json::from_slice(body).ok()?;
    let mut best: Option<String> = None;
    for t in list.as_array()? {
        let Some(v) = t.get("name").and_then(|n| n.as_str()).and_then(|n| n.strip_prefix(TAG_PREFIX)) else { continue };
        let parts: Vec<&str> = v.split('.').collect();
        if parts.len() != 3 || parts.iter().any(|p| p.is_empty() || p.len() > 6 || !p.chars().all(|c| c.is_ascii_digit())) {
            continue;
        }
        if best.as_deref().map_or(true, |b| crate::pages::version_compare(v, b) > 0) {
            best = Some(v.to_string());
        }
    }
    best
}

fn fetch(repo: &str) -> Result<Option<String>, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .user_agent(format!("hte-remote-console/{}", crate::REMOTE_VERSION))
        .build()
        .map_err(|e| e.to_string())?;
    let r = client
        .get(format!("https://api.github.com/repos/{repo}/tags?per_page=100"))
        .header("Accept", "application/vnd.github+json")
        .send()
        .map_err(|e| e.to_string())?;
    if !r.status().is_success() {
        return Err(format!("GitHub answered {}", r.status()));
    }
    let body = r.bytes().map_err(|e| e.to_string())?;
    if body.len() > 2_000_000 {
        return Err("tag list too large".into());
    }
    Ok(latest_from_tags(&body))
}

/// Check now and then once a day; the result goes to the cache the sidebar reads. Off when the check is off.
pub fn start(n: Arc<Native>) {
    if !enabled() {
        tracing::info!("release check off (HTE_REMOTE_UPDATE_CHECK)");
        return;
    }
    let store = match crate::cache::Store::from_env() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("release check off: {e}");
            return;
        }
    };
    let repo = repo();
    tracing::info!("release check: the newest {TAG_PREFIX}* tag of {repo}, once a day");
    tokio::spawn(async move {
        loop {
            let (n2, store2, repo2) = (n.clone(), store.clone(), repo.clone());
            let ok = tokio::task::spawn_blocking(move || match fetch(&repo2) {
                Ok(Some(latest)) => {
                    let c = n2.db.lock().unwrap_or_else(|e| e.into_inner());
                    match store2.put(&c, CACHE_KEY, &Val::str(&latest), KEEP, n2.now()) {
                        Ok(()) => {
                            tracing::info!("release check: newest release {latest} (running {})", crate::REMOTE_VERSION);
                            true
                        }
                        Err(e) => {
                            tracing::warn!("release check: cannot cache the result: {e:?}");
                            false
                        }
                    }
                }
                Ok(None) => {
                    tracing::info!("release check: no {TAG_PREFIX}x.y.z tag in {repo2} yet");
                    true
                }
                Err(e) => {
                    tracing::warn!("release check: {e}");
                    false
                }
            })
            .await
            .unwrap_or(false);
            tokio::time::sleep(std::time::Duration::from_secs(if ok { EVERY } else { RETRY })).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newest_stable_tag_of_ours() {
        let body = br#"[{"name":"hte-console-v0.9.0"},{"name":"hte-rd-server-v2.0.0"},{"name":"hte-rd-server-v2.10.1"},
            {"name":"hte-rd-server-v2.9.9"},{"name":"hte-rd-server-v3.0.0-rc.1"},{"name":"v1.1.1-hte.4"},{"name":"hte-rd-server-vx"}]"#;
        assert_eq!(latest_from_tags(body).as_deref(), Some("2.10.1"));
        assert_eq!(latest_from_tags(br#"[{"name":"v1.1.1-hte.3"}]"#), None);
        assert_eq!(latest_from_tags(b"not json"), None);
        assert_eq!(latest_from_tags(br#"{"message":"rate limited"}"#), None);
    }

    #[test]
    fn repo_is_owner_slash_name_or_ours() {
        std::env::set_var("HTE_REMOTE_UPDATE_REPO", "someone/../x");
        assert_eq!(repo(), DEFAULT_REPO);
        std::env::set_var("HTE_REMOTE_UPDATE_REPO", "acme/hte-fork");
        assert_eq!(repo(), "acme/hte-fork");
        std::env::remove_var("HTE_REMOTE_UPDATE_REPO");
        assert_eq!(repo(), DEFAULT_REPO);
    }
}
