//! The environment, with HTE Remote's names. Every setting that was `CORTENDESK_<X>` is `HTE_REMOTE_<X>` now; the old name is still
//! read when the new one is not set or empty (an `.env` from before the rename keeps working), with one warning per old name used.
//! Other names pass straight through to `std::env::var`.

use std::collections::HashSet;
use std::env::VarError;
use std::sync::Mutex;

pub const NEW: &str = "HTE_REMOTE_";
pub const OLD: &str = "CORTENDESK_";

static WARNED: Mutex<Option<HashSet<String>>> = Mutex::new(None);

/// `std::env::var`, except that `HTE_REMOTE_<X>` falls back to `CORTENDESK_<X>`.
pub fn var(key: &str) -> Result<String, VarError> {
    let Some(rest) = key.strip_prefix(NEW) else {
        return std::env::var(key);
    };
    let new = std::env::var(key);
    if matches!(&new, Ok(v) if !v.trim().is_empty()) {
        return new;
    }
    // unset or empty (compose writes `X: ${X:-}` as an empty value): the old name, when it has a value
    let old = format!("{OLD}{rest}");
    match std::env::var(&old) {
        Ok(v) if !v.trim().is_empty() => {
            warn_once(&old, key);
            Ok(v)
        }
        _ => new,
    }
}

fn warn_once(old: &str, new: &str) {
    if let Ok(mut g) = WARNED.lock() {
        if g.get_or_insert_with(HashSet::new).insert(old.to_string()) {
            tracing::warn!("environment: {old} is the old name of {new}; it is read for now, rename it");
        }
    }
}

/// The old names in use right now (for `status` and the deploy's check).
pub fn old_names_in_use() -> Vec<String> {
    let mut v: Vec<String> = std::env::vars().map(|(k, _)| k).filter(|k| k.starts_with(OLD)).collect();
    v.sort();
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_name_first_then_old_then_nothing() {
        // names only this test uses, so parallel tests do not race on them
        std::env::remove_var("HTE_REMOTE_ZZ_ENVTEST");
        std::env::remove_var("CORTENDESK_ZZ_ENVTEST");
        assert!(var("HTE_REMOTE_ZZ_ENVTEST").is_err());
        std::env::set_var("CORTENDESK_ZZ_ENVTEST", "old");
        assert_eq!(var("HTE_REMOTE_ZZ_ENVTEST").unwrap(), "old");
        std::env::set_var("HTE_REMOTE_ZZ_ENVTEST", "new");
        assert_eq!(var("HTE_REMOTE_ZZ_ENVTEST").unwrap(), "new");
        // an empty new value (compose's `X: ${X:-}`) falls back to an old one that has a value
        std::env::set_var("HTE_REMOTE_ZZ_ENVTEST", "");
        assert_eq!(var("HTE_REMOTE_ZZ_ENVTEST").unwrap(), "old");
        std::env::set_var("CORTENDESK_ZZ_ENVTEST", "");
        assert_eq!(var("HTE_REMOTE_ZZ_ENVTEST").unwrap(), "");
        assert!(old_names_in_use().contains(&"CORTENDESK_ZZ_ENVTEST".to_string()));
        std::env::remove_var("HTE_REMOTE_ZZ_ENVTEST");
        std::env::remove_var("CORTENDESK_ZZ_ENVTEST");
        // other names pass through
        std::env::set_var("HTE_CONSOLE_ZZ_ENVTEST", "x");
        assert_eq!(var("HTE_CONSOLE_ZZ_ENVTEST").unwrap(), "x");
        std::env::remove_var("HTE_CONSOLE_ZZ_ENVTEST");
    }
}
