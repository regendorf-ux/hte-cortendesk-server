//! HTE Remote's name (phase 9, 2.0.0). Fails on anything that brings the old name back: "CortenDesk" on a page, in a template or in a
//! string a person reads; a `CORTENDESK_*` setting read directly; `std::env::var` in the library (it must go through `envvar::var`, which
//! reads `HTE_REMOTE_<X>` first and the old name as a fallback). Run after every merge of a branch written before the rename.

use std::fs;
use std::path::{Path, PathBuf};

fn files(dir: &Path, ext: &[&str], out: &mut Vec<PathBuf>) {
    for e in fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            files(&p, ext, out);
        } else if p.extension().and_then(|x| x.to_str()).map_or(false, |x| ext.contains(&x)) {
            out.push(p);
        }
    }
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Lines that may say CortenDesk: the one credit, licence-required notices, and the web client's own replacements of the name.
const ALLOWED: [&str; 8] = [
    "github.com/marcpope/cortendesk", // Settings > About: the credit
    "Corten<span>Desk</span>",        // webclient.rs: what the bundled web client says, replaced at serve time
    "alt=\"CortenDesk\"",
    "\\u2014 CortenDesk`",
    "slug(\"CortenDesk\")",           // cache.rs: Laravel's slug of the old default APP_NAME, a test
    "(from CortenDesk)",              // asset header comments: where the file came from
    "Modified for CortenDesk",        // remixicon.css: the licence's modification notice
    "CortenDesk's",                   // hte-brand.css / webclient.rs: comments on what the brand replaces
];

fn is_comment(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("//") || t.starts_with("/*") || t.starts_with('*') || t.starts_with("{#") || t.starts_with("<!--")
}

#[test]
fn no_old_name_where_a_person_reads_it() {
    let mut list = vec![];
    files(&root().join("templates"), &["html", "txt", "js"], &mut list);
    files(&root().join("src"), &["rs"], &mut list);
    files(&root().join("assets/css"), &["css"], &mut list);
    files(&root().join("assets/js"), &["js"], &mut list);
    let mut bad = vec![];
    for f in &list {
        let text = fs::read_to_string(f).unwrap();
        let rs = f.extension().map_or(false, |x| x == "rs");
        let mut in_tests = false;
        for (n, line) in text.lines().enumerate() {
            if rs && line.starts_with("#[cfg(test)]") {
                in_tests = true; // unit tests may name the old strings they check against
            }
            if in_tests || !line.contains("CortenDesk") || ALLOWED.iter().any(|a| line.contains(a)) {
                continue;
            }
            if rs && is_comment(line) {
                continue; // history in comments is fine; strings are not
            }
            bad.push(format!("{}:{}: {}", f.strip_prefix(root()).unwrap().display(), n + 1, line.trim()));
        }
    }
    assert!(bad.is_empty(), "\"CortenDesk\" where a person reads it (say HTE Remote):\n{}", bad.join("\n"));
}

#[test]
fn settings_go_through_envvar() {
    let mut list = vec![];
    files(&root().join("src"), &["rs"], &mut list);
    files(&root().join("templates"), &["html"], &mut list);
    let mut bad = vec![];
    for f in &list {
        let name = f.file_name().unwrap().to_str().unwrap();
        if name == "envvar.rs" {
            continue;
        }
        let text = fs::read_to_string(f).unwrap();
        for (n, line) in text.lines().enumerate() {
            let at = format!("{}:{}: {}", f.strip_prefix(root()).unwrap().display(), n + 1, line.trim());
            if name != "main.rs" && line.contains("std::env::var(") {
                bad.push(format!("{at}   <- use crate::envvar::var"));
            }
            if line.contains("CORTENDESK_") && !is_comment(line) {
                bad.push(format!("{at}   <- the setting is HTE_REMOTE_<X> (envvar::var falls back to the old name)"));
            }
        }
    }
    assert!(bad.is_empty(), "settings read around the HTE_REMOTE_* names:\n{}", bad.join("\n"));
}

#[test]
fn new_archives_have_the_new_name() {
    assert_eq!(hte_console::backup::PREFIX, "hte-remote-backup-");
    assert!(hte_console::backup::is_backup_name("cortendesk-backup-20261024-033000.tar"), "old archives stay restorable");
}
