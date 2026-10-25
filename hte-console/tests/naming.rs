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
        let block_comments = f.extension().map_or(false, |x| x == "css" || x == "js" || x == "rs");
        let mut in_tests = false;
        let mut in_block = false;
        for (n, line) in text.lines().enumerate() {
            // inside a /* ... */ block (CSS, JS, Rust): the line is a comment
            let was_in_block = in_block;
            if block_comments {
                if let (Some(o), c) = (line.rfind("/*"), line.rfind("*/")) {
                    in_block = c.map_or(true, |c| c < o);
                } else if line.contains("*/") {
                    in_block = false;
                }
            }
            if rs && line.starts_with("#[cfg(test)]") {
                in_tests = true; // unit tests may name the old strings they check against
            }
            if in_tests || !line.contains("CortenDesk") {
                continue;
            }
            // an allowed phrase counts in a comment, or in the files whose job it is (the credit, the web client's replacements, a slug test)
            let fname = f.file_name().unwrap().to_str().unwrap();
            let owner = ["webclient.rs", "cache.rs", "index.html"].contains(&fname);
            let comment = was_in_block || is_comment(line);
            if (comment || owner) && ALLOWED.iter().any(|a| line.contains(a)) {
                continue;
            }
            if (rs || block_comments) && comment && !f.to_string_lossy().contains("/templates/") {
                continue; // history in source comments is fine; strings are not
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
            let bare = line.replace("envvar::var(", "");
            if name != "main.rs" && ["env::var(", "env::var_os(", "env::vars("].iter().any(|x| bare.contains(x)) {
                bad.push(format!("{at}   <- use crate::envvar::var"));
            }
            if line.contains("CORTENDESK_") && !is_comment(line) {
                bad.push(format!("{at}   <- the setting is HTE_REMOTE_<X> (envvar::var falls back to the old name)"));
            }
        }
    }
    assert!(bad.is_empty(), "settings read around the HTE_REMOTE_* names:\n{}", bad.join("\n"));
}

/// Lower case in what the browser gets (file names, placeholders): only the credit's links may name the old project.
#[test]
fn no_old_name_in_templates_lower_case() {
    let mut list = vec![];
    files(&root().join("templates"), &["html", "txt"], &mut list);
    let mut bad = vec![];
    for f in &list {
        for (n, line) in fs::read_to_string(f).unwrap().lines().enumerate() {
            if line.contains("github.com/marcpope/cortendesk") {
                continue; // the credit line (Settings > About)
            }
            let rest = line.replace("hte-cortendesk-server", "");
            if rest.to_ascii_lowercase().contains("cortendesk") && !is_comment(line) {
                bad.push(format!("{}:{}: {}", f.strip_prefix(root()).unwrap().display(), n + 1, line.trim()));
            }
        }
    }
    assert!(bad.is_empty(), "the old name in a template (say hte-remote):\n{}", bad.join("\n"));
}

/// The pages show HTE Remote's version (`crate::REMOTE_VERSION`); `api_version` (the PHP release the client API matches) is for the
/// client API, the web client's config, Diagnostics' export and the About card's "Client API level" only.
#[test]
fn pages_show_hte_remote_s_version() {
    let mut list = vec![];
    files(&root().join("src"), &["rs"], &mut list);
    let mut bad = vec![];
    for f in &list {
        let name = f.file_name().unwrap().to_str().unwrap();
        if ["webclient.rs", "diagnostics.rs"].contains(&name) {
            continue;
        }
        for (n, line) in fs::read_to_string(f).unwrap().lines().enumerate() {
            let l: String = line.chars().filter(|c| !c.is_whitespace()).collect();
            let from_api = ["\"version\":p.n.api_version", "\"version\":ctx.p.n.api_version", "\"version\":self.p.n.api_version", "\"version\".into(),json!(p.n.api_version", "\"version\".into(),json!(ctx.p.n.api_version"];
            if from_api.iter().any(|x| l.contains(x)) || (l.contains("render_page(") && l.contains("api_version")) {
                bad.push(format!("{}:{}: {}", f.strip_prefix(root()).unwrap().display(), n + 1, line.trim()));
            }
        }
    }
    assert!(bad.is_empty(), "a page's \"version\" from api_version (use crate::REMOTE_VERSION):\n{}", bad.join("\n"));
}

#[test]
fn new_archives_have_the_new_name() {
    assert_eq!(hte_console::backup::PREFIX, "hte-remote-backup-");
    assert!(hte_console::backup::is_backup_name("cortendesk-backup-20261024-033000.tar"), "old archives stay restorable");
}
