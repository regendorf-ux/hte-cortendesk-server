//! Templates: minijinja, runtime, embedded in the binary (`templates/`), the Blade views' markup converted nearly one
//! to one. `HTE_CONSOLE_TEMPLATES=<dir>` reads the templates from disk on every render instead, so a template edit
//! needs no compile (and no restart).
//!
//! Escaping is Blade's `e()` (htmlspecialchars with ENT_QUOTES: `&#039;` for a quote), applied to everything printed
//! unless it went through `|safe`; null and undefined print nothing, `true` prints `1` and `false` nothing, as PHP
//! echoes them. Undefined variables are errors, so a typo cannot render silently; `tests/pages.rs` renders every page.

use include_dir::{include_dir, Dir};
use minijinja::value::Value;
use minijinja::{Environment, Error, ErrorKind, UndefinedBehavior};
use serde::Serialize;

static EMBEDDED: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/templates");

pub struct View {
    env: Environment<'static>,
    /// When set, every render rebuilds the environment from this directory.
    dir: Option<std::path::PathBuf>,
}

fn collect(dir: &Dir<'static>, out: &mut Vec<(String, String)>) {
    for f in dir.files() {
        if let (Some(p), Some(s)) = (f.path().to_str(), f.contents_utf8()) {
            out.push((p.to_string(), s.to_string()));
        }
    }
    for d in dir.dirs() {
        collect(d, out);
    }
}

fn read_dir(root: &std::path::Path, dir: &std::path::Path, out: &mut Vec<(String, String)>) -> std::io::Result<()> {
    for e in std::fs::read_dir(dir)? {
        let p = e?.path();
        if p.is_dir() {
            read_dir(root, &p, out)?;
        } else if let (Ok(rel), Ok(s)) = (p.strip_prefix(root), std::fs::read_to_string(&p)) {
            out.push((rel.to_string_lossy().replace('\\', "/"), s));
        }
    }
    Ok(())
}

/// Blade's `{{ }}`: what PHP would echo, escaped as `e()` does unless the value is marked safe.
fn format_value(out: &mut minijinja::Output, _state: &minijinja::State, value: &Value) -> Result<(), Error> {
    if value.is_undefined() || value.is_none() {
        return Ok(());
    }
    let text = if let Some(b) = value.as_bool_like() {
        if b { "1".to_string() } else { String::new() }
    } else {
        value.to_string()
    };
    if value.is_safe() {
        out.write_str(&text).map_err(|_| Error::new(ErrorKind::WriteFailure, "write failed"))
    } else {
        out.write_str(&crate::laravel::e(&text)).map_err(|_| Error::new(ErrorKind::WriteFailure, "write failed"))
    }
}

trait BoolLike {
    fn as_bool_like(&self) -> Option<bool>;
}
impl BoolLike for Value {
    fn as_bool_like(&self) -> Option<bool> {
        if self.kind() == minijinja::value::ValueKind::Bool {
            Some(self.is_true())
        } else {
            None
        }
    }
}

fn build(templates: Vec<(String, String)>) -> Result<Environment<'static>, String> {
    let mut env = Environment::new();
    env.set_undefined_behavior(UndefinedBehavior::Strict);
    // escaping is done by the formatter (PHP's way), so the engine's own is off
    env.set_auto_escape_callback(|_| minijinja::AutoEscape::None);
    env.set_formatter(format_value);
    env.set_keep_trailing_newline(true);
    for (name, src) in templates {
        env.add_template_owned(name.clone(), src).map_err(|e| format!("template {name}: {e}"))?;
    }
    env.add_filter("ago", |ts: i64, now: i64| super::time::ago(ts, now, false));
    env.add_filter("ago_short", |ts: i64, now: i64| super::time::ago(ts, now, true));
    env.add_filter("duration", |later: i64, earlier: i64| super::time::short_absolute(later, earlier));
    env.add_filter("datetime", |ts: i64| crate::laravel::ts(ts));
    env.add_filter("ucfirst", |s: String| {
        let mut c = s.chars();
        c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_default()
    });
    env.add_filter("upper_first_char", |s: String| s.chars().next().map(|c| c.to_uppercase().collect::<String>()).unwrap_or_default());
    env.add_filter("plural", |word: String, n: i64| if n == 1 { word } else { pluralise(&word) });
    env.add_filter("urlencode", |s: String| crate::laravel::urlencode(s.as_bytes()));
    Ok(env)
}

/// `Str::plural` for the few English words the views use.
fn pluralise(w: &str) -> String {
    match w {
        "child" => "children".into(),
        _ if w.ends_with('y') && !w.ends_with("ey") => format!("{}ies", &w[..w.len() - 1]),
        _ if w.ends_with('s') || w.ends_with("sh") || w.ends_with("ch") || w.ends_with('x') => format!("{w}es"),
        _ => format!("{w}s"),
    }
}

impl View {
    pub fn from_env() -> Result<View, String> {
        match crate::envvar::var("HTE_CONSOLE_TEMPLATES").ok().filter(|d| !d.trim().is_empty()) {
            Some(d) => {
                let dir = std::path::PathBuf::from(d);
                let v = View { env: build(Self::from_disk(&dir)?)?, dir: Some(dir) };
                Ok(v)
            }
            None => View::embedded(),
        }
    }

    pub fn embedded() -> Result<View, String> {
        let mut t = vec![];
        collect(&EMBEDDED, &mut t);
        Ok(View { env: build(t)?, dir: None })
    }

    fn from_disk(dir: &std::path::Path) -> Result<Vec<(String, String)>, String> {
        let mut t = vec![];
        read_dir(dir, dir, &mut t).map_err(|e| format!("templates {}: {e}", dir.display()))?;
        Ok(t)
    }

    pub fn render<S: Serialize>(&self, name: &str, ctx: S) -> Result<String, String> {
        let live;
        let env = match &self.dir {
            Some(d) => {
                live = build(Self::from_disk(d)?)?;
                &live
            }
            None => &self.env,
        };
        let t = env.get_template(name).map_err(|e| format!("{name}: {e}"))?;
        t.render(ctx).map_err(|e| {
            let mut m = format!("{name}: {e}");
            let mut src = std::error::Error::source(&e);
            while let Some(s) = src {
                m.push_str(&format!(" <- {s}"));
                src = s.source();
            }
            m
        })
    }

    /// Every embedded template's name (the test renders the pages, this lists what exists).
    pub fn names(&self) -> Vec<String> {
        self.env.templates().map(|(n, _)| n.to_string()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn one(src: &str, ctx: serde_json::Value) -> String {
        let env = build(vec![("t.html".into(), src.into())]).unwrap();
        env.get_template("t.html").unwrap().render(ctx).unwrap()
    }

    #[test]
    fn escapes_like_blade() {
        assert_eq!(one("{{ x }}", json!({"x": "<a href=\"q\">it's & co</a>"})), "&lt;a href=&quot;q&quot;&gt;it&#039;s &amp; co&lt;/a&gt;");
        assert_eq!(one("{{ x|safe }}", json!({"x": "<b>"})), "<b>");
        assert_eq!(one("[{{ x }}]", json!({"x": null})), "[]");
        assert_eq!(one("[{{ x }}{{ y }}{{ n }}]", json!({"x": true, "y": false, "n": 5})), "[15]");
    }

    #[test]
    fn a_typo_is_an_error_not_an_empty_page() {
        let env = build(vec![("t.html".into(), "{{ nope }}".into())]).unwrap();
        assert!(env.get_template("t.html").unwrap().render(json!({})).is_err());
    }

    #[test]
    fn time_filters() {
        assert_eq!(one("{{ t|ago(n) }} / {{ t|ago_short(n) }}", json!({"t": 1000, "n": 1000 + 300})), "5 minutes ago / 5m ago");
        assert_eq!(one("{{ t|datetime }}", json!({"t": 0})), "1970-01-01 00:00:00");
        assert_eq!(one("{{ 'file'|plural(2) }} {{ 'file'|plural(1) }}", json!({})), "files file");
    }

    #[test]
    fn every_embedded_template_compiles() {
        let v = View::embedded().unwrap();
        assert!(!v.names().is_empty());
    }
}
