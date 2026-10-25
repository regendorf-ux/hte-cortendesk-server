//! `/assets/*`: the console's CSS, JS, fonts and images, embedded (`assets/`: a copy of the PHP console's
//! `public/assets` from the `hte` fork, brand files included, plus the vendored htmx). `scripts/sync-assets.sh`
//! refreshes the copy from the fork; `tests/pages.rs` pins the file list.

use axum::body::Body;
use axum::http::{header, Response, StatusCode};
use include_dir::{include_dir, Dir};

static ASSETS: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/assets");

pub fn content_type(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or("") {
        "css" => "text/css; charset=utf-8",
        "js" => "text/javascript; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// The embedded file at `path` (relative, no `..`), if any.
pub fn find(path: &str) -> Option<&'static [u8]> {
    if path.is_empty() || path.split('/').any(|s| s.is_empty() || s == "." || s == "..") {
        return None;
    }
    ASSETS.get_file(path).map(|f| f.contents())
}

pub fn names() -> Vec<String> {
    fn walk(d: &Dir<'static>, out: &mut Vec<String>) {
        for f in d.files() {
            out.push(f.path().to_string_lossy().into_owned());
        }
        for s in d.dirs() {
            walk(s, out);
        }
    }
    let mut v = vec![];
    walk(&ASSETS, &mut v);
    v.sort();
    v
}

/// `css/hte-pages.css`, `js/hte-pages.js`, `css/hte-webclient.css`, ...: written for hte-console, not copied from PHP.
fn own_file(path: &str) -> bool {
    path.rsplit('/').next().map_or(false, |f| f.starts_with("hte-") && (f.ends_with(".css") || f.ends_with(".js")))
}

pub fn respond(path: &str, head: bool) -> Response<Body> {
    match find(path) {
        Some(bytes) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, content_type(path))
            // hte-console's own files change between releases under the same `?v=` (PHP's version): always revalidated
            .header(header::CACHE_CONTROL, if own_file(path) { "no-cache" } else { "public, max-age=86400" })
            .header("x-content-type-options", "nosniff")
            .body(if head { Body::empty() } else { Body::from(bytes) })
            .unwrap(),
        None => Response::builder().status(StatusCode::NOT_FOUND).header(header::CONTENT_TYPE, "text/plain").body(Body::from("Not Found")).unwrap(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_console_files_are_there_and_nothing_escapes() {
        for f in ["css/hte-remote.css", "css/hte-brand.css", "js/shell.js", "js/theme-init.js", "vendor/bootstrap/bootstrap.min.css", "vendor/htmx/htmx.min.js", "images/hte-remote.png"] {
            assert!(find(f).is_some(), "{f}");
        }
        assert!(find("../Cargo.toml").is_none());
        assert!(find("css/../css/hte-remote.css").is_none());
        assert!(find("css//hte-remote.css").is_none());
        assert!(find("").is_none());
        assert_eq!(content_type("fonts/figtree/figtree-latin.woff2"), "font/woff2");
    }
}
