//! Serving the embedded SPA.
//!
//! The bundle is built to `server/static/` by `pnpm build` in `ui/`,
//! committed, and embedded at compile time via `include_dir!` when the
//! `embedded-ui` feature is on. Without the feature a one-page
//! fallback is served instead, so a checkout with no Node toolchain
//! still builds and runs.
//!
//! `index.html` is rewritten on the way out to carry the session
//! token, so the page never has to read it from the URL bar.

use axum::response::Response;

/// Rewritten `index.html`: the SPA shell plus the token the page will
/// use for every API call. JSON-encoding with `<` escaped means a
/// token containing `</script>` cannot break out of the block.
fn with_token(html: &str, token: &str) -> String {
    let encoded = serde_json::to_string(token)
        .unwrap_or_else(|_| "\"\"".to_owned())
        .replace('<', "\\u003c");
    let script = format!("<script>window.__INSPECTOR_TOKEN__ = {encoded};</script>");
    match html.find("</head>") {
        Some(idx) => {
            let mut out = String::with_capacity(html.len() + script.len());
            out.push_str(&html[..idx]);
            out.push_str(&script);
            out.push_str(&html[idx..]);
            out
        }
        // No </head> (a hand-written shell): prepend, so the token is
        // defined before the bundle runs either way.
        None => format!("{script}{html}"),
    }
}

fn html_response(body: String) -> Response {
    use axum::response::IntoResponse;
    (
        [
            ("content-type", "text/html; charset=utf-8"),
            // The token is in the body, so this page is never cacheable.
            ("cache-control", "no-store"),
            ("x-frame-options", "DENY"),
            ("x-content-type-options", "nosniff"),
        ],
        body,
    )
        .into_response()
}

#[cfg(feature = "embedded-ui")]
mod bundled {
    use axum::body::Body;
    use axum::extract::Path;
    use axum::http::{StatusCode, header};
    use axum::response::{IntoResponse, Response};
    use include_dir::{Dir, include_dir};

    /// The committed Vite output, included at compile time. The build
    /// treats the whole tree as a compile input because this macro
    /// reads it from disk while compiling.
    static UI_DIR: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/static");

    pub fn index(token: &str) -> Response {
        match UI_DIR.get_file("index.html") {
            Some(file) => {
                let html = String::from_utf8_lossy(file.contents());
                super::html_response(super::with_token(&html, token))
            }
            None => super::html_response(super::with_token(super::FALLBACK_HTML, token)),
        }
    }

    pub async fn asset(Path(path): Path<String>) -> Response {
        // Path traversal: reject before touching the tree. The embedded
        // `Dir` holds full `assets/...` paths, and axum has stripped the
        // prefix, so put it back for the lookup.
        if path.contains("..") || path.starts_with('/') {
            return (StatusCode::BAD_REQUEST, "bad path").into_response();
        }
        let full = format!("assets/{path}");
        let Some(file) = UI_DIR.get_file(&full) else {
            return (StatusCode::NOT_FOUND, "not found").into_response();
        };
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, guess_mime(&full))
            // Vite content-hashes every asset filename, so a hit is
            // valid forever; only index.html is uncacheable.
            .header(header::CACHE_CONTROL, "public, max-age=31536000, immutable")
            .body(Body::from(file.contents()))
            .unwrap()
    }

    fn guess_mime(path: &str) -> &'static str {
        match path.rsplit_once('.').map(|(_, ext)| ext) {
            Some("js" | "mjs") => "text/javascript; charset=utf-8",
            Some("css") => "text/css; charset=utf-8",
            Some("json") => "application/json",
            Some("svg") => "image/svg+xml",
            Some("png") => "image/png",
            Some("jpg" | "jpeg") => "image/jpeg",
            Some("webp") => "image/webp",
            Some("ico") => "image/x-icon",
            Some("woff2") => "font/woff2",
            Some("woff") => "font/woff",
            Some("map") => "application/json",
            _ => "application/octet-stream",
        }
    }
}

/// Served when the crate is built without `embedded-ui` — a working
/// binary with an honest explanation instead of a blank page.
const FALLBACK_HTML: &str = "<!doctype html><meta charset=\"utf-8\">\
     <title>mcpg-inspector</title>\
     <h1>mcpg-inspector</h1>\
     <p>This binary was built without the <code>embedded-ui</code> feature, \
     so the web UI bundle is not included. The API is live at \
     <code>/api/v1/meta</code>, and the CLI verbs \
     (<code>list</code>, <code>call</code>, <code>read</code>) work as usual.</p>";

#[cfg(not(feature = "embedded-ui"))]
mod bundled {
    use axum::extract::Path;
    use axum::http::StatusCode;
    use axum::response::{IntoResponse, Response};

    pub fn index(token: &str) -> Response {
        super::html_response(super::with_token(super::FALLBACK_HTML, token))
    }

    pub async fn asset(Path(_): Path<String>) -> Response {
        (StatusCode::NOT_FOUND, "no embedded UI").into_response()
    }
}

pub use bundled::{asset, index};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_injected_before_head_closes() {
        let html = "<!doctype html><head><title>x</title></head><body></body>";
        let out = with_token(html, "abc123");
        assert!(out.contains("window.__INSPECTOR_TOKEN__ = \"abc123\""));
        assert!(out.find("__INSPECTOR_TOKEN__").unwrap() < out.find("</head>").unwrap());
    }

    #[test]
    fn a_token_cannot_break_out_of_the_script_block() {
        let out = with_token("<head></head>", "</script><script>alert(1)</script>");
        assert!(!out.contains("</script><script>alert(1)"));
        assert!(out.contains("\\u003c/script>"));
    }

    #[test]
    fn shell_without_head_still_defines_the_token_first() {
        let out = with_token("<h1>hi</h1>", "t");
        assert!(out.starts_with("<script>"));
    }
}
