//! The HTTP API every face can drive, and the security layer in front
//! of it.
//!
//! The threat model is the one the official inspector learned the hard
//! way (CVE-2025-49596: an unauthenticated localhost daemon that could
//! spawn processes, reachable from any web page via DNS rebinding).
//! So, on by default: loopback bind, a per-boot session token on every
//! route, and origin validation that runs *before* auth and fails
//! closed.

pub mod auth;
pub mod hosted;
pub mod limit;
pub mod routes;

use std::sync::Arc;

use crate::engine::registry::Engine;

/// Everything a request handler needs.
#[derive(Clone)]
pub struct ApiState {
    /// The shared workspace. In local mode this *is* every caller's
    /// workspace; hosted mode gives each signed-in subject its own and
    /// this one stays empty.
    pub engine: Arc<Engine>,
    pub auth: Arc<auth::AuthPolicy>,
    /// Per-IP limiter. Disabled (and free) unless hosted.
    pub limiter: Arc<limit::RateLimiter>,
    /// Frames one stateless call may return. Bounds a response the caller
    /// asked for rather than a buffer the server keeps.
    pub exec_frame_limit: usize,
}

/// The caller's workspace, attached to the request by
/// [`auth::guard`].
///
/// Handlers take this rather than reaching for `ApiState::engine`, which is
/// what makes hosted isolation structural: there is no path from a request
/// to another subject's targets, so a handler cannot leak one by forgetting
/// to scope a lookup. Extraction failing means the guard did not run, which
/// is a wiring bug rather than a request the caller can provoke.
pub struct Workspace(pub Arc<Engine>);

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for Workspace {
    type Rejection = axum::response::Response;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Arc<Engine>>()
            .cloned()
            .map(Workspace)
            .ok_or_else(|| {
                use axum::response::IntoResponse;
                tracing::error!("workspace missing — a route escaped the auth guard");
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    axum::Json(serde_json::json!({
                        "error": { "code": "no_workspace", "message": "request was not authorized" }
                    })),
                )
                    .into_response()
            })
    }
}
