//! `/api/v1` — the HTTP contract every inspector face drives.

use std::convert::Infallible;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures::Stream;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{ApiState, Workspace};
use crate::engine::ops::{self, Op, OpError};
use crate::engine::registry::Engine;
use crate::engine::session::SessionError;
use crate::engine::target::TargetSpec;

/// The API routes, still awaiting state — the caller adds the SPA
/// route, applies the security layer, and supplies state once for all
/// of it.
pub fn router() -> Router<ApiState> {
    Router::new()
        .route("/api/v1/meta", get(meta))
        .route("/api/v1/targets", get(list_targets).post(add_target))
        .route(
            "/api/v1/targets/{id}",
            get(get_target).delete(remove_target),
        )
        .route("/api/v1/targets/{id}/connect", post(connect))
        .route("/api/v1/targets/{id}/disconnect", post(disconnect))
        .route("/api/v1/targets/{id}/ops/{op}", post(run_op))
        .route("/api/v1/targets/{id}/auth", get(auth))
        .route("/api/v1/targets/{id}/checks", get(checks))
        .route("/api/v1/targets/{id}/gateway", get(gateway))
        .route("/api/v1/targets/{id}/pending", get(pending))
        .route("/api/v1/targets/{id}/pending/{request}", post(respond))
        .route("/api/v1/targets/{id}/events", get(events))
        .route("/api/v1/targets/{id}/export", get(export))
        .route("/api/v1/targets/{id}/subscribe", get(subscribe))
        .route("/api/v1/exec", post(exec))
}

/// What this target requires for authorization. Deliberately does not
/// need a connected session — the question is what an unauthenticated
/// caller is told, which is exactly what a failed connect leaves you
/// wondering.
async fn auth(
    Workspace(engine): Workspace,
    Path(id): Path<String>,
) -> Result<Json<Value>, Response> {
    let entry = target(&engine, &id)?;
    let report = crate::engine::authlab::inspect(&entry.spec)
        .await
        .map_err(|message| fail(StatusCode::BAD_GATEWAY, "auth_probe_failed", &message))?;
    Ok(Json(
        serde_json::to_value(report).unwrap_or_else(|_| json!({})),
    ))
}

async fn meta(State(state): State<ApiState>) -> Json<Value> {
    Json(json!({
        "service": "mcpg-inspector",
        "version": env!("CARGO_PKG_VERSION"),
        "mode": state.engine.mode(),
        "authMode": state.auth.as_str(),
        "protocolVersions": ["2025-11-25", "2026-07-28"],
        "ops": Op::ALL.iter().map(|op| op.as_str()).collect::<Vec<_>>(),
    }))
}

async fn list_targets(Workspace(engine): Workspace) -> Json<Value> {
    let targets: Vec<Value> = engine.list().iter().map(|t| t.describe()).collect();
    Json(json!({ "targets": targets }))
}

async fn add_target(
    Workspace(engine): Workspace,
    axum::Extension(identity): axum::Extension<crate::api::auth::Identity>,
    Json(spec): Json<TargetSpec>,
) -> Result<Json<Value>, Response> {
    // Registering a target is the stateful twin of `exec` with an inline
    // target: both end in the service dialling an address the caller chose.
    if !identity.may_dial_arbitrary_targets() {
        return Err(fail(
            StatusCode::UNAUTHORIZED,
            "sign_in_required",
            "sign in to inspect a server of your own —              the pre-configured ones need no account",
        ));
    }
    let entry = engine
        .add_target(spec)
        .map_err(|message| fail(StatusCode::BAD_REQUEST, "invalid_target", &message))?;
    Ok(Json(entry.describe()))
}

async fn get_target(
    Workspace(engine): Workspace,
    Path(id): Path<String>,
) -> Result<Json<Value>, Response> {
    Ok(Json(target(&engine, &id)?.describe()))
}

async fn remove_target(
    Workspace(engine): Workspace,
    Path(id): Path<String>,
) -> Result<Json<Value>, Response> {
    if !engine.remove(&id).await {
        return Err(not_found(&id));
    }
    Ok(Json(json!({ "removed": id })))
}

async fn connect(
    Workspace(engine): Workspace,
    Path(id): Path<String>,
) -> Result<Json<Value>, Response> {
    let entry = target(&engine, &id)?;
    match entry.connect().await {
        Ok(_) => Ok(Json(entry.describe())),
        // A failed connect is reported with the target's state (which
        // now carries the reason) rather than an opaque 5xx — the whole
        // point of the tool is to show why a server would not talk.
        Err(SessionError::Spec(message)) => {
            Err(fail(StatusCode::BAD_REQUEST, "invalid_target", &message))
        }
        Err(SessionError::Client(e)) => Err(fail(
            StatusCode::BAD_GATEWAY,
            "connect_failed",
            &e.to_string(),
        )),
    }
}

async fn disconnect(
    Workspace(engine): Workspace,
    Path(id): Path<String>,
) -> Result<Json<Value>, Response> {
    let entry = target(&engine, &id)?;
    entry.disconnect().await;
    Ok(Json(entry.describe()))
}

async fn run_op(
    Workspace(engine): Workspace,
    Path((id, op)): Path<(String, String)>,
    body: Option<Json<Value>>,
) -> Result<Json<Value>, Response> {
    let entry = target(&engine, &id)?;
    let op = Op::parse(&op).ok_or_else(|| {
        fail(
            StatusCode::NOT_FOUND,
            "unknown_op",
            &format!("no op '{op}'"),
        )
    })?;
    let session = entry.session().await.ok_or_else(|| {
        fail(
            StatusCode::CONFLICT,
            "not_connected",
            "target is not connected — POST /connect first",
        )
    })?;
    let params = body.map(|Json(v)| v).unwrap_or_else(|| json!({}));
    match ops::dispatch(&session, op, &params).await {
        Ok(result) => Ok(Json(result)),
        Err(OpError::Params(message)) => {
            Err(fail(StatusCode::BAD_REQUEST, "invalid_params", &message))
        }
        Err(OpError::Client(e)) => Err(fail(StatusCode::BAD_GATEWAY, "op_failed", &e.to_string())),
    }
}

/// Server→client requests waiting on a human. Only the `interactive`
/// policy ever fills this — the others answer inline.
async fn pending(
    Workspace(engine): Workspace,
    Path(id): Path<String>,
) -> Result<Json<Value>, Response> {
    let entry = target(&engine, &id)?;
    Ok(Json(json!({
        "policy": entry.responder.policy(),
        "pending": entry.responder.pending().await,
    })))
}

/// Answer one queued request. `{"result": …}` fulfils it;
/// `{"error": {"code": …, "message": …}}` declines it — a decline is a
/// legitimate answer, so it is not an API error.
async fn respond(
    Workspace(engine): Workspace,
    Path((id, request)): Path<(String, u64)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, Response> {
    let entry = target(&engine, &id)?;
    let answer = match body.get("error") {
        Some(error) => Err((
            error.get("code").and_then(Value::as_i64).unwrap_or(-32603),
            error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("declined by the operator")
                .to_owned(),
        )),
        None => Ok(body.get("result").cloned().unwrap_or_else(|| json!({}))),
    };
    if !entry.responder.resolve(request, answer).await {
        return Err(fail(
            StatusCode::NOT_FOUND,
            "no_such_request",
            "no pending request with that id (already answered, or the session ended)",
        ));
    }
    Ok(Json(json!({ "answered": request })))
}

#[cfg(test)]
mod resume_tests {
    use super::resume_from;
    use axum::http::{HeaderMap, HeaderValue};

    fn headers(last: Option<&str>) -> HeaderMap {
        let mut map = HeaderMap::new();
        if let Some(last) = last {
            map.insert("last-event-id", HeaderValue::from_str(last).unwrap());
        }
        map
    }

    /// A browser sends `Last-Event-ID` by itself when an `EventSource`
    /// reconnects, and it is the more recent of the two by construction: the
    /// query string is whatever the page asked for on first load.
    #[test]
    fn the_header_wins_over_a_stale_query() {
        assert_eq!(resume_from(&headers(Some("42")), 0), 42);
        assert_eq!(resume_from(&headers(Some(" 42 ")), 0), 42);
    }

    /// Without a header the query is the answer — `curl` and the attached
    /// terminal have no EventSource to send one.
    #[test]
    fn without_a_header_the_query_stands() {
        assert_eq!(resume_from(&headers(None), 7), 7);
        assert_eq!(resume_from(&headers(None), 0), 0);
    }

    /// A header that is not a sequence number must not silently rewind the
    /// stream to the beginning; the caller's own `since` is the safer answer.
    #[test]
    fn an_unreadable_header_falls_back_rather_than_replaying() {
        assert_eq!(resume_from(&headers(Some("not-a-number")), 5), 5);
        assert_eq!(resume_from(&headers(Some("")), 5), 5);
    }
}

#[derive(Deserialize)]
struct EventsQuery {
    /// Resume after this sequence number; the buffered tail replays
    /// before the live stream starts.
    #[serde(default)]
    since: u64,
}

/// Where a reconnecting stream should pick up.
///
/// `Last-Event-ID` is what a browser sends by itself when an `EventSource`
/// drops and retries, so honouring it makes resumption automatic and exact.
/// `?since=` stays for callers that are not a browser — `curl`, the attached
/// TUI — and the header wins when both are present, because the header is
/// the more recent of the two by construction.
fn resume_from(headers: &axum::http::HeaderMap, since: u64) -> u64 {
    headers
        .get(axum::http::header::HeaderName::from_static("last-event-id"))
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(since)
}

async fn events(
    Workspace(engine): Workspace,
    Path(id): Path<String>,
    Query(query): Query<EventsQuery>,
    headers: axum::http::HeaderMap,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, Response> {
    let entry = target(&engine, &id)?;
    let backlog = entry.events.since(resume_from(&headers, query.since));
    let mut live = entry.events.subscribe();
    let stream = async_stream::stream! {
        for event in backlog {
            // The id is the frame's own sequence number, which is what makes
            // the resume exact rather than approximate.
            let seq = event.seq;
            if let Ok(event) = Event::default().id(seq.to_string()).json_data(&event) {
                yield Ok(event);
            }
        }
        loop {
            match live.recv().await {
                Ok(event) => {
                    let seq = event.seq;
                    if let Ok(event) = Event::default().id(seq.to_string()).json_data(&event) {
                        yield Ok(event);
                    }
                }
                // Lagged: the client fell behind the broadcast window.
                // Keep the stream open — it resyncs with `?since=`.
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    };
    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

/// The frame log as JSONL — one event per line, generated per request
/// and never written server-side.
async fn export(
    Workspace(engine): Workspace,
    Path(id): Path<String>,
) -> Result<Response, Response> {
    let entry = target(&engine, &id)?;
    // A recording, not a bare frame dump: the header is what makes the file
    // self-describing, and the redaction pass is what makes it safe to send
    // to someone. See `docs/inspector/rfcs/0003-recording-replay.md`.
    let header = crate::engine::recording::RecordingHeader {
        kind: crate::engine::recording::KIND.to_owned(),
        version: crate::engine::recording::VERSION,
        recorded_at_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or_default(),
        // `describe()` is the redacted view the API already returns; the
        // configured spec, with its bearer, is never what gets written.
        target: entry.describe(),
        negotiated_version: match entry.state() {
            crate::engine::registry::SessionState::Ready { negotiated_version } => {
                Some(negotiated_version)
            }
            _ => None,
        },
        redacted: true,
    };
    let frames: Vec<_> = entry
        .events
        .snapshot()
        .into_iter()
        .map(|mut event| {
            event.body = crate::engine::recording::redact_frame(&event.body);
            event
        })
        .collect();
    let body = crate::engine::recording::write(&header, &frames);
    Ok((
        [
            ("content-type", "application/x-ndjson"),
            (
                "content-disposition",
                "attachment; filename=\"inspector-recording.jsonl\"",
            ),
        ],
        body,
    )
        .into_response())
}

/// `Response` is the error type every handler in this module already
/// returns, so boxing it here would only move the allocation and force an
/// unboxing at each `?`.
#[allow(clippy::result_large_err)]
fn target(
    engine: &Engine,
    id: &str,
) -> Result<std::sync::Arc<crate::engine::registry::TargetEntry>, Response> {
    engine.get(id).ok_or_else(|| not_found(id))
}

fn not_found(id: &str) -> Response {
    fail(
        StatusCode::NOT_FOUND,
        "no_such_target",
        &format!("no target '{id}'"),
    )
}

fn fail(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(json!({ "error": { "code": code, "message": message } })),
    )
        .into_response()
}

/// Run one operation against one target, keeping nothing.
///
/// The stateless path. `targetId` names something the operator pre-wired and
/// is open to anyone; `target` is an address the caller chose, and a hosted
/// instance requires a signed-in identity for it — that dial is the abuse
/// surface, not the reading.
async fn exec(
    State(state): State<ApiState>,
    Workspace(engine): Workspace,
    axum::Extension(identity): axum::Extension<crate::api::auth::Identity>,
    Json(req): Json<crate::engine::stateless::ExecRequest>,
) -> Result<Json<Value>, Response> {
    use crate::engine::stateless::{self, ExecError};

    let spec = match (&req.target_id, &req.target) {
        (Some(_), Some(_)) => {
            return Err(fail(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "pass either `targetId` or `target`, not both",
            ));
        }
        (Some(id), None) => target(&engine, id)?.spec.clone(),
        (None, Some(spec)) => {
            if !identity.may_dial_arbitrary_targets() {
                return Err(fail(
                    StatusCode::UNAUTHORIZED,
                    "sign_in_required",
                    "sign in to inspect a server of your own — \
                     the pre-configured ones need no account",
                ));
            }
            let mut spec = spec.clone();
            // The hosted profile applies to a supplied target exactly as it
            // does to a registered one: no process spawning, and no reach
            // into private address space. Overridden rather than validated,
            // because a rejection only teaches the caller to omit the field.
            if engine.mode() == crate::engine::registry::Mode::Hosted {
                if spec.is_stdio() {
                    return Err(fail(
                        StatusCode::BAD_REQUEST,
                        "invalid_target",
                        "stdio targets are not available in hosted mode",
                    ));
                }
                spec.allow_private = false;
            }
            spec
        }
        (None, None) => {
            return Err(fail(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "pass a `targetId` or a `target`",
            ));
        }
    };

    match stateless::exec(&spec, &req.op, &req.params, state.exec_frame_limit).await {
        Ok(out) => Ok(Json(
            serde_json::to_value(out).unwrap_or_else(|_| json!({})),
        )),
        Err(ExecError::Params(message)) => {
            Err(fail(StatusCode::BAD_REQUEST, "invalid_request", &message))
        }
        Err(ExecError::Connect(e)) => Err(fail(
            StatusCode::BAD_GATEWAY,
            "connect_failed",
            &e.to_string(),
        )),
        Err(ExecError::Op(e)) => Err(fail(StatusCode::BAD_GATEWAY, "op_failed", &e.to_string())),
    }
}

#[derive(Deserialize)]
struct SubscribeQuery {
    /// Resource URIs to watch, comma-separated. Absent watches none — the
    /// list-changed flags below are independent of it.
    #[serde(default)]
    uris: Option<String>,
    /// Catalog changes. Default on: a client that opened this stream at all
    /// wants to know when what it is showing stops being true.
    #[serde(default = "yes")]
    lists: bool,
}

fn yes() -> bool {
    true
}

/// Stream the changes a target pushes.
///
/// The one surface that cannot be served statelessly: a subscription is a
/// held-open connection to the upstream, so it belongs to a registered
/// target on this replica. A hosted deployment pins the caller here for the
/// life of the stream — see `docs/inspector/HOSTED.md`.
async fn subscribe(
    Workspace(engine): Workspace,
    Path(id): Path<String>,
    Query(query): Query<SubscribeQuery>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, Response> {
    let entry = target(&engine, &id)?;
    let session = entry.session().await.ok_or_else(|| {
        fail(
            StatusCode::CONFLICT,
            "not_connected",
            "connect the target before subscribing",
        )
    })?;

    let spec = mcpg_mcp_client::upstream::SubscriptionSpec {
        resource_uris: query
            .uris
            .as_deref()
            .map(|raw| {
                raw.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
        tools_list_changed: query.lists,
        prompts_list_changed: query.lists,
        resources_list_changed: query.lists,
    };

    let mut pushes = session
        .subscribe(&spec)
        .await
        .map_err(|e| fail(StatusCode::BAD_GATEWAY, "subscribe_failed", &e.to_string()))?;

    let stream = async_stream::stream! {
        use futures::StreamExt;
        while let Some(push) = pushes.next().await {
            if let Ok(event) = Event::default().json_data(&push) {
                yield Ok(event);
            }
        }
    };
    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

/// Run the portable protocol checks against a connected target.
///
/// Needs a session because the checks are about the wire this target
/// actually negotiated — a check written for the stateless revision proves
/// nothing about a server speaking the sessionful one.
/// What the mcpg gateway behind this target says about itself. Needs a
/// connected session for the endpoint URL, not for the read — `/runtime` is
/// unauthenticated, and the point of the panel is the case where the MCP
/// surface looks fine and something behind it does not.
async fn gateway(
    Workspace(engine): Workspace,
    Path(id): Path<String>,
) -> Result<Json<Value>, Response> {
    let entry = target(&engine, &id)?;
    let session = entry.session().await.ok_or_else(|| {
        fail(
            StatusCode::CONFLICT,
            "not_connected",
            "connect the target before reading its gateway",
        )
    })?;
    let report = crate::engine::gateway::for_session(&session, entry.spec.allow_private)
        .await
        .map_err(|message| fail(StatusCode::BAD_GATEWAY, "gateway_unavailable", &message))?;
    Ok(Json(
        serde_json::to_value(report).unwrap_or_else(|_| json!({})),
    ))
}

async fn checks(
    Workspace(engine): Workspace,
    Path(id): Path<String>,
) -> Result<Json<Value>, Response> {
    let entry = target(&engine, &id)?;
    let session = entry.session().await.ok_or_else(|| {
        fail(
            StatusCode::CONFLICT,
            "not_connected",
            "connect the target before running checks",
        )
    })?;
    let url = session.endpoint_url().ok_or_else(|| {
        fail(
            StatusCode::BAD_REQUEST,
            "not_http",
            "the protocol checks probe an HTTP endpoint; a stdio target has none",
        )
    })?;
    let report =
        crate::engine::checks::run(url, session.negotiated_version(), entry.spec.allow_private)
            .await
            .map_err(|message| fail(StatusCode::BAD_GATEWAY, "checks_failed", &message))?;
    Ok(Json(
        serde_json::to_value(report).unwrap_or_else(|_| json!({})),
    ))
}
