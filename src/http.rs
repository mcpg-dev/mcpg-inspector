use std::sync::Arc;

use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;

use crate::api::{ApiState, auth::AuthPolicy};
use crate::config::ServeArgs;
use crate::engine::registry::{Engine, Mode};

pub fn run_serve(args: ServeArgs) -> ! {
    init_tracing(args.dev);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let code = match runtime.block_on(serve(&args)) {
        Ok(()) => 0,
        Err(err) => {
            eprintln!(
                "{}",
                json!({"error": {"code": "serve", "message": err.to_string()}})
            );
            1
        }
    };
    std::process::exit(code);
}

/// A configuration refusal, as the io::Error `serve` returns.
fn invalid(message: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message)
}

async fn serve(args: &ServeArgs) -> std::io::Result<()> {
    // A wildcard bind exposes the API — which can spawn processes — to
    // the whole network, so it takes a deliberately ugly opt-in.
    // `--bind` parses to a SocketAddr, so `is_unspecified` is exact:
    // the alternate spellings a string check would have to chase
    // (`0`, `0x0`, `::`, fullwidth digits) never survive parsing.
    if args.bind.ip().is_unspecified() && !args.dangerously_bind_all_interfaces {
        return Err(invalid(format!(
            "refusing to bind every interface ({}) — the API can spawn processes. \
             Bind a specific address, or pass --dangerously-bind-all-interfaces.",
            args.bind
        )));
    }
    if args.auth_none && !args.bind.ip().is_loopback() {
        return Err(invalid(
            "--auth-none is only allowed on a loopback bind".to_owned(),
        ));
    }
    // Hosted serves strangers. Anonymity is not a mode it has, and a pinned
    // token would be one shared credential for everyone — including a shared
    // workspace, which is the property hosted mode exists to avoid.
    if args.hosted && args.auth_none {
        return Err(invalid(
            "--auth-none cannot be combined with --hosted: a hosted instance \
             authenticates every caller through OIDC"
                .to_owned(),
        ));
    }
    if args.hosted && args.session_token.is_some() {
        return Err(invalid(
            "--session-token cannot be combined with --hosted: one shared token \
             would give every caller the same workspace"
                .to_owned(),
        ));
    }

    let engine = Arc::new(Engine::new(
        if args.hosted {
            Mode::Hosted
        } else {
            Mode::Local
        },
        args.frame_buffer,
    ));
    for spec in resolve_targets(&args.targets).map_err(invalid)? {
        let name = spec.name.clone();
        let entry = engine.add_target(spec).map_err(invalid)?;
        tracing::info!(
            target_id = %entry.id,
            named = name.is_some(),
            bearer = entry.spec.bearer.is_some(),
            "pre-wired target"
        );
    }

    let auth = Arc::new(if args.hosted {
        AuthPolicy::oidc(Arc::new(hosted_auth(args)?))
    } else if args.auth_none {
        AuthPolicy::none(args.bind)
    } else {
        AuthPolicy::token(
            args.session_token
                .clone()
                .unwrap_or_else(|| format!("{}", uuid::Uuid::new_v4().simple())),
            args.bind,
        )
    });
    let state = ApiState {
        engine,
        auth: Arc::clone(&auth),
        // Local serves one operator on loopback and needs no limiter;
        // hosted serves strangers, and every guarded route can make the
        // process dial an arbitrary URL.
        limiter: Arc::new(crate::api::limit::RateLimiter::new(
            if args.hosted {
                args.rate_limit_per_min
            } else {
                0
            },
            args.rate_limit_burst,
        )),
        exec_frame_limit: 500,
    };

    let state_for_auth = state.clone();
    // Everything that carries data sits behind the guard. The SPA
    // shell is guarded too, so the operator must open the printed
    // URL — which is also how the page learns its token.
    let protected = crate::api::routes::router()
        .route("/", get(index))
        // Any other path is one of the SPA's own routes — serve the
        // shell and let the client router take it.
        .fallback(get(index))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::api::auth::guard,
        ))
        .with_state(state);
    // The bundle is NOT behind the guard: a browser fetches
    // `<script src>` with no Authorization header, so guarding it
    // would 401 the very code that is supposed to present the token.
    // It is the same public JS/CSS every install ships — the data it
    // fetches is what the guard protects. Health probes are outside
    // for a different reason: the supervisor polls /readyz before it
    // can know a token.
    let mut app = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/assets/{*path}", get(crate::static_ui::asset));
    // Sign-in routes sit outside the guard — they are how a caller becomes
    // authorized, so guarding them would be a loop.
    if auth.hosted().is_some() {
        app = app.merge(
            auth_router()
                // The client-metadata document IS this instance's OAuth
                // client_id, so a server has to be able to fetch it without
                // a credential — guarding it would make the id unresolvable.
                .route(
                    crate::engine::oauth::CLIENT_METADATA_PATH,
                    get(client_metadata_document),
                )
                .with_state(state_for_auth),
        );
    }
    let app = app.merge(protected);

    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    let bound = listener.local_addr()?;
    announce(&bound, &auth, args.open_browser);
    // `into_make_service_with_connect_info` is what makes the peer
    // address reachable in the guard; without it the limiter would see
    // no address and let every request through.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
}

/// Print the URL a browser should open. The token rides in the query
/// because the page has no other way to learn it on first load; it is
/// also injected into the page itself, so it never has to be re-sent.
fn announce(bound: &std::net::SocketAddr, auth: &AuthPolicy, open_browser: bool) {
    let base = format!("http://{bound}/");
    let url = match auth {
        AuthPolicy::Token { token, .. } => format!("{base}?token={token}"),
        AuthPolicy::None { .. } => base,
        // Hosted is reached at its public URL through a proxy; the bound
        // socket is an implementation detail nobody should be told to open.
        AuthPolicy::Oidc { hosted, .. } => format!("{}/", hosted.public_url()),
    };
    eprintln!();
    eprintln!("  mcpg-inspector — open:");
    eprintln!();
    eprintln!("    {url}");
    eprintln!();
    if open_browser && let Err(e) = webbrowser::open(&url) {
        tracing::warn!("could not open a browser: {e}");
    }
}

/// Parse `--target` specs and fold in the supervisor-minted gateway
/// credential: `MCPG_INSPECTOR_GATEWAY_TOKEN` becomes the bearer of the
/// target named `gateway` (when it has none of its own). The token
/// travels via environment only — it must never appear on argv.
fn resolve_targets(specs: &[String]) -> Result<Vec<crate::engine::target::TargetSpec>, String> {
    let gateway_token = std::env::var("MCPG_INSPECTOR_GATEWAY_TOKEN").ok();
    specs
        .iter()
        .map(|spec| {
            let mut target = crate::engine::target::TargetSpec::parse_cli(spec)?;
            if target.bearer.is_none()
                && target.name.as_deref() == Some("gateway")
                && let Some(token) = &gateway_token
            {
                target.bearer = Some(token.clone());
            }
            Ok(target)
        })
        .collect()
}

async fn healthz() -> Json<serde_json::Value> {
    Json(json!({"status": "ok"}))
}

async fn readyz() -> Json<serde_json::Value> {
    Json(json!({"status": "ready"}))
}

/// The SPA shell, carrying the session token the page will use for
/// every API call — so the token need not live in the URL bar.
async fn index(
    axum::extract::State(state): axum::extract::State<ApiState>,
) -> impl axum::response::IntoResponse {
    let token = match state.auth.as_ref() {
        AuthPolicy::Token { token, .. } => token.as_str(),
        // Hosted identity rides an HttpOnly cookie the page must not read,
        // and OIDC sessions are never revealed to the document.
        AuthPolicy::None { .. } | AuthPolicy::Oidc { .. } => "",
    };
    crate::static_ui::index(token)
}

/// SIGTERM matters here: the gateway supervisor's PDEATHSIG delivers it
/// when the parent dies without running destructors.
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
    }
}

fn init_tracing(dev: bool) {
    let default = if dev { "debug" } else { "info" };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

/// The OIDC endpoints: unguarded by construction, because they are how a
/// caller *becomes* authorized. They exist only in hosted mode.
pub fn auth_router() -> Router<ApiState> {
    Router::new()
        .route("/auth/login", get(auth_login))
        .route("/auth/callback", get(auth_callback))
        .route("/auth/logout", get(auth_logout))
}

#[derive(serde::Deserialize)]
struct LoginQuery {
    #[serde(default)]
    next: Option<String>,
}

async fn auth_login(
    axum::extract::State(state): axum::extract::State<ApiState>,
    axum::extract::Query(query): axum::extract::Query<LoginQuery>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let Some(hosted) = state.auth.hosted() else {
        return sign_in_unavailable();
    };
    match hosted.begin(query.next.as_deref().unwrap_or("/")).await {
        Ok(url) => axum::response::Redirect::temporary(&url).into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "could not start a sign-in");
            login_error(&e.to_string())
        }
    }
}

#[derive(serde::Deserialize)]
struct CallbackQuery {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

async fn auth_callback(
    axum::extract::State(state): axum::extract::State<ApiState>,
    axum::extract::Query(query): axum::extract::Query<CallbackQuery>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let Some(hosted) = state.auth.hosted() else {
        return sign_in_unavailable();
    };
    // The provider's own refusal is its answer; report it rather than
    // treating a missing code as a malformed request.
    if let Some(error) = query.error {
        let detail = query
            .error_description
            .map(|d| format!(": {d}"))
            .unwrap_or_default();
        return login_error(&format!("the identity provider refused: {error}{detail}"));
    }
    let (Some(code), Some(oauth_state)) = (query.code, query.state) else {
        return login_error("the sign-in response was missing its code");
    };

    match hosted.complete(&code, &oauth_state).await {
        Ok((session, next)) => {
            tracing::info!(subject = %session.subject, "session opened");
            (
                [(
                    axum::http::header::SET_COOKIE,
                    hosted.session_cookie(&session.id),
                )],
                axum::response::Redirect::temporary(&next),
            )
                .into_response()
        }
        Err(e) => {
            // Logged with the reason, shown without it: an exchange failure
            // can carry provider detail a stranger has no business reading.
            tracing::warn!(error = %e, "sign-in did not complete");
            login_error(&e.to_string())
        }
    }
}

async fn auth_logout(
    axum::extract::State(state): axum::extract::State<ApiState>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let Some(hosted) = state.auth.hosted() else {
        return sign_in_unavailable();
    };
    if let Some(id) = crate::api::hosted::session_from_cookies(
        headers.get("cookie").and_then(|v| v.to_str().ok()),
    ) {
        hosted.end(&id);
    }
    (
        [(axum::http::header::SET_COOKIE, hosted.clearing_cookie())],
        axum::response::Redirect::temporary("/"),
    )
        .into_response()
}

fn sign_in_unavailable() -> axum::response::Response {
    use axum::response::IntoResponse;
    (
        axum::http::StatusCode::NOT_FOUND,
        axum::Json(serde_json::json!({
            "error": {
                "code": "no_sign_in",
                "message": "this instance does not use OIDC sign-in"
            }
        })),
    )
        .into_response()
}

/// A sign-in failure reaches a browser, so it is a page rather than JSON.
fn login_error(message: &str) -> axum::response::Response {
    use axum::response::IntoResponse;
    let escaped = message
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    (
        axum::http::StatusCode::BAD_REQUEST,
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        format!(
            "<!doctype html><meta charset=utf-8><title>Sign-in failed</title>\
             <style>body{{font-family:system-ui;max-width:32rem;margin:5rem auto}}\
             code{{background:#f4f4f5;padding:.15rem .35rem;border-radius:.25rem}}</style>\
             <h1>Sign-in failed</h1><p>{escaped}</p>\
             <p><a href=\"/auth/login\">Try again</a></p>"
        ),
    )
        .into_response()
}

/// Build the hosted identity layer, or say exactly which piece is missing.
///
/// Every field is required rather than defaulted: a hosted instance that
/// silently came up without an issuer would serve strangers with no
/// authentication at all, which is the one failure this mode cannot have.
fn hosted_auth(args: &ServeArgs) -> std::io::Result<crate::api::hosted::HostedAuth> {
    let missing = |flag: &str, env: &str| invalid(format!("--hosted requires {flag} (env {env})"));
    let issuer = args
        .oidc_issuer
        .as_deref()
        .ok_or_else(|| missing("--oidc-issuer", "MCPG_INSPECTOR_OIDC_ISSUER"))?;
    let issuer: url::Url = issuer
        .parse()
        .map_err(|e| invalid(format!("--oidc-issuer is not a URL: {e}")))?;
    let client_id = args
        .oidc_client_id
        .clone()
        .ok_or_else(|| missing("--oidc-client-id", "MCPG_INSPECTOR_OIDC_CLIENT_ID"))?;
    let public_url = args
        .public_url
        .clone()
        .ok_or_else(|| missing("--public-url", "MCPG_INSPECTOR_PUBLIC_URL"))?;
    if !public_url.starts_with("https://") && !public_url.starts_with("http://") {
        return Err(invalid(
            "--public-url must be an absolute http(s) URL".to_owned(),
        ));
    }
    Ok(crate::api::hosted::HostedAuth::new(
        issuer,
        client_id,
        args.oidc_client_secret.clone(),
        public_url,
        args.frame_buffer,
        args.max_sessions,
        args.max_targets,
    ))
}

/// This instance's OAuth client-metadata document.
///
/// Unauthenticated by design: an authorization server fetches this URL to
/// learn who the `client_id` belongs to, and it has no credential to offer.
async fn client_metadata_document(
    axum::extract::State(state): axum::extract::State<ApiState>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    match state.auth.hosted() {
        Some(hosted) => {
            Json(crate::engine::oauth::client_metadata(hosted.public_url())).into_response()
        }
        None => sign_in_unavailable(),
    }
}
