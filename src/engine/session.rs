use std::sync::Arc;

use mcpg_mcp_client::tap::SharedTap;
use mcpg_mcp_client::upstream::{McpUpstream, SubscriptionSpec, UpstreamError, connect_upstream};
use mcpg_mcp_client::wire::{
    UpstreamPrompt, UpstreamResource, UpstreamResourceTemplate, UpstreamTool,
};
use serde_json::{Value, json};

use super::responders::{BridgeHandler, MAX_MRTR_ROUNDS, Responder};
use super::target::TargetSpec;

/// A connected target. Wraps the shared MCP client; the negotiated
/// wire is captured at connect (the probe's verdict under
/// `protocol_version: auto`).
pub struct Session {
    upstream: Arc<dyn McpUpstream>,
    responder: Arc<Responder>,
    /// Kept so transport-level checks can address the same endpoint
    /// the session negotiated against.
    endpoint_url: Option<String>,
}

impl Session {
    /// `event_log` is the same log `tap` writes into, passed concretely
    /// because a replayed recording appends frames that already have their
    /// own sequence numbers and timestamps — which a `FrameTap`, whose job
    /// is to stamp new ones, cannot express.
    pub async fn connect(
        spec: &TargetSpec,
        tap: Option<SharedTap>,
        responder: Arc<Responder>,
        event_log: Option<&Arc<crate::engine::eventlog::EventLog>>,
    ) -> Result<Self, SessionError> {
        // A recording is answered from the file rather than dialed; nothing
        // else about a session changes, which is why every screen replays
        // without knowing it is doing so.
        if let crate::engine::target::TargetKind::Recording { path } = &spec.kind {
            let text = std::fs::read_to_string(path)
                .map_err(|e| SessionError::Spec(format!("cannot read {path}: {e}")))?;
            let recording = crate::engine::recording::parse(&text).map_err(SessionError::Spec)?;
            let replayed = crate::engine::recording::RecordedUpstream::new(recording);
            // The frames it was recorded with are the frames it shows, so the
            // wire screen of a replay is the wire of the original exchange.
            match event_log {
                // The API and the TUI read a real log, so the replay keeps
                // its own sequence numbers and timestamps: the wire screen of
                // a replay should be the wire of the original exchange.
                Some(log) => {
                    for frame in replayed.frames() {
                        log.replay(frame.clone());
                    }
                }
                // The one-shot verbs install a printing tap instead, which
                // has no notion of a frame that already happened. Re-stamping
                // is harmless there — it prints, it does not store.
                None => {
                    if let Some(tap) = tap.as_ref() {
                        for frame in replayed.frames() {
                            tap.on_frame(
                                direction_of(&frame.direction),
                                channel_of(&frame.channel),
                                frame.body.as_bytes(),
                            );
                        }
                    }
                }
            }
            return Ok(Self {
                upstream: Arc::new(replayed),
                responder,
                endpoint_url: None,
            });
        }
        let mut opts = spec.connect_options(tap).map_err(SessionError::Spec)?;
        // What the server may ask for is decided by what this session
        // can actually answer.
        opts.client_capabilities = responder.policy().client_capabilities();
        let endpoint_url = match &spec.kind {
            crate::engine::target::TargetKind::Http { url } => Some(url.clone()),
            crate::engine::target::TargetKind::Stdio { .. }
            | crate::engine::target::TargetKind::Recording { .. } => None,
        };
        // AAuth: obtain the person / auth token the spec asks for before the
        // first request — the consent-bearing modes may defer on the person
        // server, and that wait belongs before the MCP session opens.
        if let (Some(aauth), Some(url)) = (&spec.aauth, endpoint_url.as_deref()) {
            let signer = Arc::new(
                crate::engine::aauth::AauthSigner::new(aauth).map_err(SessionError::Spec)?,
            );
            signer.acquire(url).await.map_err(SessionError::Spec)?;
            opts.signer = Some(signer);
        }
        let upstream = connect_upstream(opts).await.map_err(SessionError::Client)?;
        Ok(Self {
            upstream,
            responder,
            endpoint_url,
        })
    }

    pub fn responder(&self) -> &Arc<Responder> {
        &self.responder
    }

    /// The HTTP endpoint this session dials, when it has one. `None`
    /// for stdio, which has no URL to run transport checks against.
    pub fn endpoint_url(&self) -> Option<&str> {
        self.endpoint_url.as_deref()
    }

    /// The wire string this session actually speaks.
    pub fn negotiated_version(&self) -> &'static str {
        if self.upstream.wire_is_modern() {
            "2026-07-28"
        } else {
            "2025-11-25"
        }
    }

    pub async fn list_tools(&self) -> Result<Vec<UpstreamTool>, UpstreamError> {
        self.upstream.list_tools().await
    }

    pub async fn list_resources(&self) -> Result<Vec<UpstreamResource>, UpstreamError> {
        self.upstream.list_resources().await
    }

    pub async fn list_resource_templates(
        &self,
    ) -> Result<Vec<UpstreamResourceTemplate>, UpstreamError> {
        self.upstream.list_resource_templates().await
    }

    pub async fn list_prompts(&self) -> Result<Vec<UpstreamPrompt>, UpstreamError> {
        self.upstream.list_prompts().await
    }

    /// Call a tool, answering whatever the server asks for along the
    /// way.
    ///
    /// The two wires suspend differently and both are handled here. On
    /// the sessionful wire the server issues requests as frames on the
    /// call's stream, so the call takes the client's bridged path with
    /// the responder attached. On the stateless wire it returns
    /// `resultType: "input_required"`, and the client must answer each
    /// entry and REPLAY the call carrying `requestState` plus
    /// `inputResponses` — the loop below, bounded so a server that
    /// keeps suspending cannot pin the inspector forever.
    pub async fn call_tool(
        &self,
        name: &str,
        arguments: Option<&Value>,
    ) -> Result<Value, UpstreamError> {
        if !self.responder.policy().bridges() {
            return self.upstream.call_tool(name, arguments).await;
        }
        if !self.upstream.wire_is_modern() {
            let handler = BridgeHandler {
                responder: Arc::clone(&self.responder),
            };
            return self
                .upstream
                .call_tool_bridged(name, arguments, None, &handler, None)
                .await;
        }
        self.call_tool_mrtr(name, arguments).await
    }

    /// The stateless-wire suspension loop (SEP-2322).
    async fn call_tool_mrtr(
        &self,
        name: &str,
        arguments: Option<&Value>,
    ) -> Result<Value, UpstreamError> {
        use mcpg_mcp_wire::v_2026_07_28::wire::mrtr::{
            META_KEY_INPUT_RESPONSES, META_KEY_REQUEST_STATE, RESULT_TYPE_INPUT_REQUIRED,
        };

        let arguments = arguments.cloned();
        // Resumption metadata rides on `params._meta`, NOT inside the
        // tool's arguments: a server reads `_meta` beside `name` and
        // `arguments`, so answers tucked into the arguments object are
        // never seen and the call suspends again forever.
        let mut resume_meta: Option<Value> = None;
        for round in 0..MAX_MRTR_ROUNDS {
            let result = self
                .upstream
                .call_tool_with_meta(name, arguments.as_ref(), resume_meta.as_ref())
                .await?;
            let suspended = result.get("resultType").and_then(Value::as_str)
                == Some(RESULT_TYPE_INPUT_REQUIRED);
            if !suspended {
                return Ok(result);
            }
            let request_state = result
                .get("requestState")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    UpstreamError::Protocol(
                        "input_required result carried no requestState to echo".to_owned(),
                    )
                })?
                .to_owned();
            let requests = result
                .get("inputRequests")
                .and_then(Value::as_object)
                .ok_or_else(|| {
                    UpstreamError::Protocol(
                        "input_required result carried no inputRequests".to_owned(),
                    )
                })?;

            // Answer every entry, keyed by the server's correlation
            // token. A declined entry travels as an error envelope
            // rather than aborting the call: what a refusal means is
            // the server's decision, not the client's.
            let mut answers = serde_json::Map::new();
            for (token, request) in requests {
                let method = request
                    .get("method")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
                let answer = self.responder.answer(&method, params, "mrtr").await;
                answers.insert(
                    token.clone(),
                    match answer {
                        Ok(value) => value,
                        Err((code, message)) => {
                            json!({ "error": { "code": code, "message": message } })
                        }
                    },
                );
            }

            resume_meta = Some(json!({
                META_KEY_REQUEST_STATE: request_state,
                META_KEY_INPUT_RESPONSES: Value::Object(answers),
            }));

            tracing::debug!(round = round + 1, tool = %name, "MRTR round");
        }
        Err(UpstreamError::Protocol(format!(
            "tool '{name}' still requesting input after {MAX_MRTR_ROUNDS} rounds — giving up"
        )))
    }

    pub async fn read_resource(&self, uri: &str) -> Result<Value, UpstreamError> {
        self.upstream.read_resource(uri).await
    }

    /// Render a prompt. Arguments are the `{name: value}` map the prompt's
    /// own `arguments` list describes — a prompt is a template, and this is
    /// the only way to see what it expands to.
    pub async fn get_prompt(
        &self,
        name: &str,
        arguments: Option<&Value>,
    ) -> Result<Value, UpstreamError> {
        self.upstream.get_prompt(name, arguments).await
    }

    /// Ask for argument completions.
    ///
    /// `reference` is `{"type":"ref/prompt","name":…}` or
    /// `{"type":"ref/resource","uri":…}`; `argument` is `{name, value}` with
    /// the prefix typed so far. `context` carries arguments already filled
    /// in, which is what lets a server narrow later suggestions.
    pub async fn complete(
        &self,
        reference: &Value,
        argument: &Value,
        context: Option<&Value>,
    ) -> Result<Value, UpstreamError> {
        self.upstream.complete(reference, argument, context).await
    }

    /// Subscribe to the changes `spec` names and stream them.
    ///
    /// The stream lives as long as the caller holds it, which is why this is
    /// the one surface a stateless request cannot serve.
    pub async fn subscribe(
        &self,
        spec: &SubscriptionSpec,
    ) -> Result<std::pin::Pin<Box<dyn futures::Stream<Item = Value> + Send>>, UpstreamError> {
        self.upstream.open_subscriptions(spec).await
    }

    pub async fn close(&self) {
        self.upstream.close().await;
    }
}

/// A recorded direction, back as the tap's own type.
fn direction_of(direction: &str) -> mcpg_mcp_client::tap::FrameDirection {
    match direction {
        "sent" => mcpg_mcp_client::tap::FrameDirection::Sent,
        _ => mcpg_mcp_client::tap::FrameDirection::Received,
    }
}

/// A recorded channel, back as the tap's own type. An unknown channel is
/// reported as the transport it most likely was rather than dropped: a frame
/// nobody can name is still a frame worth seeing.
fn channel_of(channel: &str) -> mcpg_mcp_client::tap::FrameChannel {
    match channel {
        "http-request" => mcpg_mcp_client::tap::FrameChannel::HttpRequest,
        "http-response" => mcpg_mcp_client::tap::FrameChannel::HttpResponse,
        "http-sse" => mcpg_mcp_client::tap::FrameChannel::HttpSse,
        "stdio-stderr" => mcpg_mcp_client::tap::FrameChannel::StdioStderr,
        _ => mcpg_mcp_client::tap::FrameChannel::Stdio,
    }
}

#[derive(Debug)]
pub enum SessionError {
    /// The target spec itself is unusable (bad combination, bad URL).
    Spec(String),
    /// The client failed to connect or operate.
    Client(UpstreamError),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Spec(m) => write!(f, "{m}"),
            Self::Client(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for SessionError {}
