//! Recordings: what an exchange looked like, written down and read back.
//!
//! A recording is a file — NDJSON, one header then the frames as the wire log
//! holds them. Sharing one is sending it. The inspector writes and reads
//! recordings and stores none — nothing is persisted server-side — while
//! still letting someone else look at what happened.
//! See `docs/inspector/rfcs/0003-recording-replay.md`.
//!
//! Replaying is a target kind rather than a mode, so every surface the
//! inspector already has works on a recording without knowing it is one.

use std::collections::HashMap;

use mcpg_mcp_client::upstream::{
    McpUpstream, SubscriptionSpec, UpstreamError, UpstreamServerRequestHandler,
};
use mcpg_mcp_client::wire::{
    UpstreamPrompt, UpstreamResource, UpstreamResourceTemplate, UpstreamTool,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::engine::eventlog::WireEvent;

/// The first line of a recording: what it is, and what it is of.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordingHeader {
    /// Fixed discriminator, so a stray NDJSON file is refused rather than
    /// half-read.
    pub kind: String,
    pub version: u32,
    pub recorded_at_ms: u64,
    /// The target as the API describes it — never as it is configured. A
    /// bearer token is reported as configured and never written out.
    pub target: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub negotiated_version: Option<String>,
    /// Whether the frames were run through credential redaction. Recorded so
    /// a reader knows a pass was made rather than assuming one.
    pub redacted: bool,
}

pub const KIND: &str = "mcpg-inspector-recording";
pub const VERSION: u32 = 1;

/// Write a recording: the header, then every frame.
pub fn write(header: &RecordingHeader, frames: &[WireEvent]) -> String {
    let mut out = String::new();
    if let Ok(line) = serde_json::to_string(header) {
        out.push_str(&line);
        out.push('\n');
    }
    for frame in frames {
        if let Ok(line) = serde_json::to_string(frame) {
            out.push_str(&line);
            out.push('\n');
        }
    }
    out
}

/// Redact a frame body for export.
///
/// The body is a JSON-RPC frame; parsing it is what lets the shared
/// credential pass see the structure. A body that will not parse is passed
/// through the text redactor alone rather than dropped — an unparseable
/// frame is often the thing being investigated.
pub fn redact_frame(body: &str) -> String {
    match serde_json::from_str::<Value>(body) {
        Ok(value) => mcpg_sensitive::redact::redact_credentials_with(
            &value,
            mcpg_plugin_protocol::redact::redact_in_text,
        )
        .to_string(),
        Err(_) => mcpg_plugin_protocol::redact::redact_in_text(body),
    }
}

/// A parsed recording.
#[derive(Debug)]
pub struct Recording {
    pub header: RecordingHeader,
    pub frames: Vec<WireEvent>,
    /// Recorded answers, keyed by what was asked.
    answers: HashMap<Key, Value>,
}

/// What identifies an exchange well enough to replay it: the method, plus the
/// entity named in the request where there is one. Arguments are deliberately
/// NOT part of the key — a recording holds one call per tool in the common
/// case, and refusing to replay it because a whitespace differs would make
/// the feature useless.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Key(String, Option<String>);

pub fn parse(text: &str) -> Result<Recording, String> {
    let mut lines = text.lines().filter(|line| !line.trim().is_empty());
    let first = lines.next().ok_or("the recording is empty")?;
    let header: RecordingHeader = serde_json::from_str(first)
        .map_err(|e| format!("the first line is not a recording header: {e}"))?;
    if header.kind != KIND {
        return Err(format!(
            "not an mcpg-inspector recording (kind: {})",
            header.kind
        ));
    }
    if header.version > VERSION {
        return Err(format!(
            "recording version {} is newer than this inspector understands ({VERSION})",
            header.version
        ));
    }

    let frames: Vec<WireEvent> = lines
        .filter_map(|line| serde_json::from_str::<WireEvent>(line).ok())
        .collect();

    // Pair each request with its response by JSON-RPC id. Both halves are in
    // the log, in order, and the id is what makes the pairing exact rather
    // than positional — a stream can interleave.
    let mut pending: HashMap<String, Key> = HashMap::new();
    let mut answers = HashMap::new();
    for frame in &frames {
        let Ok(body) = serde_json::from_str::<Value>(&frame.body) else {
            continue;
        };
        let id = body.get("id").map(id_key);
        if let Some(method) = body.get("method").and_then(Value::as_str) {
            if let Some(id) = id {
                pending.insert(id, Key(method.to_owned(), entity_of(method, &body)));
            }
            continue;
        }
        if let (Some(id), Some(result)) = (id, body.get("result"))
            && let Some(key) = pending.remove(&id)
        {
            answers.insert(key, result.clone());
        }
    }

    Ok(Recording {
        header,
        frames,
        answers,
    })
}

fn id_key(id: &Value) -> String {
    match id {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// The entity a request names, for the methods where one distinguishes two
/// otherwise identical calls.
fn entity_of(method: &str, body: &Value) -> Option<String> {
    let params = body.get("params")?;
    let field = match method {
        "tools/call" | "prompts/get" => "name",
        "resources/read" => "uri",
        _ => return None,
    };
    params.get(field)?.as_str().map(str::to_owned)
}

impl Recording {
    fn answer(&self, method: &str, entity: Option<&str>) -> Result<Value, UpstreamError> {
        let key = Key(method.to_owned(), entity.map(str::to_owned));
        if let Some(found) = self.answers.get(&key) {
            return Ok(found.clone());
        }
        // Being explicit about the edge of the recording beats inventing an
        // answer that looks like the server's.
        Err(UpstreamError::Protocol(match entity {
            Some(entity) => format!("this recording has no {method} for '{entity}'"),
            None => format!("this recording has no {method}"),
        }))
    }

    fn list<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        field: &str,
    ) -> Result<Vec<T>, UpstreamError> {
        let answer = self.answer(method, None)?;
        let items = answer.get(field).cloned().unwrap_or_else(|| json!([]));
        serde_json::from_value(items)
            .map_err(|e| UpstreamError::Protocol(format!("recorded {method} is unreadable: {e}")))
    }
}

/// A session served entirely from a recording. Dials nothing — which is the
/// point, since the server may be gone.
pub struct RecordedUpstream {
    recording: Recording,
}

impl RecordedUpstream {
    pub fn new(recording: Recording) -> Self {
        Self { recording }
    }

    pub fn negotiated_version(&self) -> Option<&str> {
        self.recording.header.negotiated_version.as_deref()
    }

    pub fn frames(&self) -> &[WireEvent] {
        &self.recording.frames
    }
}

#[async_trait::async_trait]
impl McpUpstream for RecordedUpstream {
    async fn list_tools(&self) -> Result<Vec<UpstreamTool>, UpstreamError> {
        self.recording.list("tools/list", "tools")
    }

    async fn list_resources(&self) -> Result<Vec<UpstreamResource>, UpstreamError> {
        self.recording.list("resources/list", "resources")
    }

    async fn list_resource_templates(
        &self,
    ) -> Result<Vec<UpstreamResourceTemplate>, UpstreamError> {
        self.recording
            .list("resources/templates/list", "resourceTemplates")
    }

    async fn list_prompts(&self) -> Result<Vec<UpstreamPrompt>, UpstreamError> {
        self.recording.list("prompts/list", "prompts")
    }

    async fn read_resource(&self, uri: &str) -> Result<Value, UpstreamError> {
        self.recording.answer("resources/read", Some(uri))
    }

    async fn get_prompt(
        &self,
        name: &str,
        _arguments: Option<&Value>,
    ) -> Result<Value, UpstreamError> {
        self.recording.answer("prompts/get", Some(name))
    }

    async fn call_tool_with_meta(
        &self,
        name: &str,
        _arguments: Option<&Value>,
        _meta: Option<&Value>,
    ) -> Result<Value, UpstreamError> {
        self.recording.answer("tools/call", Some(name))
    }

    async fn call_tool_bridged(
        &self,
        name: &str,
        arguments: Option<&Value>,
        _input_schema: Option<&Value>,
        _handler: &dyn UpstreamServerRequestHandler,
        _progress_token: Option<&Value>,
    ) -> Result<Value, UpstreamError> {
        // A recorded exchange has already been answered; there is nobody to
        // ask again, so the bridge is a plain call.
        self.call_tool_with_meta(name, arguments, None).await
    }

    async fn read_resource_bridged(
        &self,
        uri: &str,
        _handler: &dyn UpstreamServerRequestHandler,
    ) -> Result<Value, UpstreamError> {
        self.read_resource(uri).await
    }

    async fn get_prompt_bridged(
        &self,
        name: &str,
        arguments: Option<&Value>,
        _handler: &dyn UpstreamServerRequestHandler,
    ) -> Result<Value, UpstreamError> {
        self.get_prompt(name, arguments).await
    }

    async fn complete(
        &self,
        _reference: &Value,
        _argument: &Value,
        _context: Option<&Value>,
    ) -> Result<Value, UpstreamError> {
        self.recording.answer("completion/complete", None)
    }

    async fn open_notifications(
        &self,
    ) -> Result<std::pin::Pin<Box<dyn futures::Stream<Item = Value> + Send>>, UpstreamError> {
        Ok(Box::pin(futures::stream::empty()))
    }

    async fn open_subscriptions(
        &self,
        _spec: &SubscriptionSpec,
    ) -> Result<std::pin::Pin<Box<dyn futures::Stream<Item = Value> + Send>>, UpstreamError> {
        // The notifications a server pushed are in the frame log; nothing new
        // will arrive, and an empty stream says that without an error.
        Ok(Box::pin(futures::stream::empty()))
    }

    fn wire_is_modern(&self) -> bool {
        self.recording.header.negotiated_version.as_deref() == Some("2026-07-28")
    }

    async fn close(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(seq: u64, direction: &str, body: &str) -> WireEvent {
        WireEvent {
            seq,
            ts_ms: seq,
            direction: direction.to_owned(),
            channel: "http".to_owned(),
            body: body.to_owned(),
        }
    }

    fn recorded() -> String {
        let header = RecordingHeader {
            kind: KIND.to_owned(),
            version: VERSION,
            recorded_at_ms: 1,
            target: json!({ "id": "gateway" }),
            negotiated_version: Some("2026-07-28".to_owned()),
            redacted: true,
        };
        write(
            &header,
            &[
                frame(
                    1,
                    "sent",
                    r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
                ),
                frame(
                    2,
                    "received",
                    r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"echo"}]}}"#,
                ),
                frame(
                    3,
                    "sent",
                    r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo"}}"#,
                ),
                frame(
                    4,
                    "received",
                    r#"{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"hi"}]}}"#,
                ),
            ],
        )
    }

    #[tokio::test]
    async fn a_recording_answers_what_it_recorded() {
        let upstream = RecordedUpstream::new(parse(&recorded()).expect("parse"));
        let tools = upstream.list_tools().await.expect("tools");
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "echo");

        let called = upstream
            .call_tool_with_meta("echo", None, None)
            .await
            .expect("call");
        assert_eq!(called["content"][0]["text"], "hi");
        assert!(upstream.wire_is_modern());
    }

    /// The edge of a recording has to be visible. Inventing an answer that
    /// looks like the server's is the one thing a replay must not do.
    #[tokio::test]
    async fn what_was_not_recorded_says_so() {
        let upstream = RecordedUpstream::new(parse(&recorded()).expect("parse"));
        let missing = upstream
            .call_tool_with_meta("never.called", None, None)
            .await;
        let message = format!("{}", missing.expect_err("should not invent an answer"));
        assert!(message.contains("no tools/call"), "{message}");
        assert!(message.contains("never.called"), "{message}");

        // A surface the recording never touched is empty, not an error: the
        // server may genuinely have had none.
        let prompts = upstream.list_prompts().await;
        assert!(prompts.is_err(), "an unrecorded LIST is also unknown");
    }

    /// Responses are paired to requests by JSON-RPC id, because a stream can
    /// interleave and position proves nothing.
    #[tokio::test]
    async fn interleaved_frames_pair_by_id() {
        let header = RecordingHeader {
            kind: KIND.to_owned(),
            version: VERSION,
            recorded_at_ms: 1,
            target: json!({}),
            negotiated_version: None,
            redacted: false,
        };
        let text = write(
            &header,
            &[
                frame(1, "sent", r#"{"id":1,"method":"tools/list"}"#),
                frame(2, "sent", r#"{"id":2,"method":"prompts/list"}"#),
                // Answered out of order, which is legal.
                frame(
                    3,
                    "received",
                    r#"{"id":2,"result":{"prompts":[{"name":"p"}]}}"#,
                ),
                frame(
                    4,
                    "received",
                    r#"{"id":1,"result":{"tools":[{"name":"t"}]}}"#,
                ),
            ],
        );
        let upstream = RecordedUpstream::new(parse(&text).expect("parse"));
        assert_eq!(upstream.list_tools().await.expect("tools")[0].name, "t");
        assert_eq!(upstream.list_prompts().await.expect("prompts")[0].name, "p");
    }

    #[test]
    fn a_file_that_is_not_a_recording_is_refused() {
        assert!(parse("").unwrap_err().contains("empty"));
        assert!(parse("not json\n").unwrap_err().contains("header"));
        assert!(
            parse(r#"{"kind":"something-else","version":1,"recordedAtMs":0,"target":{},"redacted":false}"#)
                .unwrap_err()
                .contains("not an mcpg-inspector recording")
        );
        let newer = r#"{"kind":"mcpg-inspector-recording","version":99,"recordedAtMs":0,"target":{},"redacted":false}"#;
        assert!(parse(newer).unwrap_err().contains("newer"));
    }

    /// A recording travels; a credential must not travel in it.
    #[test]
    fn frame_bodies_are_redacted_on_the_way_out() {
        let body = r#"{"params":{"arguments":{"api_key":"sk-live-1234567890","note":"hello"}}}"#;
        let redacted = redact_frame(body);
        assert!(!redacted.contains("sk-live-1234567890"), "{redacted}");
        assert!(redacted.contains("hello"), "ordinary values survive");

        // An unparseable frame is often the thing being investigated, so it
        // is redacted as text rather than dropped.
        let broken = redact_frame("{not json api_key=sk-live-1234567890");
        assert!(broken.contains("not json"), "{broken}");
    }
}
