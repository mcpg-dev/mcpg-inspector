//! Stateless execution: one request, one dial, one answer.
//!
//! The stateful engine keeps a registry of targets, each holding a live
//! session, a frame buffer and — in a shared deployment — an owner. That is
//! the right shape for a local operator and the wrong one for a public
//! instance: it makes the server the custodian of other people's server URLs
//! and credentials, pins a user to whichever replica holds their session, and
//! turns a restart into a logout.
//!
//! Here the browser is the custodian. Every call carries the target it wants,
//! the server dials it, runs one operation, and returns the answer together
//! with the frames that produced it. Nothing about the caller survives the
//! response, so any replica can serve any request and a restart costs a
//! reconnect rather than a session.
//!
//! What this cannot do is hold a stream open — a subscription is state by
//! definition. Those keep the stateful path and pin to one replica; see
//! `docs/inspector/HOSTED.md`.

use std::sync::{Arc, Mutex};

use mcpg_mcp_client::tap::{FrameChannel, FrameDirection, FrameTap};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::ops::{self, Op, OpError};
use super::responders::{Responder, ResponderPolicy};
use super::session::{Session, SessionError};
use super::target::TargetSpec;

/// One raw frame, as it goes back to the caller.
#[derive(Clone, Debug, Serialize)]
pub struct Frame {
    pub direction: &'static str,
    pub channel: &'static str,
    pub body: String,
}

/// Collects the frames of a single exchange.
///
/// Bounded, because a caller can ask for a resource whose body is larger than
/// anything worth showing, and this buffer is charged to the request rather
/// than to a quota someone signed up for.
#[derive(Default)]
struct FrameCollector {
    frames: Mutex<Vec<Frame>>,
    limit: usize,
}

impl FrameCollector {
    fn new(limit: usize) -> Self {
        Self {
            frames: Mutex::new(Vec::new()),
            limit,
        }
    }

    fn take(&self) -> Vec<Frame> {
        std::mem::take(&mut *self.frames.lock().expect("frames lock"))
    }
}

impl FrameTap for FrameCollector {
    fn on_frame(&self, direction: FrameDirection, channel: FrameChannel, bytes: &[u8]) {
        let mut frames = self.frames.lock().expect("frames lock");
        if frames.len() >= self.limit {
            return;
        }
        frames.push(Frame {
            direction: direction.as_str(),
            channel: channel.as_str(),
            body: String::from_utf8_lossy(bytes).into_owned(),
        });
    }
}

/// What a stateless call asks for.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecRequest {
    /// A target the operator pre-wired, by id. Mutually exclusive with
    /// `target`; this is the form an anonymous caller may use, because the
    /// operator chose what it points at.
    #[serde(default)]
    pub target_id: Option<String>,
    /// A target the caller supplies. Dialing an arbitrary address on the
    /// caller's behalf is the privileged operation here, which is why a
    /// shared deployment asks who is asking.
    #[serde(default)]
    pub target: Option<TargetSpec>,
    pub op: String,
    #[serde(default)]
    pub params: Value,
}

/// What it gets back.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecResponse {
    pub result: Value,
    /// The wire the probe settled on, so the caller can show it without a
    /// second round trip.
    pub negotiated_version: &'static str,
    /// Every frame of this exchange, in order. The caller accumulates them;
    /// the server keeps none.
    pub frames: Vec<Frame>,
}

#[derive(Debug)]
pub enum ExecError {
    /// The request itself is malformed.
    Params(String),
    /// The target could not be dialled.
    Connect(SessionError),
    /// The operation failed.
    Op(OpError),
}

impl std::fmt::Display for ExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Params(m) => write!(f, "{m}"),
            Self::Connect(e) => write!(f, "{e}"),
            Self::Op(e) => write!(f, "{e}"),
        }
    }
}

/// Run one operation against one target and throw the connection away.
///
/// `frame_limit` bounds what comes back; the connection is closed before
/// returning, so nothing outlives the call.
pub async fn exec(
    spec: &TargetSpec,
    op_name: &str,
    params: &Value,
    frame_limit: usize,
) -> Result<ExecResponse, ExecError> {
    let op =
        Op::parse(op_name).ok_or_else(|| ExecError::Params(format!("unknown op '{op_name}'")))?;

    let collector = Arc::new(FrameCollector::new(frame_limit));
    let tap = Arc::clone(&collector) as mcpg_mcp_client::tap::SharedTap;

    // A stateless call has nobody watching an elicitation queue, so the
    // responder declines server→client requests rather than parking the
    // request until it times out. The caller's own policy is honoured when
    // it supplied one — a mock answer is the headless equivalent of a human.
    let policy = match &spec.responder {
        ResponderPolicy::Interactive => ResponderPolicy::AutoDecline,
        other => other.clone(),
    };
    let responder = Arc::new(Responder::new(policy));
    let session = Session::connect(spec, Some(tap), responder, None)
        .await
        .map_err(ExecError::Connect)?;

    let outcome = ops::dispatch(&session, op, params).await;
    let negotiated_version = session.negotiated_version();
    session.close().await;

    match outcome {
        Ok(result) => Ok(ExecResponse {
            result,
            negotiated_version,
            frames: collector.take(),
        }),
        Err(e) => Err(ExecError::Op(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_collector_stops_at_its_limit() {
        let collector = FrameCollector::new(2);
        for _ in 0..5 {
            collector.on_frame(FrameDirection::Sent, FrameChannel::HttpRequest, b"{}");
        }
        assert_eq!(collector.take().len(), 2);
    }

    #[test]
    fn taking_frames_empties_the_buffer() {
        let collector = FrameCollector::new(10);
        collector.on_frame(FrameDirection::Sent, FrameChannel::HttpRequest, b"a");
        assert_eq!(collector.take().len(), 1);
        assert!(collector.take().is_empty());
    }

    /// A frame is returned with its direction and channel, so a caller can
    /// render the same wire view the stateful path shows.
    #[test]
    fn frames_carry_direction_and_channel() {
        let collector = FrameCollector::new(10);
        collector.on_frame(FrameDirection::Received, FrameChannel::HttpSse, b"hi");
        let frames = collector.take();
        assert_eq!(frames[0].direction, "received");
        assert_eq!(frames[0].channel, "http-sse");
        assert_eq!(frames[0].body, "hi");
    }

    #[tokio::test]
    async fn an_unknown_op_is_refused_before_anything_is_dialled() {
        let spec: TargetSpec =
            serde_json::from_value(serde_json::json!({"url": "http://127.0.0.1:9/mcp"})).unwrap();
        let err = exec(&spec, "not.an.op", &serde_json::json!({}), 10)
            .await
            .unwrap_err();
        assert!(matches!(err, ExecError::Params(_)), "{err}");
        assert!(err.to_string().contains("not.an.op"));
    }
}
