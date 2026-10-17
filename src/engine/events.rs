//! MCP Events from the client side: the callbacks the inspector offers a
//! server for webhook subscriptions, and what deliveries and streams are
//! checked for.
//!
//! A subscription made through the inspector gets a callback of its own,
//! `/hooks/{target}/{sid}`, and a `whsec_` secret minted for it alone. A
//! delivery is taken only with a valid Standard Webhooks signature made
//! with that secret and a fresh timestamp; anything else is refused before
//! its body is parsed, and nothing a delivery says makes the inspector act.
//! A delivery taken lands in the target's wire log as a `webhook` frame and
//! in its subscription's record, which the checks read.
//!
//! Each target keeps its own [`EventWatch`], so a workspace sees only its
//! own subscriptions; the process-wide [`HookDirectory`] only routes a
//! delivery to the watch that minted its `sid`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex, Weak};
use std::time::Instant;

use mcpg_mcp_client::tap::{FrameChannel, FrameDirection, FrameTap};
use mcpg_mcp_wire::v_2026_07_28::extensions::events::wire::{
    CONTROL_WEBHOOK_ID_PREFIX, ControlEnvelope, MAX_STREAM_HEARTBEAT_MS,
    METHOD_NOTIFICATIONS_ACTIVE, StreamFrame, WebhookBody, WebhookSecret,
};
use mcpg_standard_webhooks::{Verifier, WhsecSecret};
use serde::Serialize;
use serde_json::{Map, Value};

use super::checks::{CheckResult, Outcome};
use super::eventlog::EventLog;

/// Path prefix of the inspector's webhook callbacks.
pub const HOOKS_PATH: &str = "/hooks";
/// Largest delivery body taken: the extension's cap.
pub const MAX_DELIVERY_BYTES: usize =
    mcpg_mcp_wire::v_2026_07_28::extensions::events::wire::MAX_WEBHOOK_BODY_BYTES;
/// Deliveries kept per subscription.
const KEPT_DELIVERIES: usize = 200;
/// Push stream reports kept per target.
const KEPT_STREAMS: usize = 10;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// One delivery a callback took.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Delivery {
    /// Position among everything the callback took, from 1. Old deliveries
    /// are dropped; the numbering goes on.
    pub seq: u64,
    pub webhook_id: String,
    /// `event`, `gap`, `terminated` or `verification`.
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    /// Whether the body carried a `cursor` member, `null` included.
    pub has_cursor: bool,
    pub received_at_ms: u64,
    pub body: Value,
}

struct Hook {
    name: String,
    arguments: Map<String, Value>,
    url: String,
    verifier: Verifier,
    wire: Option<Arc<EventLog>>,
    deliveries: Vec<Delivery>,
    taken: u64,
    /// Deliveries refused for their signature or timestamp.
    refused: u64,
}

/// A callback just made for a subscription.
#[derive(Debug, Clone)]
pub struct MintedHook {
    pub sid: String,
    pub url: String,
    pub secret: WebhookSecret,
}

/// What a callback answers one POST with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookReply {
    /// No callback has this path.
    Unknown,
    /// The signature or its timestamp is wrong.
    Unauthorized,
    /// The body is not a delivery.
    BadRequest,
    /// A verification challenge, echoed.
    Challenge(String),
    Accepted,
}

/// A subscription's callback, as the API shows it.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HookView {
    pub sid: String,
    pub name: String,
    pub arguments: Map<String, Value>,
    pub url: String,
    pub refused: u64,
    pub deliveries: Vec<Delivery>,
    pub checks: Vec<CheckResult>,
}

/// What one push stream showed, kept for the checks.
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamReport {
    pub name: String,
    pub frames: u64,
    pub events: u64,
    pub heartbeats: u64,
    /// The longest time between two data frames, in milliseconds.
    pub longest_gap_ms: u64,
    pub first_frame: Option<String>,
    /// Event and heartbeat frames that carried no `cursor` member.
    pub missing_cursor: u64,
    /// Frames that are not a stream notification the extension defines.
    pub malformed: u64,
    /// `terminated` when the server ended the subscription on the stream.
    pub ended_with: Option<String>,
    #[serde(skip)]
    last_frame_at: Option<u64>,
    /// Which tracker writes this report; older reports are dropped, so a
    /// position in the list does not stay put.
    #[serde(skip)]
    id: u64,
}

/// Routes a delivery to the watch whose callback it is for.
#[derive(Default)]
pub struct HookDirectory {
    routes: Mutex<HashMap<String, (String, Weak<EventWatch>)>>,
}

impl HookDirectory {
    pub fn new() -> Self {
        Self::default()
    }

    fn register(&self, sid: &str, target: &str, watch: &Arc<EventWatch>) {
        let mut routes = self.routes.lock().expect("routes lock");
        routes.retain(|_, (_, watch)| watch.strong_count() > 0);
        routes.insert(sid.to_owned(), (target.to_owned(), Arc::downgrade(watch)));
    }

    /// Take one POST to `/hooks/{target}/{sid}`.
    pub fn receive(
        &self,
        target: &str,
        sid: &str,
        headers: &axum::http::HeaderMap,
        body: &[u8],
    ) -> HookReply {
        let watch = {
            let routes = self.routes.lock().expect("routes lock");
            routes
                .get(sid)
                .filter(|(owner, _)| owner == target)
                .and_then(|(_, watch)| watch.upgrade())
        };
        match watch {
            Some(watch) => watch.receive(sid, headers, body),
            None => HookReply::Unknown,
        }
    }
}

/// The webhook callbacks and the push stream reports of one target.
#[derive(Default)]
pub struct EventWatch {
    hooks: Mutex<HashMap<String, Hook>>,
    streams: Mutex<Vec<StreamReport>>,
    opened_streams: std::sync::atomic::AtomicU64,
}

impl EventWatch {
    pub fn new() -> Self {
        Self::default()
    }

    /// Make a callback under `base`, routed by `directory`, for a
    /// subscription of `target` to `name` with `arguments`. Frames it takes
    /// go to `wire`.
    pub fn mint(
        self: &Arc<Self>,
        directory: &HookDirectory,
        target: &str,
        base: &str,
        name: &str,
        arguments: &Map<String, Value>,
        wire: Option<Arc<EventLog>>,
    ) -> MintedHook {
        let sid = uuid::Uuid::new_v4().simple().to_string();
        let mut key = [0u8; 32];
        key[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        key[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        let signing = WhsecSecret::from_key_bytes(&key).expect("32 bytes make a secret");
        let secret = WebhookSecret::from_signing_secret(&signing);
        let url = format!(
            "{}{HOOKS_PATH}/{}/{sid}",
            base.trim_end_matches('/'),
            percent_segment(target)
        );
        let verifier = Verifier::new(vec![signing]).expect("one secret");
        self.hooks.lock().expect("hooks lock").insert(
            sid.clone(),
            Hook {
                name: name.to_owned(),
                arguments: arguments.clone(),
                url: url.clone(),
                verifier,
                wire,
                deliveries: Vec::new(),
                taken: 0,
                refused: 0,
            },
        );
        directory.register(&sid, target, self);
        MintedHook { sid, url, secret }
    }

    /// Take one POST to the callback `sid`.
    pub fn receive(&self, sid: &str, headers: &axum::http::HeaderMap, body: &[u8]) -> HookReply {
        let mut hooks = self.hooks.lock().expect("hooks lock");
        let Some(hook) = hooks.get_mut(sid) else {
            return HookReply::Unknown;
        };
        let Ok(verified) = hook
            .verifier
            .verify_headers(headers, body, now_ms() / 1_000)
        else {
            hook.refused += 1;
            return HookReply::Unauthorized;
        };
        let Ok(value) = serde_json::from_slice::<Value>(body) else {
            return HookReply::BadRequest;
        };
        let has_cursor = value.get("cursor").is_some();
        let Ok(delivery) = WebhookBody::from_value(value.clone()) else {
            return HookReply::BadRequest;
        };
        if let Some(wire) = &hook.wire {
            wire.on_frame(FrameDirection::Received, FrameChannel::Webhook, body);
        }
        let (kind, event_id, reply) = match delivery {
            WebhookBody::Event(occurrence) => {
                ("event", Some(occurrence.event_id), HookReply::Accepted)
            }
            WebhookBody::Control(envelope) => {
                let reply = match &envelope {
                    ControlEnvelope::Verification { challenge } => {
                        HookReply::Challenge(challenge.clone())
                    }
                    ControlEnvelope::Gap { .. } | ControlEnvelope::Terminated { .. } => {
                        HookReply::Accepted
                    }
                };
                (envelope.kind(), None, reply)
            }
        };
        hook.taken += 1;
        hook.deliveries.push(Delivery {
            seq: hook.taken,
            webhook_id: verified.msg_id,
            kind,
            event_id,
            has_cursor,
            received_at_ms: now_ms(),
            body: value,
        });
        let excess = hook.deliveries.len().saturating_sub(KEPT_DELIVERIES);
        hook.deliveries.drain(..excess);
        reply
    }

    /// The subscription the callback `sid` serves: its name, arguments and
    /// URL, which are what an unsubscribe names.
    pub fn subscription(&self, sid: &str) -> Option<(String, Map<String, Value>, String)> {
        self.hooks
            .lock()
            .expect("hooks lock")
            .get(sid)
            .map(|hook| (hook.name.clone(), hook.arguments.clone(), hook.url.clone()))
    }

    /// Forget the callback `sid`. Whether one was there.
    pub fn remove(&self, sid: &str) -> bool {
        self.hooks.lock().expect("hooks lock").remove(sid).is_some()
    }

    /// The callbacks, with what each took and its checks.
    pub fn hooks(&self) -> Vec<HookView> {
        let hooks = self.hooks.lock().expect("hooks lock");
        let mut views: Vec<HookView> = hooks
            .iter()
            .map(|(sid, hook)| HookView {
                sid: sid.clone(),
                name: hook.name.clone(),
                arguments: hook.arguments.clone(),
                url: hook.url.clone(),
                refused: hook.refused,
                deliveries: hook.deliveries.clone(),
                checks: delivery_checks(&hook.deliveries, hook.refused),
            })
            .collect();
        views.sort_by(|a, b| a.sid.cmp(&b.sid));
        views
    }

    /// Start the report of a push stream of `name`.
    pub fn stream_opened(self: &Arc<Self>, name: &str) -> StreamTracker {
        let id = self
            .opened_streams
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut streams = self.streams.lock().expect("streams lock");
        let excess = (streams.len() + 1).saturating_sub(KEPT_STREAMS);
        streams.drain(..excess);
        streams.push(StreamReport {
            name: name.to_owned(),
            id,
            ..StreamReport::default()
        });
        StreamTracker {
            watch: Arc::clone(self),
            id,
            opened: Instant::now(),
        }
    }

    /// The push streams, newest last, with their checks.
    pub fn streams(&self) -> Vec<(StreamReport, Vec<CheckResult>)> {
        self.streams
            .lock()
            .expect("streams lock")
            .iter()
            .map(|report| (report.clone(), stream_checks(report)))
            .collect()
    }
}

/// Records what one push stream sends.
pub struct StreamTracker {
    watch: Arc<EventWatch>,
    id: u64,
    opened: Instant,
}

impl StreamTracker {
    /// Note one frame the stream sent.
    pub fn frame(&self, frame: &Value) {
        let mut streams = self.watch.streams.lock().expect("streams lock");
        let Some(report) = streams.iter_mut().find(|report| report.id == self.id) else {
            return;
        };
        let at = self.opened.elapsed().as_millis() as u64;
        report.frames += 1;
        if report.first_frame.is_none() {
            report.first_frame = Some(
                frame
                    .get("method")
                    .and_then(Value::as_str)
                    .unwrap_or("?")
                    .to_owned(),
            );
        }
        let gap = at.saturating_sub(report.last_frame_at.unwrap_or(0));
        report.longest_gap_ms = report.longest_gap_ms.max(gap);
        report.last_frame_at = Some(at);
        let decoded = StreamFrame::from_notification(frame);
        match &decoded {
            Some(StreamFrame::Event(_)) => report.events += 1,
            Some(StreamFrame::Heartbeat { .. }) => report.heartbeats += 1,
            Some(StreamFrame::Terminated(_)) => report.ended_with = Some("terminated".to_owned()),
            Some(StreamFrame::Active { .. } | StreamFrame::Error(_)) => {}
            None => report.malformed += 1,
        }
        // Read raw: a `null` cursor is an answer, a missing one is not, and
        // the decoded frame holds both as `None`.
        let positioned = matches!(
            decoded,
            Some(StreamFrame::Event(_) | StreamFrame::Heartbeat { .. })
        );
        if positioned && frame.get("params").and_then(|p| p.get("cursor")).is_none() {
            report.missing_cursor += 1;
        }
    }
}

fn check(id: &str, description: &str, pass: bool, detail: Option<String>) -> CheckResult {
    CheckResult {
        id: id.to_owned(),
        description: description.to_owned(),
        outcome: if pass { Outcome::Pass } else { Outcome::Fail },
        detail,
    }
}

/// The checks of what one callback took.
fn delivery_checks(deliveries: &[Delivery], refused: u64) -> Vec<CheckResult> {
    let mut by_event: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for delivery in deliveries {
        if let Some(event_id) = delivery.event_id.as_deref() {
            by_event
                .entry(event_id)
                .or_default()
                .push(&delivery.webhook_id);
        }
    }
    let unstable: Vec<&str> = by_event
        .iter()
        .filter(|(_, ids)| ids.windows(2).any(|pair| pair[0] != pair[1]))
        .map(|(event_id, _)| *event_id)
        .collect();
    let foreign: Vec<&str> = deliveries
        .iter()
        .filter(|d| d.event_id.as_deref().is_some_and(|id| id != d.webhook_id))
        .map(|d| d.webhook_id.as_str())
        .collect();
    let misnamed_controls = deliveries
        .iter()
        .filter(|d| d.event_id.is_none() && !d.webhook_id.starts_with(CONTROL_WEBHOOK_ID_PREFIX))
        .count();
    let dotted: BTreeSet<&str> = deliveries
        .iter()
        .filter(|d| d.webhook_id.contains('.'))
        .map(|d| d.webhook_id.as_str())
        .collect();
    let cursorless = deliveries
        .iter()
        .filter(|d| d.kind == "event" && !d.has_cursor)
        .count();
    vec![
        check(
            "events.webhook.signature",
            "every delivery is signed with the subscription's secret and is fresh",
            refused == 0,
            (refused > 0).then(|| format!("{refused} deliveries refused")),
        ),
        check(
            "events.webhook.id-is-event-id",
            "an event's webhook-id is its eventId",
            foreign.is_empty(),
            (!foreign.is_empty()).then(|| foreign.join(", ")),
        ),
        check(
            "events.webhook.stable-retries",
            "a retried event keeps its webhook-id",
            unstable.is_empty(),
            (!unstable.is_empty()).then(|| unstable.join(", ")),
        ),
        check(
            "events.webhook.control-ids",
            "a control envelope's webhook-id starts with msg_",
            misnamed_controls == 0,
            (misnamed_controls > 0).then(|| format!("{misnamed_controls} envelopes")),
        ),
        check(
            "events.webhook.id-has-no-dot",
            "no webhook-id contains \".\", as Standard Webhooks requires of a sender (a \
             Standard Webhooks rule, not an MCP Events one)",
            dotted.is_empty(),
            (!dotted.is_empty()).then(|| dotted.into_iter().collect::<Vec<_>>().join(", ")),
        ),
        check(
            "events.webhook.cursor",
            "every event body carries a cursor (null for a type without replay)",
            cursorless == 0,
            (cursorless > 0).then(|| format!("{cursorless} events without one")),
        ),
    ]
}

/// The checks of one push stream.
fn stream_checks(report: &StreamReport) -> Vec<CheckResult> {
    vec![
        check(
            "events.stream.active-first",
            "the first frame is notifications/events/active",
            report.first_frame.is_none()
                || report.first_frame.as_deref() == Some(METHOD_NOTIFICATIONS_ACTIVE),
            report.first_frame.clone(),
        ),
        check(
            "events.stream.well-formed",
            "every frame is a notification the extension defines, with its required fields",
            report.malformed == 0,
            (report.malformed > 0).then(|| format!("{} frames", report.malformed)),
        ),
        check(
            "events.stream.heartbeat",
            "a data frame at least every 30 s",
            report.longest_gap_ms <= MAX_STREAM_HEARTBEAT_MS,
            Some(format!("longest gap {} ms", report.longest_gap_ms)),
        ),
        check(
            "events.stream.cursor",
            "every event and heartbeat carries a cursor (null for a type without replay)",
            report.missing_cursor == 0,
            (report.missing_cursor > 0).then(|| format!("{} frames", report.missing_cursor)),
        ),
    ]
}

/// `segment` with the characters a path segment cannot hold escaped.
fn percent_segment(segment: &str) -> String {
    segment
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn signed(secret: &WebhookSecret, id: &str, body: &[u8]) -> axum::http::HeaderMap {
        let secret = secret.signing_secret();
        let headers =
            mcpg_standard_webhooks::sign_message(&[&secret], id, now_ms() / 1_000, body).unwrap();
        let mut map = axum::http::HeaderMap::new();
        map.insert("webhook-id", headers.id.parse().unwrap());
        map.insert("webhook-timestamp", headers.timestamp.parse().unwrap());
        map.insert("webhook-signature", headers.signature.parse().unwrap());
        map
    }

    #[test]
    fn a_callback_takes_only_what_its_own_secret_signed() {
        let directory = HookDirectory::new();
        let watch = Arc::new(EventWatch::new());
        let wire = Arc::new(EventLog::new(16));
        let hook = watch.mint(
            &directory,
            "t 1",
            "http://127.0.0.1:9/",
            "orders.created",
            &Map::new(),
            Some(Arc::clone(&wire)),
        );
        assert!(hook.url.starts_with("http://127.0.0.1:9/hooks/t%201/"));
        let other = watch.mint(
            &directory,
            "t 1",
            "http://127.0.0.1:9",
            "orders.created",
            &Map::new(),
            None,
        );
        let body = serde_json::to_vec(&json!({
            "eventId": "e1", "name": "orders.created", "timestamp": "2026-10-10T00:00:00Z",
            "data": {}, "cursor": "c1"
        }))
        .unwrap();
        let receive = |id: &str, secret: &WebhookSecret, body: &[u8]| {
            directory.receive("t 1", &hook.sid, &signed(secret, id, body), body)
        };

        assert_eq!(
            receive("e1", &other.secret, &body),
            HookReply::Unauthorized,
            "another subscription's secret"
        );
        assert_eq!(
            directory.receive("t 2", &hook.sid, &signed(&hook.secret, "e1", &body), &body),
            HookReply::Unknown,
            "another target's path"
        );
        assert_eq!(receive("e1", &hook.secret, &body), HookReply::Accepted);
        assert_eq!(
            receive("e2", &hook.secret, &body),
            HookReply::Accepted,
            "a retry under another id is taken, and flagged"
        );
        let challenge = serde_json::to_vec(&ControlEnvelope::Verification {
            challenge: "n-1".to_owned(),
        })
        .unwrap();
        assert_eq!(
            receive("msg_verification_x", &hook.secret, &challenge),
            HookReply::Challenge("n-1".to_owned())
        );
        assert_eq!(
            wire.snapshot().len(),
            3,
            "each taken delivery is a webhook frame"
        );

        let view = watch
            .hooks()
            .into_iter()
            .find(|v| v.sid == hook.sid)
            .unwrap();
        assert_eq!(view.deliveries.len(), 3);
        let outcome = |id: &str| {
            view.checks
                .iter()
                .find(|c| c.id == id)
                .map(|c| c.outcome.clone())
                .unwrap()
        };
        assert_eq!(outcome("events.webhook.signature"), Outcome::Fail);
        assert_eq!(outcome("events.webhook.stable-retries"), Outcome::Fail);
        assert_eq!(outcome("events.webhook.id-is-event-id"), Outcome::Fail);
        assert_eq!(outcome("events.webhook.control-ids"), Outcome::Pass);
        assert_eq!(outcome("events.webhook.id-has-no-dot"), Outcome::Pass);
        assert_eq!(outcome("events.webhook.cursor"), Outcome::Pass);

        assert_eq!(
            watch
                .subscription(&hook.sid)
                .map(|(name, _, url)| (name, url)),
            Some(("orders.created".to_owned(), hook.url.clone()))
        );
        assert!(watch.remove(&hook.sid));
        assert!(!watch.remove(&hook.sid), "a callback is removed once");
        assert_eq!(
            receive("e1", &hook.secret, &body),
            HookReply::Unknown,
            "a removed callback takes nothing"
        );
        drop(watch);
        assert_eq!(
            directory.receive(
                "t 1",
                &other.sid,
                &signed(&other.secret, "e1", &body),
                &body
            ),
            HookReply::Unknown,
            "a removed target takes nothing"
        );
    }

    #[test]
    fn a_tracker_writes_its_own_report_after_older_ones_drop() {
        let watch = Arc::new(EventWatch::new());
        let first = watch.stream_opened("first");
        for _ in 0..KEPT_STREAMS {
            let _ = watch.stream_opened("later");
        }
        let kept = watch.stream_opened("kept");
        let event = json!({
            "method": "notifications/events/event",
            "params": {
                "eventId": "e1", "name": "kept",
                "timestamp": "2026-10-10T00:00:00Z", "data": {}, "cursor": null
            }
        });
        first.frame(&event);
        kept.frame(&event);
        let streams = watch.streams();
        assert_eq!(streams.len(), KEPT_STREAMS);
        assert!(streams.iter().all(|(report, _)| report.name != "first"));
        let counted: Vec<(&str, u64)> = streams
            .iter()
            .filter(|(report, _)| report.events > 0)
            .map(|(report, _)| (report.name.as_str(), report.events))
            .collect();
        assert_eq!(counted, vec![("kept", 1)]);
    }

    #[test]
    fn a_stream_report_checks_its_frames() {
        let watch = Arc::new(EventWatch::new());
        {
            let tracker = watch.stream_opened("orders.created");
            tracker.frame(&json!({
                "method": "notifications/events/active", "params": { "cursor": "c0", "truncated": false }
            }));
            tracker.frame(&json!({
                "method": "notifications/events/event",
                "params": {
                    "eventId": "e1", "name": "orders.created",
                    "timestamp": "2026-10-10T00:00:00Z", "data": {}
                }
            }));
            tracker.frame(&json!({
                "method": "notifications/events/heartbeat", "params": { "cursor": null }
            }));
        }
        let streams = watch.streams();
        let (report, checks) = &streams[0];
        assert_eq!((report.events, report.heartbeats), (1, 1));
        assert_eq!(report.malformed, 0);
        let outcome = |id: &str| {
            checks
                .iter()
                .find(|c| c.id == id)
                .map(|c| c.outcome.clone())
                .unwrap()
        };
        assert_eq!(outcome("events.stream.active-first"), Outcome::Pass);
        assert_eq!(outcome("events.stream.heartbeat"), Outcome::Pass);
        assert_eq!(
            outcome("events.stream.cursor"),
            Outcome::Fail,
            "the event had no cursor"
        );
        assert_eq!(outcome("events.stream.well-formed"), Outcome::Pass);

        let broken = Arc::new(EventWatch::new());
        broken.stream_opened("orders.created").frame(&json!({
            "method": "notifications/events/event", "params": { "eventId": "e1" }
        }));
        let (report, checks) = &broken.streams()[0];
        assert_eq!((report.events, report.malformed), (0, 1));
        assert!(
            checks
                .iter()
                .any(|c| c.id == "events.stream.well-formed" && c.outcome == Outcome::Fail),
            "an event without its required fields is not one"
        );
    }
}
