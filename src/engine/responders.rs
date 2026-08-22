//! Answering what a server asks the client for.
//!
//! Both regimes land here. On the sessionful wire the server issues
//! `sampling/createMessage`, `elicitation/create` or `roots/list` as
//! JSON-RPC requests on the call's stream; on the stateless wire it
//! returns `resultType: "input_required"` with an `inputRequests` map
//! that the client answers and replays (MRTR, SEP-2322). The policy
//! below decides the answer in both, so a target behaves the same way
//! whichever wire it negotiated.
//!
//! What the inspector will NOT do is call a model. A sampling request
//! is answered by a human or by a canned stub — an inspector that
//! quietly spends someone's tokens is a different product.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use mcpg_mcp_client::upstream::UpstreamServerRequestHandler;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::{Mutex, oneshot};

/// A malicious or broken server could suspend forever; every
/// self-driven retry loop needs a ceiling.
pub const MAX_MRTR_ROUNDS: usize = 10;

/// How this target answers server→client requests.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "kebab-case")]
pub enum ResponderPolicy {
    /// Queue the request for a human and block until they answer.
    #[default]
    Interactive,
    /// Refuse with -32601, exactly as a client that never advertised
    /// the capability would.
    AutoDecline,
    /// Answer from canned values — the headless/CI mode.
    Mock(MockAnswers),
}

/// Canned answers for `mock`. Everything is optional: an unset kind
/// declines rather than inventing an answer.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct MockAnswers {
    /// Text the stubbed model "returns" for `sampling/createMessage`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sampling_text: Option<String>,
    /// Content object returned for an accepted `elicitation/create`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elicitation_content: Option<Value>,
    /// Roots reported for `roots/list`, as `{name, uri}` pairs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roots: Vec<Root>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Root {
    pub name: String,
    pub uri: String,
}

impl ResponderPolicy {
    /// The client capabilities this policy can honestly back.
    ///
    /// Advertising a capability the policy would decline invites
    /// requests that can only fail; advertising none hides the very
    /// behavior an inspector exists to exercise. So the advertisement
    /// follows the policy.
    pub fn client_capabilities(&self) -> Value {
        match self {
            Self::AutoDecline => json!({}),
            Self::Interactive => json!({
                "sampling": {},
                "elicitation": {},
                "roots": { "listChanged": false },
            }),
            Self::Mock(answers) => {
                let mut caps = serde_json::Map::new();
                if answers.sampling_text.is_some() {
                    caps.insert("sampling".into(), json!({}));
                }
                if answers.elicitation_content.is_some() {
                    caps.insert("elicitation".into(), json!({}));
                }
                if !answers.roots.is_empty() {
                    caps.insert("roots".into(), json!({ "listChanged": false }));
                }
                Value::Object(caps)
            }
        }
    }

    /// Whether a call should take the bridged path at all. With
    /// nothing to answer, the plain path is the honest one.
    pub fn bridges(&self) -> bool {
        !matches!(self, Self::AutoDecline)
    }
}

/// A server→client request waiting for an answer.
#[derive(Clone, Debug, Serialize)]
pub struct PendingRequest {
    pub id: u64,
    /// `sampling/createMessage`, `elicitation/create`, `roots/list`.
    pub method: String,
    pub params: Value,
    /// Which regime produced it — the UI says so, because the two
    /// behave differently on timeout and cancellation.
    pub regime: &'static str,
}

/// A JSON-RPC error as the responder carries it: code and message.
type RpcError = (i64, String);

/// One queued request and the channel its answer travels back on.
type Waiter = (PendingRequest, oneshot::Sender<Result<Value, RpcError>>);

/// The queue of unanswered server→client requests, plus the policy
/// that decides how they get answered.
pub struct Responder {
    policy: ResponderPolicy,
    next_id: AtomicU64,
    waiting: Mutex<Vec<Waiter>>,
}

impl Responder {
    pub fn new(policy: ResponderPolicy) -> Self {
        Self {
            policy,
            next_id: AtomicU64::new(1),
            waiting: Mutex::new(Vec::new()),
        }
    }

    pub fn policy(&self) -> &ResponderPolicy {
        &self.policy
    }

    /// The requests currently waiting on a human.
    pub async fn pending(&self) -> Vec<PendingRequest> {
        self.waiting
            .lock()
            .await
            .iter()
            .map(|(request, _)| request.clone())
            .collect()
    }

    /// Answer a queued request. `Ok(value)` fulfils it; `Err` declines
    /// it with a JSON-RPC error.
    pub async fn resolve(&self, id: u64, answer: Result<Value, (i64, String)>) -> bool {
        let mut waiting = self.waiting.lock().await;
        let Some(index) = waiting.iter().position(|(request, _)| request.id == id) else {
            return false;
        };
        let (_, sender) = waiting.remove(index);
        sender.send(answer).is_ok()
    }

    /// Decide one request. Interactive parks it on the queue and waits;
    /// the other policies answer immediately.
    pub async fn answer(
        &self,
        method: &str,
        params: Value,
        regime: &'static str,
    ) -> Result<Value, (i64, String)> {
        match &self.policy {
            ResponderPolicy::AutoDecline => Err(decline(method)),
            ResponderPolicy::Mock(answers) => mock_answer(method, answers),
            ResponderPolicy::Interactive => {
                let (tx, rx) = oneshot::channel();
                let request = PendingRequest {
                    id: self.next_id.fetch_add(1, Ordering::Relaxed),
                    method: method.to_owned(),
                    params,
                    regime,
                };
                self.waiting.lock().await.push((request, tx));
                // Dropping the sender (session closed, target removed)
                // resolves as a decline rather than hanging the call.
                rx.await.unwrap_or_else(|_| {
                    Err((
                        -32603,
                        "inspector session ended before the request was answered".to_owned(),
                    ))
                })
            }
        }
    }
}

/// The decline a client that never advertised the capability would
/// send — the same shape the gateway's own federation bridge uses.
fn decline(method: &str) -> (i64, String) {
    (
        -32601,
        format!("inspector declined '{method}' (responder policy: auto-decline)"),
    )
}

fn mock_answer(method: &str, answers: &MockAnswers) -> Result<Value, (i64, String)> {
    match method {
        "sampling/createMessage" => match &answers.sampling_text {
            Some(text) => Ok(json!({
                "role": "assistant",
                "content": { "type": "text", "text": text },
                "model": "mcpg-inspector-stub",
                "stopReason": "endTurn",
            })),
            None => Err(decline(method)),
        },
        "elicitation/create" => match &answers.elicitation_content {
            Some(content) => Ok(json!({ "action": "accept", "content": content })),
            // Declining an elicitation is a legitimate answer, not an
            // error: the server asked, the user said no.
            None => Ok(json!({ "action": "decline" })),
        },
        "roots/list" => Ok(json!({
            "roots": answers
                .roots
                .iter()
                .map(|r| json!({ "name": r.name, "uri": r.uri }))
                .collect::<Vec<_>>(),
        })),
        other => Err(decline(other)),
    }
}

/// Adapter letting the shared client drive the responder on the
/// sessionful wire, where requests arrive as frames on the call's
/// stream.
pub struct BridgeHandler {
    pub responder: Arc<Responder>,
}

#[async_trait::async_trait]
impl UpstreamServerRequestHandler for BridgeHandler {
    async fn handle(&self, method: &str, params: Value) -> Result<Value, (i64, String)> {
        self.responder.answer(method, params, "sessionful").await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_follow_the_policy() {
        // Declining everything advertises nothing, so a well-behaved
        // server never asks.
        assert_eq!(
            ResponderPolicy::AutoDecline.client_capabilities(),
            json!({})
        );

        let interactive = ResponderPolicy::Interactive.client_capabilities();
        assert!(interactive.get("sampling").is_some());
        assert!(interactive.get("elicitation").is_some());
        assert!(interactive.get("roots").is_some());

        // A mock advertises only what it can actually answer.
        let partial = ResponderPolicy::Mock(MockAnswers {
            sampling_text: Some("hi".into()),
            ..Default::default()
        });
        let caps = partial.client_capabilities();
        assert!(caps.get("sampling").is_some());
        assert!(caps.get("elicitation").is_none(), "{caps}");
        assert!(caps.get("roots").is_none(), "{caps}");
    }

    #[tokio::test]
    async fn auto_decline_answers_immediately_with_method_not_found() {
        let responder = Responder::new(ResponderPolicy::AutoDecline);
        let err = responder
            .answer("elicitation/create", json!({}), "sessionful")
            .await
            .unwrap_err();
        assert_eq!(err.0, -32601);
        assert!(responder.pending().await.is_empty());
    }

    #[tokio::test]
    async fn mock_answers_what_it_has_and_declines_the_rest() {
        let responder = Responder::new(ResponderPolicy::Mock(MockAnswers {
            sampling_text: Some("stubbed".into()),
            roots: vec![Root {
                name: "repo".into(),
                uri: "file:///repo".into(),
            }],
            ..Default::default()
        }));

        let sampled = responder
            .answer("sampling/createMessage", json!({}), "sessionful")
            .await
            .unwrap();
        assert_eq!(sampled["content"]["text"], "stubbed");
        assert_eq!(sampled["model"], "mcpg-inspector-stub");

        let roots = responder
            .answer("roots/list", json!({}), "sessionful")
            .await
            .unwrap();
        assert_eq!(roots["roots"][0]["uri"], "file:///repo");

        // No canned content: an elicitation is DECLINED, which is a
        // valid answer — not an error the server has to handle.
        let elicited = responder
            .answer("elicitation/create", json!({}), "sessionful")
            .await
            .unwrap();
        assert_eq!(elicited["action"], "decline");
    }

    #[tokio::test]
    async fn interactive_parks_the_request_until_it_is_resolved() {
        let responder = Arc::new(Responder::new(ResponderPolicy::Interactive));
        let answering = Arc::clone(&responder);
        let task = tokio::spawn(async move {
            answering
                .answer("elicitation/create", json!({"message": "name?"}), "mrtr")
                .await
        });

        // The request shows up on the queue with its params intact.
        let mut queued = responder.pending().await;
        for _ in 0..50 {
            if !queued.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            queued = responder.pending().await;
        }
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].method, "elicitation/create");
        assert_eq!(queued[0].params["message"], "name?");
        assert_eq!(queued[0].regime, "mrtr");

        assert!(
            responder
                .resolve(queued[0].id, Ok(json!({"action": "accept"})))
                .await
        );
        let answer = task.await.unwrap().unwrap();
        assert_eq!(answer["action"], "accept");
        assert!(responder.pending().await.is_empty());
    }

    #[tokio::test]
    async fn a_dropped_responder_declines_rather_than_hanging() {
        let responder = Arc::new(Responder::new(ResponderPolicy::Interactive));
        let answering = Arc::clone(&responder);
        let task =
            tokio::spawn(async move { answering.answer("roots/list", json!({}), "mrtr").await });
        // Let it queue, then tear the queue down as a closing session would.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        responder.waiting.lock().await.clear();
        let err = task.await.unwrap().unwrap_err();
        assert_eq!(err.0, -32603);
    }
}
