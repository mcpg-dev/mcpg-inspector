//! Typed operations, named once so every face reaches the same set.
//!
//! The API dispatches by name and the one-shot verbs call the same
//! functions, which is what keeps `mcpg-inspector call` and the web
//! UI's call button honestly equivalent.

use std::sync::Arc;

use mcpg_mcp_client::upstream::UpstreamError;
use mcpg_mcp_wire::v_2026_07_28::extensions::events::wire::{
    DeliveryMode, PollEventsParams, SubscribeEventsParams, TtlRequest, UnsubscribeDelivery,
    UnsubscribeEventsParams, WebhookDelivery, arguments_from,
};
use serde_json::{Map, Value, json};

use super::eventlog::EventLog;
use super::events::{EventWatch, HookDirectory};
use super::session::Session;

/// What an operation may use beyond the session.
#[derive(Clone, Copy, Default)]
pub struct OpContext<'a> {
    /// The target the session belongs to.
    pub target: &'a str,
    /// The target's webhook callbacks, and the directory that routes
    /// deliveries to them; `None` where nothing stays to receive one, as
    /// in a stateless call.
    pub hooks: Option<(&'a Arc<EventWatch>, &'a HookDirectory)>,
    /// The base URL a server reaches this inspector's callbacks at, when
    /// the caller names none.
    pub callback_base: Option<&'a str>,
    /// The wire log the callbacks write their deliveries to.
    pub wire: Option<&'a Arc<EventLog>>,
}

/// Every operation the engine can run against a connected target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    ListTools,
    ListResources,
    ListResourceTemplates,
    ListPrompts,
    CallTool,
    ReadResource,
    GetPrompt,
    Complete,
    ListEvents,
    PollEvents,
    SubscribeEvents,
    UnsubscribeEvents,
}

impl Op {
    /// Wire name, as it appears in `POST /api/v1/targets/{id}/ops/{op}`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ListTools => "tools.list",
            Self::ListResources => "resources.list",
            Self::ListResourceTemplates => "resources.templates.list",
            Self::ListPrompts => "prompts.list",
            Self::CallTool => "tools.call",
            Self::ReadResource => "resources.read",
            Self::GetPrompt => "prompts.get",
            Self::Complete => "completion.complete",
            Self::ListEvents => "events.list",
            Self::PollEvents => "events.poll",
            Self::SubscribeEvents => "events.subscribe",
            Self::UnsubscribeEvents => "events.unsubscribe",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|op| op.as_str() == name)
    }

    pub const ALL: [Op; 12] = [
        Op::ListTools,
        Op::ListResources,
        Op::ListResourceTemplates,
        Op::ListPrompts,
        Op::CallTool,
        Op::ReadResource,
        Op::GetPrompt,
        Op::Complete,
        Op::ListEvents,
        Op::PollEvents,
        Op::SubscribeEvents,
        Op::UnsubscribeEvents,
    ];
}

/// Failure of a dispatched operation: bad parameters from the caller,
/// or the client's own error.
#[derive(Debug)]
pub enum OpError {
    Params(String),
    Client(UpstreamError),
}

impl std::fmt::Display for OpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Params(m) => write!(f, "{m}"),
            Self::Client(e) => write!(f, "{e}"),
        }
    }
}

/// Run one operation. `params` carries `name`/`arguments` for `tools.call`
/// and `prompts.get`, and `uri` for `resources.read`; the list ops ignore it.
/// The events ops take the extension's own params (`events.poll`:
/// `name`, `arguments`, `cursor`, `maxEvents`; `events.subscribe`: `name`,
/// `arguments`, `cursor`, `ttlMs`, and `callbackBase` for where the server
/// reaches this inspector; `events.unsubscribe`: the `sid` subscribe
/// returned).
pub async fn dispatch(
    ctx: &OpContext<'_>,
    session: &Session,
    op: Op,
    params: &Value,
) -> Result<Value, OpError> {
    match op {
        Op::ListEvents => {
            let mut body = json!({ "events": call(session.list_events().await)? });
            if let Some(advertised) = session.events_capability() {
                body["advertised"] = advertised.to_value();
            }
            Ok(body)
        }
        Op::PollEvents => {
            let params: PollEventsParams = serde_json::from_value(params.clone())
                .map_err(|e| OpError::Params(format!("events.poll: {e}")))?;
            Ok(json!({ "result": call(session.poll_events(&params).await)? }))
        }
        Op::SubscribeEvents => subscribe(ctx, session, params).await,
        Op::UnsubscribeEvents => unsubscribe(ctx, session, params).await,
        Op::ListTools => Ok(json!({ "tools": call(session.list_tools().await)? })),
        Op::ListResources => Ok(json!({ "resources": call(session.list_resources().await)? })),
        Op::ListResourceTemplates => Ok(json!({
            "resourceTemplates": call(session.list_resource_templates().await)?
        })),
        Op::ListPrompts => Ok(json!({ "prompts": call(session.list_prompts().await)? })),
        Op::CallTool => {
            let name = params
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| OpError::Params("tools.call needs a `name`".to_owned()))?;
            let arguments = params.get("arguments");
            Ok(json!({ "result": call(session.call_tool(name, arguments).await)? }))
        }
        Op::ReadResource => {
            let uri = params
                .get("uri")
                .and_then(Value::as_str)
                .ok_or_else(|| OpError::Params("resources.read needs a `uri`".to_owned()))?;
            Ok(json!({ "result": call(session.read_resource(uri).await)? }))
        }
        Op::GetPrompt => {
            let name = params
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| OpError::Params("prompts.get needs a `name`".to_owned()))?;
            let arguments = params.get("arguments");
            Ok(json!({ "result": call(session.get_prompt(name, arguments).await)? }))
        }
        Op::Complete => {
            let reference = params.get("ref").ok_or_else(|| {
                OpError::Params(
                    "completion.complete needs a `ref` naming a prompt or resource template"
                        .to_owned(),
                )
            })?;
            let argument = params.get("argument").ok_or_else(|| {
                OpError::Params(
                    "completion.complete needs an `argument` of {name, value}".to_owned(),
                )
            })?;
            let context = params.get("context");
            Ok(json!({
                "result": call(session.complete(reference, argument, context).await)?
            }))
        }
    }
}

/// `events.subscribe`: a webhook subscription whose callback is this
/// inspector. The secret is minted here and never returned: the inspector
/// is the receiver.
async fn subscribe(
    ctx: &OpContext<'_>,
    session: &Session,
    params: &Value,
) -> Result<Value, OpError> {
    let (hooks, directory) = ctx.hooks.ok_or_else(|| {
        OpError::Params(
            "events.subscribe needs a registered target: a stateless call has no callback"
                .to_owned(),
        )
    })?;
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| OpError::Params("events.subscribe needs a `name`".to_owned()))?;
    let arguments = arguments_of(params)?;
    let base = params
        .get("callbackBase")
        .and_then(Value::as_str)
        .or(ctx.callback_base)
        .ok_or_else(|| {
            OpError::Params(
                "events.subscribe needs a `callbackBase` the server can reach this inspector at"
                    .to_owned(),
            )
        })?;
    let ttl_ms = TtlRequest::from_field(params.get("ttlMs"))
        .map_err(|message| OpError::Params(format!("events.subscribe: `ttlMs`: {message}")))?;
    let hook = hooks.mint(
        directory,
        ctx.target,
        base,
        name,
        &arguments,
        ctx.wire.cloned(),
    );
    let request = SubscribeEventsParams {
        name: name.to_owned(),
        arguments,
        delivery: WebhookDelivery {
            mode: DeliveryMode::Webhook.as_str().to_owned(),
            url: hook.url.clone(),
            secret: hook.secret.clone(),
        },
        cursor: params
            .get("cursor")
            .and_then(Value::as_str)
            .map(str::to_owned),
        max_age_ms: None,
        ttl_ms,
        meta: None,
    };
    match session.subscribe_events(&request).await {
        Ok(result) => Ok(json!({
            "result": result,
            "hook": { "sid": hook.sid, "url": hook.url },
        })),
        Err(error) => {
            hooks.remove(&hook.sid);
            Err(OpError::Client(error))
        }
    }
}

/// `events.unsubscribe`: end the subscription `sid` named, upstream and
/// then here. A refused unsubscribe keeps the callback, since the server
/// still delivers to it.
async fn unsubscribe(
    ctx: &OpContext<'_>,
    session: &Session,
    params: &Value,
) -> Result<Value, OpError> {
    let (hooks, _) = ctx.hooks.ok_or_else(|| {
        OpError::Params("events.unsubscribe needs a registered target".to_owned())
    })?;
    let sid = params.get("sid").and_then(Value::as_str).ok_or_else(|| {
        OpError::Params("events.unsubscribe needs the `sid` subscribe returned".to_owned())
    })?;
    let (name, arguments, url) = hooks
        .subscription(sid)
        .ok_or_else(|| OpError::Params(format!("no subscription `{sid}` here")))?;
    let request = UnsubscribeEventsParams {
        name,
        arguments,
        delivery: UnsubscribeDelivery {
            mode: Some(DeliveryMode::Webhook.as_str().to_owned()),
            url,
        },
        meta: None,
    };
    call(session.unsubscribe_events(&request).await)?;
    hooks.remove(sid);
    Ok(json!({ "unsubscribed": sid }))
}

/// The `arguments` object of `params`.
fn arguments_of(params: &Value) -> Result<Map<String, Value>, OpError> {
    arguments_from(params.get("arguments")).map_err(|message| OpError::Params(message.to_owned()))
}

fn call<T: serde::Serialize>(result: Result<T, UpstreamError>) -> Result<Value, OpError> {
    let value = result.map_err(OpError::Client)?;
    serde_json::to_value(value).map_err(|e| OpError::Params(format!("serialize result: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_names_round_trip_and_are_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for op in Op::ALL {
            assert!(
                seen.insert(op.as_str()),
                "duplicate op name {}",
                op.as_str()
            );
            assert_eq!(Op::parse(op.as_str()), Some(op));
        }
        assert_eq!(Op::parse("nope"), None);
    }
}
