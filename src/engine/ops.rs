//! Typed operations, named once so every face reaches the same set.
//!
//! The API dispatches by name and the one-shot verbs call the same
//! functions, which is what keeps `mcpg-inspector call` and the web
//! UI's call button honestly equivalent.

use mcpg_mcp_client::upstream::UpstreamError;
use serde_json::{Value, json};

use super::session::Session;

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
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|op| op.as_str() == name)
    }

    pub const ALL: [Op; 8] = [
        Op::ListTools,
        Op::ListResources,
        Op::ListResourceTemplates,
        Op::ListPrompts,
        Op::CallTool,
        Op::ReadResource,
        Op::GetPrompt,
        Op::Complete,
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
pub async fn dispatch(session: &Session, op: Op, params: &Value) -> Result<Value, OpError> {
    match op {
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
