//! Serving the terminal from this process's own engine.
//!
//! The other half of [`mcpg_inspector_tui::api::InspectorApi`] — the adapter
//! that maps this crate's engine onto the shapes the screens read. It lives
//! here rather than in the terminal crate because it is the *engine's* side
//! of that port: the interface says what it needs, and the server is what
//! knows how to produce it.

use std::sync::Arc;

use mcpg_inspector_tui::api::{Catalog, InspectorApi, PushStream};
use mcpg_inspector_tui::schema::PromptArgument;
use mcpg_inspector_tui::state::{PendingRow, PromptRow, ResourceRow, TargetRow, ToolRow};
use mcpg_inspector_tui::view::{
    CheckRow, CheckSummary, GatewayCheckRow, GatewayPluginRow, GatewayView, Outcome, SessionView,
    WireRow,
};
use serde_json::Value;

use crate::engine::registry::{Engine, SessionState, TargetEntry};

pub struct LocalApi {
    engine: Arc<Engine>,
}

impl LocalApi {
    pub fn new(engine: Arc<Engine>) -> Self {
        Self { engine }
    }

    fn entry(&self, id: &str) -> Result<Arc<TargetEntry>, String> {
        self.engine
            .get(id)
            .ok_or_else(|| format!("no target '{id}'"))
    }

    async fn session(&self, id: &str) -> Result<Arc<crate::engine::session::Session>, String> {
        self.entry(id)?
            .session()
            .await
            .ok_or_else(|| "connect the target first (c)".to_owned())
    }
}

#[async_trait::async_trait]
impl InspectorApi for LocalApi {
    async fn targets(&self) -> Vec<TargetRow> {
        self.engine
            .list()
            .iter()
            .map(|entry| TargetRow {
                id: entry.id.clone(),
                endpoint: match &entry.spec.kind {
                    crate::engine::target::TargetKind::Http { url } => url.clone(),
                    crate::engine::target::TargetKind::Stdio { command, .. } => {
                        format!("stdio:{command}")
                    }
                    crate::engine::target::TargetKind::Recording { path } => {
                        format!("recording:{path}")
                    }
                },
                session: session_view(entry.state()),
            })
            .collect()
    }

    async fn connect(&self, id: &str) -> Result<(), String> {
        self.entry(id)?
            .connect()
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    async fn disconnect(&self, id: &str) -> Result<(), String> {
        self.entry(id)?.disconnect().await;
        Ok(())
    }

    async fn catalog(&self, id: &str) -> Catalog {
        let mut catalog = Catalog::default();
        let Ok(session) = self.session(id).await else {
            return catalog;
        };
        match session.list_tools().await {
            Ok(tools) => {
                catalog.tools = tools
                    .into_iter()
                    .map(|tool| ToolRow {
                        name: tool.name,
                        description: tool.description,
                        app_uri: tool.meta.as_ref().and_then(|meta| {
                            mcpg_mcp_wire::shared::apps::tool_resource_uri(meta).map(str::to_owned)
                        }),
                        input_schema: tool.input_schema,
                        output_schema: tool.output_schema,
                    })
                    .collect()
            }
            Err(e) => catalog.errors.push(format!("tools/list: {e}")),
        }
        match session.list_resources().await {
            Ok(resources) => {
                catalog.resources = resources
                    .into_iter()
                    .map(|r| ResourceRow {
                        uri: r.uri,
                        name: Some(r.name),
                        description: r.description,
                        is_template: false,
                    })
                    .collect()
            }
            Err(e) => catalog.errors.push(format!("resources/list: {e}")),
        }
        if let Ok(templates) = session.list_resource_templates().await {
            catalog
                .resources
                .extend(templates.into_iter().map(|t| ResourceRow {
                    uri: t.uri_template,
                    name: Some(t.name),
                    description: t.description,
                    is_template: true,
                }));
        }
        match session.list_prompts().await {
            Ok(prompts) => {
                catalog.prompts = prompts
                    .into_iter()
                    .map(|p| PromptRow {
                        arguments: p
                            .arguments
                            .iter()
                            .map(|a| PromptArgument {
                                name: a.name.clone(),
                                description: a.description.clone(),
                                required: a.required,
                            })
                            .collect(),
                        name: p.name,
                        description: p.description,
                    })
                    .collect()
            }
            Err(e) => catalog.errors.push(format!("prompts/list: {e}")),
        }
        catalog
    }

    async fn call_tool(&self, id: &str, name: &str, args: &Value) -> Result<Value, String> {
        self.session(id)
            .await?
            .call_tool(name, Some(args))
            .await
            .map_err(|e| e.to_string())
    }

    async fn read_resource(&self, id: &str, uri: &str) -> Result<Value, String> {
        self.session(id)
            .await?
            .read_resource(uri)
            .await
            .map_err(|e| e.to_string())
    }

    async fn get_prompt(&self, id: &str, name: &str, args: &Value) -> Result<Value, String> {
        self.session(id)
            .await?
            .get_prompt(name, Some(args))
            .await
            .map_err(|e| e.to_string())
    }

    async fn wire(&self, id: &str) -> Vec<WireRow> {
        self.entry(id)
            .map(|entry| {
                entry
                    .events
                    .snapshot()
                    .into_iter()
                    .map(|event| WireRow {
                        seq: event.seq,
                        ts_ms: event.ts_ms,
                        direction: event.direction,
                        channel: event.channel,
                        body: event.body,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    async fn checks(&self, id: &str) -> Result<CheckSummary, String> {
        let session = self.session(id).await?;
        let url = session.endpoint_url().ok_or_else(|| {
            "the protocol checks probe an HTTP endpoint; a stdio target has none".to_owned()
        })?;
        let report = crate::engine::checks::run(
            url,
            session.negotiated_version(),
            self.entry(id)?.spec.allow_private,
        )
        .await?;
        Ok(CheckSummary {
            protocol_version: report.protocol_version,
            passed: report.passed,
            failed: report.failed,
            skipped: report.skipped,
            checks: report
                .checks
                .into_iter()
                .map(|check| CheckRow {
                    id: check.id,
                    description: check.description,
                    outcome: match check.outcome {
                        crate::engine::checks::Outcome::Pass => Outcome::Pass,
                        crate::engine::checks::Outcome::Fail => Outcome::Fail,
                        crate::engine::checks::Outcome::Skip => Outcome::Skip,
                    },
                    detail: check.detail,
                })
                .collect(),
        })
    }

    async fn gateway(&self, id: &str) -> Result<GatewayView, String> {
        let session = self.session(id).await?;
        let report =
            crate::engine::gateway::for_session(&session, self.entry(id)?.spec.allow_private)
                .await?;
        Ok(GatewayView {
            service: report.service,
            version: report.version,
            uptime_secs: report.uptime_secs,
            readiness: report.readiness,
            failing_checks: report
                .failing_checks
                .into_iter()
                .map(|check| GatewayCheckRow {
                    name: check.name,
                    status: check.status,
                    detail: check.detail,
                })
                .collect(),
            log_level: report.log_level,
            plugin_count: report.plugin_count,
            plugins: report
                .plugins
                .into_iter()
                .map(|plugin| GatewayPluginRow {
                    id: plugin.id,
                    version: plugin.version,
                    class: plugin.class,
                    state: plugin.state,
                })
                .collect(),
        })
    }

    async fn pending(&self, id: &str) -> Vec<PendingRow> {
        let Ok(entry) = self.entry(id) else {
            return Vec::new();
        };
        entry
            .responder
            .pending()
            .await
            .into_iter()
            .map(|request| PendingRow {
                id: request.id,
                method: request.method,
                params: serde_json::to_string_pretty(&request.params).unwrap_or_default(),
                regime: request.regime.to_owned(),
            })
            .collect()
    }

    async fn respond(
        &self,
        id: &str,
        request: u64,
        answer: Result<Value, String>,
    ) -> Result<(), String> {
        let answer = answer.map_err(|message| (-32601, message));
        if self.entry(id)?.responder.resolve(request, answer).await {
            Ok(())
        } else {
            Err("no longer waiting".to_owned())
        }
    }

    async fn subscribe(&self, id: &str, uris: &[String]) -> Result<PushStream, String> {
        let spec = mcpg_mcp_client::upstream::SubscriptionSpec {
            resource_uris: uris.to_vec(),
            tools_list_changed: true,
            prompts_list_changed: true,
            resources_list_changed: true,
        };
        self.session(id)
            .await?
            .subscribe(&spec)
            .await
            .map_err(|e| e.to_string())
    }

    async fn recording(&self, id: &str) -> Result<String, String> {
        let entry = self.entry(id)?;
        Ok(crate::engine::recording::write(
            &crate::engine::recording::RecordingHeader {
                kind: crate::engine::recording::KIND.to_owned(),
                version: crate::engine::recording::VERSION,
                recorded_at_ms: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or_default(),
                target: entry.describe(),
                negotiated_version: match entry.state() {
                    SessionState::Ready { negotiated_version } => Some(negotiated_version),
                    _ => None,
                },
                redacted: true,
            },
            &entry
                .events
                .snapshot()
                .into_iter()
                .map(|mut event| {
                    event.body = crate::engine::recording::redact_frame(&event.body);
                    event
                })
                .collect::<Vec<_>>(),
        ))
    }

    async fn complete(
        &self,
        id: &str,
        reference: &Value,
        argument: &str,
        typed: &str,
    ) -> Result<Vec<String>, String> {
        let result = self
            .session(id)
            .await?
            .complete(
                reference,
                &serde_json::json!({ "name": argument, "value": typed }),
                None,
            )
            .await
            .map_err(|e| e.to_string())?;
        Ok(mcpg_inspector_tui::api::completion_values(&result))
    }
}

/// The engine's session state as the screens read it.
fn session_view(state: SessionState) -> SessionView {
    match state {
        SessionState::Idle => SessionView::Idle,
        SessionState::Connecting => SessionView::Connecting,
        SessionState::Ready { negotiated_version } => SessionView::Ready { negotiated_version },
        SessionState::Failed { message } => SessionView::Failed { message },
    }
}
