//! Capability snapshots, and the diff between two of them.
//!
//! A snapshot is what a server advertises, normalized so two of them
//! can be compared: sorted, with each entry's schema reduced to a hash
//! so a reordered-but-identical schema does not read as a change.
//!
//! Two questions it answers. In CI: has this server's surface drifted
//! from the one we pinned? Interactively: what does the gateway's
//! plugin chain add, remove or rewrite between an upstream and what a
//! client finally sees — which is the diff the gateway makes uniquely
//! askable.

use std::collections::BTreeMap;

use mcpg_mcp_wire::v_2026_07_28::extensions::events::schema::{SchemaRole, is_additive_change};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::session::Session;

/// One advertised capability, reduced to what a comparison cares
/// about.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Hash of the input schema, so an equivalent schema written in a
    /// different key order compares equal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// What a server advertised, at one moment, over one wire.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    /// The wire this snapshot was taken over. A capability set can
    /// legitimately differ between wires, so a diff says so rather
    /// than blaming the server.
    pub protocol_version: String,
    #[serde(default)]
    pub tools: BTreeMap<String, Entry>,
    #[serde(default)]
    pub resources: BTreeMap<String, Entry>,
    #[serde(default)]
    pub resource_templates: BTreeMap<String, Entry>,
    #[serde(default)]
    pub prompts: BTreeMap<String, Entry>,
    #[serde(default)]
    pub events: BTreeMap<String, EventEntry>,
}

/// One event type. Its schemas are kept whole, not hashed: whether a
/// change breaks a subscriber depends on what changed in them.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Delivery modes, sorted.
    #[serde(default)]
    pub delivery: Vec<String>,
    #[serde(default)]
    pub input_schema: Value,
    #[serde(default)]
    pub payload_schema: Value,
}

/// Stable hash of a JSON value: serialized through `BTreeMap`-backed
/// canonical form so key order cannot change the digest.
fn hash_json(value: &Value) -> String {
    fn canonical(value: &Value) -> Value {
        match value {
            Value::Object(map) => Value::Object(
                map.iter()
                    .map(|(k, v)| (k.clone(), canonical(v)))
                    .collect::<serde_json::Map<_, _>>(),
            ),
            Value::Array(items) => Value::Array(items.iter().map(canonical).collect()),
            other => other.clone(),
        }
    }
    // serde_json's Map preserves insertion order unless `preserve_order`
    // is off; sorting explicitly makes the digest independent of it.
    let mut sorted: Vec<(String, Value)> = match canonical(value) {
        Value::Object(map) => map.into_iter().collect(),
        other => {
            let mut hasher = Sha256::new();
            hasher.update(other.to_string().as_bytes());
            return hasher
                .finalize()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()[..16]
                .to_owned();
        }
    };
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let rebuilt = Value::Object(sorted.into_iter().collect());
    let mut hasher = Sha256::new();
    hasher.update(rebuilt.to_string().as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()[..16]
        .to_owned()
}

fn hash_opt(value: Option<&Value>) -> Option<String> {
    value.map(hash_json)
}

/// Take a snapshot of everything a connected target advertises.
///
/// A capability the server does not implement answers with an error;
/// that is a legitimate answer, not a failure, so the surface is
/// recorded as empty rather than aborting the snapshot.
pub async fn capture(session: &Session) -> Snapshot {
    let mut snapshot = Snapshot {
        protocol_version: session.negotiated_version().to_owned(),
        ..Default::default()
    };

    if let Ok(tools) = session.list_tools().await {
        for tool in tools {
            snapshot.tools.insert(
                tool.name.clone(),
                Entry {
                    title: tool.title.clone(),
                    description: tool.description.clone(),
                    input_schema: hash_opt(tool.input_schema.as_ref()),
                    output_schema: hash_opt(tool.output_schema.as_ref()),
                    annotations: hash_opt(tool.annotations.as_ref()),
                    mime_type: None,
                },
            );
        }
    }
    if let Ok(resources) = session.list_resources().await {
        for resource in resources {
            snapshot.resources.insert(
                resource.uri.clone(),
                Entry {
                    title: resource.title.clone(),
                    description: resource.description.clone(),
                    mime_type: resource.mime_type.clone(),
                    ..Default::default()
                },
            );
        }
    }
    if let Ok(templates) = session.list_resource_templates().await {
        for template in templates {
            snapshot.resource_templates.insert(
                template.uri_template.clone(),
                Entry {
                    title: template.title.clone(),
                    description: template.description.clone(),
                    mime_type: template.mime_type.clone(),
                    ..Default::default()
                },
            );
        }
    }
    if let Ok(prompts) = session.list_prompts().await {
        for prompt in prompts {
            let arguments = serde_json::to_value(&prompt.arguments).ok();
            snapshot.prompts.insert(
                prompt.name.clone(),
                Entry {
                    title: prompt.title.clone(),
                    description: prompt.description.clone(),
                    input_schema: hash_opt(arguments.as_ref()),
                    ..Default::default()
                },
            );
        }
    }
    if let Ok(events) = session.list_events().await {
        for event in events {
            let mut delivery: Vec<String> = event
                .delivery
                .iter()
                .map(|mode| mode.as_str().to_owned())
                .collect();
            delivery.sort();
            delivery.dedup();
            snapshot.events.insert(
                event.name,
                EventEntry {
                    description: event.description,
                    delivery,
                    input_schema: event.input_schema,
                    payload_schema: event.payload_schema,
                },
            );
        }
    }
    snapshot
}

/// One difference between two snapshots.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Change {
    /// `tools`, `resources`, `resourceTemplates`, `prompts`, `events`.
    pub surface: &'static str,
    pub name: String,
    pub kind: ChangeKind,
    /// Which fields differ, for `changed`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<&'static str>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChangeKind {
    Added,
    Removed,
    Changed,
    /// Changed in a way every existing client absorbs: an event type
    /// whose schemas only describe more, or that offers more delivery
    /// modes.
    Extended,
}

/// How strictly a diff is judged.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum DiffMode {
    /// Additions and extensions are fine; removals and changed shapes
    /// are not. This is what "did we break a client" means.
    #[default]
    Compatible,
    /// Any difference at all fails — for pinning an exact surface.
    Strict,
}

#[derive(Clone, Debug, Serialize)]
pub struct Diff {
    pub changes: Vec<Change>,
    /// Set when the two snapshots were taken over different wires:
    /// the surfaces are then expected to differ, and the caller is
    /// told rather than left to infer it from the changes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_version_differs: Option<[String; 2]>,
    /// Whether the diff passes under the requested mode.
    pub ok: bool,
}

pub fn diff(before: &Snapshot, after: &Snapshot, mode: DiffMode) -> Diff {
    let mut changes = Vec::new();
    compare("tools", &before.tools, &after.tools, &mut changes);
    compare(
        "resources",
        &before.resources,
        &after.resources,
        &mut changes,
    );
    compare(
        "resourceTemplates",
        &before.resource_templates,
        &after.resource_templates,
        &mut changes,
    );
    compare("prompts", &before.prompts, &after.prompts, &mut changes);
    compare_events(&before.events, &after.events, &mut changes);

    let ok = match mode {
        DiffMode::Strict => changes.is_empty(),
        DiffMode::Compatible => changes
            .iter()
            .all(|c| matches!(c.kind, ChangeKind::Added | ChangeKind::Extended)),
    };
    let protocol_version_differs = (before.protocol_version != after.protocol_version).then(|| {
        [
            before.protocol_version.clone(),
            after.protocol_version.clone(),
        ]
    });
    Diff {
        changes,
        protocol_version_differs,
        ok,
    }
}

fn compare(
    surface: &'static str,
    before: &BTreeMap<String, Entry>,
    after: &BTreeMap<String, Entry>,
    out: &mut Vec<Change>,
) {
    for (name, old) in before {
        match after.get(name) {
            None => out.push(Change {
                surface,
                name: name.clone(),
                kind: ChangeKind::Removed,
                fields: Vec::new(),
            }),
            Some(new) if new != old => {
                let mut fields = Vec::new();
                if old.title != new.title {
                    fields.push("title");
                }
                if old.description != new.description {
                    fields.push("description");
                }
                if old.input_schema != new.input_schema {
                    fields.push("inputSchema");
                }
                if old.output_schema != new.output_schema {
                    fields.push("outputSchema");
                }
                if old.annotations != new.annotations {
                    fields.push("annotations");
                }
                if old.mime_type != new.mime_type {
                    fields.push("mimeType");
                }
                out.push(Change {
                    surface,
                    name: name.clone(),
                    kind: ChangeKind::Changed,
                    fields,
                });
            }
            Some(_) => {}
        }
    }
    added(surface, before, after, out);
}

fn added<T>(
    surface: &'static str,
    before: &BTreeMap<String, T>,
    after: &BTreeMap<String, T>,
    out: &mut Vec<Change>,
) {
    for name in after.keys() {
        if !before.contains_key(name) {
            out.push(Change {
                surface,
                name: name.clone(),
                kind: ChangeKind::Added,
                fields: Vec::new(),
            });
        }
    }
}

/// Event types by the rule a subscriber lives under: schemas judged by
/// [`is_additive_change`], delivery modes that may grow but not shrink.
/// A changed description is a change, as it is for a tool: a model reads
/// it.
fn compare_events(
    before: &BTreeMap<String, EventEntry>,
    after: &BTreeMap<String, EventEntry>,
    out: &mut Vec<Change>,
) {
    for (name, old) in before {
        let Some(new) = after.get(name) else {
            out.push(Change {
                surface: "events",
                name: name.clone(),
                kind: ChangeKind::Removed,
                fields: Vec::new(),
            });
            continue;
        };
        if new == old {
            continue;
        }
        let mut fields = Vec::new();
        let mut breaking = false;
        if old.description != new.description {
            fields.push("description");
            breaking = true;
        }
        if old.delivery != new.delivery {
            fields.push("delivery");
            breaking |= !old.delivery.iter().all(|mode| new.delivery.contains(mode));
        }
        if old.input_schema != new.input_schema {
            fields.push("inputSchema");
            breaking |=
                !is_additive_change(&old.input_schema, &new.input_schema, SchemaRole::Input);
        }
        if old.payload_schema != new.payload_schema {
            fields.push("payloadSchema");
            breaking |= !is_additive_change(
                &old.payload_schema,
                &new.payload_schema,
                SchemaRole::Payload,
            );
        }
        out.push(Change {
            surface: "events",
            name: name.clone(),
            kind: if breaking {
                ChangeKind::Changed
            } else {
                ChangeKind::Extended
            },
            fields,
        });
    }
    added("events", before, after, out);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tool(entry: Entry) -> Snapshot {
        Snapshot {
            protocol_version: "2026-07-28".to_owned(),
            tools: BTreeMap::from([("t".to_owned(), entry)]),
            ..Default::default()
        }
    }

    #[test]
    fn schema_hash_ignores_key_order_but_not_content() {
        let a = json!({ "type": "object", "properties": { "x": { "type": "string" } } });
        let b = json!({ "properties": { "x": { "type": "string" } }, "type": "object" });
        assert_eq!(hash_json(&a), hash_json(&b), "key order must not matter");

        let c = json!({ "type": "object", "properties": { "x": { "type": "number" } } });
        assert_ne!(hash_json(&a), hash_json(&c), "content must matter");
    }

    #[test]
    fn additions_are_compatible_but_removals_are_not() {
        let before = tool(Entry::default());
        let mut after = before.clone();
        after.tools.insert("new".to_owned(), Entry::default());

        let compatible = diff(&before, &after, DiffMode::Compatible);
        assert!(compatible.ok, "adding a tool keeps old clients working");
        assert_eq!(compatible.changes.len(), 1);
        assert_eq!(compatible.changes[0].kind, ChangeKind::Added);

        // The same diff under strict is a failure.
        assert!(!diff(&before, &after, DiffMode::Strict).ok);

        // Removing one is never compatible.
        let removed = diff(&after, &before, DiffMode::Compatible);
        assert!(!removed.ok);
        assert_eq!(removed.changes[0].kind, ChangeKind::Removed);
    }

    #[test]
    fn a_changed_schema_names_the_field_and_fails_compatible() {
        let before = tool(Entry {
            input_schema: Some("aaa".to_owned()),
            description: Some("old".to_owned()),
            ..Default::default()
        });
        let after = tool(Entry {
            input_schema: Some("bbb".to_owned()),
            description: Some("new".to_owned()),
            ..Default::default()
        });
        let d = diff(&before, &after, DiffMode::Compatible);
        assert!(!d.ok);
        assert_eq!(d.changes[0].kind, ChangeKind::Changed);
        assert!(d.changes[0].fields.contains(&"inputSchema"));
        assert!(d.changes[0].fields.contains(&"description"));
    }

    #[test]
    fn a_cross_wire_diff_says_so() {
        let before = tool(Entry::default());
        let mut after = before.clone();
        after.protocol_version = "2025-11-25".to_owned();
        let d = diff(&before, &after, DiffMode::Compatible);
        // Identical surfaces, so no changes — but the caller is told
        // the comparison spans two wires rather than having to guess.
        assert!(d.changes.is_empty());
        assert_eq!(
            d.protocol_version_differs,
            Some(["2026-07-28".to_owned(), "2025-11-25".to_owned()])
        );
    }

    fn event(entry: EventEntry) -> Snapshot {
        Snapshot {
            protocol_version: "2026-07-28".to_owned(),
            events: BTreeMap::from([("e".to_owned(), entry)]),
            ..Default::default()
        }
    }

    fn order_event() -> EventEntry {
        EventEntry {
            description: Some("an order".to_owned()),
            delivery: vec!["poll".to_owned()],
            input_schema: json!({ "type": "object", "properties": { "shop": { "type": "string" } } }),
            payload_schema: json!({
                "type": "object",
                "properties": { "id": { "type": "string" } },
                "required": ["id"]
            }),
        }
    }

    #[test]
    fn an_event_that_only_describes_more_is_extended_and_compatible() {
        let before = event(order_event());
        let mut grown = order_event();
        grown.delivery.push("webhook".to_owned());
        grown.payload_schema["properties"]["total"] = json!({ "type": "number" });
        grown.input_schema["properties"]["region"] = json!({ "type": "string" });
        let after = event(grown);

        let d = diff(&before, &after, DiffMode::Compatible);
        assert!(d.ok, "{:?}", d.changes);
        assert_eq!(d.changes[0].kind, ChangeKind::Extended);
        assert_eq!(
            d.changes[0].fields,
            vec!["delivery", "inputSchema", "payloadSchema"]
        );
        assert!(!diff(&before, &after, DiffMode::Strict).ok);
    }

    #[test]
    fn an_event_that_breaks_a_subscriber_is_changed() {
        let before = event(order_event());

        let mut fewer_modes = order_event();
        fewer_modes.delivery = vec!["push".to_owned()];
        let mut lost_guarantee = order_event();
        lost_guarantee.payload_schema["required"] = json!([]);
        let mut new_demand = order_event();
        new_demand.input_schema["required"] = json!(["shop"]);
        let mut retyped = order_event();
        retyped.payload_schema["properties"]["id"] = json!({ "type": "number" });

        for (case, after) in [
            ("a delivery mode removed", fewer_modes),
            ("a payload field no longer required", lost_guarantee),
            ("an argument newly required", new_demand),
            ("a payload field retyped", retyped),
        ] {
            let d = diff(&before, &event(after), DiffMode::Compatible);
            assert!(!d.ok, "{case}");
            assert_eq!(d.changes[0].kind, ChangeKind::Changed, "{case}");
        }
    }

    #[test]
    fn a_snapshot_without_events_still_reads() {
        let old: Snapshot =
            serde_json::from_value(json!({ "protocol_version": "2025-11-25", "tools": {} }))
                .unwrap();
        assert!(old.events.is_empty());
        let d = diff(&old, &event(order_event()), DiffMode::Compatible);
        assert!(d.ok);
        assert_eq!(d.changes[0].kind, ChangeKind::Added);
    }

    #[test]
    fn an_identical_surface_is_clean_under_both_modes() {
        let snapshot = tool(Entry {
            input_schema: Some("aaa".to_owned()),
            ..Default::default()
        });
        assert!(diff(&snapshot, &snapshot, DiffMode::Strict).ok);
        assert!(diff(&snapshot, &snapshot, DiffMode::Compatible).ok);
    }
}
