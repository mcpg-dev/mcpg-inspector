//! Two questions you can only answer by asking a server repeatedly: how fast
//! is it, and what does it do with input it said it would not accept.
//!
//! Both call real tools on a real server, which is the whole point and also
//! the hazard. A tool named `billing.refund` moves money whether or not the
//! arguments were generated. So the case generation is pure and tested here,
//! and the decision about WHICH tools may be called is made before any of it
//! runs — see [`is_safe_to_fuzz`].

use std::time::Instant;

use serde::Serialize;
use serde_json::{Map, Value, json};

// ---------------------------------------------------------------------------
// bench
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BenchReport {
    pub tool: String,
    pub calls: usize,
    pub ok: usize,
    pub failed: usize,
    /// Milliseconds, fractional. Timed in microseconds because a local stdio
    /// server answers well inside a millisecond, and a report of `0` cannot be
    /// told apart from one that measured nothing.
    ///
    /// Percentiles are of the calls that answered at all — a failure has no
    /// latency worth averaging in, and mixing them in is how a broken server
    /// comes out looking fast.
    pub min_ms: f64,
    pub p50_ms: f64,
    pub p90_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
    pub total_ms: f64,
}

/// Microseconds to milliseconds, at a resolution someone can act on.
fn ms(micros: u64) -> f64 {
    (micros as f64 / 10.0).round() / 100.0
}

/// Percentile by nearest-rank on a sorted slice. Not interpolated: with the
/// sample sizes an inspector runs, an interpolated p99 is a number nobody
/// measured.
pub fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
}

/// `latencies` and `total` are microseconds.
pub fn summarize(tool: &str, mut latencies: Vec<u64>, failed: usize, total: u64) -> BenchReport {
    latencies.sort_unstable();
    BenchReport {
        tool: tool.to_owned(),
        calls: latencies.len() + failed,
        ok: latencies.len(),
        failed,
        min_ms: ms(latencies.first().copied().unwrap_or(0)),
        p50_ms: ms(percentile(&latencies, 50.0)),
        p90_ms: ms(percentile(&latencies, 90.0)),
        p99_ms: ms(percentile(&latencies, 99.0)),
        max_ms: ms(latencies.last().copied().unwrap_or(0)),
        total_ms: ms(total),
    }
}

/// One timed call. Returns the latency, or `None` when it did not answer.
pub async fn timed<F, Fut>(call: F) -> (Option<u64>, Option<String>)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<Value, String>>,
{
    let started = Instant::now();
    match call().await {
        Ok(_) => (Some(started.elapsed().as_micros() as u64), None),
        Err(message) => (None, Some(message)),
    }
}

// ---------------------------------------------------------------------------
// fuzz
// ---------------------------------------------------------------------------

/// May this tool be called with generated arguments?
///
/// Only when the server says it is read-only. An unannotated tool is NOT
/// treated as safe: "we do not know" and "it is harmless" are different
/// answers, and only one of them is true of `billing.refund`.
pub fn is_safe_to_fuzz(annotations: Option<&Value>) -> bool {
    annotations
        .and_then(|a| a.get("readOnlyHint"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// One thing to send, and why it is worth sending.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FuzzCase {
    /// Short, stable name for the shape being tested.
    pub case: String,
    /// What a correct server should do with it.
    pub expect: Expectation,
    pub arguments: Value,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Expectation {
    /// The schema describes this input, so it should be accepted.
    Accept,
    /// The schema forbids it, so a refusal is the correct answer.
    Reject,
}

/// The longest string a case will send.
///
/// Long enough to find a server that never bounded a field, short enough that
/// running the suite is not itself an attack. An inspector that could be
/// pointed at someone else's server has to stay on the right side of that.
const LONG_STRING: usize = 4096;

/// Cases derived from a tool's input schema.
///
/// Each one tests a claim the schema makes. A schema that claims nothing
/// produces almost nothing — which is itself the finding, and the report says
/// so rather than inventing cases the server never promised anything about.
pub fn cases_for(schema: Option<&Value>) -> Vec<FuzzCase> {
    let properties = schema
        .and_then(|s| s.get("properties"))
        .and_then(Value::as_object);
    let required: Vec<&str> = schema
        .and_then(|s| s.get("required"))
        .and_then(Value::as_array)
        .map(|list| list.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();

    let mut cases = Vec::new();

    // A valid call first: without one, a server that rejects everything looks
    // as correct as a server that rejects the right things.
    if let Some(properties) = properties {
        let mut valid = Map::new();
        for (name, property) in properties {
            if required.contains(&name.as_str()) {
                valid.insert(name.clone(), sample_for(property));
            }
        }
        cases.push(FuzzCase {
            case: "valid-minimal".to_owned(),
            expect: Expectation::Accept,
            arguments: Value::Object(valid.clone()),
        });

        // Each required field, left out in turn.
        for name in &required {
            let mut missing = valid.clone();
            missing.remove(*name);
            cases.push(FuzzCase {
                case: format!("missing-required:{name}"),
                expect: Expectation::Reject,
                arguments: Value::Object(missing),
            });
        }

        // Each typed field, sent as something else.
        for (name, property) in properties {
            let Some(wrong) = wrong_type_for(property) else {
                continue;
            };
            let mut mistyped = valid.clone();
            mistyped.insert(name.clone(), wrong);
            cases.push(FuzzCase {
                case: format!("wrong-type:{name}"),
                expect: Expectation::Reject,
                arguments: Value::Object(mistyped),
            });
        }

        // A string field with far more in it than anyone declared.
        if let Some((name, _)) = properties
            .iter()
            .find(|(_, p)| p.get("type").and_then(Value::as_str) == Some("string"))
        {
            let mut long = valid.clone();
            long.insert(name.clone(), json!("A".repeat(LONG_STRING)));
            cases.push(FuzzCase {
                case: format!("oversized:{name}"),
                // Not a rejection: a schema with no `maxLength` has not
                // forbidden this, so accepting it is legal. It is reported
                // for what it costs, not as a fault.
                expect: Expectation::Accept,
                arguments: Value::Object(long),
            });
        }

        // A key the schema never mentioned.
        let mut extra = valid;
        extra.insert("__mcpg_inspector_unknown".to_owned(), json!(true));
        cases.push(FuzzCase {
            case: "unknown-property".to_owned(),
            expect: Expectation::Accept,
            arguments: Value::Object(extra),
        });
    }

    // Empty arguments: correct when nothing is required, refused otherwise.
    cases.push(FuzzCase {
        case: "empty".to_owned(),
        expect: if required.is_empty() {
            Expectation::Accept
        } else {
            Expectation::Reject
        },
        arguments: json!({}),
    });

    cases
}

/// A value a field would legitimately hold.
fn sample_for(property: &Value) -> Value {
    if let Some(first) = property
        .get("enum")
        .and_then(Value::as_array)
        .and_then(|options| options.first())
    {
        return first.clone();
    }
    match property.get("type").and_then(Value::as_str) {
        Some("integer") => json!(1),
        Some("number") => json!(1.5),
        Some("boolean") => json!(true),
        Some("array") => json!([]),
        Some("object") => json!({}),
        // Including an untyped field: a string is the value most servers can
        // at least parse, which keeps the "valid" case valid.
        _ => json!("mcpg-inspector"),
    }
}

/// A value of the wrong type for this field, or `None` when the schema does
/// not say enough for "wrong" to mean anything.
fn wrong_type_for(property: &Value) -> Option<Value> {
    match property.get("type").and_then(Value::as_str)? {
        "string" => Some(json!(12345)),
        "integer" | "number" => Some(json!("not-a-number")),
        "boolean" => Some(json!("yes")),
        "array" => Some(json!("not-an-array")),
        "object" => Some(json!("not-an-object")),
        _ => None,
    }
}

/// What the server actually did with one case.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FuzzOutcome {
    pub case: String,
    pub expect: Expectation,
    pub got: Verdict,
    /// Set when the answer is worth reading — the error, or a note.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// True when what happened is not what the schema promised.
    pub surprising: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    /// Answered normally.
    Accepted,
    /// Answered with `isError: true` — a tool-level refusal.
    ToolError,
    /// Answered with a JSON-RPC error — a protocol-level refusal.
    ProtocolError,
    /// Did not answer: the transport failed, which is never a correct way to
    /// refuse a call.
    NoAnswer,
}

/// Read one result into a verdict, and say whether it surprises.
pub fn judge(case: &FuzzCase, result: Result<&Value, &str>) -> FuzzOutcome {
    let (got, detail) = match result {
        Ok(value) if value.get("isError").and_then(Value::as_bool) == Some(true) => (
            Verdict::ToolError,
            value
                .get("content")
                .map(|c| one_line(&c.to_string()))
                .or_else(|| Some("isError".to_owned())),
        ),
        Ok(_) => (Verdict::Accepted, None),
        Err(message) if looks_like_protocol_error(message) => {
            (Verdict::ProtocolError, Some(one_line(message)))
        }
        Err(message) => (Verdict::NoAnswer, Some(one_line(message))),
    };
    let refused = matches!(got, Verdict::ToolError | Verdict::ProtocolError);
    let surprising = match case.expect {
        // Accepting what the schema forbids is the finding this exists for.
        Expectation::Reject => !refused,
        // As is refusing what it allows — and never answering at all.
        Expectation::Accept => refused || got == Verdict::NoAnswer,
    };
    FuzzOutcome {
        case: case.case.clone(),
        expect: case.expect,
        got,
        detail,
        surprising,
    }
}

/// A JSON-RPC error is a refusal; a transport failure is not. Distinguishing
/// them is the difference between "the server said no" and "the server fell
/// over", and only one of those is a correct answer.
fn looks_like_protocol_error(message: &str) -> bool {
    message.contains("-320") || message.contains("-321") || message.contains("JSON-RPC")
}

fn one_line(text: &str) -> String {
    let flat: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let trimmed = flat.trim();
    if trimmed.chars().count() <= 160 {
        trimmed.to_owned()
    } else {
        trimmed.chars().take(160).collect::<String>() + "…"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schema() -> Value {
        json!({
            "type": "object",
            "properties": {
                "title": { "type": "string" },
                "count": { "type": "integer" },
                "urgent": { "type": "boolean" },
            },
            "required": ["title"],
        })
    }

    /// Read-only is the only safe answer. "We do not know" is not the same as
    /// "it is harmless", and a tool that moves money is usually the one that
    /// forgot to annotate itself.
    #[test]
    fn only_a_declared_read_only_tool_may_be_fuzzed() {
        assert!(is_safe_to_fuzz(Some(&json!({ "readOnlyHint": true }))));
        assert!(!is_safe_to_fuzz(Some(&json!({ "readOnlyHint": false }))));
        assert!(!is_safe_to_fuzz(Some(&json!({ "destructiveHint": false }))));
        assert!(
            !is_safe_to_fuzz(Some(&json!({}))),
            "unannotated is not safe"
        );
        assert!(!is_safe_to_fuzz(None), "absent is not safe");
    }

    /// Every case tests a claim the schema makes, and the valid one has to be
    /// there: without it a server that refuses everything looks as correct as
    /// one that refuses the right things.
    #[test]
    fn cases_cover_what_the_schema_claims() {
        let cases = cases_for(Some(&schema()));
        let names: Vec<&str> = cases.iter().map(|c| c.case.as_str()).collect();
        assert!(names.contains(&"valid-minimal"), "{names:?}");
        assert!(names.contains(&"missing-required:title"), "{names:?}");
        assert!(names.contains(&"wrong-type:count"), "{names:?}");
        assert!(names.contains(&"unknown-property"), "{names:?}");
        assert!(
            names.iter().any(|n| n.starts_with("oversized:")),
            "{names:?}"
        );

        let valid = cases.iter().find(|c| c.case == "valid-minimal").unwrap();
        assert_eq!(valid.expect, Expectation::Accept);
        assert_eq!(valid.arguments["title"], json!("mcpg-inspector"));
        assert!(
            valid.arguments.get("count").is_none(),
            "minimal means required only"
        );

        let mistyped = cases.iter().find(|c| c.case == "wrong-type:count").unwrap();
        assert_eq!(mistyped.expect, Expectation::Reject);
        assert_eq!(mistyped.arguments["count"], json!("not-a-number"));
    }

    /// A schema that claims nothing cannot be contradicted, and inventing
    /// cases anyway would report a server for breaking a rule nobody wrote.
    #[test]
    fn a_schema_that_claims_nothing_yields_almost_nothing() {
        let cases = cases_for(None);
        assert_eq!(cases.len(), 1);
        assert_eq!(cases[0].case, "empty");
        assert_eq!(
            cases[0].expect,
            Expectation::Accept,
            "nothing is required, so empty is legal"
        );
    }

    /// The finding this exists for: a server that accepts what its own schema
    /// forbids.
    #[test]
    fn accepting_what_the_schema_forbids_is_surprising() {
        let cases = cases_for(Some(&schema()));
        let missing = cases
            .iter()
            .find(|c| c.case == "missing-required:title")
            .unwrap();

        let accepted = judge(missing, Ok(&json!({ "content": [] })));
        assert_eq!(accepted.got, Verdict::Accepted);
        assert!(accepted.surprising, "a required field was not enforced");

        let refused = judge(missing, Err("JSON-RPC -32602: title is required"));
        assert_eq!(refused.got, Verdict::ProtocolError);
        assert!(!refused.surprising, "refusing is the correct answer");

        let tool_error = judge(missing, Ok(&json!({ "isError": true, "content": [] })));
        assert_eq!(tool_error.got, Verdict::ToolError);
        assert!(!tool_error.surprising);
    }

    /// Falling over is never a correct way to refuse, so it surprises whether
    /// the case was meant to be accepted or rejected.
    #[test]
    fn never_answering_is_always_surprising() {
        let cases = cases_for(Some(&schema()));
        for case in &cases {
            let dead = judge(case, Err("connection closed before a response"));
            assert_eq!(dead.got, Verdict::NoAnswer, "{}", case.case);
            assert!(dead.surprising, "{} should surprise", case.case);
        }
    }

    /// Refusing a call the schema allows is a finding too — a server whose
    /// implementation is stricter than what it advertises.
    #[test]
    fn refusing_what_the_schema_allows_is_surprising() {
        let cases = cases_for(Some(&schema()));
        let valid = cases.iter().find(|c| c.case == "valid-minimal").unwrap();
        let refused = judge(valid, Err("JSON-RPC -32602: nope"));
        assert!(refused.surprising);
    }

    #[test]
    fn percentiles_are_nearest_rank_over_what_answered() {
        // microseconds in, fractional milliseconds out
        let report = summarize(
            "t",
            vec![10_000, 20_000, 30_000, 40_000, 100_000],
            2,
            500_000,
        );
        assert_eq!(report.calls, 7, "failures count as calls");
        assert_eq!(report.ok, 5);
        assert_eq!(report.failed, 2);
        assert_eq!(report.min_ms, 10.0);
        assert_eq!(report.max_ms, 100.0);
        assert_eq!(report.p50_ms, 30.0);
        assert_eq!(report.p90_ms, 100.0);
        assert_eq!(report.total_ms, 500.0);
        assert_eq!(percentile(&[], 50.0), 0, "no sample, no percentile");
        assert_eq!(percentile(&[7], 99.0), 7);
    }

    #[test]
    fn sub_millisecond_calls_report_a_number_not_zero() {
        // A local stdio server lands here, and whole milliseconds would round
        // the whole report to 0 — indistinguishable from having measured
        // nothing.
        let report = summarize("t", vec![120, 340, 780], 0, 1_240);
        assert_eq!(report.min_ms, 0.12);
        assert_eq!(report.p50_ms, 0.34);
        assert_eq!(report.max_ms, 0.78);
    }
}
