//! One-shot CLI verbs: `list`, `call`, `read`. Human chatter goes to
//! stderr; with `--json`, the result document is the only thing on
//! stdout. Exit codes are the stable contract from the crate root.

use std::sync::Arc;

use mcpg_mcp_client::tap::SharedTap;
use mcpg_mcp_client::upstream::UpstreamError;
use serde_json::{Value, json};

use crate::engine::client_auth::{AssertionAudience, AssertionKey, ClientAuthMethod};
use crate::engine::eventlog::StderrWirePrinter;
use crate::engine::idjag::SubjectTokenType;
use crate::engine::keys::SigningAlg;
use crate::engine::oauth::ClientAuthOptions;
use crate::engine::responders::{MockAnswers, ResponderPolicy, Root};
use crate::engine::session::{Session, SessionError};
use crate::engine::snapshot::DiffMode;
use crate::engine::target::{TargetSpec, VersionPolicy};

#[derive(clap::Args, Debug)]
pub struct TargetArgs {
    /// Target: an http(s) URL, `stdio:<command> [args…]`, or a JSON
    /// target object
    pub target: String,
    /// Bearer token sent to the target
    #[arg(long, env = "MCPG_INSPECTOR_BEARER", hide_env_values = true)]
    pub bearer: Option<String>,
    /// Present --bearer as a DPoP-bound token (RFC 9449), proving
    /// possession with the key in this file: the private JWK `login
    /// --dpop-key` writes, or a PKCS#8 PEM (ES256 or EdDSA)
    #[arg(long, env = "MCPG_INSPECTOR_DPOP_KEY", value_name = "PATH")]
    pub dpop_key: Option<std::path::PathBuf>,
    /// Extra request header, NAME=VALUE (repeatable)
    #[arg(long = "header", value_name = "NAME=VALUE")]
    pub headers: Vec<String>,
    /// Wire selection: probe (auto) or pin a revision
    #[arg(long, value_enum, default_value_t = VersionPolicy::Auto)]
    pub protocol_version: VersionPolicy,
    /// Refuse targets that resolve to private/loopback addresses
    #[arg(long)]
    pub no_private: bool,
    /// Per-call timeout
    #[arg(long, default_value_t = 30_000)]
    pub timeout_ms: u64,
    /// Dump every raw wire frame to stderr as it happens
    #[arg(long)]
    pub wire: bool,
    /// Emit the result as JSON on stdout (and nothing else on stdout)
    #[arg(long)]
    pub json: bool,

    // ── AAuth ──────────────────────────────────────────────────────
    /// Sign requests with AAuth using this Ed25519 seed (unpadded
    /// base64url, 32 bytes). `mcpg inspector aauth-keygen` prints one.
    #[arg(
        long,
        env = "MCPG_INSPECTOR_AAUTH_KEY",
        hide_env_values = true,
        value_name = "SEED"
    )]
    pub aauth_key: Option<String>,
    /// Agent identifier to self-issue an agent token for,
    /// `aauth:local@domain`
    #[arg(long, value_name = "AGENT_ID", requires = "aauth_key")]
    pub aauth_agent: Option<String>,
    /// Agent provider URL claimed as `iss` when self-issuing
    #[arg(long, value_name = "URL", requires = "aauth_key")]
    pub aauth_issuer: Option<String>,
    /// Present this pre-minted `aa-agent+jwt` instead of self-issuing
    #[arg(
        long,
        env = "MCPG_INSPECTOR_AAUTH_TOKEN",
        hide_env_values = true,
        value_name = "JWT",
        requires = "aauth_key"
    )]
    pub aauth_token: Option<String>,
    /// Cover an extra component in the signature (repeatable), e.g.
    /// `@query` — whatever the resource lists in
    /// `additional_signature_components`
    #[arg(long = "aauth-cover", value_name = "COMPONENT")]
    pub aauth_cover: Vec<String>,
    /// The agent's person server (claimed as `ps`; dialled for person and
    /// auth tokens when --aauth-credential asks)
    #[arg(long, value_name = "URL", requires = "aauth_key")]
    pub aauth_person_server: Option<String>,
    /// Which AAuth credential to present: `agent` (default), `person` (a
    /// person token from the person server for the target), or `auth`
    /// (person token → resource token → auth token for --aauth-scopes).
    /// Consent-bearing modes print the interaction URL and code and wait.
    #[arg(long, value_name = "MODE", requires = "aauth_person_server")]
    pub aauth_credential: Option<crate::engine::aauth::AauthCredential>,
    /// Space-separated scope values to request with `--aauth-credential auth`
    #[arg(long, value_name = "SCOPES", requires = "aauth_credential")]
    pub aauth_scopes: Option<String>,
    /// How long to wait for the person's consent, seconds
    #[arg(long, value_name = "SECS", default_value_t = 180)]
    pub aauth_consent_timeout: u64,
    /// Present this pre-obtained `aa-person+jwt` / `aa-auth+jwt` as-is
    /// (bound to --aauth-key) instead of acquiring one
    #[arg(
        long,
        env = "MCPG_INSPECTOR_AAUTH_PRESENT",
        hide_env_values = true,
        value_name = "JWT",
        requires = "aauth_key"
    )]
    pub aauth_present: Option<String>,
    /// After acquiring a person / auth token, write it to this file (0600)
    #[arg(long, value_name = "PATH", requires = "aauth_credential")]
    pub aauth_save_credential: Option<std::path::PathBuf>,

    // ── responder stubs ────────────────────────────────────────────
    // A one-shot verb has nobody watching a queue, so it DECLINES
    // server→client requests by default rather than blocking forever.
    // Each flag below supplies a canned answer for one kind and, by
    // doing so, advertises the matching capability.
    /// Answer `sampling/createMessage` with this text
    #[arg(long, value_name = "TEXT")]
    pub sampling_stub: Option<String>,
    /// Answer `elicitation/create` with this JSON content (or @file)
    #[arg(long, value_name = "JSON|@FILE")]
    pub elicit_stub: Option<String>,
    /// Report this root for `roots/list`: NAME=URI (repeatable)
    #[arg(long = "root", value_name = "NAME=URI")]
    pub roots: Vec<String>,
}

#[derive(clap::Args, Debug)]
pub struct ListArgs {
    #[command(flatten)]
    pub target: TargetArgs,
    /// What to list
    #[arg(value_enum)]
    pub entity: Entity,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum Entity {
    Tools,
    Resources,
    Templates,
    Prompts,
}

#[derive(clap::Args, Debug)]
pub struct CallArgs {
    #[command(flatten)]
    pub target: TargetArgs,
    /// Tool name
    pub tool: String,
    /// Tool arguments: inline JSON, or @file
    #[arg(long = "args", value_name = "JSON|@FILE")]
    pub args: Option<String>,
}

#[derive(clap::Args, Debug)]
pub struct ReadArgs {
    #[command(flatten)]
    pub target: TargetArgs,
    /// Resource URI
    pub uri: String,
}

#[derive(clap::Args, Debug)]
pub struct PromptArgs {
    #[command(flatten)]
    pub target: TargetArgs,
    /// Prompt name
    pub prompt: String,
    /// Prompt arguments: inline JSON, or @file
    #[arg(long = "args", value_name = "JSON|@FILE")]
    pub args: Option<String>,
}

#[derive(clap::Args, Debug)]
pub struct ConfigArgs {
    #[command(flatten)]
    pub target: TargetArgs,
}

#[derive(clap::Args, Debug)]
pub struct CompleteArgs {
    #[command(flatten)]
    pub target: TargetArgs,
    /// What is being completed: `prompt:<name>` or `resource:<uriTemplate>`
    #[arg(value_name = "REF")]
    pub reference: String,
    /// Argument name, or URI-template variable name
    pub argument: String,
    /// The prefix typed so far
    #[arg(default_value = "")]
    pub value: String,
}

#[derive(clap::Args, Debug)]
pub struct AuthArgs {
    #[command(flatten)]
    pub target: TargetArgs,
}

#[derive(clap::Args, Debug)]
pub struct SnapshotArgs {
    #[command(flatten)]
    pub target: TargetArgs,
}

#[derive(clap::Args, Debug)]
pub struct DiffArgs {
    #[command(flatten)]
    pub target: TargetArgs,
    /// Compare against a second target instead of a file
    #[arg(long, value_name = "TARGET", conflicts_with = "against")]
    pub with: Option<String>,
    /// Compare against a snapshot file written by `snapshot`
    #[arg(long, value_name = "FILE")]
    pub against: Option<String>,
    /// `compatible` allows additions; `strict` allows nothing
    #[arg(long, value_enum, default_value_t = DiffMode::Compatible)]
    pub mode: DiffMode,
}

#[derive(clap::Args, Debug)]
pub struct CheckArgs {
    #[command(flatten)]
    pub target: TargetArgs,
}

#[derive(clap::Args, Debug)]
pub struct GatewayArgs {
    #[command(flatten)]
    pub target: TargetArgs,
}

#[derive(clap::Args, Debug)]
pub struct BenchArgs {
    #[command(flatten)]
    pub target: TargetArgs,

    /// Tool to call
    pub tool: String,

    /// Tool arguments: inline JSON, or @file
    #[arg(long = "args", value_name = "JSON")]
    pub args: Option<String>,

    /// How many times to call it
    #[arg(short = 'n', long, default_value_t = 20)]
    pub calls: usize,

    /// Calls to make before timing starts, so the first connection's cost
    /// is not reported as the server's latency
    #[arg(long, default_value_t = 2)]
    pub warmup: usize,
}

#[derive(clap::Args, Debug)]
pub struct FuzzArgs {
    #[command(flatten)]
    pub target: TargetArgs,

    /// Tool to fuzz. Omit to fuzz every tool that is safe to.
    pub tool: Option<String>,

    /// Also fuzz tools that are NOT declared read-only.
    ///
    /// Off by default, and deliberately awkward to turn on: these calls are
    /// real, and a tool that moves money is usually the one that forgot to
    /// annotate itself.
    #[arg(long)]
    pub include_writes: bool,
}

/// Exit-code classes (the crate-root contract).
const EXIT_USAGE: i32 = 1;
const EXIT_CONNECT: i32 = 2;
const EXIT_AUTH: i32 = 3;
const EXIT_UNREACHABLE: i32 = 4;
const EXIT_OP: i32 = 5;

pub fn run_list(args: ListArgs) -> ! {
    run(args.target, move |session| async move {
        let doc = match args.entity {
            Entity::Tools => json!({ "tools": session.list_tools().await? }),
            Entity::Resources => json!({ "resources": session.list_resources().await? }),
            Entity::Templates => {
                json!({ "resourceTemplates": session.list_resource_templates().await? })
            }
            Entity::Prompts => json!({ "prompts": session.list_prompts().await? }),
        };
        Ok((doc, 0))
    })
}

pub fn run_call(args: CallArgs) -> ! {
    let arguments = match args.args.as_deref().map(parse_args_input).transpose() {
        Ok(v) => v,
        Err(message) => fail(EXIT_USAGE, "usage", &message, args.target.json),
    };
    run(args.target, move |session| async move {
        let result = session.call_tool(&args.tool, arguments.as_ref()).await?;
        // A tool-level failure is a successful RPC with `isError: true`;
        // scripts branch on the op exit class.
        let code = if result.get("isError").and_then(Value::as_bool) == Some(true) {
            EXIT_OP
        } else {
            0
        };
        Ok((json!({ "result": result }), code))
    })
}

pub fn run_read(args: ReadArgs) -> ! {
    run(args.target, move |session| async move {
        let result = session.read_resource(&args.uri).await?;
        Ok((json!({ "result": result }), 0))
    })
}

/// Render a prompt. A prompt is a template; listing it shows only its
/// shape, so this is the only way to see what it expands to.
pub fn run_prompt(args: PromptArgs) -> ! {
    let arguments = match args.args.as_deref().map(parse_args_input).transpose() {
        Ok(v) => v,
        Err(message) => fail(EXIT_USAGE, "usage", &message, args.target.json),
    };
    run(args.target, move |session| async move {
        let result = session.get_prompt(&args.prompt, arguments.as_ref()).await?;
        Ok((json!({ "result": result }), 0))
    })
}

/// Emit the mcpg federation config for a target.
///
/// Connect once for the wire, probe once for the authorization posture, and
/// render the block. Everything it fills in is something an operator would
/// otherwise look up by hand, in exactly the places the inspector has just
/// checked.
pub fn run_config(args: ConfigArgs) -> ! {
    let json_out = args.target.json;
    let spec = match build_spec(&args.target) {
        Ok(s) => s,
        Err(message) => fail(EXIT_USAGE, "usage", &message, json_out),
    };
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => fail(EXIT_USAGE, "usage", &format!("runtime: {e}"), json_out),
    };
    let code = runtime.block_on(async move {
        let report = match crate::engine::authlab::inspect(&spec).await {
            Ok(r) => r,
            Err(message) => return fail_code(EXIT_CONNECT, "connect", &message, json_out),
        };
        // Connect for the probe's verdict, so the emitted wire is the one
        // this server actually speaks. A server that refuses an anonymous
        // connect still gets a config; it falls back to the sessionful wire,
        // which is what an unprobed gateway would assume anyway.
        let responder = Arc::new(crate::engine::responders::Responder::new(
            ResponderPolicy::AutoDecline,
        ));
        let negotiated = match Session::connect(&spec, None, responder, None).await {
            Ok(session) => {
                let v = session.negotiated_version();
                session.close().await;
                v
            }
            Err(_) => "2025-11-25",
        };
        match crate::engine::mcpgconfig::generate(&spec, &report, negotiated) {
            Ok(generated) => {
                if json_out {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&generated).unwrap_or_default()
                    );
                } else {
                    // Notes go to stderr so the YAML on stdout stays
                    // pasteable without editing.
                    for note in &generated.todo {
                        eprintln!("  note: {note}");
                    }
                    if !generated.todo.is_empty() {
                        eprintln!();
                    }
                    print!("{}", generated.yaml);
                }
                0
            }
            Err(message) => fail_code(EXIT_USAGE, "usage", &message, json_out),
        }
    });
    std::process::exit(code);
}

/// Ask what would complete an argument.
///
/// The reference is spelled `prompt:<name>` or `resource:<uriTemplate>`
/// rather than as JSON, because this is the one call whose whole purpose is
/// being cheap enough to run while typing.
pub fn run_complete(args: CompleteArgs) -> ! {
    let json_out = args.target.json;
    let reference = match args.reference.split_once(':') {
        Some(("prompt", name)) => json!({ "type": "ref/prompt", "name": name }),
        Some(("resource", uri)) => json!({ "type": "ref/resource", "uri": uri }),
        _ => fail(
            EXIT_USAGE,
            "usage",
            "reference must be `prompt:<name>` or `resource:<uriTemplate>`",
            json_out,
        ),
    };
    let argument = json!({ "name": args.argument, "value": args.value });
    run(args.target, move |session| async move {
        let result = session.complete(&reference, &argument, None).await?;
        Ok((json!({ "result": result }), 0))
    })
}

/// What does the gateway on the other end say about itself?
///
/// Exits 5 when it reports something worth acting on — a readiness check that
/// is not passing, or a plugin that loaded but is not active — so a smoke test
/// can gate on "the gateway is actually serving", not merely "it answered".
pub fn run_gateway(args: GatewayArgs) -> ! {
    let allow_private = !args.target.no_private;
    run(args.target, move |session| async move {
        let report = crate::engine::gateway::for_session(&session, allow_private)
            .await
            .map_err(UpstreamError::Protocol)?;
        let attention = report.needs_attention();
        let doc = serde_json::to_value(&report).unwrap_or_else(|_| json!({}));
        Ok((doc, if attention { EXIT_OP } else { 0 }))
    })
}

/// How fast is it? Sequentially, because concurrency measures a different
/// thing and an inspector pointed at someone else's server should not be the
/// one deciding to load-test it.
pub fn run_bench(args: BenchArgs) -> ! {
    let arguments = match args.args.as_deref().map(parse_args_input).transpose() {
        Ok(v) => v,
        Err(message) => fail(EXIT_USAGE, "usage", &message, args.target.json),
    };
    if args.calls == 0 {
        fail(
            EXIT_USAGE,
            "usage",
            "-n must be at least 1",
            args.target.json,
        );
    }
    run(args.target, move |session| async move {
        for _ in 0..args.warmup {
            let _ = session.call_tool(&args.tool, arguments.as_ref()).await;
        }
        let mut latencies = Vec::with_capacity(args.calls);
        let mut failed = 0usize;
        let started = std::time::Instant::now();
        for _ in 0..args.calls {
            let (took, _) = crate::engine::probe::timed(|| async {
                session
                    .call_tool(&args.tool, arguments.as_ref())
                    .await
                    .map_err(|e| e.to_string())
            })
            .await;
            match took {
                Some(ms) => latencies.push(ms),
                None => failed += 1,
            }
        }
        let report = crate::engine::probe::summarize(
            &args.tool,
            latencies,
            failed,
            started.elapsed().as_micros() as u64,
        );
        let any_failed = report.failed > 0;
        let doc = serde_json::to_value(&report).unwrap_or_else(|_| json!({}));
        Ok((doc, if any_failed { EXIT_OP } else { 0 }))
    })
}

/// What does it do with input its own schema forbids?
///
/// Only read-only tools, unless told otherwise. The cases come from the
/// schema, so a server is only ever measured against what it advertised.
pub fn run_fuzz(args: FuzzArgs) -> ! {
    run(args.target, move |session| async move {
        let tools = session.list_tools().await?;
        let chosen: Vec<_> = tools
            .into_iter()
            .filter(|tool| match &args.tool {
                Some(name) => &tool.name == name,
                None => true,
            })
            .collect();
        if chosen.is_empty() {
            return Err(UpstreamError::Protocol(match &args.tool {
                Some(name) => format!("no tool named '{name}' on this target"),
                None => "this target advertises no tools".to_owned(),
            }));
        }

        let mut reports = Vec::new();
        let mut skipped = Vec::new();
        let mut surprises = 0usize;
        for tool in chosen {
            let safe = crate::engine::probe::is_safe_to_fuzz(tool.annotations.as_ref());
            if !safe && !args.include_writes {
                skipped.push(json!({
                    "tool": tool.name,
                    "why": "not declared read-only; pass --include-writes to fuzz it anyway",
                }));
                continue;
            }
            let cases = crate::engine::probe::cases_for(tool.input_schema.as_ref());
            let mut outcomes = Vec::new();
            for case in &cases {
                let answered = session
                    .call_tool(&tool.name, Some(&case.arguments))
                    .await
                    .map_err(|e| e.to_string());
                let outcome =
                    crate::engine::probe::judge(case, answered.as_ref().map_err(String::as_str));
                if outcome.surprising {
                    surprises += 1;
                }
                outcomes.push(outcome);
            }
            reports.push(json!({
                "tool": tool.name,
                "readOnly": safe,
                "cases": outcomes,
            }));
        }

        let doc = json!({
            "fuzz": reports,
            "skipped": skipped,
            "surprising": surprises,
        });
        Ok((doc, if surprises == 0 { 0 } else { EXIT_OP }))
    })
}

/// Capture what the target advertises, normalized for comparison.
pub fn run_snapshot(args: SnapshotArgs) -> ! {
    run(args.target, move |session| async move {
        let snapshot = crate::engine::snapshot::capture(&session).await;
        let doc = serde_json::to_value(&snapshot).unwrap_or_else(|_| json!({}));
        Ok((doc, 0))
    })
}

/// Compare a target against a saved snapshot or against a second
/// target. Exit 5 when the diff fails its mode, so CI can gate on it.
pub fn run_diff(args: DiffArgs) -> ! {
    let json_out = args.target.json;
    let mode = args.mode;
    let with = args.with.clone();
    let against = args.against.clone();
    if with.is_none() && against.is_none() {
        fail(
            EXIT_USAGE,
            "usage",
            "diff needs --with <target> or --against <file>",
            json_out,
        );
    }
    run(args.target, move |session| async move {
        let current = crate::engine::snapshot::capture(&session).await;
        let baseline = match (&against, &with) {
            (Some(path), _) => {
                let text = std::fs::read_to_string(path)
                    .map_err(|e| UpstreamError::Protocol(format!("cannot read {path}: {e}")))?;
                serde_json::from_str(&text).map_err(|e| {
                    UpstreamError::Protocol(format!("{path} is not a snapshot: {e}"))
                })?
            }
            (None, Some(other)) => {
                let spec = crate::engine::target::TargetSpec::parse_cli(other)
                    .map_err(UpstreamError::Protocol)?;
                let responder = std::sync::Arc::new(crate::engine::responders::Responder::new(
                    spec.responder.clone(),
                ));
                let second = Session::connect(&spec, None, responder, None)
                    .await
                    .map_err(|e| UpstreamError::Protocol(e.to_string()))?;
                let snapshot = crate::engine::snapshot::capture(&second).await;
                second.close().await;
                snapshot
            }
            (None, None) => unreachable!("checked above"),
        };
        // Baseline first: the question is what changed relative to it.
        let diff = crate::engine::snapshot::diff(&baseline, &current, mode);
        let ok = diff.ok;
        let doc = serde_json::to_value(&diff).unwrap_or_else(|_| json!({}));
        Ok((doc, if ok { 0 } else { EXIT_OP }))
    })
}

/// Run the portable protocol checks against the target's endpoint.
pub fn run_check(args: CheckArgs) -> ! {
    let allow_private = !args.target.no_private;
    run(args.target, move |session| async move {
        let url = session
            .endpoint_url()
            .ok_or_else(|| {
                UpstreamError::Protocol(
                    "checks run over HTTP; a stdio target has no endpoint".to_owned(),
                )
            })?
            .to_owned();
        let report = crate::engine::checks::run(&url, session.negotiated_version(), allow_private)
            .await
            .map_err(UpstreamError::Protocol)?;
        let failed = report.failed;
        let doc = serde_json::to_value(&report).unwrap_or_else(|_| json!({}));
        Ok((doc, if failed == 0 { 0 } else { EXIT_OP }))
    })
}

/// `auth` deliberately does NOT connect: the whole question is what an
/// unauthenticated caller is told, so it runs its own credential-free
/// probe and reports the chain.
pub fn run_auth(args: AuthArgs) -> ! {
    let json_out = args.target.json;
    let spec = match build_spec(&args.target) {
        Ok(spec) => spec,
        Err(message) => fail(EXIT_USAGE, "usage", &message, json_out),
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let code = runtime.block_on(async move {
        match crate::engine::authlab::inspect(&spec).await {
            Ok(report) => {
                let doc = serde_json::to_value(&report).unwrap_or_else(|_| json!({}));
                if !json_out {
                    eprintln!("{}", report.verdict);
                }
                print_doc(&doc, json_out);
                // A 2xx probe is a clean run; a challenge — or any other
                // refusal — is the auth-required class, which is what a
                // script branches on.
                if report.answered_without_credential {
                    0
                } else {
                    EXIT_AUTH
                }
            }
            Err(message) => fail_code(EXIT_CONNECT, "auth_probe_failed", &message, json_out),
        }
    });
    std::process::exit(code);
}

/// Shared verb skeleton: parse target → connect (tap per `--wire`) →
/// run the op → print. The op returns `(document, exit_code)` where a
/// non-zero code marks an op-class failure with printable output.
fn run<F, Fut>(target_args: TargetArgs, op: F) -> !
where
    F: FnOnce(Arc<Session>) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<(Value, i32), UpstreamError>> + Send,
{
    let json_out = target_args.json;
    let spec = match build_spec(&target_args) {
        Ok(spec) => spec,
        Err(message) => fail(EXIT_USAGE, "usage", &message, json_out),
    };
    let tap: Option<SharedTap> = target_args.wire.then(|| {
        let printer: SharedTap = Arc::new(StderrWirePrinter);
        printer
    });
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let code = runtime.block_on(async move {
        let responder = std::sync::Arc::new(crate::engine::responders::Responder::new(
            spec.responder.clone(),
        ));
        let session = match Session::connect(&spec, tap, responder, None).await {
            Ok(session) => Arc::new(session),
            Err(SessionError::Spec(message)) => {
                return fail_code(EXIT_USAGE, "usage", &message, json_out);
            }
            Err(SessionError::Client(e)) => {
                return fail_code(
                    error_exit_class(&e),
                    error_class(&e),
                    &e.to_string(),
                    json_out,
                );
            }
        };
        eprintln!(
            "connected: negotiated protocol version {}",
            session.negotiated_version()
        );
        let outcome = op(Arc::clone(&session)).await;
        session.close().await;
        match outcome {
            Ok((doc, code)) => {
                print_doc(&doc, json_out);
                code
            }
            Err(e) => fail_code(
                error_exit_class(&e),
                error_class(&e),
                &e.to_string(),
                json_out,
            ),
        }
    });
    std::process::exit(code);
}

fn build_spec(args: &TargetArgs) -> Result<TargetSpec, String> {
    let mut spec = TargetSpec::parse_cli(&args.target)?;
    if args.bearer.is_some() {
        spec.bearer = args.bearer.clone();
    }
    for header in &args.headers {
        let (name, value) = header
            .split_once('=')
            .ok_or_else(|| format!("--header '{header}' is not NAME=VALUE"))?;
        spec.headers.insert(name.to_owned(), value.to_owned());
    }
    // A pin given on the command line beats the spec's own (JSON form).
    if args.protocol_version != VersionPolicy::Auto {
        spec.protocol_version = args.protocol_version;
    }
    if args.no_private {
        spec.allow_private = false;
    }
    spec.timeout_ms = args.timeout_ms;
    spec.responder = responder_policy(args)?;
    if let Some(path) = &args.dpop_key {
        if !path.exists() {
            return Err(format!(
                "no DPoP key at {}; `login --dpop-key {}` creates one",
                path.display(),
                path.display()
            ));
        }
        spec.dpop = Some(Arc::new(crate::engine::dpop::DpopKey::from_file(path)?));
    }
    if let Some(key) = &args.aauth_key {
        spec.aauth = Some(crate::engine::aauth::AauthSpec {
            key: key.clone(),
            token: args.aauth_token.clone(),
            issuer: args.aauth_issuer.clone(),
            agent: args.aauth_agent.clone(),
            person_server: args.aauth_person_server.clone(),
            credential: args.aauth_credential,
            scopes: args.aauth_scopes.clone(),
            present: args.aauth_present.clone(),
            save_credential: args.aauth_save_credential.clone(),
            consent_timeout_secs: args.aauth_consent_timeout,
            cover: args.aauth_cover.clone(),
            content_digest: true,
        });
    }
    Ok(spec)
}

/// The responder a one-shot run should use.
///
/// Interactive is wrong here: nothing is watching the queue, so a
/// server that elicits would hang the command forever — the silent
/// stall that makes a debugging tool useless. Absent stubs it declines
/// (advertising nothing, so a well-behaved server never asks); with
/// stubs it answers exactly what was supplied.
fn responder_policy(args: &TargetArgs) -> Result<ResponderPolicy, String> {
    let mut roots = Vec::new();
    for entry in &args.roots {
        let (name, uri) = entry
            .split_once('=')
            .ok_or_else(|| format!("--root '{entry}' is not NAME=URI"))?;
        roots.push(Root {
            name: name.to_owned(),
            uri: uri.to_owned(),
        });
    }
    let elicitation_content = args
        .elicit_stub
        .as_deref()
        .map(parse_args_input)
        .transpose()?;
    if args.sampling_stub.is_none() && elicitation_content.is_none() && roots.is_empty() {
        return Ok(ResponderPolicy::AutoDecline);
    }
    Ok(ResponderPolicy::Mock(MockAnswers {
        sampling_text: args.sampling_stub.clone(),
        elicitation_content,
        roots,
    }))
}

fn print_doc(doc: &Value, json_out: bool) {
    if json_out {
        println!("{doc}");
        return;
    }
    println!("{}", serde_json::to_string_pretty(doc).expect("serialize"));
}

/// Map a client error to its exit-code class.
fn error_exit_class(e: &UpstreamError) -> i32 {
    match e {
        UpstreamError::Http {
            status: 401 | 403, ..
        } => EXIT_AUTH,
        UpstreamError::Connect(_) | UpstreamError::Transport(_) => EXIT_UNREACHABLE,
        UpstreamError::JsonRpc { .. } => EXIT_OP,
        _ => EXIT_CONNECT,
    }
}

fn error_class(e: &UpstreamError) -> &'static str {
    match e {
        UpstreamError::Http {
            status: 401 | 403, ..
        } => "auth_required",
        UpstreamError::Connect(_) => "connect",
        UpstreamError::Transport(_) => "unreachable",
        UpstreamError::Http { .. } => "http",
        UpstreamError::Protocol(_) => "protocol",
        UpstreamError::Rebinding(_) => "rebinding",
        UpstreamError::ResponseTooLarge { .. } => "response_too_large",
        UpstreamError::JsonRpc { .. } => "jsonrpc",
        UpstreamError::NotLinked { .. } => "not_linked",
    }
}

/// Print the single-line JSON error envelope on stderr and return the
/// exit code (async-path variant).
fn fail_code(code: i32, class: &str, message: &str, _json_out: bool) -> i32 {
    eprintln!(
        "{}",
        json!({ "error": { "code": class, "message": message } })
    );
    code
}

fn fail(code: i32, class: &str, message: &str, json_out: bool) -> ! {
    std::process::exit(fail_code(code, class, message, json_out));
}

fn parse_args_input(input: &str) -> Result<Value, String> {
    let text = if let Some(path) = input.strip_prefix('@') {
        std::fs::read_to_string(path).map_err(|e| format!("cannot read args file '{path}': {e}"))?
    } else {
        input.to_owned()
    };
    serde_json::from_str(&text).map_err(|e| format!("tool arguments are not valid JSON: {e}"))
}

#[derive(clap::Args, Debug)]
pub struct AauthKeygenArgs {
    /// Agent identifier, `aauth:local@domain`. The domain should be one
    /// you control — that is where a verifier looks for the key.
    #[arg(long, value_name = "AGENT_ID")]
    pub agent: String,
    /// Agent provider URL claimed as `iss`. Defaults to `https://` plus
    /// the domain of `--agent`.
    #[arg(long, value_name = "URL")]
    pub issuer: Option<String>,
    /// Write the two well-known documents under this directory, laid out
    /// as they must be served (`.well-known/aauth-agent.json`,
    /// `.well-known/jwks.json`)
    #[arg(long, value_name = "DIR")]
    pub publish: Option<std::path::PathBuf>,
    /// Permit an `http://` issuer with an explicit port, so the identity can
    /// be served from loopback. Matches the gateway plugin's
    /// `insecure_dev_mode`; never use it for a real identity.
    #[arg(long)]
    pub insecure_dev: bool,
    #[arg(long)]
    pub json: bool,
}

/// Mint an AAuth agent identity.
///
/// AAuth has no registration step: trust is rooted in domain control plus a
/// published JWKS, so enrolling is generating a key and serving two static
/// documents. This prints both, and the seed to pass as `--aauth-key`.
pub fn run_aauth_keygen(args: AauthKeygenArgs) -> ! {
    use mcpg_aauth_core as aauth;

    let outcome = (|| -> Result<(), String> {
        let agent =
            aauth::ident::AgentId::parse(&args.agent).map_err(|e| format!("--agent: {e}"))?;
        let issuer = args
            .issuer
            .clone()
            .unwrap_or_else(|| format!("https://{}", agent.domain));
        aauth::ident::validate_server_identifier(&issuer, args.insecure_dev).map_err(|e| {
            let hint = if args.insecure_dev {
                ""
            } else {
                " (an http:// loopback issuer needs --insecure-dev)"
            };
            format!("--issuer: {e}{hint}")
        })?;

        let key = aauth::jwk::generate_signing_key();
        let jwk = aauth::jwk::Jwk::from_verifying_key(&key.verifying_key());
        let thumbprint = jwk.thumbprint().map_err(|e| e.to_string())?;
        let seed = aauth::b64::encode(key.as_bytes());

        let agent_doc = serde_json::json!({
            "issuer": issuer,
            "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
        });
        let mut published = jwk.clone();
        published.kid = Some(thumbprint.clone());
        // draft-hardt-httpbis-signature-key tightens RFC 7517: a published JWK
        // MUST name its algorithm, and §3.3 requires the fully-specified form.
        // `Jwk::from_verifying_key` already sets it; assert rather than assume.
        debug_assert_eq!(published.alg.as_deref(), Some(aauth::jwt::ALG_ED25519));
        let jwks_doc = serde_json::json!({ "keys": [published] });

        if let Some(dir) = &args.publish {
            let well_known = dir.join(".well-known");
            std::fs::create_dir_all(&well_known)
                .map_err(|e| format!("cannot create {}: {e}", well_known.display()))?;
            for (name, doc) in [("aauth-agent.json", &agent_doc), ("jwks.json", &jwks_doc)] {
                let path = well_known.join(name);
                std::fs::write(&path, serde_json::to_string_pretty(doc).unwrap())
                    .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
            }
        }

        if args.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "agent": args.agent,
                    "issuer": issuer,
                    "key": seed,
                    "thumbprint": thumbprint,
                    "wellKnown": {
                        ".well-known/aauth-agent.json": agent_doc,
                        ".well-known/jwks.json": jwks_doc,
                    },
                }))
                .unwrap()
            );
            return Ok(());
        }

        println!("agent      {}", args.agent);
        println!("issuer     {issuer}");
        println!("thumbprint {thumbprint}");
        println!();
        println!("key (keep secret — pass as --aauth-key or MCPG_INSPECTOR_AAUTH_KEY):");
        println!("  {seed}");
        println!();
        match &args.publish {
            Some(dir) => println!(
                "wrote {}/.well-known/aauth-agent.json and jwks.json",
                dir.display()
            ),
            None => {
                println!("serve these two documents under {issuer} for the identity to verify:");
                println!();
                println!("/.well-known/aauth-agent.json");
                println!("{}", serde_json::to_string_pretty(&agent_doc).unwrap());
                println!();
                println!("/.well-known/jwks.json");
                println!("{}", serde_json::to_string_pretty(&jwks_doc).unwrap());
            }
        }
        Ok(())
    })();

    match outcome {
        Ok(()) => std::process::exit(0),
        Err(e) => fail(1, "usage", &e, args.json),
    }
}

#[derive(clap::Args, Debug)]
pub struct LoginArgs {
    #[command(flatten)]
    pub target: TargetArgs,
    /// Pre-registered OAuth client, or the https URL of the client's
    /// metadata document. Omit to register dynamically (RFC 7591) for a
    /// browser sign-in; an ID-JAG login needs it, because the ID-JAG names
    /// the client.
    #[arg(long, value_name = "ID")]
    pub client_id: Option<String>,
    /// Secret of --client-id at the authorization server
    #[arg(
        long,
        env = "MCPG_INSPECTOR_CLIENT_SECRET",
        hide_env_values = true,
        value_name = "SECRET"
    )]
    pub client_secret: Option<String>,
    /// How --client-id authenticates at the token endpoint. Defaults to
    /// private_key_jwt with --client-key, a secret method with
    /// --client-secret, else none (a public client).
    #[arg(long, value_enum, value_name = "METHOD")]
    pub client_auth: Option<ClientAuthMethod>,
    /// Private key (PEM, or a P-256 / Ed25519 private JWK) that signs
    /// --client-id's private_key_jwt assertions
    #[arg(long, value_name = "PATH")]
    pub client_key: Option<std::path::PathBuf>,
    /// `kid` of --client-key, as the authorization server knows it
    #[arg(long, value_name = "KID", requires = "client_key")]
    pub client_key_id: Option<String>,
    /// Algorithm of --client-key; defaults to what the key is
    #[arg(long, value_enum, value_name = "ALG", requires = "client_key")]
    pub client_signing_alg: Option<SigningAlg>,
    /// `aud` of --client-id's assertions
    #[arg(long, value_enum, value_name = "AUD", default_value_t = AssertionAudience::Issuer)]
    pub client_assertion_audience: AssertionAudience,
    /// Initial access token for dynamic registration (RFC 7591 §3), for a
    /// server that does not take anonymous registrations
    #[arg(
        long,
        env = "MCPG_INSPECTOR_REGISTRATION_TOKEN",
        hide_env_values = true,
        value_name = "TOKEN"
    )]
    pub registration_token: Option<String>,
    /// Scope to request (repeatable). Defaults to what the challenge asked
    /// for, else (browser sign-in only) what the authorization server
    /// advertises.
    #[arg(long = "scope", value_name = "SCOPE")]
    pub scopes: Vec<String>,
    /// RFC 9396 authorization details to ask for: a JSON array, or @file
    #[arg(long, value_name = "JSON|@FILE")]
    pub authorization_details: Option<String>,
    /// Print the authorization URL instead of opening a browser
    #[arg(long)]
    pub no_browser: bool,
    /// Write the access token to this file (owner-only) instead of stdout
    #[arg(long, value_name = "PATH")]
    pub token_file: Option<std::path::PathBuf>,

    // ── enterprise-managed authorization (ID-JAG) ──────────────────
    // Any of these selects the ID-JAG login in place of the browser.
    /// The IdP's token endpoint, where the subject token is exchanged for
    /// an ID-JAG (RFC 8693)
    #[arg(long, value_name = "URL")]
    pub idp_token_url: Option<String>,
    /// The subject token: the user's ID token (or SAML assertion, or IdP
    /// refresh token)
    #[arg(
        long,
        env = "MCPG_INSPECTOR_SUBJECT_TOKEN",
        hide_env_values = true,
        value_name = "TOKEN",
        conflicts_with = "subject_token_file"
    )]
    pub subject_token: Option<String>,
    /// Read the subject token from this file, or `-` for stdin
    #[arg(long, value_name = "PATH")]
    pub subject_token_file: Option<String>,
    /// What the subject token is
    #[arg(long, value_enum, value_name = "TYPE", default_value_t = SubjectTokenType::IdToken)]
    pub subject_token_type: SubjectTokenType,
    /// The inspector's client id at the IdP
    #[arg(long, value_name = "ID")]
    pub idp_client_id: Option<String>,
    /// Secret of --idp-client-id
    #[arg(
        long,
        env = "MCPG_INSPECTOR_IDP_CLIENT_SECRET",
        hide_env_values = true,
        value_name = "SECRET"
    )]
    pub idp_client_secret: Option<String>,
    /// How --idp-client-id authenticates at the IdP (default as for
    /// --client-auth)
    #[arg(long, value_enum, value_name = "METHOD")]
    pub idp_client_auth: Option<ClientAuthMethod>,
    /// Private key that signs --idp-client-id's private_key_jwt assertions
    #[arg(long, value_name = "PATH")]
    pub idp_client_key: Option<std::path::PathBuf>,
    /// `kid` of --idp-client-key, as the IdP knows it
    #[arg(long, value_name = "KID", requires = "idp_client_key")]
    pub idp_client_key_id: Option<String>,
    /// Algorithm of --idp-client-key; defaults to what the key is
    #[arg(long, value_enum, value_name = "ALG", requires = "idp_client_key")]
    pub idp_client_signing_alg: Option<SigningAlg>,
    /// `aud` of --idp-client-id's assertions: the token endpoint URL, which
    /// Okta expects, or the IdP issuer (--idp-issuer)
    #[arg(
        long,
        value_enum,
        value_name = "AUD",
        default_value_t = AssertionAudience::TokenEndpoint
    )]
    pub idp_assertion_audience: AssertionAudience,
    /// The IdP's issuer identifier, for --idp-assertion-audience issuer
    #[arg(long, value_name = "URL")]
    pub idp_issuer: Option<String>,
    /// An ID-JAG obtained elsewhere, redeemed as it is (skips the IdP)
    #[arg(
        long,
        env = "MCPG_INSPECTOR_ID_JAG",
        hide_env_values = true,
        value_name = "JWT",
        conflicts_with_all = ["id_jag_file", "idp_token_url"]
    )]
    pub id_jag: Option<String>,
    /// Read a ready ID-JAG from this file, or `-` for stdin
    #[arg(long, value_name = "PATH", conflicts_with = "idp_token_url")]
    pub id_jag_file: Option<String>,
}

impl LoginArgs {
    /// Whether this is an ID-JAG login rather than a browser sign-in.
    fn id_jag_mode(&self) -> bool {
        self.idp_token_url.is_some()
            || self.subject_token.is_some()
            || self.subject_token_file.is_some()
            || self.id_jag.is_some()
            || self.id_jag_file.is_some()
    }
}

/// Walk the discovery chain, then actually sign in.
///
/// `auth` tells an operator what a server wants; this gets it, with a
/// browser (authorization code + PKCE) or, given an IdP token endpoint and
/// a subject token or a ready ID-JAG, without one (enterprise-managed
/// authorization). The token goes to stdout, or to `--token-file`, and is
/// the one to pass back as `--bearer`. Nothing else it handles — a subject
/// token, an ID-JAG, a secret, a key — is printed.
pub fn run_login(mut args: LoginArgs) -> ! {
    let json_out = args.target.json;
    // The login creates this key; `build_spec` only reads an existing one.
    let dpop_path = args.target.dpop_key.take();
    let spec = match build_spec(&args.target) {
        Ok(s) => s,
        Err(message) => fail(EXIT_USAGE, "usage", &message, json_out),
    };
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => fail(EXIT_USAGE, "usage", &format!("runtime: {e}"), json_out),
    };

    let code = runtime.block_on(async move {
        let report = match crate::engine::authlab::inspect(&spec).await {
            Ok(r) => r,
            Err(message) => return fail_code(EXIT_CONNECT, "connect", &message, json_out),
        };
        // Without a token endpoint there is no grant to run, and the report
        // already says why the chain stopped — hand that back rather than a
        // second, vaguer message.
        if report.token_endpoint.is_none() {
            return fail_code(EXIT_AUTH, "auth_required", &report.verdict, json_out);
        }
        let discovered = match rediscover(&spec).await {
            Ok(d) => d,
            Err(message) => return fail_code(EXIT_AUTH, "auth_required", &message, json_out),
        };
        let dpop = match &dpop_path {
            Some(path) => match open_dpop_key(path, &discovered) {
                Ok(key) => Some(key),
                Err(message) => return fail_code(EXIT_USAGE, "usage", &message, json_out),
            },
            None => None,
        };
        let challenge_scope = report.challenge.as_ref().and_then(|c| c.scope.clone());
        let outcome = if args.id_jag_mode() {
            let opts = match id_jag_options(&args, &discovered, dpop) {
                Ok(opts) => opts,
                Err(message) => return fail_code(EXIT_USAGE, "usage", &message, json_out),
            };
            crate::engine::idjag::login(&discovered, challenge_scope.as_deref(), &opts).await
        } else {
            let opts = match browser_options(&args, dpop) {
                Ok(opts) => opts,
                Err(message) => return fail_code(EXIT_USAGE, "usage", &message, json_out),
            };
            crate::engine::oauth::login(&discovered, challenge_scope.as_deref(), &opts).await
        };
        match outcome {
            Ok(outcome) => report_login(&outcome, &args, dpop_path.as_deref(), json_out),
            Err(message) => fail_code(EXIT_AUTH, "auth_required", &message, json_out),
        }
    });
    std::process::exit(code);
}

/// The DPoP key at `path`, created for an algorithm the authorization
/// server accepts when there is no file yet.
fn open_dpop_key(
    path: &std::path::Path,
    discovered: &mcpg_mcp_client::auth::DiscoveredOauth,
) -> Result<Arc<crate::engine::dpop::DpopKey>, String> {
    let (key, created) = crate::engine::dpop::DpopKey::load_or_create(
        path,
        &discovered.dpop_signing_alg_values_supported,
    )?;
    if created {
        eprintln!(
            "created a DPoP key ({}) in {} (owner-only; keep it with the token)",
            key.alg_name(),
            path.display()
        );
    }
    Ok(Arc::new(key))
}

/// A private key for `private_key_jwt`, read from `path`.
fn assertion_key(
    path: &std::path::Path,
    alg: Option<SigningAlg>,
    key_id: Option<&String>,
    audience: AssertionAudience,
) -> Result<AssertionKey, String> {
    Ok(AssertionKey {
        key: Arc::new(crate::engine::keys::SigningKey::from_file(path, alg)?),
        key_id: key_id.cloned(),
        audience,
    })
}

/// How the client named by `--client-id` authenticates.
fn client_auth_options(args: &LoginArgs) -> Result<ClientAuthOptions, String> {
    let key = args
        .client_key
        .as_deref()
        .map(|path| {
            assertion_key(
                path,
                args.client_signing_alg,
                args.client_key_id.as_ref(),
                args.client_assertion_audience,
            )
        })
        .transpose()?;
    Ok(ClientAuthOptions {
        method: args.client_auth,
        secret: args.client_secret.clone(),
        key,
    })
}

fn authorization_details(args: &LoginArgs) -> Result<Option<String>, String> {
    let Some(input) = args.authorization_details.as_deref() else {
        return Ok(None);
    };
    let value = parse_args_input(input).map_err(|e| format!("--authorization-details: {e}"))?;
    if !value.is_array() {
        return Err("--authorization-details must be a JSON array (RFC 9396 §2)".to_owned());
    }
    Ok(Some(value.to_string()))
}

fn browser_options(
    args: &LoginArgs,
    dpop: Option<Arc<crate::engine::dpop::DpopKey>>,
) -> Result<crate::engine::oauth::LoginOptions, String> {
    Ok(crate::engine::oauth::LoginOptions {
        client_id: args.client_id.clone(),
        client_auth: client_auth_options(args)?,
        registration_token: args.registration_token.clone(),
        public_url: None,
        scopes: args.scopes.clone(),
        no_browser: args.no_browser,
        visit: None,
        dpop,
        authorization_details: authorization_details(args)?,
    })
}

fn id_jag_options(
    args: &LoginArgs,
    discovered: &mcpg_mcp_client::auth::DiscoveredOauth,
    dpop: Option<Arc<crate::engine::dpop::DpopKey>>,
) -> Result<crate::engine::idjag::IdJagOptions, String> {
    use crate::engine::idjag::{IdJagOptions, IdJagSource, IdpExchange};

    if args.registration_token.is_some() || args.no_browser {
        return Err(
            "--registration-token and --no-browser belong to the browser sign-in; an ID-JAG \
             login registers nothing and opens no browser"
                .to_owned(),
        );
    }
    let client_id = args.client_id.clone().ok_or(
        "an ID-JAG login needs --client-id: the client as registered at the MCP server's \
         authorization server, which the ID-JAG names",
    )?;
    let client = client_auth_options(args)?.credentials("--client", client_id, discovered)?;
    if args.subject_token_file.as_deref() == Some("-") && args.id_jag_file.as_deref() == Some("-") {
        return Err("only one of --subject-token-file and --id-jag-file can read stdin".to_owned());
    }
    let supplied = match (&args.id_jag, &args.id_jag_file) {
        (Some(id_jag), _) => Some(id_jag.clone()),
        (None, Some(path)) => Some(read_secret_input(path, "--id-jag-file")?),
        (None, None) => None,
    };
    let source = match supplied {
        Some(id_jag) => {
            if args.subject_token.is_some() || args.subject_token_file.is_some() {
                return Err(
                    "a ready ID-JAG needs no subject token; pass one or the other".to_owned(),
                );
            }
            IdJagSource::Supplied(id_jag)
        }
        None => {
            let token_endpoint = args.idp_token_url.clone().ok_or(
                "a subject token is exchanged at the IdP: pass --idp-token-url, or pass a ready \
                 ID-JAG with --id-jag-file",
            )?;
            let subject_token = match (&args.subject_token, &args.subject_token_file) {
                (Some(token), _) => token.clone(),
                (None, Some(path)) => read_secret_input(path, "--subject-token-file")?,
                (None, None) => {
                    return Err("--idp-token-url needs the user's subject token: \
                         --subject-token-file PATH (or - for stdin)"
                        .to_owned());
                }
            };
            let idp_client_id = args.idp_client_id.clone().ok_or(
                "--idp-token-url needs --idp-client-id: the inspector's client at the IdP",
            )?;
            let key = args
                .idp_client_key
                .as_deref()
                .map(|path| {
                    assertion_key(
                        path,
                        args.idp_client_signing_alg,
                        args.idp_client_key_id.as_ref(),
                        args.idp_assertion_audience,
                    )
                })
                .transpose()?;
            if key
                .as_ref()
                .is_some_and(|k| k.audience == AssertionAudience::Issuer)
                && args.idp_issuer.is_none()
            {
                return Err("--idp-assertion-audience issuer needs --idp-issuer".to_owned());
            }
            let idp_client = crate::engine::client_auth::ClientCredentials::build(
                "--idp-client",
                idp_client_id,
                args.idp_client_auth,
                args.idp_client_secret.clone(),
                key,
                &[],
            )?;
            IdJagSource::Exchange(Box::new(IdpExchange {
                token_endpoint,
                issuer: args.idp_issuer.clone(),
                client: idp_client,
                subject_token,
                subject_token_type: args.subject_token_type,
            }))
        }
    };
    Ok(IdJagOptions {
        source,
        client,
        scopes: args.scopes.clone(),
        dpop,
        authorization_details: authorization_details(args)?,
    })
}

/// A token or grant from a file, or from stdin for `-`.
fn read_secret_input(path: &str, flag: &str) -> Result<String, String> {
    let text = if path == "-" {
        use std::io::Read as _;
        let mut text = String::new();
        std::io::stdin()
            .read_to_string(&mut text)
            .map_err(|e| format!("{flag}: cannot read stdin: {e}"))?;
        text
    } else {
        std::fs::read_to_string(path).map_err(|e| format!("{flag}: cannot read {path}: {e}"))?
    };
    let text = text.trim().to_owned();
    if text.is_empty() {
        return Err(format!("{flag}: {path} is empty"));
    }
    Ok(text)
}

/// Print what the login produced: the token on stdout (or into
/// `--token-file`), and everything else about it on stderr.
fn report_login(
    outcome: &crate::engine::oauth::LoginOutcome,
    args: &LoginArgs,
    dpop_path: Option<&std::path::Path>,
    json_out: bool,
) -> i32 {
    use crate::engine::oauth::{Grant, Registration};

    if let Some(path) = &args.token_file
        && let Err(message) = crate::engine::keys::write_private_file(
            path,
            format!("{}\n", outcome.access_token).as_bytes(),
            true,
        )
    {
        return fail_code(EXIT_USAGE, "usage", &message, json_out);
    }
    if json_out {
        let mut doc = serde_json::to_value(outcome).unwrap_or_else(|_| json!({}));
        if let (Some(path), Some(object)) = (&args.token_file, doc.as_object_mut()) {
            object.remove("access_token");
            object.remove("refresh_token");
            object.insert("token_file".to_owned(), json!(path.display().to_string()));
        }
        println!("{}", serde_json::to_string_pretty(&doc).unwrap_or_default());
        return 0;
    }
    eprintln!("signed in as client {}", outcome.client_id);
    eprintln!(
        "  grant:    {}",
        match outcome.grant {
            Grant::AuthorizationCode => "authorization code with PKCE (browser sign-in)",
            Grant::IdJag => "ID-JAG redeemed with the JWT bearer grant (enterprise-managed)",
        }
    );
    eprintln!(
        "  client:   {} ({})",
        match outcome.registration {
            Registration::PreRegistered => "pre-registered",
            Registration::ClientIdMetadata => "client-ID metadata document",
            Registration::Dynamic => "registered dynamically for this login",
        },
        outcome.client_auth.as_str()
    );
    if let Some(id_jag) = &outcome.id_jag {
        eprintln!(
            "  id-jag:   {} by {}",
            if id_jag.source == "exchange" {
                "exchanged at the IdP"
            } else {
                "supplied"
            },
            id_jag.iss.as_deref().unwrap_or("an unnamed issuer")
        );
    }
    if let Some(scope) = &outcome.scope {
        eprintln!("  scope:    {scope}");
    }
    if let Some(details) = &outcome.authorization_details {
        eprintln!("  details:  {details}");
    }
    if let Some(expires) = outcome.expires_in {
        eprintln!("  expires:  {expires}s");
    }
    eprintln!("  audience: {}", outcome.resource);
    let dpop_flag = match (&outcome.dpop_jkt, dpop_path) {
        (Some(jkt), Some(path)) => {
            eprintln!("  bound:    DPoP key {jkt} in {}", path.display());
            format!(" --dpop-key {}", path.display())
        }
        _ => String::new(),
    };
    for warning in &outcome.warnings {
        eprintln!("  warning:  {warning}");
    }
    match &args.token_file {
        Some(path) => eprintln!(
            "\nthe token is in {}; pass it back with --bearer \"$(cat {})\"{dpop_flag}",
            path.display(),
            path.display()
        ),
        None => {
            eprintln!("\npass this back with --bearer{dpop_flag}:\n");
            println!("{}", outcome.access_token);
        }
    }
    0
}

/// Re-run discovery for its full result.
///
/// The lab reports the chain as steps; the grant needs the endpoints. Both
/// call the same walk, so they cannot describe different servers.
async fn rediscover(spec: &TargetSpec) -> Result<mcpg_mcp_client::auth::DiscoveredOauth, String> {
    use crate::engine::target::TargetKind;
    let TargetKind::Http { url } = &spec.kind else {
        return Err("login applies to http targets".to_owned());
    };
    mcpg_mcp_client::auth::discover_oauth(
        url,
        mcpg_mcp_client::auth::DiscoveryPolicy {
            allow_private: spec.allow_private,
            allow_insecure_http: url.starts_with("http://"),
        },
    )
    .await
}
