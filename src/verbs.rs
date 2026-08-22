//! One-shot CLI verbs: `list`, `call`, `read`. Human chatter goes to
//! stderr; with `--json`, the result document is the only thing on
//! stdout. Exit codes are the stable contract from the crate root.

use std::sync::Arc;

use mcpg_mcp_client::tap::SharedTap;
use mcpg_mcp_client::upstream::UpstreamError;
use serde_json::{Value, json};

use crate::engine::eventlog::StderrWirePrinter;
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
    #[arg(long, env = "MCPG_INSPECTOR_BEARER")]
    pub bearer: Option<String>,
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
    #[arg(long, env = "MCPG_INSPECTOR_AAUTH_KEY", value_name = "SEED")]
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
    /// Pre-registered OAuth client. Omit to register dynamically
    /// (RFC 7591), which most MCP authorization servers support because
    /// clients cannot pre-register everywhere.
    #[arg(long, value_name = "ID")]
    pub client_id: Option<String>,
    /// Scope to request (repeatable). Defaults to what the challenge asked
    /// for, else what the authorization server advertises.
    #[arg(long = "scope", value_name = "SCOPE")]
    pub scopes: Vec<String>,
    /// Print the authorization URL instead of opening a browser
    #[arg(long)]
    pub no_browser: bool,
}

/// Walk the discovery chain, then actually sign in.
///
/// `auth` tells an operator what a server wants; this gets it. The token it
/// prints is the one to pass back as `--bearer`.
pub fn run_login(args: LoginArgs) -> ! {
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

        let opts = crate::engine::oauth::LoginOptions {
            client_id: args.client_id.clone(),
            public_url: None,
            scopes: args.scopes.clone(),
            no_browser: args.no_browser,
            visit: None,
        };
        let challenge_scope = report.challenge.as_ref().and_then(|c| c.scope.clone());
        match crate::engine::oauth::login(&discovered, challenge_scope.as_deref(), &opts).await {
            Ok(outcome) => {
                if json_out {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&outcome).unwrap_or_default()
                    );
                } else {
                    eprintln!("signed in as client {}", outcome.client_id);
                    eprintln!(
                        "  client:   {}",
                        match outcome.registration {
                            crate::engine::oauth::Registration::PreRegistered => "pre-registered",
                            crate::engine::oauth::Registration::ClientIdMetadata =>
                                "client-ID metadata document",
                            crate::engine::oauth::Registration::Dynamic =>
                                "registered dynamically for this login",
                        }
                    );
                    if let Some(scope) = &outcome.scope {
                        eprintln!("  scope:    {scope}");
                    }
                    if let Some(expires) = outcome.expires_in {
                        eprintln!("  expires:  {expires}s");
                    }
                    eprintln!("  audience: {}", outcome.resource);
                    eprintln!("\npass this back with --bearer:\n");
                    println!("{}", outcome.access_token);
                }
                0
            }
            Err(message) => fail_code(EXIT_AUTH, "auth_required", &message, json_out),
        }
    });
    std::process::exit(code);
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
