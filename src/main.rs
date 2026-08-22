use clap::{Parser, Subcommand};
use mcpg_inspector::{config, http, verbs};

#[derive(Parser)]
#[command(name = "mcpg-inspector", version, about = "MCP inspector for mcpg")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the web UI and HTTP API
    Serve(config::ServeArgs),
    /// Interactive terminal UI
    #[cfg(feature = "tui")]
    Tui(mcpg_inspector_tui::TuiArgs),
    /// List tools, resources, templates or prompts of a target
    List(verbs::ListArgs),
    /// Call a tool on a target
    Call(verbs::CallArgs),
    /// Read a resource from a target
    Read(verbs::ReadArgs),
    /// Render a prompt from a target
    Prompt(verbs::PromptArgs),
    /// Ask what would complete a prompt argument or template variable
    Complete(verbs::CompleteArgs),
    /// Report what a target requires for authorization
    Auth(verbs::AuthArgs),
    /// Emit the mcpg federation config for a target
    Config(verbs::ConfigArgs),
    /// Sign in to a target and print the token (OAuth + PKCE)
    Login(verbs::LoginArgs),
    /// Run the portable protocol checks against a target
    Check(verbs::CheckArgs),
    /// What the mcpg gateway behind this endpoint says about itself
    Gateway(verbs::GatewayArgs),
    /// Time a tool: how long does this server take to answer
    Bench(verbs::BenchArgs),
    /// Send a tool what its own schema forbids, and report what happened
    Fuzz(verbs::FuzzArgs),
    /// Export a capability snapshot of a target
    Snapshot(verbs::SnapshotArgs),
    /// Diff a target against a snapshot file or a second target
    Diff(verbs::DiffArgs),
    /// Generate an AAuth agent identity: an Ed25519 key plus the
    /// well-known documents that make it verifiable
    AauthKeygen(verbs::AauthKeygenArgs),
}

/// Exit codes are a stable contract, defined in `verbs`: 0 ok, 1
/// usage, 2 connect/probe, 3 auth required, 4 unreachable, 5 op/tool
/// error.
fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve(args) => http::run_serve(args),
        #[cfg(feature = "tui")]
        // The terminal crate knows nothing about the engine; this is where
        // one gets built for it when the run is not `--attach`ed elsewhere.
        Command::Tui(args) => mcpg_inspector_tui::run(args, |args| {
            let engine = std::sync::Arc::new(mcpg_inspector::engine::registry::Engine::new(
                mcpg_inspector::engine::registry::Mode::Local,
                args.frame_buffer,
            ));
            for spec in &args.targets {
                engine.add_target(mcpg_inspector::engine::target::TargetSpec::parse_cli(spec)?)?;
            }
            Ok(std::sync::Arc::new(
                mcpg_inspector::local_api::LocalApi::new(engine),
            ))
        }),
        Command::List(args) => verbs::run_list(args),
        Command::Call(args) => verbs::run_call(args),
        Command::Read(args) => verbs::run_read(args),
        Command::Prompt(args) => verbs::run_prompt(args),
        Command::Complete(args) => verbs::run_complete(args),
        Command::Auth(args) => verbs::run_auth(args),
        Command::Config(args) => verbs::run_config(args),
        Command::Login(args) => verbs::run_login(args),
        Command::Check(args) => verbs::run_check(args),
        Command::Gateway(args) => verbs::run_gateway(args),
        Command::Bench(args) => verbs::run_bench(args),
        Command::Fuzz(args) => verbs::run_fuzz(args),
        Command::Snapshot(args) => verbs::run_snapshot(args),
        Command::Diff(args) => verbs::run_diff(args),
        Command::AauthKeygen(args) => verbs::run_aauth_keygen(args),
    }
}
