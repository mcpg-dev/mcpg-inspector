//! The standalone terminal binary: the same TUI `mcpg-inspector tui`
//! runs, under its own name so the published TUI image needs no
//! subcommand. The flag surface is the subcommand's, verbatim, and the
//! engine below is the identical construction the subcommand performs
//! for a run that is not `--attach`ed to a running inspector.

use std::sync::Arc;

use clap::Parser;

#[derive(Parser)]
#[command(
    name = "mcpg-inspector-tui",
    bin_name = "mcpg-inspector-tui",
    version,
    about = "MCP inspector — terminal UI"
)]
struct Cli {
    #[command(flatten)]
    args: mcpg_inspector_tui::TuiArgs,
}

fn main() -> ! {
    let cli = Cli::parse();
    mcpg_inspector_tui::run(cli.args, |args| {
        let engine = Arc::new(mcpg_inspector::engine::registry::Engine::new(
            mcpg_inspector::engine::registry::Mode::Local,
            args.frame_buffer,
        ));
        for spec in &args.targets {
            engine.add_target(mcpg_inspector::engine::target::TargetSpec::parse_cli(spec)?)?;
        }
        Ok(Arc::new(mcpg_inspector::local_api::LocalApi::new(engine)))
    })
}
