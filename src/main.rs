use cc_audit::{
    Cli, Commands,
    handlers::{handle_check, handle_hook, handle_init_config, handle_mcp_server, handle_proxy},
};
use clap::{CommandFactory, Parser};
use std::process::ExitCode;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

fn init_tracing(verbose: bool) {
    let filter = if verbose {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("cc_audit=debug"))
    } else {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("cc_audit=warn"))
    };

    tracing_subscriber::registry()
        .with(fmt::layer().with_target(true).with_level(true))
        .with(filter)
        .init();
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    init_tracing(cli.verbose);

    match cli.command {
        None => {
            // No subcommand: show help
            Cli::command().print_help().ok();
            println!(); // Add newline after help
            ExitCode::SUCCESS
        }
        Some(Commands::Init { path }) => handle_init_config(&path),
        Some(Commands::Check(args)) => handle_check(&args, cli.verbose),
        Some(Commands::Hook { action }) => handle_hook(action),
        Some(Commands::Serve) => handle_mcp_server(),
        Some(Commands::Proxy(args)) => handle_proxy(&args),
    }
}
