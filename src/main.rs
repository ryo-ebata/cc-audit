use cc_audit::{
    Cli,
    handlers::{
        handle_baseline, handle_check_drift, handle_compare, handle_fix, handle_hook_mode,
        handle_init_config, handle_init_hook, handle_mcp_server, handle_pin, handle_pin_verify,
        handle_proxy, handle_remove_hook, handle_report_fp, handle_save_baseline,
        handle_save_profile, handle_sbom, handle_show_profile, run_normal_mode, run_watch_mode,
    },
};
use clap::Parser;
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

    // Handle config initialization
    if cli.init {
        return handle_init_config(&cli);
    }

    // Handle hook installation/removal
    if cli.init_hook {
        return handle_init_hook(&cli);
    }

    if cli.remove_hook {
        return handle_remove_hook(&cli);
    }

    // Handle --save-baseline <file>
    if let Some(ref baseline_path) = cli.save_baseline {
        return handle_save_baseline(&cli, baseline_path);
    }

    // Handle baseline creation (legacy --baseline)
    if cli.baseline {
        return handle_baseline(&cli);
    }

    // Handle drift detection
    if cli.check_drift {
        return handle_check_drift(&cli);
    }

    // Handle --compare <path1> <path2>
    if let Some(ref paths) = cli.compare {
        return handle_compare(&cli, paths);
    }

    // Handle --fix or --fix-dry-run
    if cli.fix || cli.fix_dry_run {
        return handle_fix(&cli);
    }

    // Handle --mcp-server
    if cli.mcp_server {
        return handle_mcp_server();
    }

    // Handle --hook-mode (Claude Code Hook integration)
    if cli.hook_mode {
        return handle_hook_mode();
    }

    // Handle --pin (create MCP tool pins)
    if cli.pin || cli.pin_update {
        return handle_pin(&cli);
    }

    // Handle --pin-verify (verify MCP tool pins)
    if cli.pin_verify {
        return handle_pin_verify(&cli);
    }

    // Handle --save-profile
    if let Some(ref profile_name) = cli.save_profile {
        return handle_save_profile(&cli, profile_name);
    }

    // Handle --report-fp (false positive reporting)
    if cli.report_fp {
        return handle_report_fp(&cli);
    }

    // Handle --sbom (SBOM generation)
    if cli.sbom {
        return handle_sbom(&cli);
    }

    // Handle --proxy (proxy mode)
    if cli.proxy {
        return handle_proxy(&cli);
    }

    // Handle --profile (info mode when no paths to scan)
    if let Some(ref profile_name) = cli.profile {
        // If profile is specified but paths are essentially just ".", show profile info
        if cli.paths.len() == 1 && cli.paths[0].as_os_str() == "." && !cli.paths[0].exists() {
            return handle_show_profile(profile_name);
        }
    }

    if cli.watch {
        return run_watch_mode(&cli);
    }

    // Normal mode (with optional --baseline-file comparison)
    run_normal_mode(&cli)
}
