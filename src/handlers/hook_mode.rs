//! Handler for hook mode.

use crate::hook_mode;
use std::process::ExitCode;

/// Handle the `--hook-mode` flag.
///
/// This function runs cc-audit in hook mode, reading JSON from stdin
/// and writing a JSON response to stdout.
pub fn handle_hook_mode() -> ExitCode {
    let exit_code = hook_mode::run_hook_mode();
    ExitCode::from(exit_code as u8)
}
