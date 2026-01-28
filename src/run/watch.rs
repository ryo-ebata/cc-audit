//! Watch mode support for continuous scanning.

use crate::{CheckArgs, FileWatcher};

use super::client::resolve_scan_paths_from_check_args;
use super::formatter::format_result_check_args;
use super::scanner::run_scan_with_check_args;

/// Result of running in watch mode.
#[derive(Debug)]
pub enum WatchModeResult {
    /// Watcher was successfully set up, initial scan was done.
    Success,
    /// Failed to create watcher.
    WatcherCreationFailed(String),
    /// Failed to watch a path.
    WatchPathFailed(String, String),
}

/// Set up watch mode and return the file watcher.
pub fn setup_watch_mode(args: &CheckArgs) -> Result<FileWatcher, WatchModeResult> {
    let mut watcher = match FileWatcher::new() {
        Ok(w) => w,
        Err(e) => {
            return Err(WatchModeResult::WatcherCreationFailed(e.to_string()));
        }
    };

    // Resolve and watch all paths
    let watch_paths = resolve_scan_paths_from_check_args(args);
    for path in &watch_paths {
        if let Err(e) = watcher.watch(path) {
            return Err(WatchModeResult::WatchPathFailed(
                path.display().to_string(),
                e.to_string(),
            ));
        }
    }

    Ok(watcher)
}

/// Run one iteration of the watch loop.
pub fn watch_iteration(args: &CheckArgs) -> Option<String> {
    run_scan_with_check_args(args).map(|result| format_result_check_args(args, &result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn test_watch_mode_result_variants() {
        let success = WatchModeResult::Success;
        assert!(matches!(success, WatchModeResult::Success));

        let failed = WatchModeResult::WatcherCreationFailed("error".to_string());
        assert!(matches!(failed, WatchModeResult::WatcherCreationFailed(_)));

        let path_failed =
            WatchModeResult::WatchPathFailed("/path".to_string(), "error".to_string());
        assert!(matches!(
            path_failed,
            WatchModeResult::WatchPathFailed(_, _)
        ));
    }

    #[test]
    fn test_setup_watch_mode_valid_path() {
        let temp_dir = TempDir::new().unwrap();
        let args = CheckArgs {
            paths: vec![temp_dir.path().to_path_buf()],
            ..Default::default()
        };

        let result = setup_watch_mode(&args);
        assert!(result.is_ok());
    }

    #[test]
    fn test_setup_watch_mode_invalid_path() {
        let args = CheckArgs {
            paths: vec![PathBuf::from("/nonexistent/path/12345")],
            ..Default::default()
        };

        let result = setup_watch_mode(&args);
        assert!(result.is_err());
    }
}
