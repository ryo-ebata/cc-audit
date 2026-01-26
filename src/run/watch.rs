//! Watch mode support for continuous scanning.

use crate::{Cli, FileWatcher};

use super::client::resolve_scan_paths;
use super::formatter::format_result;
use super::scanner::run_scan;

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
pub fn setup_watch_mode(cli: &Cli) -> Result<FileWatcher, WatchModeResult> {
    let mut watcher = match FileWatcher::new() {
        Ok(w) => w,
        Err(e) => {
            return Err(WatchModeResult::WatcherCreationFailed(e.to_string()));
        }
    };

    // Resolve and watch all paths
    let watch_paths = resolve_scan_paths(cli);
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
pub fn watch_iteration(cli: &Cli) -> Option<String> {
    run_scan(cli).map(|result| format_result(cli, &result))
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
        let cli = Cli {
            paths: vec![temp_dir.path().to_path_buf()],
            ..Default::default()
        };

        let result = setup_watch_mode(&cli);
        assert!(result.is_ok());
    }

    #[test]
    fn test_setup_watch_mode_invalid_path() {
        let cli = Cli {
            paths: vec![PathBuf::from("/nonexistent/path/12345")],
            ..Default::default()
        };

        let result = setup_watch_mode(&cli);
        assert!(result.is_err());
    }
}
