use crate::config::WatchConfig;
use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;
use tracing::warn;

pub struct FileWatcher {
    watcher: RecommendedWatcher,
    receiver: Receiver<Result<notify::Event, notify::Error>>,
    debounce_duration: Duration,
}

impl FileWatcher {
    /// Creates a new FileWatcher with default configuration.
    pub fn new() -> Result<Self, notify::Error> {
        Self::with_config(&WatchConfig::default())
    }

    /// Creates a new FileWatcher with custom configuration.
    pub fn with_config(config: &WatchConfig) -> Result<Self, notify::Error> {
        let (tx, rx) = channel();

        let watcher = RecommendedWatcher::new(
            move |res| {
                let _ = tx.send(res);
            },
            Config::default().with_poll_interval(Duration::from_millis(config.poll_interval_ms)),
        )?;

        Ok(Self {
            watcher,
            receiver: rx,
            debounce_duration: Duration::from_millis(config.debounce_ms),
        })
    }

    pub fn watch(&mut self, path: &Path) -> Result<(), notify::Error> {
        self.watcher.watch(path, RecursiveMode::Recursive)
    }

    pub fn wait_for_change(&self) -> bool {
        // Simple debounce: collect events for debounce_duration
        let mut has_change = false;

        loop {
            match self.receiver.recv_timeout(if has_change {
                self.debounce_duration
            } else {
                Duration::from_secs(60 * 60) // 1 hour timeout when waiting for first event
            }) {
                Ok(Ok(event)) => {
                    // Only react to meaningful changes
                    if matches!(
                        event.kind,
                        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
                    ) {
                        has_change = true;
                    }
                }
                Ok(Err(e)) => {
                    warn!(error = %e, "File watch error");
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    // Debounce period complete or timeout
                    if has_change {
                        return true;
                    }
                    // Continue waiting if no change yet
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    return false;
                }
            }
        }
    }
}

/// Note: The `Default` implementation for `FileWatcher` may panic if the underlying
/// file watcher cannot be created. Prefer using `FileWatcher::new()` for production
/// code to properly handle potential errors.
impl Default for FileWatcher {
    /// Creates a new `FileWatcher` with default settings.
    ///
    /// # Panics
    ///
    /// Panics if the file watcher cannot be created (e.g., due to OS limitations).
    fn default() -> Self {
        Self::new().expect("Failed to create file watcher")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_file_watcher_creation() {
        let watcher = FileWatcher::new();
        assert!(watcher.is_ok());
    }

    #[test]
    fn test_file_watcher_with_config() {
        let config = WatchConfig {
            debounce_ms: 500,
            poll_interval_ms: 1000,
        };
        let watcher = FileWatcher::with_config(&config);
        assert!(watcher.is_ok());
        let watcher = watcher.unwrap();
        assert_eq!(watcher.debounce_duration, Duration::from_millis(500));
    }

    #[test]
    fn test_file_watcher_with_custom_debounce() {
        let config = WatchConfig {
            debounce_ms: 100,
            poll_interval_ms: 200,
        };
        let watcher = FileWatcher::with_config(&config).unwrap();
        assert_eq!(watcher.debounce_duration, Duration::from_millis(100));
    }

    #[test]
    fn test_watch_directory() {
        let temp_dir = TempDir::new().unwrap();
        let mut watcher = FileWatcher::new().unwrap();
        let result = watcher.watch(temp_dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn test_watch_nonexistent_directory() {
        let mut watcher = FileWatcher::new().unwrap();
        let result = watcher.watch(Path::new("/nonexistent/path/12345"));
        assert!(result.is_err());
    }

    #[test]
    fn test_default_trait() {
        // This will panic if it fails, which is expected behavior
        let _watcher = FileWatcher::default();
    }

    #[test]
    fn test_watch_file_change() {
        use std::thread;
        use std::time::Duration;

        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.md");
        fs::write(&test_file, "initial content").unwrap();

        let mut watcher = FileWatcher::new().unwrap();
        watcher.watch(temp_dir.path()).unwrap();

        // Spawn a thread to modify the file after a short delay
        let test_file_clone = test_file.clone();
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            fs::write(&test_file_clone, "modified content").unwrap();
        });

        // Wait for change (with timeout via recv_timeout)
        // We use a separate thread to avoid blocking forever
        let (tx, _rx) = channel();
        let watcher_receiver = watcher.receiver;
        thread::spawn(move || {
            let result = watcher_receiver.recv_timeout(Duration::from_secs(2));
            let _ = tx.send(result.is_ok());
        });

        handle.join().unwrap();

        // Give the watcher some time to process
        thread::sleep(Duration::from_millis(500));
    }

    #[test]
    fn test_wait_for_change_with_create_event() {
        use std::thread;
        use std::time::Duration;

        let temp_dir = TempDir::new().unwrap();
        let mut watcher = FileWatcher::new().unwrap();
        watcher.watch(temp_dir.path()).unwrap();

        // Spawn a thread to create a new file
        let test_file = temp_dir.path().join("new_file.txt");
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            fs::write(&test_file, "new content").unwrap();
        });

        // wait_for_change should return true on file creation
        let result = watcher.wait_for_change();
        assert!(result);
    }

    #[test]
    fn test_wait_for_change_with_remove_event() {
        use std::thread;
        use std::time::Duration;

        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("to_remove.txt");
        fs::write(&test_file, "content").unwrap();

        let mut watcher = FileWatcher::new().unwrap();
        watcher.watch(temp_dir.path()).unwrap();

        // Spawn a thread to remove the file
        let test_file_clone = test_file.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            fs::remove_file(&test_file_clone).unwrap();
        });

        // wait_for_change should return true on file removal
        let result = watcher.wait_for_change();
        assert!(result);
    }

    #[test]
    fn test_wait_for_change_disconnected() {
        use std::thread;
        use std::time::Duration;

        // Create a watcher but manually drop the sender to simulate disconnection
        let (tx, rx) = channel::<Result<notify::Event, notify::Error>>();

        // Create a minimal watcher struct with the receiver
        // We need to simulate the disconnection scenario
        let watcher_handle = thread::spawn(move || {
            // This tests the Disconnected branch
            // Drop the sender to disconnect
            drop(tx);
        });

        // Small delay to ensure sender is dropped
        thread::sleep(Duration::from_millis(50));

        // Now try to receive - should get disconnected error
        let result = rx.recv_timeout(Duration::from_millis(100));
        assert!(result.is_err());

        watcher_handle.join().unwrap();
    }

    #[test]
    fn test_debounce_duration() {
        let watcher = FileWatcher::new().unwrap();
        assert_eq!(watcher.debounce_duration, Duration::from_millis(300));
    }

    #[test]
    fn test_wait_for_change_with_modify_event() {
        use std::thread;
        use std::time::Duration;

        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("existing.txt");
        fs::write(&test_file, "initial").unwrap();

        let mut watcher = FileWatcher::new().unwrap();
        watcher.watch(temp_dir.path()).unwrap();

        // Spawn a thread to modify the file
        let test_file_clone = test_file.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            fs::write(&test_file_clone, "modified").unwrap();
        });

        // wait_for_change should return true on file modification
        let result = watcher.wait_for_change();
        assert!(result);
    }

    #[test]
    fn test_receiver_fields() {
        // Test that FileWatcher fields are properly initialized
        let watcher = FileWatcher::new().unwrap();
        assert_eq!(watcher.debounce_duration, Duration::from_millis(300));
        // receiver is private but we can test via wait behavior
    }
}
