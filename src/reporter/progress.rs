//! Progress bar for terminal output during scanning.
//!
//! Uses Braille pattern characters for a modern, high-density display.

use indicatif::{ProgressBar, ProgressStyle};

/// Minimum number of files to display progress bar
const MIN_FILES_FOR_PROGRESS: usize = 10;

/// Progress bar manager for scan operations.
pub struct ScanProgress {
    bar: Option<ProgressBar>,
}

impl ScanProgress {
    /// Create a new progress bar if conditions are met.
    ///
    /// Progress bar is only shown if:
    /// - Total files >= 10
    /// - Running in TTY (interactive terminal)
    /// - Not in CI mode
    pub fn new(total_files: usize, is_tty: bool, is_ci: bool) -> Self {
        let bar = if should_show_progress(total_files, is_tty, is_ci) {
            Some(create_progress_bar(total_files))
        } else {
            None
        };

        Self { bar }
    }

    /// Increment progress by one file.
    pub fn inc(&self) {
        if let Some(bar) = &self.bar {
            bar.inc(1);
        }
    }

    /// Finish and clear the progress bar.
    pub fn finish(&self) {
        if let Some(bar) = &self.bar {
            bar.finish_and_clear();
        }
    }
}

/// Check if progress bar should be displayed.
fn should_show_progress(total_files: usize, is_tty: bool, is_ci: bool) -> bool {
    total_files >= MIN_FILES_FOR_PROGRESS && is_tty && !is_ci
}

/// Create a progress bar with Braille pattern style.
fn create_progress_bar(total: usize) -> ProgressBar {
    let pb = ProgressBar::new(total as u64);
    pb.set_style(
        ProgressStyle::with_template(
            "Scanning {bar:40} {pos:>4}/{len:4} files ({percent:>3}%) [{elapsed_precise} < {eta_precise}]",
        )
        .expect("Invalid progress bar template")
        .progress_chars("⣿⣀ "), // Braille pattern: filled, current, empty
    );
    pb
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_show_progress_below_threshold() {
        // 9 files - below threshold
        assert!(!should_show_progress(9, true, false));
    }

    #[test]
    fn test_should_show_progress_at_threshold() {
        // 10 files - at threshold, should show
        assert!(should_show_progress(10, true, false));
    }

    #[test]
    fn test_should_show_progress_above_threshold() {
        // 100 files - above threshold, should show
        assert!(should_show_progress(100, true, false));
    }

    #[test]
    fn test_should_not_show_in_non_tty() {
        // Non-TTY environment (e.g., piped output)
        assert!(!should_show_progress(100, false, false));
    }

    #[test]
    fn test_should_not_show_in_ci() {
        // CI environment
        assert!(!should_show_progress(100, true, true));
    }

    #[test]
    fn test_should_not_show_non_tty_and_ci() {
        // Both non-TTY and CI
        assert!(!should_show_progress(100, false, true));
    }

    #[test]
    fn test_new_creates_bar_when_conditions_met() {
        let progress = ScanProgress::new(10, true, false);
        assert!(progress.bar.is_some());
    }

    #[test]
    fn test_new_no_bar_when_below_threshold() {
        let progress = ScanProgress::new(9, true, false);
        assert!(progress.bar.is_none());
    }

    #[test]
    fn test_new_no_bar_when_non_tty() {
        let progress = ScanProgress::new(100, false, false);
        assert!(progress.bar.is_none());
    }

    #[test]
    fn test_new_no_bar_when_ci() {
        let progress = ScanProgress::new(100, true, true);
        assert!(progress.bar.is_none());
    }

    #[test]
    fn test_inc_with_bar() {
        let progress = ScanProgress::new(10, true, false);
        // Should not panic
        progress.inc();
    }

    #[test]
    fn test_inc_without_bar() {
        let progress = ScanProgress::new(5, true, false);
        // Should not panic even without bar
        progress.inc();
    }

    #[test]
    fn test_finish_with_bar() {
        let progress = ScanProgress::new(10, true, false);
        // Should not panic
        progress.finish();
    }

    #[test]
    fn test_finish_without_bar() {
        let progress = ScanProgress::new(5, true, false);
        // Should not panic even without bar
        progress.finish();
    }

    #[test]
    fn test_create_progress_bar() {
        // Verify that create_progress_bar doesn't panic and creates a valid bar
        let pb = create_progress_bar(100);
        assert_eq!(pb.length(), Some(100));
    }
}
