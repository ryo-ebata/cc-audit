//! Remote repository scanning handlers.

use crate::remote::{AWESOME_CLAUDE_CODE_URL, GitCloner};
use crate::run::EffectiveConfig;
use crate::{CheckArgs, ClonedRepo, Config, run_scan_with_check_args};
use colored::Colorize;
use std::fs;
use std::io::{BufRead, BufReader};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;

use super::run_normal_check_mode;

#[derive(Debug, Clone, Copy)]
struct FindingCounts {
    total: usize,
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
}

#[derive(Debug)]
enum BatchFailure {
    Clone(String),
    Scan,
}

fn finding_counts(result: &crate::ScanResult) -> FindingCounts {
    FindingCounts {
        total: result.summary.critical
            + result.summary.high
            + result.summary.medium
            + result.summary.low,
        critical: result.summary.critical,
        high: result.summary.high,
        medium: result.summary.medium,
        low: result.summary.low,
    }
}

fn scan_owned_repository<T, R, E, F>(repository: T, scan: F) -> Result<R, E>
where
    F: FnOnce(&T) -> Result<R, E>,
{
    scan(&repository)
}

fn run_bounded_batch<T, E, F>(items: &[String], limit: usize, operation: F) -> Vec<Result<T, E>>
where
    T: Send,
    E: Send,
    F: Fn(&str) -> Result<T, E> + Send + Sync,
{
    if items.is_empty() {
        return Vec::new();
    }

    let worker_count = limit.max(1).min(items.len());
    let next_index = Arc::new(AtomicUsize::new(0));
    let (sender, receiver) = mpsc::channel();
    let operation = &operation;

    thread::scope(|scope| {
        for _ in 0..worker_count {
            let next_index = Arc::clone(&next_index);
            let sender = sender.clone();
            scope.spawn(move || {
                loop {
                    let index = next_index.fetch_add(1, Ordering::Relaxed);
                    if index >= items.len() {
                        break;
                    }
                    let result = operation(&items[index]);
                    sender
                        .send((index, result))
                        .expect("batch receiver is alive");
                }
            });
        }
        drop(sender);

        let mut results: Vec<Option<Result<T, E>>> = (0..items.len()).map(|_| None).collect();
        for (index, result) in receiver {
            results[index] = Some(result);
        }
        results
            .into_iter()
            .map(|result| result.expect("every batch item has a result"))
            .collect()
    })
}

fn scan_cloned_repository(
    cloner: &GitCloner,
    url: &str,
    git_ref: &str,
    args: &CheckArgs,
    effective: &EffectiveConfig,
) -> Result<FindingCounts, BatchFailure> {
    let cloned = cloner
        .clone(url, git_ref)
        .map_err(|error| BatchFailure::Clone(error.to_string()))?;
    let result = scan_owned_repository(cloned, |cloned| {
        let scan_args = args.for_batch_scan(vec![cloned.path().to_path_buf()], effective);
        run_scan_with_check_args(&scan_args).ok_or(BatchFailure::Scan)
    })?;
    Ok(finding_counts(&result))
}

fn read_remote_list<R: BufRead>(reader: R) -> Result<Vec<String>, (usize, std::io::Error)> {
    let mut urls = Vec::new();
    for (index, line) in reader.lines().enumerate() {
        let line_number = index + 1;
        let line = line.map_err(|error| (line_number, error))?;
        let line = line.trim().to_string();
        if !line.is_empty() && !line.starts_with('#') {
            urls.push(line);
        }
    }
    Ok(urls)
}

fn read_remote_list_then<R, T, F>(reader: R, on_success: F) -> Result<T, (usize, std::io::Error)>
where
    R: BufRead,
    F: FnOnce(Vec<String>) -> T,
{
    let urls = read_remote_list(reader)?;
    Ok(on_success(urls))
}

/// Handle --remote command: scan a single remote repository.
pub fn handle_remote_scan(args: &CheckArgs) -> ExitCode {
    let url = match &args.remote {
        Some(u) => u,
        None => {
            eprintln!("Error: --remote requires a URL");
            return ExitCode::from(2);
        }
    };

    // Load config from current directory to get effective settings
    let config = Config::load(Some(std::path::Path::new(".")));
    let effective = EffectiveConfig::from_check_args_and_config(args, &config);

    println!("Cloning repository: {}", url);

    // Create cloner with optional authentication (use effective config for auth)
    let cloner = if let Some(ref token) = effective.remote_auth {
        GitCloner::new().with_auth_token(Some(token.clone()))
    } else {
        GitCloner::new()
    };

    // Clone the repository (use effective config for git_ref)
    let cloned: ClonedRepo = match cloner.clone(url, &effective.git_ref) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to clone repository: {}", e);
            return ExitCode::from(2);
        }
    };

    println!("Scanning: {}", cloned.path().display());

    // Create CheckArgs for scanning the cloned repo
    let scan_args = args.for_scan(vec![cloned.path().to_path_buf()], &effective);

    // Run the scan
    run_normal_check_mode(&scan_args)
}

/// Handle --remote-list command: scan multiple repositories from a file.
pub fn handle_remote_list_scan(args: &CheckArgs) -> ExitCode {
    let list_path = match &args.remote_list {
        Some(p) => p,
        None => {
            eprintln!("Error: --remote-list requires a file path");
            return ExitCode::from(2);
        }
    };

    // Load config from current directory to get effective settings
    let config = Config::load(Some(std::path::Path::new(".")));
    let effective = EffectiveConfig::from_check_args_and_config(args, &config);

    // Read URLs from file
    let file = match fs::File::open(list_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to open URL list file: {}", e);
            return ExitCode::from(2);
        }
    };

    let reader = BufReader::new(file);
    let urls = match read_remote_list_then(reader, |urls| urls) {
        Ok(urls) => urls,
        Err((line, error)) => {
            eprintln!(
                "Failed to read URL list {} at line {}: {}",
                list_path.display(),
                line,
                error
            );
            return ExitCode::from(2);
        }
    };

    if urls.is_empty() {
        eprintln!("No URLs found in {}", list_path.display());
        return ExitCode::from(2);
    }

    println!("Found {} repositories to scan", urls.len());

    let cloner = if let Some(ref token) = effective.remote_auth {
        GitCloner::new().with_auth_token(Some(token.clone()))
    } else {
        GitCloner::new()
    };

    let results = run_bounded_batch(&urls, effective.parallel_clones, |url| {
        scan_cloned_repository(&cloner, url, &effective.git_ref, args, &effective)
    });
    let mut total_findings = 0;
    let mut failed_count = 0;

    for (i, (url, result)) in urls.iter().zip(results).enumerate() {
        println!("\n[{}/{}] Scanning: {}", i + 1, urls.len(), url);
        match result {
            Ok(counts) => {
                total_findings += counts.total;
                println!(
                    "  {} {} findings ({} critical, {} high, {} medium, {} low)",
                    if counts.total > 0 {
                        "⚠".yellow()
                    } else {
                        "✓".green()
                    },
                    counts.total,
                    counts.critical,
                    counts.high,
                    counts.medium,
                    counts.low
                );
            }
            Err(BatchFailure::Scan) => {
                failed_count += 1;
                eprintln!("  {} Scan failed", "✗".red());
            }
            Err(BatchFailure::Clone(error)) => {
                failed_count += 1;
                eprintln!("  {} Clone failed: {}", "✗".red(), error);
            }
        }
    }

    println!("\n{}", "═".repeat(50));
    println!(
        "Summary: {} repos scanned, {} total findings, {} failed",
        urls.len() - failed_count,
        total_findings,
        failed_count
    );

    if total_findings > 0 || failed_count > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// Handle --awesome-claude-code command: scan awesome-claude-code repository links.
pub fn handle_awesome_claude_code_scan(args: &CheckArgs) -> ExitCode {
    println!("Fetching awesome-claude-code repository...");

    // Load config from current directory to get effective settings
    let config = Config::load(Some(std::path::Path::new(".")));
    let effective = EffectiveConfig::from_check_args_and_config(args, &config);

    let cloner = if let Some(ref token) = effective.remote_auth {
        GitCloner::new().with_auth_token(Some(token.clone()))
    } else {
        GitCloner::new()
    };

    // Clone awesome-claude-code to get the README
    let awesome_repo: ClonedRepo = match cloner.clone(AWESOME_CLAUDE_CODE_URL, "HEAD") {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to clone awesome-claude-code: {}", e);
            return ExitCode::from(2);
        }
    };

    // Parse README.md for GitHub URLs
    let readme_path = awesome_repo.path().join("README.md");
    let readme_content = match fs::read_to_string(&readme_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to read README.md: {}", e);
            return ExitCode::from(2);
        }
    };

    // Extract GitHub URLs from markdown
    let github_url_pattern =
        regex::Regex::new(r"https://github\.com/[a-zA-Z0-9_-]+/[a-zA-Z0-9_.-]+")
            .expect("Invalid regex");

    let urls: Vec<String> = github_url_pattern
        .find_iter(&readme_content)
        .map(|m| m.as_str().to_string())
        .filter(|url| !url.contains("anthropics/awesome-claude-code")) // Exclude self
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    if urls.is_empty() {
        eprintln!("No GitHub URLs found in awesome-claude-code README");
        return ExitCode::from(2);
    }

    println!("Found {} repositories to scan", urls.len());

    let batch_results = run_bounded_batch(&urls, effective.parallel_clones, |url| {
        scan_cloned_repository(&cloner, url, "HEAD", args, &effective)
    });
    let mut total_findings = 0;
    let mut failed_count = 0;
    let mut results: Vec<(String, usize, usize, usize, usize, usize)> = Vec::new();

    for (i, (url, result)) in urls.iter().zip(batch_results).enumerate() {
        println!("\n[{}/{}] Scanning: {}", i + 1, urls.len(), url);
        match result {
            Ok(counts) => {
                total_findings += counts.total;
                results.push((
                    url.clone(),
                    counts.total,
                    counts.critical,
                    counts.high,
                    counts.medium,
                    counts.low,
                ));
                println!(
                    "  {} {} findings ({} critical, {} high, {} medium, {} low)",
                    if counts.total > 0 {
                        "⚠".yellow()
                    } else {
                        "✓".green()
                    },
                    counts.total,
                    counts.critical,
                    counts.high,
                    counts.medium,
                    counts.low
                );
            }
            Err(BatchFailure::Scan) => {
                failed_count += 1;
                eprintln!("  {} Scan failed", "✗".red());
            }
            Err(BatchFailure::Clone(error)) => {
                failed_count += 1;
                eprintln!("  {} Clone failed: {}", "✗".red(), error);
            }
        }
    }

    // Print summary
    println!("\n{}", "═".repeat(60));
    println!(
        "{} Summary: {} repos scanned, {} total findings, {} failed {}",
        "".bold(),
        urls.len() - failed_count,
        total_findings,
        failed_count,
        "".bold()
    );

    if effective.summary {
        println!("\n{}", "Repository Results:".bold());
        println!("{:-<60}", "");

        // Sort by total findings (descending)
        let mut sorted_results = results.clone();
        sorted_results.sort_by(|a, b| b.1.cmp(&a.1));

        for (url, _total, critical, high, medium, low) in sorted_results {
            let status = if critical > 0 || high > 0 {
                "FAIL".red().bold()
            } else if medium > 0 || low > 0 {
                "WARN".yellow()
            } else {
                "PASS".green()
            };
            println!(
                "{} {} (C:{} H:{} M:{} L:{})",
                status,
                url.replace("https://github.com/", ""),
                critical,
                high,
                medium,
                low
            );
        }
    }

    if total_findings > 0 || failed_count > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read};
    use std::sync::atomic::AtomicUsize;
    use std::sync::{Condvar, Mutex, mpsc};
    use std::time::Duration;

    struct MockClone {
        dropped: Arc<AtomicUsize>,
    }

    struct StartGate {
        started: Mutex<usize>,
        ready: Condvar,
    }

    impl Drop for MockClone {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    struct FailingReader {
        first_chunk: Vec<u8>,
        offset: usize,
        failed: bool,
    }

    impl Read for FailingReader {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if self.offset < self.first_chunk.len() {
                let length = (self.first_chunk.len() - self.offset).min(buffer.len());
                buffer[..length]
                    .copy_from_slice(&self.first_chunk[self.offset..self.offset + length]);
                self.offset += length;
                Ok(length)
            } else if !self.failed {
                self.failed = true;
                Err(std::io::Error::other("injected URL list read failure"))
            } else {
                Err(std::io::Error::other("injected URL list read failure"))
            }
        }
    }

    #[test]
    fn read_remote_list_filters_comments_and_blank_lines() {
        let input = b"\n# ignored\n https://example.com/one \n\nhttps://example.com/two\n";
        let urls = read_remote_list(BufReader::new(Cursor::new(input))).unwrap();

        assert_eq!(urls, ["https://example.com/one", "https://example.com/two"]);
    }

    #[test]
    fn read_remote_list_rejects_invalid_utf8_at_beginning_without_partial_urls() {
        let input = b"\xffhttps://user:secret@example.com/repo\nhttps://example.com/later\n";
        let clone_calls = Arc::new(AtomicUsize::new(0));
        let error = read_remote_list_then(BufReader::new(Cursor::new(input)), {
            let clone_calls = Arc::clone(&clone_calls);
            move |_| {
                clone_calls.fetch_add(1, Ordering::Relaxed);
            }
        })
        .unwrap_err();

        assert_eq!(error.0, 1);
        assert!(error.1.to_string().contains("valid UTF-8"));
        assert!(!error.1.to_string().contains("secret"));
        assert_eq!(clone_calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn read_remote_list_rejects_invalid_utf8_after_valid_url_without_partial_urls() {
        let input = b"https://example.com/first\n\xffhttps://user:secret@example.com/repo\nhttps://example.com/later\n";
        let clone_calls = Arc::new(AtomicUsize::new(0));
        let error = read_remote_list_then(BufReader::new(Cursor::new(input)), {
            let clone_calls = Arc::clone(&clone_calls);
            move |_| {
                clone_calls.fetch_add(1, Ordering::Relaxed);
            }
        })
        .unwrap_err();

        assert_eq!(error.0, 2);
        assert!(error.1.to_string().contains("valid UTF-8"));
        assert!(!error.1.to_string().contains("secret"));
        assert_eq!(clone_calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn read_remote_list_rejects_midstream_io_error_without_partial_urls() {
        let reader = FailingReader {
            first_chunk: b"https://example.com/first\n".to_vec(),
            offset: 0,
            failed: false,
        };
        let clone_calls = Arc::new(AtomicUsize::new(0));
        let error = read_remote_list_then(BufReader::new(reader), {
            let clone_calls = Arc::clone(&clone_calls);
            move |_| {
                clone_calls.fetch_add(1, Ordering::Relaxed);
            }
        })
        .unwrap_err();

        assert_eq!(error.0, 2);
        assert!(
            error
                .1
                .to_string()
                .contains("injected URL list read failure")
        );
        assert_eq!(clone_calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn bounded_batch_respects_limit_and_releases_completed_clones() {
        let urls: Vec<String> = (0..6).map(|index| format!("repo-{index}")).collect();
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(StartGate {
            started: Mutex::new(0),
            ready: Condvar::new(),
        });
        let start_count = Arc::new(AtomicUsize::new(0));
        let (repo_2_done_tx, repo_2_done_rx) = mpsc::channel();
        let (repo_1_done_tx, repo_1_done_rx) = mpsc::channel();
        let repo_2_done_rx = Arc::new(Mutex::new(repo_2_done_rx));
        let repo_1_done_rx = Arc::new(Mutex::new(repo_1_done_rx));
        let results = run_bounded_batch(&urls, 3, {
            let active = Arc::clone(&active);
            let maximum = Arc::clone(&maximum);
            let dropped = Arc::clone(&dropped);
            let started = Arc::clone(&started);
            let start_count = Arc::clone(&start_count);
            let repo_2_done_rx = Arc::clone(&repo_2_done_rx);
            let repo_1_done_rx = Arc::clone(&repo_1_done_rx);
            move |url| {
                let clone = MockClone {
                    dropped: Arc::clone(&dropped),
                };
                let current = active.fetch_add(1, Ordering::Relaxed) + 1;
                maximum.fetch_max(current, Ordering::Relaxed);
                if start_count.fetch_add(1, Ordering::Relaxed) < 3 {
                    let gate = Arc::clone(&started);
                    let mut count = gate.started.lock().unwrap();
                    *count += 1;
                    count = gate
                        .ready
                        .wait_timeout_while(count, Duration::from_secs(1), |count| *count < 3)
                        .unwrap()
                        .0;
                    assert_eq!(*count, 3, "all workers must reach the start gate");
                    gate.ready.notify_all();
                }
                match url {
                    "repo-2" => repo_2_done_tx.send(()).unwrap(),
                    "repo-1" => {
                        repo_2_done_rx
                            .lock()
                            .unwrap()
                            .recv_timeout(Duration::from_secs(1))
                            .unwrap();
                        repo_1_done_tx.send(()).unwrap();
                    }
                    "repo-0" => repo_1_done_rx
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(1))
                        .unwrap(),
                    _ => {}
                }
                active.fetch_sub(1, Ordering::Relaxed);
                scan_owned_repository(clone, |_| Ok::<_, ()>(url.to_owned()))
            }
        });

        assert_eq!(results.len(), urls.len());
        assert_eq!(maximum.load(Ordering::Relaxed), 3);
        assert_eq!(dropped.load(Ordering::Relaxed), urls.len());
        assert_eq!(results[0].as_ref().unwrap(), "repo-0");
        assert_eq!(results[1].as_ref().unwrap(), "repo-1");
        assert_eq!(results[2].as_ref().unwrap(), "repo-2");
    }

    #[test]
    fn bounded_batch_handles_zero_limit_and_partial_failures() {
        let urls: Vec<String> = (0..4).map(|index| format!("repo-{index}")).collect();
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let results = run_bounded_batch(&urls, 0, {
            let active = Arc::clone(&active);
            let maximum = Arc::clone(&maximum);
            let dropped = Arc::clone(&dropped);
            move |url| {
                let clone = MockClone {
                    dropped: Arc::clone(&dropped),
                };
                let current = active.fetch_add(1, Ordering::Relaxed) + 1;
                maximum.fetch_max(current, Ordering::Relaxed);
                if url == "repo-2" {
                    let result = scan_owned_repository(clone, |_| Err::<usize, _>("scan failed"));
                    active.fetch_sub(1, Ordering::Relaxed);
                    result
                } else {
                    let result = scan_owned_repository(clone, |_| Ok::<_, &str>(url.len()));
                    active.fetch_sub(1, Ordering::Relaxed);
                    result
                }
            }
        });

        assert_eq!(results.len(), urls.len());
        assert_eq!(maximum.load(Ordering::Relaxed), 1);
        assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
        assert_eq!(results[0].as_ref().unwrap(), &6);
        assert_eq!(dropped.load(Ordering::Relaxed), urls.len());
    }
}
