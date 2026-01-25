use crate::error::{AuditError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

const BASELINE_FILENAME: &str = ".cc-audit-baseline.json";

/// Represents a baseline snapshot for drift detection (rug pull prevention)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    /// Version of the baseline format
    pub version: String,
    /// When the baseline was created
    pub created_at: String,
    /// Hash of each scanned file
    pub file_hashes: HashMap<String, FileHash>,
    /// Total number of files
    pub file_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHash {
    pub hash: String,
    pub size: u64,
}

/// Result of drift detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftReport {
    /// Files that were modified since baseline
    pub modified: Vec<DriftEntry>,
    /// Files that were added since baseline
    pub added: Vec<String>,
    /// Files that were removed since baseline
    pub removed: Vec<String>,
    /// Whether any drift was detected
    pub has_drift: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftEntry {
    pub path: String,
    pub baseline_hash: String,
    pub current_hash: String,
}

impl Baseline {
    /// Create a new baseline from a directory
    pub fn from_directory(dir: &Path) -> Result<Self> {
        let mut file_hashes = HashMap::new();

        if dir.is_file() {
            // Single file
            let hash = Self::hash_file(dir)?;
            file_hashes.insert(dir.display().to_string(), hash);
        } else if dir.is_dir() {
            // Directory - walk and hash all relevant files
            for entry in walkdir::WalkDir::new(dir)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file())
                .filter(|e| Self::is_relevant_file(e.path()))
            {
                let path = entry.path();
                let relative_path = path.strip_prefix(dir).unwrap_or(path).display().to_string();
                let hash = Self::hash_file(path)?;
                file_hashes.insert(relative_path, hash);
            }
        }

        let file_count = file_hashes.len();

        Ok(Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            file_hashes,
            file_count,
        })
    }

    /// Check if a file is relevant for baseline (config, skill, mcp files)
    fn is_relevant_file(path: &Path) -> bool {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default()
            .to_lowercase();

        // Include common configuration and skill files
        matches!(
            ext.as_str(),
            "md" | "json" | "yaml" | "yml" | "toml" | "sh" | "bash" | "zsh"
        ) || matches!(
            name.to_lowercase().as_str(),
            "skill.md"
                | "mcp.json"
                | ".mcp.json"
                | "settings.json"
                | "dockerfile"
                | "package.json"
                | "cargo.toml"
                | "requirements.txt"
        )
    }

    /// Hash a single file
    fn hash_file(path: &Path) -> Result<FileHash> {
        let content = fs::read(path).map_err(|e| AuditError::ReadError {
            path: path.display().to_string(),
            source: e,
        })?;

        let mut hasher = Sha256::new();
        hasher.update(&content);
        let hash = format!("{:x}", hasher.finalize());

        let metadata = fs::metadata(path).map_err(|e| AuditError::ReadError {
            path: path.display().to_string(),
            source: e,
        })?;

        Ok(FileHash {
            hash,
            size: metadata.len(),
        })
    }

    /// Save baseline to file
    pub fn save(&self, dir: &Path) -> Result<()> {
        let baseline_path = if dir.is_file() {
            dir.parent()
                .unwrap_or(Path::new("."))
                .join(BASELINE_FILENAME)
        } else {
            dir.join(BASELINE_FILENAME)
        };

        let json = serde_json::to_string_pretty(self).map_err(|e| AuditError::ParseError {
            path: baseline_path.display().to_string(),
            message: e.to_string(),
        })?;

        fs::write(&baseline_path, json).map_err(|e| AuditError::ReadError {
            path: baseline_path.display().to_string(),
            source: e,
        })?;

        Ok(())
    }

    /// Load baseline from file
    pub fn load(dir: &Path) -> Result<Self> {
        let baseline_path = if dir.is_file() {
            dir.parent()
                .unwrap_or(Path::new("."))
                .join(BASELINE_FILENAME)
        } else {
            dir.join(BASELINE_FILENAME)
        };

        if !baseline_path.exists() {
            return Err(AuditError::FileNotFound(
                baseline_path.display().to_string(),
            ));
        }

        let content = fs::read_to_string(&baseline_path).map_err(|e| AuditError::ReadError {
            path: baseline_path.display().to_string(),
            source: e,
        })?;

        serde_json::from_str(&content).map_err(|e| AuditError::ParseError {
            path: baseline_path.display().to_string(),
            message: e.to_string(),
        })
    }

    /// Check for drift against current state
    pub fn check_drift(&self, dir: &Path) -> Result<DriftReport> {
        let current = Self::from_directory(dir)?;

        let mut modified = Vec::new();
        let mut added = Vec::new();
        let mut removed = Vec::new();

        // Check for modified and removed files
        for (path, baseline_hash) in &self.file_hashes {
            match current.file_hashes.get(path) {
                Some(current_hash) => {
                    if baseline_hash.hash != current_hash.hash {
                        modified.push(DriftEntry {
                            path: path.clone(),
                            baseline_hash: baseline_hash.hash.clone(),
                            current_hash: current_hash.hash.clone(),
                        });
                    }
                }
                None => {
                    removed.push(path.clone());
                }
            }
        }

        // Check for added files
        for path in current.file_hashes.keys() {
            if !self.file_hashes.contains_key(path) {
                added.push(path.clone());
            }
        }

        let has_drift = !modified.is_empty() || !added.is_empty() || !removed.is_empty();

        Ok(DriftReport {
            modified,
            added,
            removed,
            has_drift,
        })
    }
}

impl DriftReport {
    /// Format the drift report for terminal output
    pub fn format_terminal(&self) -> String {
        use colored::Colorize;

        let mut output = String::new();

        if !self.has_drift {
            output.push_str(
                &"No drift detected. Baseline is up to date.\n"
                    .green()
                    .to_string(),
            );
            return output;
        }

        output.push_str(&format!(
            "{}\n\n",
            "━━━ DRIFT DETECTED (Rug Pull Alert) ━━━".red().bold()
        ));

        if !self.modified.is_empty() {
            output.push_str(&format!("{}\n", "Modified files:".yellow().bold()));
            for entry in &self.modified {
                output.push_str(&format!("  {} {}\n", "~".yellow(), entry.path));
                let baseline_display = if entry.baseline_hash.len() >= 16 {
                    &entry.baseline_hash[..16]
                } else {
                    &entry.baseline_hash
                };
                let current_display = if entry.current_hash.len() >= 16 {
                    &entry.current_hash[..16]
                } else {
                    &entry.current_hash
                };
                output.push_str(&format!("    Baseline: {}\n", baseline_display));
                output.push_str(&format!("    Current:  {}\n", current_display));
            }
            output.push('\n');
        }

        if !self.added.is_empty() {
            output.push_str(&format!("{}\n", "Added files:".green().bold()));
            for path in &self.added {
                output.push_str(&format!("  {} {}\n", "+".green(), path));
            }
            output.push('\n');
        }

        if !self.removed.is_empty() {
            output.push_str(&format!("{}\n", "Removed files:".red().bold()));
            for path in &self.removed {
                output.push_str(&format!("  {} {}\n", "-".red(), path));
            }
            output.push('\n');
        }

        output.push_str(&format!(
            "Summary: {} modified, {} added, {} removed\n",
            self.modified.len(),
            self.added.len(),
            self.removed.len()
        ));

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_baseline_from_directory() {
        let temp_dir = TempDir::new().unwrap();
        let skill_md = temp_dir.path().join("SKILL.md");
        fs::write(&skill_md, "# Test Skill").unwrap();

        let baseline = Baseline::from_directory(temp_dir.path()).unwrap();
        assert_eq!(baseline.file_count, 1);
        assert!(baseline.file_hashes.contains_key("SKILL.md"));
    }

    #[test]
    fn test_baseline_save_and_load() {
        let temp_dir = TempDir::new().unwrap();
        let skill_md = temp_dir.path().join("SKILL.md");
        fs::write(&skill_md, "# Test Skill").unwrap();

        let baseline = Baseline::from_directory(temp_dir.path()).unwrap();
        baseline.save(temp_dir.path()).unwrap();

        let loaded = Baseline::load(temp_dir.path()).unwrap();
        assert_eq!(baseline.file_count, loaded.file_count);
    }

    #[test]
    fn test_drift_detection_no_changes() {
        let temp_dir = TempDir::new().unwrap();
        let skill_md = temp_dir.path().join("SKILL.md");
        fs::write(&skill_md, "# Test Skill").unwrap();

        let baseline = Baseline::from_directory(temp_dir.path()).unwrap();
        let drift = baseline.check_drift(temp_dir.path()).unwrap();

        assert!(!drift.has_drift);
        assert!(drift.modified.is_empty());
        assert!(drift.added.is_empty());
        assert!(drift.removed.is_empty());
    }

    #[test]
    fn test_drift_detection_modified_file() {
        let temp_dir = TempDir::new().unwrap();
        let skill_md = temp_dir.path().join("SKILL.md");
        fs::write(&skill_md, "# Test Skill").unwrap();

        let baseline = Baseline::from_directory(temp_dir.path()).unwrap();

        // Modify the file
        fs::write(&skill_md, "# Modified Skill with malicious content").unwrap();

        let drift = baseline.check_drift(temp_dir.path()).unwrap();

        assert!(drift.has_drift);
        assert_eq!(drift.modified.len(), 1);
        assert_eq!(drift.modified[0].path, "SKILL.md");
    }

    #[test]
    fn test_drift_detection_added_file() {
        let temp_dir = TempDir::new().unwrap();
        let skill_md = temp_dir.path().join("SKILL.md");
        fs::write(&skill_md, "# Test Skill").unwrap();

        let baseline = Baseline::from_directory(temp_dir.path()).unwrap();

        // Add a new file
        let new_file = temp_dir.path().join("mcp.json");
        fs::write(&new_file, "{}").unwrap();

        let drift = baseline.check_drift(temp_dir.path()).unwrap();

        assert!(drift.has_drift);
        assert_eq!(drift.added.len(), 1);
        assert!(drift.added.contains(&"mcp.json".to_string()));
    }

    #[test]
    fn test_drift_detection_removed_file() {
        let temp_dir = TempDir::new().unwrap();
        let skill_md = temp_dir.path().join("SKILL.md");
        fs::write(&skill_md, "# Test Skill").unwrap();

        let baseline = Baseline::from_directory(temp_dir.path()).unwrap();

        // Remove the file
        fs::remove_file(&skill_md).unwrap();

        let drift = baseline.check_drift(temp_dir.path()).unwrap();

        assert!(drift.has_drift);
        assert_eq!(drift.removed.len(), 1);
        assert!(drift.removed.contains(&"SKILL.md".to_string()));
    }

    #[test]
    fn test_hash_consistency() {
        let temp_dir = TempDir::new().unwrap();
        let skill_md = temp_dir.path().join("SKILL.md");
        fs::write(&skill_md, "# Test Skill").unwrap();

        let hash1 = Baseline::hash_file(&skill_md).unwrap();
        let hash2 = Baseline::hash_file(&skill_md).unwrap();

        assert_eq!(hash1.hash, hash2.hash);
    }

    #[test]
    fn test_baseline_load_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let result = Baseline::load(temp_dir.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_drift_report_format() {
        let report = DriftReport {
            modified: vec![DriftEntry {
                path: "SKILL.md".to_string(),
                // SHA-256 hash is 64 characters, code displays first 16
                baseline_hash: "abc123def456789012345678901234567890123456789012345678901234"
                    .to_string(),
                current_hash: "def456abc123789012345678901234567890123456789012345678901234"
                    .to_string(),
            }],
            added: vec!["new.json".to_string()],
            removed: vec!["old.md".to_string()],
            has_drift: true,
        };

        let output = report.format_terminal();
        assert!(output.contains("DRIFT DETECTED"));
        assert!(output.contains("Modified files"));
        assert!(output.contains("Added files"));
        assert!(output.contains("Removed files"));
    }
}
