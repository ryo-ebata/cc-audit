pub mod hook;
pub mod skill;

use crate::error::{AuditError, Result};
use crate::rules::Finding;
use std::path::Path;

pub use hook::HookScanner;
pub use skill::SkillScanner;

pub trait Scanner {
    fn scan_file(&self, path: &Path) -> Result<Vec<Finding>>;
    fn scan_directory(&self, dir: &Path) -> Result<Vec<Finding>>;

    fn scan_path(&self, path: &Path) -> Result<Vec<Finding>> {
        if !path.exists() {
            return Err(AuditError::FileNotFound(path.display().to_string()));
        }

        if path.is_file() {
            return self.scan_file(path);
        }

        if !path.is_dir() {
            return Err(AuditError::NotADirectory(path.display().to_string()));
        }

        self.scan_directory(path)
    }
}
