use ignore::gitignore::{Gitignore, GitignoreBuilder};
use std::path::Path;

#[derive(Default)]
pub struct IgnoreFilter {
    gitignore: Option<Gitignore>,
    include_tests: bool,
    include_node_modules: bool,
    include_vendor: bool,
}

impl IgnoreFilter {
    pub fn new(root: &Path) -> Self {
        let gitignore = Self::load_ignorefiles(root);

        Self {
            gitignore,
            include_tests: false,
            include_node_modules: false,
            include_vendor: false,
        }
    }

    pub fn with_include_tests(mut self, include: bool) -> Self {
        self.include_tests = include;
        self
    }

    pub fn with_include_node_modules(mut self, include: bool) -> Self {
        self.include_node_modules = include;
        self
    }

    pub fn with_include_vendor(mut self, include: bool) -> Self {
        self.include_vendor = include;
        self
    }

    fn load_ignorefiles(root: &Path) -> Option<Gitignore> {
        let mut builder = GitignoreBuilder::new(root);
        let mut has_patterns = false;

        // Load .gitignore first (if it exists and there's a .git directory)
        let git_dir = root.join(".git");
        let gitignore_file = root.join(".gitignore");
        if git_dir.exists() && gitignore_file.exists() && builder.add(&gitignore_file).is_none() {
            has_patterns = true;
        }

        // Load .cc-auditignore (overrides/extends .gitignore)
        let cc_audit_ignore = root.join(".cc-auditignore");
        if cc_audit_ignore.exists() && builder.add(&cc_audit_ignore).is_none() {
            has_patterns = true;
        }

        if has_patterns {
            builder.build().ok()
        } else {
            None
        }
    }

    pub fn is_ignored(&self, path: &Path) -> bool {
        // Check default exclusions first
        if !self.include_tests && self.is_test_path(path) {
            return true;
        }

        if !self.include_node_modules && self.is_node_modules_path(path) {
            return true;
        }

        if !self.include_vendor && self.is_vendor_path(path) {
            return true;
        }

        // Check .cc-auditignore patterns
        if let Some(ref gitignore) = self.gitignore {
            let is_dir = path.is_dir();
            return gitignore.matched(path, is_dir).is_ignore();
        }

        false
    }

    fn is_test_path(&self, path: &Path) -> bool {
        path.components().any(|c| {
            let name = c.as_os_str().to_string_lossy();
            name == "tests"
                || name == "test"
                || name == "__tests__"
                || name == "spec"
                || name == "specs"
                || name.ends_with("_test")
                || name.ends_with(".test")
        })
    }

    fn is_node_modules_path(&self, path: &Path) -> bool {
        path.components()
            .any(|c| c.as_os_str().to_string_lossy() == "node_modules")
    }

    fn is_vendor_path(&self, path: &Path) -> bool {
        path.components().any(|c| {
            let name = c.as_os_str().to_string_lossy();
            name == "vendor" || name == "vendors" || name == "third_party"
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_default_excludes_tests() {
        let dir = TempDir::new().unwrap();
        let filter = IgnoreFilter::new(dir.path());

        assert!(filter.is_ignored(Path::new("/project/tests/test_file.rs")));
        assert!(filter.is_ignored(Path::new("/project/__tests__/spec.js")));
        assert!(filter.is_ignored(Path::new("/project/spec/helpers.rb")));
        assert!(!filter.is_ignored(Path::new("/project/src/main.rs")));
    }

    #[test]
    fn test_default_excludes_node_modules() {
        let dir = TempDir::new().unwrap();
        let filter = IgnoreFilter::new(dir.path());

        assert!(filter.is_ignored(Path::new("/project/node_modules/package/index.js")));
        assert!(!filter.is_ignored(Path::new("/project/src/index.js")));
    }

    #[test]
    fn test_default_excludes_vendor() {
        let dir = TempDir::new().unwrap();
        let filter = IgnoreFilter::new(dir.path());

        assert!(filter.is_ignored(Path::new("/project/vendor/bundle/gems")));
        assert!(filter.is_ignored(Path::new("/project/third_party/lib")));
        assert!(!filter.is_ignored(Path::new("/project/src/lib")));
    }

    #[test]
    fn test_include_tests() {
        let dir = TempDir::new().unwrap();
        let filter = IgnoreFilter::new(dir.path()).with_include_tests(true);

        assert!(!filter.is_ignored(Path::new("/project/tests/test_file.rs")));
    }

    #[test]
    fn test_include_node_modules() {
        let dir = TempDir::new().unwrap();
        let filter = IgnoreFilter::new(dir.path()).with_include_node_modules(true);

        assert!(!filter.is_ignored(Path::new("/project/node_modules/package/index.js")));
    }

    #[test]
    fn test_include_vendor() {
        let dir = TempDir::new().unwrap();
        let filter = IgnoreFilter::new(dir.path()).with_include_vendor(true);

        assert!(!filter.is_ignored(Path::new("/project/vendor/bundle/gems")));
    }

    #[test]
    fn test_custom_ignorefile() {
        let dir = TempDir::new().unwrap();
        let ignore_file = dir.path().join(".cc-auditignore");
        fs::write(&ignore_file, "*.generated.js\nbuild/\n").unwrap();

        let filter = IgnoreFilter::new(dir.path());

        let generated_file = dir.path().join("app.generated.js");
        fs::write(&generated_file, "").unwrap();

        assert!(filter.is_ignored(&generated_file));
    }

    #[test]
    fn test_no_ignorefile() {
        let dir = TempDir::new().unwrap();
        let filter = IgnoreFilter::new(dir.path());

        assert!(!filter.is_ignored(&dir.path().join("src/main.rs")));
    }

    #[test]
    fn test_default_trait() {
        let filter = IgnoreFilter::default();

        // Default should exclude tests, node_modules, vendor
        assert!(filter.is_ignored(Path::new("/project/tests/test.rs")));
        assert!(filter.is_ignored(Path::new("/project/node_modules/pkg")));
        assert!(filter.is_ignored(Path::new("/project/vendor/lib")));
    }

    #[test]
    fn test_chained_configuration() {
        let dir = TempDir::new().unwrap();
        let filter = IgnoreFilter::new(dir.path())
            .with_include_tests(true)
            .with_include_node_modules(true)
            .with_include_vendor(true);

        assert!(!filter.is_ignored(Path::new("/project/tests/test.rs")));
        assert!(!filter.is_ignored(Path::new("/project/node_modules/pkg")));
        assert!(!filter.is_ignored(Path::new("/project/vendor/lib")));
    }

    #[test]
    fn test_gitignore_patterns() {
        let dir = TempDir::new().unwrap();
        let ignore_file = dir.path().join(".cc-auditignore");
        fs::write(
            &ignore_file,
            r#"
# Comment
*.log
/dist/
!important.log
"#,
        )
        .unwrap();

        let filter = IgnoreFilter::new(dir.path());

        let log_file = dir.path().join("debug.log");
        fs::write(&log_file, "").unwrap();
        assert!(filter.is_ignored(&log_file));

        // Normal src file should not be ignored
        let src_file = dir.path().join("main.rs");
        fs::write(&src_file, "").unwrap();
        assert!(!filter.is_ignored(&src_file));
    }

    #[test]
    fn test_is_test_path_variations() {
        let filter = IgnoreFilter::default();

        assert!(filter.is_test_path(Path::new("/project/tests/unit")));
        assert!(filter.is_test_path(Path::new("/project/test/fixtures")));
        assert!(filter.is_test_path(Path::new("/project/__tests__/spec")));
        assert!(filter.is_test_path(Path::new("/project/spec/helpers")));
        assert!(filter.is_test_path(Path::new("/project/specs/api")));
        assert!(filter.is_test_path(Path::new("/project/file_test")));
        assert!(filter.is_test_path(Path::new("/project/api.test")));
        assert!(!filter.is_test_path(Path::new("/project/src/main.rs")));
        assert!(!filter.is_test_path(Path::new("/project/contest/app.js"))); // Should not match 'test' in 'contest'
    }
}
