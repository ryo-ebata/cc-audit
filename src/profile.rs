use crate::error::{AuditError, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// A named scan profile containing preset configurations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub strict: bool,
    #[serde(default)]
    pub recursive: bool,
    #[serde(default)]
    pub ci: bool,
    #[serde(default)]
    pub verbose: bool,
    #[serde(default)]
    pub skip_comments: bool,
    #[serde(default)]
    pub fix_hint: bool,
    #[serde(default)]
    pub no_malware_scan: bool,
    #[serde(default)]
    pub deep_scan: bool,
    #[serde(default)]
    pub min_confidence: String,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub scan_type: Option<String>,
    #[serde(default)]
    pub disabled_rules: Vec<String>,
}

impl Profile {
    /// Get a built-in profile by name
    pub fn builtin(name: &str) -> Option<Self> {
        match name {
            "default" => Some(Self::default_profile()),
            "strict" => Some(Self::strict_profile()),
            "ci" => Some(Self::ci_profile()),
            "quick" => Some(Self::quick_profile()),
            _ => None,
        }
    }

    fn default_profile() -> Self {
        Self {
            name: "default".to_string(),
            description: "Default balanced scan configuration".to_string(),
            strict: false,
            recursive: true,
            ci: false,
            verbose: false,
            skip_comments: false,
            fix_hint: false,
            no_malware_scan: false,
            deep_scan: false,
            min_confidence: "tentative".to_string(),
            format: None,
            scan_type: None,
            disabled_rules: vec![],
        }
    }

    fn strict_profile() -> Self {
        Self {
            name: "strict".to_string(),
            description: "Strict mode - all findings reported, no rules disabled".to_string(),
            strict: true,
            recursive: true,
            ci: false,
            verbose: true,
            skip_comments: false,
            fix_hint: true,
            no_malware_scan: false,
            deep_scan: true,
            min_confidence: "tentative".to_string(),
            format: None,
            scan_type: None,
            disabled_rules: vec![],
        }
    }

    fn ci_profile() -> Self {
        Self {
            name: "ci".to_string(),
            description: "CI/CD optimized - non-interactive, JSON output".to_string(),
            strict: true,
            recursive: true,
            ci: true,
            verbose: false,
            skip_comments: true,
            fix_hint: false,
            no_malware_scan: false,
            deep_scan: false,
            min_confidence: "firm".to_string(),
            format: Some("json".to_string()),
            scan_type: None,
            disabled_rules: vec![],
        }
    }

    fn quick_profile() -> Self {
        Self {
            name: "quick".to_string(),
            description: "Quick scan - high confidence only, no deep scan".to_string(),
            strict: false,
            recursive: true,
            ci: false,
            verbose: false,
            skip_comments: true,
            fix_hint: false,
            no_malware_scan: true, // Skip malware scan for speed
            deep_scan: false,
            min_confidence: "certain".to_string(),
            format: None,
            scan_type: None,
            disabled_rules: vec![],
        }
    }

    /// Load a profile from the profiles directory
    pub fn load(name: &str) -> Result<Self> {
        // First try built-in profiles
        if let Some(profile) = Self::builtin(name) {
            return Ok(profile);
        }

        // Then try user profiles
        let profile_path = Self::get_profile_path(name)?;

        if !profile_path.exists() {
            return Err(AuditError::FileNotFound(format!(
                "Profile '{}' not found. Available built-in profiles: default, strict, ci, quick",
                name
            )));
        }

        let content = fs::read_to_string(&profile_path).map_err(|e| AuditError::ReadError {
            path: profile_path.display().to_string(),
            source: e,
        })?;

        serde_yaml::from_str(&content).map_err(|e| AuditError::ParseError {
            path: profile_path.display().to_string(),
            message: e.to_string(),
        })
    }

    /// Save a profile to the profiles directory
    pub fn save(&self) -> Result<PathBuf> {
        let profiles_dir = Self::get_profiles_dir()?;
        fs::create_dir_all(&profiles_dir).map_err(|e| AuditError::ReadError {
            path: profiles_dir.display().to_string(),
            source: e,
        })?;

        let profile_path = profiles_dir.join(format!("{}.yaml", self.name));

        let content = serde_yaml::to_string(self).map_err(|e| AuditError::ParseError {
            path: profile_path.display().to_string(),
            message: e.to_string(),
        })?;

        fs::write(&profile_path, content).map_err(|e| AuditError::ReadError {
            path: profile_path.display().to_string(),
            source: e,
        })?;

        Ok(profile_path)
    }

    /// List all available profiles (built-in and user)
    pub fn list_all() -> Vec<String> {
        let mut profiles = vec![
            "default".to_string(),
            "strict".to_string(),
            "ci".to_string(),
            "quick".to_string(),
        ];

        // Add user profiles
        if let Ok(dir) = Self::get_profiles_dir()
            && let Ok(entries) = fs::read_dir(dir)
        {
            for entry in entries.flatten() {
                if let Some(name) = entry.path().file_stem()
                    && let Some(name_str) = name.to_str()
                    && !profiles.contains(&name_str.to_string())
                {
                    profiles.push(name_str.to_string());
                }
            }
        }

        profiles
    }

    fn get_profiles_dir() -> Result<PathBuf> {
        let home = dirs::home_dir().ok_or_else(|| {
            AuditError::FileNotFound("Could not determine home directory".to_string())
        })?;

        Ok(home.join(".config").join("cc-audit").join("profiles"))
    }

    fn get_profile_path(name: &str) -> Result<PathBuf> {
        let profiles_dir = Self::get_profiles_dir()?;
        Ok(profiles_dir.join(format!("{}.yaml", name)))
    }

    /// Apply profile settings to effective config
    pub fn apply_to_config(&self, config: &mut crate::config::ScanConfig) {
        config.strict = config.strict || self.strict;
        config.recursive = config.recursive || self.recursive;
        config.ci = config.ci || self.ci;
        config.verbose = config.verbose || self.verbose;
        config.skip_comments = config.skip_comments || self.skip_comments;
        config.fix_hint = config.fix_hint || self.fix_hint;
        config.no_malware_scan = config.no_malware_scan || self.no_malware_scan;

        if !self.min_confidence.is_empty() && config.min_confidence.is_none() {
            config.min_confidence = Some(self.min_confidence.clone());
        }

        if let Some(ref format) = self.format
            && config.format.is_none()
        {
            config.format = Some(format.clone());
        }

        if let Some(ref scan_type) = self.scan_type
            && config.scan_type.is_none()
        {
            config.scan_type = Some(scan_type.clone());
        }
    }
}

impl Default for Profile {
    fn default() -> Self {
        Self::default_profile()
    }
}

/// Create a profile from CheckArgs settings
pub fn profile_from_check_args(name: &str, args: &crate::CheckArgs, verbose: bool) -> Profile {
    Profile {
        name: name.to_string(),
        description: "Custom profile saved from CLI settings".to_string(),
        strict: args.strict,
        recursive: !args.no_recursive,
        ci: args.ci,
        verbose,
        skip_comments: args.skip_comments,
        fix_hint: args.fix_hint,
        no_malware_scan: args.no_malware_scan,
        deep_scan: args.deep_scan,
        min_confidence: args
            .min_confidence
            .map(|c| format!("{:?}", c).to_lowercase())
            .unwrap_or_else(|| "tentative".to_string()),
        format: Some(format!("{:?}", args.format).to_lowercase()),
        scan_type: Some(format!("{:?}", args.scan_type).to_lowercase()),
        disabled_rules: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ScanConfig;

    #[test]
    fn test_builtin_profiles() {
        assert!(Profile::builtin("default").is_some());
        assert!(Profile::builtin("strict").is_some());
        assert!(Profile::builtin("ci").is_some());
        assert!(Profile::builtin("quick").is_some());
        assert!(Profile::builtin("nonexistent").is_none());
    }

    #[test]
    fn test_default_profile() {
        let profile = Profile::default_profile();
        assert_eq!(profile.name, "default");
        assert!(!profile.strict);
        assert!(profile.recursive);
    }

    #[test]
    fn test_strict_profile() {
        let profile = Profile::strict_profile();
        assert_eq!(profile.name, "strict");
        assert!(profile.strict);
        assert!(profile.verbose);
        assert!(profile.deep_scan);
    }

    #[test]
    fn test_ci_profile() {
        let profile = Profile::ci_profile();
        assert_eq!(profile.name, "ci");
        assert!(profile.ci);
        assert!(profile.strict);
        assert_eq!(profile.format, Some("json".to_string()));
    }

    #[test]
    fn test_quick_profile() {
        let profile = Profile::quick_profile();
        assert_eq!(profile.name, "quick");
        assert!(profile.no_malware_scan);
        assert!(!profile.deep_scan);
        assert_eq!(profile.min_confidence, "certain");
    }

    #[test]
    fn test_list_all_includes_builtins() {
        let profiles = Profile::list_all();
        assert!(profiles.contains(&"default".to_string()));
        assert!(profiles.contains(&"strict".to_string()));
        assert!(profiles.contains(&"ci".to_string()));
        assert!(profiles.contains(&"quick".to_string()));
    }

    #[test]
    fn test_profile_serialize_deserialize() {
        let profile = Profile::strict_profile();
        let yaml = serde_yaml::to_string(&profile).unwrap();
        let parsed: Profile = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(profile.name, parsed.name);
        assert_eq!(profile.strict, parsed.strict);
    }

    #[test]
    fn test_default_trait() {
        let profile = Profile::default();
        assert_eq!(profile.name, "default");
    }

    #[test]
    fn test_load_builtin_profile() {
        let profile = Profile::load("default").unwrap();
        assert_eq!(profile.name, "default");

        let profile = Profile::load("strict").unwrap();
        assert_eq!(profile.name, "strict");
    }

    #[test]
    fn test_load_nonexistent_profile() {
        let result = Profile::load("nonexistent_profile_xyz");
        assert!(result.is_err());
    }

    #[test]
    fn test_apply_to_config_basic() {
        let profile = Profile::strict_profile();
        let mut config = ScanConfig::default();

        profile.apply_to_config(&mut config);

        assert!(config.strict);
        assert!(config.verbose);
        assert!(config.fix_hint);
    }

    #[test]
    fn test_apply_to_config_min_confidence() {
        let profile = Profile::ci_profile();
        let mut config = ScanConfig::default();

        profile.apply_to_config(&mut config);

        assert_eq!(config.min_confidence, Some("firm".to_string()));
    }

    #[test]
    fn test_apply_to_config_format() {
        let profile = Profile::ci_profile();
        let mut config = ScanConfig::default();

        profile.apply_to_config(&mut config);

        assert_eq!(config.format, Some("json".to_string()));
    }

    #[test]
    fn test_apply_to_config_does_not_override_existing() {
        let profile = Profile::ci_profile();
        let mut config = ScanConfig {
            format: Some("sarif".to_string()),
            min_confidence: Some("certain".to_string()),
            ..Default::default()
        };

        profile.apply_to_config(&mut config);

        // Existing values should not be overridden
        assert_eq!(config.format, Some("sarif".to_string()));
        assert_eq!(config.min_confidence, Some("certain".to_string()));
    }

    #[test]
    fn test_apply_to_config_scan_type() {
        let mut profile = Profile::default_profile();
        profile.scan_type = Some("hook".to_string());
        let mut config = ScanConfig::default();

        profile.apply_to_config(&mut config);

        assert_eq!(config.scan_type, Some("hook".to_string()));
    }

    #[test]
    fn test_apply_to_config_no_malware_scan() {
        let profile = Profile::quick_profile();
        let mut config = ScanConfig::default();

        profile.apply_to_config(&mut config);

        assert!(config.no_malware_scan);
    }

    #[test]
    fn test_apply_to_config_empty_min_confidence() {
        let mut profile = Profile::default_profile();
        profile.min_confidence = String::new();
        let mut config = ScanConfig::default();

        profile.apply_to_config(&mut config);

        // Empty min_confidence should not set config
        assert!(config.min_confidence.is_none());
    }

    #[test]
    fn test_get_profiles_dir() {
        let result = Profile::get_profiles_dir();
        assert!(result.is_ok());
        let path = result.unwrap();
        assert!(path.ends_with("profiles"));
    }

    #[test]
    fn test_get_profile_path() {
        let result = Profile::get_profile_path("test_profile");
        assert!(result.is_ok());
        let path = result.unwrap();
        assert!(path.ends_with("test_profile.yaml"));
    }

    #[test]
    fn test_profile_debug_trait() {
        let profile = Profile::default();
        let debug_str = format!("{:?}", profile);
        assert!(debug_str.contains("Profile"));
        assert!(debug_str.contains("default"));
    }

    #[test]
    fn test_profile_clone_trait() {
        let profile = Profile::strict_profile();
        let cloned = profile.clone();
        assert_eq!(profile.name, cloned.name);
        assert_eq!(profile.strict, cloned.strict);
    }

    #[test]
    fn test_profile_from_check_args() {
        use crate::CheckArgs;

        let args = CheckArgs {
            strict: true,
            ..Default::default()
        };
        let profile = profile_from_check_args("test_profile", &args, true);

        assert_eq!(profile.name, "test_profile");
        assert!(profile.strict);
        assert!(profile.verbose);
        assert!(profile.description.contains("Custom profile"));
    }

    #[test]
    fn test_profile_from_check_args_with_options() {
        use crate::CheckArgs;

        let args = CheckArgs {
            skip_comments: true,
            fix_hint: true,
            no_malware_scan: true,
            deep_scan: true,
            ..Default::default()
        };
        let profile = profile_from_check_args("custom", &args, false);

        assert!(profile.skip_comments);
        assert!(profile.fix_hint);
        assert!(profile.no_malware_scan);
        assert!(profile.deep_scan);
    }

    #[test]
    fn test_profile_from_check_args_format_and_type() {
        use crate::{CheckArgs, OutputFormat, ScanType};

        let args = CheckArgs {
            format: OutputFormat::Json,
            scan_type: ScanType::Hook,
            ..Default::default()
        };
        let profile = profile_from_check_args("json_profile", &args, false);

        assert!(profile.format.is_some());
        assert!(profile.scan_type.is_some());
    }

    #[test]
    fn test_profile_save_and_load() {
        // This test creates a temp profile and verifies it can be saved and loaded
        // Note: This writes to the user's config directory
        let profile = Profile {
            name: "test_save_load_unique_12345".to_string(),
            description: "Test profile for save/load".to_string(),
            strict: true,
            recursive: true,
            ci: false,
            verbose: true,
            skip_comments: false,
            fix_hint: true,
            no_malware_scan: false,
            deep_scan: true,
            min_confidence: "firm".to_string(),
            format: Some("json".to_string()),
            scan_type: Some("hook".to_string()),
            disabled_rules: vec!["PE-001".to_string()],
        };

        // Save the profile
        let save_result = profile.save();
        assert!(save_result.is_ok());
        let saved_path = save_result.unwrap();
        assert!(saved_path.exists());

        // Load the profile back
        let loaded = Profile::load("test_save_load_unique_12345");
        assert!(loaded.is_ok());
        let loaded_profile = loaded.unwrap();
        assert_eq!(loaded_profile.name, "test_save_load_unique_12345");
        assert!(loaded_profile.strict);
        assert!(loaded_profile.deep_scan);
        assert_eq!(loaded_profile.format, Some("json".to_string()));

        // Clean up
        let _ = fs::remove_file(saved_path);
    }

    #[test]
    fn test_apply_to_config_recursive() {
        let profile = Profile::default_profile();
        let mut config = ScanConfig {
            recursive: false,
            ..Default::default()
        };

        profile.apply_to_config(&mut config);

        // Profile has recursive=true, so it should be true after apply
        assert!(config.recursive);
    }

    #[test]
    fn test_apply_to_config_ci() {
        let profile = Profile::ci_profile();
        let mut config = ScanConfig::default();

        profile.apply_to_config(&mut config);

        assert!(config.ci);
    }

    #[test]
    fn test_apply_to_config_skip_comments() {
        let profile = Profile::quick_profile();
        let mut config = ScanConfig::default();

        profile.apply_to_config(&mut config);

        assert!(config.skip_comments);
    }

    #[test]
    fn test_profile_disabled_rules() {
        let profile = Profile {
            name: "test".to_string(),
            description: "Test".to_string(),
            strict: false,
            recursive: true,
            ci: false,
            verbose: false,
            skip_comments: false,
            fix_hint: false,
            no_malware_scan: false,
            deep_scan: false,
            min_confidence: "tentative".to_string(),
            format: None,
            scan_type: None,
            disabled_rules: vec!["PE-001".to_string(), "SC-001".to_string()],
        };

        assert_eq!(profile.disabled_rules.len(), 2);
        assert!(profile.disabled_rules.contains(&"PE-001".to_string()));
    }

    #[test]
    fn test_profile_from_check_args_ci_mode() {
        use crate::CheckArgs;

        let args = CheckArgs {
            ci: true,
            ..Default::default()
        };
        let profile = profile_from_check_args("ci_profile", &args, false);

        assert!(profile.ci);
        assert!(profile.recursive); // default is recursive (no_recursive=false)
    }

    #[test]
    fn test_profile_from_check_args_recursive() {
        use crate::CheckArgs;

        let args = CheckArgs {
            no_recursive: false, // recursive enabled
            ..Default::default()
        };
        let profile = profile_from_check_args("recursive_profile", &args, false);

        assert!(profile.recursive);
    }

    #[test]
    fn test_profile_from_check_args_no_recursive() {
        use crate::CheckArgs;

        let args = CheckArgs {
            no_recursive: true, // recursive disabled
            ..Default::default()
        };
        let profile = profile_from_check_args("non_recursive_profile", &args, false);

        assert!(!profile.recursive);
    }

    #[test]
    fn test_list_all_includes_user_profiles() {
        // Save a user profile
        let profile = Profile {
            name: "test_user_profile_list_all".to_string(),
            description: "Test user profile".to_string(),
            strict: false,
            recursive: true,
            ci: false,
            verbose: false,
            skip_comments: false,
            fix_hint: false,
            no_malware_scan: false,
            deep_scan: false,
            min_confidence: "tentative".to_string(),
            format: None,
            scan_type: None,
            disabled_rules: vec![],
        };

        let save_result = profile.save();
        assert!(save_result.is_ok());
        let saved_path = save_result.unwrap();

        // list_all should include the user profile
        let profiles = Profile::list_all();
        assert!(profiles.contains(&"test_user_profile_list_all".to_string()));

        // Clean up
        let _ = fs::remove_file(saved_path);
    }

    #[test]
    fn test_load_user_profile_from_file() {
        // Save a user profile
        let profile = Profile {
            name: "test_load_user_profile".to_string(),
            description: "Test for loading".to_string(),
            strict: true,
            recursive: false,
            ci: true,
            verbose: true,
            skip_comments: true,
            fix_hint: true,
            no_malware_scan: true,
            deep_scan: true,
            min_confidence: "certain".to_string(),
            format: Some("sarif".to_string()),
            scan_type: Some("docker".to_string()),
            disabled_rules: vec!["PE-001".to_string()],
        };

        let save_result = profile.save();
        assert!(save_result.is_ok());
        let saved_path = save_result.unwrap();

        // Load the profile back
        let loaded = Profile::load("test_load_user_profile");
        assert!(loaded.is_ok());
        let loaded_profile = loaded.unwrap();

        assert_eq!(loaded_profile.name, "test_load_user_profile");
        assert!(loaded_profile.strict);
        assert!(!loaded_profile.recursive);
        assert!(loaded_profile.ci);
        assert!(loaded_profile.verbose);
        assert!(loaded_profile.skip_comments);
        assert!(loaded_profile.fix_hint);
        assert!(loaded_profile.no_malware_scan);
        assert!(loaded_profile.deep_scan);
        assert_eq!(loaded_profile.min_confidence, "certain");
        assert_eq!(loaded_profile.format, Some("sarif".to_string()));
        assert_eq!(loaded_profile.scan_type, Some("docker".to_string()));
        assert_eq!(loaded_profile.disabled_rules, vec!["PE-001".to_string()]);

        // Clean up
        let _ = fs::remove_file(saved_path);
    }

    #[test]
    fn test_apply_to_config_with_none_format() {
        let mut profile = Profile::default_profile();
        profile.format = None;
        let config = ScanConfig {
            format: None,
            ..Default::default()
        };
        let mut config = config;

        profile.apply_to_config(&mut config);

        // Format should remain None
        assert!(config.format.is_none());
    }

    #[test]
    fn test_apply_to_config_with_none_scan_type() {
        let mut profile = Profile::default_profile();
        profile.scan_type = None;
        let config = ScanConfig {
            scan_type: None,
            ..Default::default()
        };
        let mut config = config;

        profile.apply_to_config(&mut config);

        // scan_type should remain None
        assert!(config.scan_type.is_none());
    }

    #[test]
    fn test_profile_with_all_fields() {
        let profile = Profile {
            name: "complete".to_string(),
            description: "Complete profile with all fields".to_string(),
            strict: true,
            recursive: true,
            ci: true,
            verbose: true,
            skip_comments: true,
            fix_hint: true,
            no_malware_scan: true,
            deep_scan: true,
            min_confidence: "firm".to_string(),
            format: Some("html".to_string()),
            scan_type: Some("mcp".to_string()),
            disabled_rules: vec!["PE-001".to_string(), "SC-001".to_string()],
        };

        // Verify all fields
        assert_eq!(profile.name, "complete");
        assert!(profile.strict);
        assert!(profile.recursive);
        assert!(profile.ci);
        assert!(profile.verbose);
        assert!(profile.skip_comments);
        assert!(profile.fix_hint);
        assert!(profile.no_malware_scan);
        assert!(profile.deep_scan);
        assert_eq!(profile.min_confidence, "firm");
        assert_eq!(profile.format, Some("html".to_string()));
        assert_eq!(profile.scan_type, Some("mcp".to_string()));
        assert_eq!(profile.disabled_rules.len(), 2);
    }
}
