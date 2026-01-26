//! Input source resolution.

use crate::cli::{Cli, ScanType};
use crate::client::{ClientType, DetectedClient, detect_client, detect_installed_clients};
use std::path::PathBuf;

/// The source of input for scanning.
#[derive(Debug, Clone)]
pub enum InputSource {
    /// Local file or directory paths specified by user.
    LocalPaths(Vec<PathBuf>),
    /// Remote repository URL.
    RemoteUrl {
        url: String,
        git_ref: String,
        auth_token: Option<String>,
    },
    /// List of remote repository URLs from a file.
    RemoteList {
        file: PathBuf,
        git_ref: String,
        auth_token: Option<String>,
    },
    /// All installed AI coding clients.
    AllClients,
    /// A specific AI coding client.
    SpecificClient(ClientType),
    /// Awesome Claude Code repositories.
    AwesomeClaudeCode,
}

impl InputSource {
    /// Determine the input source from CLI arguments.
    pub fn from_cli(cli: &Cli) -> Self {
        if cli.all_clients {
            return Self::AllClients;
        }

        if let Some(client) = cli.client {
            return Self::SpecificClient(client);
        }

        if let Some(ref url) = cli.remote {
            return Self::RemoteUrl {
                url: url.clone(),
                git_ref: cli.git_ref.clone(),
                auth_token: cli.remote_auth.clone(),
            };
        }

        if let Some(ref file) = cli.remote_list {
            return Self::RemoteList {
                file: file.clone(),
                git_ref: cli.git_ref.clone(),
                auth_token: cli.remote_auth.clone(),
            };
        }

        if cli.awesome_claude_code {
            return Self::AwesomeClaudeCode;
        }

        Self::LocalPaths(cli.paths.clone())
    }

    /// Check if this is a local source.
    pub fn is_local(&self) -> bool {
        matches!(
            self,
            Self::LocalPaths(_) | Self::AllClients | Self::SpecificClient(_)
        )
    }

    /// Check if this is a remote source.
    pub fn is_remote(&self) -> bool {
        matches!(
            self,
            Self::RemoteUrl { .. } | Self::RemoteList { .. } | Self::AwesomeClaudeCode
        )
    }
}

/// Resolves input sources to concrete scan targets.
pub struct SourceResolver;

impl SourceResolver {
    /// Resolve the input source to a list of paths to scan.
    pub fn resolve(cli: &Cli) -> ResolvedInput {
        let source = InputSource::from_cli(cli);

        match source {
            InputSource::LocalPaths(paths) => ResolvedInput {
                paths,
                source: ResolvedSource::Local,
                clients: Vec::new(),
            },
            InputSource::AllClients => {
                let clients = detect_installed_clients();
                let paths: Vec<PathBuf> = clients.iter().flat_map(|c| c.all_configs()).collect();

                ResolvedInput {
                    paths,
                    source: ResolvedSource::Client,
                    clients,
                }
            }
            InputSource::SpecificClient(client_type) => {
                let clients: Vec<DetectedClient> = detect_client(client_type).into_iter().collect();
                let paths: Vec<PathBuf> = clients.iter().flat_map(|c| c.all_configs()).collect();

                ResolvedInput {
                    paths,
                    source: ResolvedSource::Client,
                    clients,
                }
            }
            InputSource::RemoteUrl {
                url,
                git_ref,
                auth_token,
            } => ResolvedInput {
                paths: Vec::new(),
                source: ResolvedSource::Remote {
                    urls: vec![url],
                    git_ref,
                    auth_token,
                },
                clients: Vec::new(),
            },
            InputSource::RemoteList {
                file,
                git_ref,
                auth_token,
            } => {
                // URLs will be loaded from file later
                ResolvedInput {
                    paths: Vec::new(),
                    source: ResolvedSource::Remote {
                        urls: vec![file.to_string_lossy().to_string()],
                        git_ref,
                        auth_token,
                    },
                    clients: Vec::new(),
                }
            }
            InputSource::AwesomeClaudeCode => ResolvedInput {
                paths: Vec::new(),
                source: ResolvedSource::AwesomeClaudeCode,
                clients: Vec::new(),
            },
        }
    }

    /// Get the scan type from CLI or infer from input.
    pub fn scan_type(cli: &Cli) -> ScanType {
        cli.scan_type
    }
}

/// The source type after resolution.
#[derive(Debug, Clone)]
pub enum ResolvedSource {
    /// Local file system paths.
    Local,
    /// Client configuration paths.
    Client,
    /// Remote repository URLs.
    Remote {
        urls: Vec<String>,
        git_ref: String,
        auth_token: Option<String>,
    },
    /// Awesome Claude Code repositories.
    AwesomeClaudeCode,
}

/// Resolved input ready for scanning.
#[derive(Debug, Clone)]
pub struct ResolvedInput {
    /// Paths to scan (for local sources).
    pub paths: Vec<PathBuf>,
    /// The resolved source type.
    pub source: ResolvedSource,
    /// Detected clients (if source is Client).
    pub clients: Vec<DetectedClient>,
}

impl ResolvedInput {
    /// Check if there are any paths to scan.
    pub fn has_paths(&self) -> bool {
        !self.paths.is_empty()
    }

    /// Check if this is a remote source requiring clone.
    pub fn requires_clone(&self) -> bool {
        matches!(
            self.source,
            ResolvedSource::Remote { .. } | ResolvedSource::AwesomeClaudeCode
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_input_source_from_local_paths() {
        let cli = Cli {
            paths: vec![PathBuf::from("./test")],
            ..Default::default()
        };
        let source = InputSource::from_cli(&cli);
        assert!(matches!(source, InputSource::LocalPaths(_)));
        assert!(source.is_local());
        assert!(!source.is_remote());
    }

    #[test]
    fn test_input_source_all_clients() {
        let cli = Cli {
            all_clients: true,
            ..Default::default()
        };
        let source = InputSource::from_cli(&cli);
        assert!(matches!(source, InputSource::AllClients));
        assert!(source.is_local());
    }

    #[test]
    fn test_input_source_specific_client() {
        let cli = Cli {
            client: Some(ClientType::Claude),
            ..Default::default()
        };
        let source = InputSource::from_cli(&cli);
        assert!(matches!(
            source,
            InputSource::SpecificClient(ClientType::Claude)
        ));
        assert!(source.is_local());
    }

    #[test]
    fn test_input_source_remote_url() {
        let cli = Cli {
            remote: Some("https://github.com/user/repo".to_string()),
            git_ref: "main".to_string(),
            ..Default::default()
        };
        let source = InputSource::from_cli(&cli);
        assert!(matches!(source, InputSource::RemoteUrl { .. }));
        assert!(source.is_remote());
        assert!(!source.is_local());
    }

    #[test]
    fn test_input_source_awesome_claude_code() {
        let cli = Cli {
            awesome_claude_code: true,
            ..Default::default()
        };
        let source = InputSource::from_cli(&cli);
        assert!(matches!(source, InputSource::AwesomeClaudeCode));
        assert!(source.is_remote());
    }

    #[test]
    fn test_resolved_input_has_paths() {
        let input = ResolvedInput {
            paths: vec![PathBuf::from("./test")],
            source: ResolvedSource::Local,
            clients: Vec::new(),
        };
        assert!(input.has_paths());
        assert!(!input.requires_clone());

        let empty = ResolvedInput {
            paths: Vec::new(),
            source: ResolvedSource::Local,
            clients: Vec::new(),
        };
        assert!(!empty.has_paths());
    }

    #[test]
    fn test_resolved_input_requires_clone() {
        let remote = ResolvedInput {
            paths: Vec::new(),
            source: ResolvedSource::Remote {
                urls: vec!["https://github.com/user/repo".to_string()],
                git_ref: "main".to_string(),
                auth_token: None,
            },
            clients: Vec::new(),
        };
        assert!(remote.requires_clone());

        let awesome = ResolvedInput {
            paths: Vec::new(),
            source: ResolvedSource::AwesomeClaudeCode,
            clients: Vec::new(),
        };
        assert!(awesome.requires_clone());
    }

    #[test]
    fn test_input_source_remote_list() {
        let cli = Cli {
            remote_list: Some(PathBuf::from("repos.txt")),
            git_ref: "main".to_string(),
            remote_auth: Some("token123".to_string()),
            ..Default::default()
        };
        let source = InputSource::from_cli(&cli);
        match &source {
            InputSource::RemoteList {
                file,
                git_ref,
                auth_token,
            } => {
                assert_eq!(*file, PathBuf::from("repos.txt"));
                assert_eq!(*git_ref, "main");
                assert_eq!(*auth_token, Some("token123".to_string()));
            }
            _ => panic!("Expected RemoteList"),
        }
        assert!(source.is_remote());
    }

    #[test]
    fn test_input_source_remote_url_with_auth() {
        let cli = Cli {
            remote: Some("https://github.com/user/repo".to_string()),
            git_ref: "develop".to_string(),
            remote_auth: Some("my_token".to_string()),
            ..Default::default()
        };
        let source = InputSource::from_cli(&cli);
        match &source {
            InputSource::RemoteUrl {
                url,
                git_ref,
                auth_token,
            } => {
                assert_eq!(url, "https://github.com/user/repo");
                assert_eq!(git_ref, "develop");
                assert_eq!(*auth_token, Some("my_token".to_string()));
            }
            _ => panic!("Expected RemoteUrl"),
        }
    }

    #[test]
    fn test_source_resolver_resolve_local() {
        let cli = Cli {
            paths: vec![PathBuf::from("./src")],
            ..Default::default()
        };
        let resolved = SourceResolver::resolve(&cli);
        assert!(matches!(resolved.source, ResolvedSource::Local));
        assert_eq!(resolved.paths, vec![PathBuf::from("./src")]);
        assert!(!resolved.requires_clone());
    }

    #[test]
    fn test_source_resolver_resolve_remote() {
        let cli = Cli {
            remote: Some("https://github.com/user/repo".to_string()),
            git_ref: "main".to_string(),
            ..Default::default()
        };
        let resolved = SourceResolver::resolve(&cli);
        assert!(matches!(resolved.source, ResolvedSource::Remote { .. }));
        assert!(resolved.requires_clone());
    }

    #[test]
    fn test_source_resolver_resolve_remote_list() {
        let cli = Cli {
            remote_list: Some(PathBuf::from("repos.txt")),
            git_ref: "main".to_string(),
            ..Default::default()
        };
        let resolved = SourceResolver::resolve(&cli);
        assert!(matches!(resolved.source, ResolvedSource::Remote { .. }));
    }

    #[test]
    fn test_source_resolver_resolve_awesome() {
        let cli = Cli {
            awesome_claude_code: true,
            ..Default::default()
        };
        let resolved = SourceResolver::resolve(&cli);
        assert!(matches!(resolved.source, ResolvedSource::AwesomeClaudeCode));
        assert!(resolved.requires_clone());
    }

    #[test]
    fn test_source_resolver_scan_type() {
        let cli = Cli {
            scan_type: ScanType::Mcp,
            ..Default::default()
        };
        assert_eq!(SourceResolver::scan_type(&cli), ScanType::Mcp);
    }

    #[test]
    fn test_resolved_source_debug() {
        let local = ResolvedSource::Local;
        let debug_str = format!("{:?}", local);
        assert!(debug_str.contains("Local"));

        let client = ResolvedSource::Client;
        let debug_str = format!("{:?}", client);
        assert!(debug_str.contains("Client"));

        let awesome = ResolvedSource::AwesomeClaudeCode;
        let debug_str = format!("{:?}", awesome);
        assert!(debug_str.contains("AwesomeClaudeCode"));
    }

    #[test]
    fn test_resolved_input_debug() {
        let input = ResolvedInput {
            paths: vec![PathBuf::from("./test")],
            source: ResolvedSource::Local,
            clients: Vec::new(),
        };
        let debug_str = format!("{:?}", input);
        assert!(debug_str.contains("ResolvedInput"));
    }

    #[test]
    fn test_input_source_debug() {
        let source = InputSource::AllClients;
        let debug_str = format!("{:?}", source);
        assert!(debug_str.contains("AllClients"));
    }

    #[test]
    fn test_resolved_input_client_not_requires_clone() {
        let client = ResolvedInput {
            paths: Vec::new(),
            source: ResolvedSource::Client,
            clients: Vec::new(),
        };
        assert!(!client.requires_clone());
    }
}
