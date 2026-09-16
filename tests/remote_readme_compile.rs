//! Compile-only checks for the public remote API shown in `src/remote/README.md`.

use cc_audit::remote::{ClonedRepo, GitCloner, RemoteError};
use clap::Parser;

#[allow(dead_code)]
fn remote_readme_api_example() -> Result<(), RemoteError> {
    let cloner = GitCloner::new();
    let repo: ClonedRepo = cloner.clone("https://github.com/user/repo", "HEAD")?;
    let _path = repo.path();

    let cloner = GitCloner::new().with_auth_token(Some("ghp_xxx".to_string()));
    let _repo = cloner.clone("https://github.com/org/private-repo", "HEAD")?;

    let _repo = GitCloner::new().clone("https://github.com/user/repo", "v1.0.0")?;
    Ok(())
}

#[test]
fn remote_readme_api_example_is_compile_only() {
    // The function above intentionally is not called: this test performs no network I/O.
}

#[test]
fn remote_readme_cli_examples_parse_without_network() {
    let cases: Vec<(Vec<&str>, &str)> = vec![
        (
            vec![
                "cc-audit",
                "check",
                "--remote",
                "https://github.com/user/repo",
            ],
            "remote",
        ),
        (
            vec![
                "cc-audit",
                "check",
                "--remote",
                "https://github.com/user/repo",
                "--git-ref",
                "feature-branch",
            ],
            "ref",
        ),
        (
            vec![
                "cc-audit",
                "check",
                "--remote",
                "https://github.com/org/private-repo",
                "--remote-auth",
                "token",
            ],
            "auth",
        ),
        (
            vec![
                "cc-audit",
                "check",
                "--remote-list",
                "repos.txt",
                "--parallel-clones",
                "8",
            ],
            "list-parallel",
        ),
        (
            vec!["cc-audit", "check", "--remote-list", "repositories.txt"],
            "list",
        ),
        (
            vec!["cc-audit", "check", "--awesome-claude-code"],
            "awesome",
        ),
    ];

    for (argv, name) in cases {
        let cli = cc_audit::cli::Cli::try_parse_from(argv)
            .unwrap_or_else(|error| panic!("README CLI example {name} did not parse: {error}"));
        let Some(cc_audit::cli::Commands::Check(args)) = cli.command else {
            panic!("README CLI example {name} did not select check");
        };

        match name {
            "remote" => assert_eq!(args.remote.as_deref(), Some("https://github.com/user/repo")),
            "ref" => assert_eq!(args.git_ref, "feature-branch"),
            "auth" => assert_eq!(args.remote_auth.as_deref(), Some("token")),
            "list-parallel" => {
                assert_eq!(
                    args.remote_list.as_deref(),
                    Some(std::path::Path::new("repos.txt"))
                );
                assert_eq!(args.parallel_clones, 8);
            }
            "list" => assert_eq!(
                args.remote_list.as_deref(),
                Some(std::path::Path::new("repositories.txt"))
            ),
            "awesome" => assert!(args.awesome_claude_code),
            _ => unreachable!(),
        }
    }
}
