//! Compile-only checks for the public remote API shown in `src/remote/README.md`.

use cc_audit::remote::{ClonedRepo, GitCloner, RemoteError};

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
