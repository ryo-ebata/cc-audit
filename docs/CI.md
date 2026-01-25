# CI/CD Automation

This document describes the CI/CD pipelines and automation configured for cc-audit.

## Overview

| Automation | Trigger | Description |
|------------|---------|-------------|
| [CI](#ci-checks) | Push, PR | Format, lint, test, docs |
| [Security](#security-checks) | Push, PR | Vulnerability scanning |
| [Performance](#performance-checks) | Push, PR | Benchmarks, binary size |
| [Self Audit](#self-audit) | Push, PR | Dogfooding with cc-audit |
| [Commitlint](#commit-linting) | PR | Conventional Commits validation |
| [Release](#release-automation) | Push to main | Automated versioning and release |

## CI Checks

**Workflow:** `.github/workflows/ci.yml`

| Job | Description | Local Command |
|-----|-------------|---------------|
| fmt | Code formatting check | `just fmt-check` |
| clippy | Linter with all warnings as errors | `just lint-all` |
| test | Run all tests | `just test-all` |
| doc | Build documentation | `just doc` |
| coverage | Code coverage report | `just coverage-all` |

Run all CI checks locally:
```bash
just ci-main
```

## Security Checks

**Workflow:** `.github/workflows/security.yml`

| Job | Description | Local Command |
|-----|-------------|---------------|
| audit | Check for known vulnerabilities | `just security-audit` |
| deny | Dependency license and advisory check | `just security-deny` |
| vet | Supply chain security | `just security-vet` |

Run all security checks locally:
```bash
just ci-security
```

## Performance Checks

**Workflow:** `.github/workflows/performance.yml`

| Job | Description | Local Command |
|-----|-------------|---------------|
| benchmark | Run criterion benchmarks | `just bench` |
| binary-size | Check binary size threshold | `just binary-size` |

Run performance checks locally:
```bash
just ci-performance
```

## Self Audit

**Workflow:** `.github/workflows/self-audit.yml`

Runs cc-audit on its own codebase (dogfooding).

```bash
just self-audit
```

## MSRV Check

**Workflow:** `.github/workflows/msrv.yml`

Verifies the Minimum Supported Rust Version (MSRV).

```bash
just msrv-verify
```

## Semver Check

**Workflow:** `.github/workflows/semver.yml`

Checks API compatibility against the previous release.

```bash
just semver-check
```

## Commit Linting

**Workflow:** `.github/workflows/commitlint.yml`

Validates that commits follow [Conventional Commits](https://www.conventionalcommits.org/) format.

### Allowed Types

| Type | Description |
|------|-------------|
| `feat` | A new feature |
| `fix` | A bug fix |
| `docs` | Documentation changes |
| `style` | Code style changes (formatting) |
| `refactor` | Code refactoring |
| `perf` | Performance improvements |
| `test` | Adding or updating tests |
| `build` | Build system changes |
| `ci` | CI configuration changes |
| `chore` | Other changes |
| `revert` | Revert a previous commit |

### Examples

```bash
feat: add JSON output format
fix(parser): handle empty input correctly
docs: update installation instructions
feat!: change API response format  # Breaking change
```

### Local Setup

Enable local commit validation:
```bash
just setup-hooks
```

## Release Automation

**Workflows:**
- `.github/workflows/release-please.yml` - Automated versioning
- `.github/workflows/release.yml` - Build and publish

### How It Works

```
1. Push to main with conventional commits
   │
   ▼
2. release-please analyzes commits
   │
   ├─ fix: commits → patch bump (0.5.0 → 0.5.1)
   ├─ feat: commits → minor bump (0.5.0 → 0.6.0)
   └─ feat!: or BREAKING CHANGE → major bump (0.5.0 → 1.0.0)
   │
   ▼
3. Release PR created/updated automatically
   │  - CHANGELOG.md updated
   │  - Cargo.toml version bumped
   │
   ▼
4. CI checks run on Release PR
   │
   ▼
5. Auto-merge when all checks pass
   │
   ▼
6. Tag created (e.g., v0.6.0)
   │
   ▼
7. release.yml triggered
   │  - Build binaries for all platforms
   │  - Create GitHub Release
   │  - Upload artifacts with checksums
   │
   ▼
8. Release complete!
```

### Supported Platforms

| Platform | Target |
|----------|--------|
| macOS (Intel) | x86_64-apple-darwin |
| macOS (Apple Silicon) | aarch64-apple-darwin |
| Linux (glibc) | x86_64-unknown-linux-gnu |
| Linux (glibc, ARM) | aarch64-unknown-linux-gnu |
| Linux (musl) | x86_64-unknown-linux-musl |
| Windows | x86_64-pc-windows-msvc |

### Manual Release (if needed)

If you need to trigger a release manually:
```bash
git tag v0.6.0
git push origin v0.6.0
```

## Running All CI Locally

```bash
# Quick check (format + lint)
just ci-quick

# Main CI checks
just ci-main

# Full CI (includes security)
just ci-all

# Extended CI (includes performance and mutation testing)
just ci-extended
```

## GitHub Repository Settings

For full automation, ensure these settings are enabled:

### Branch Protection (Settings → Branches → main)
- ☑ Require a pull request before merging
- ☑ Require status checks to pass before merging
- ☑ Require branches to be up to date before merging

### Pull Requests (Settings → General → Pull Requests)
- ☑ Allow auto-merge

## Workflow Files

| File | Purpose |
|------|---------|
| `ci.yml` | Main CI checks |
| `security.yml` | Security scanning |
| `performance.yml` | Benchmarks |
| `self-audit.yml` | Dogfooding |
| `msrv.yml` | MSRV verification |
| `semver.yml` | API compatibility |
| `commitlint.yml` | Commit message linting |
| `release-please.yml` | Automated versioning |
| `release.yml` | Build and publish |
| `fuzz.yml` | Fuzz testing |
| `mutation.yml` | Mutation testing |
| `terraform.yml` | Infrastructure validation |
