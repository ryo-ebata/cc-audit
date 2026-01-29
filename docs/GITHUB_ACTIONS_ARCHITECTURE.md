# GitHub Actions Architecture

This document describes the GitHub Actions CI/CD architecture for the cc-audit project.

## Overview

The cc-audit project uses a multi-workflow CI/CD pipeline organized by purpose and execution frequency. Each workflow focuses on a specific aspect of code quality, security, or deployment.

## Workflow Categories

### Core CI (Runs on every PR/push to main)

These workflows validate code correctness and quality on every change.

#### `ci.yml` - Continuous Integration
**Purpose:** Primary code quality checks
**Trigger:** Push to main, Pull requests
**Jobs:**
- **changes** - Detect modified Rust files to skip unnecessary checks
- **fmt** - Code formatting validation (`cargo fmt --check`)
- **clippy** - Linting with Clippy (`cargo clippy -- -D warnings`)
- **test** - Unit and integration tests on Ubuntu, macOS, Windows
- **coverage** - Code coverage reporting (Codecov integration)
- **doc** - Documentation generation validation
- **ci-result** - Aggregated result check using `check-results` action

**Exit Criteria:** All jobs must pass to merge PR

---

#### `security.yml` - Security Auditing
**Purpose:** Dependency and supply chain security
**Trigger:** Push to main, Pull requests, Weekly schedule (Monday 00:00 UTC)
**Jobs:**
- **changes** - Detect Rust/dependency changes
- **audit** - CVE database scan (`cargo audit`)
- **deny** - License and policy checks (`cargo-deny`)
- **supply-chain** - Supply chain verification (`cargo vet`)
- **advisory-db** - RustSec advisory database check
- **outdated** - Outdated dependency detection
- **security-result** - Aggregated result check

**Error Handling:** Warnings for supply chain issues, failures for known CVEs

---

#### `self-audit.yml` - Self-Validation
**Purpose:** Validate cc-audit itself using its own security checks
**Trigger:** Push to main, Pull requests
**Jobs:**
- **self-audit** - Runs 7 scan types:
  - Skill scanning
  - Hook scanning
  - MCP configuration scanning
  - Command scanning
  - Dockerfile scanning
  - Dependency scanning
  - Strict mode CI validation
- **self-audit-result** - Aggregated result check

**Outputs:**
- Terminal, JSON, SARIF, and Markdown reports for each scan type
- SARIF uploaded to GitHub Security tab (7 categories)
- All reports saved as artifacts (30-day retention)
- Enhanced summary table with collapsed terminal outputs

**Unique Features:**
- Multi-format report generation (28 files per run)
- GitHub Security tab integration via SARIF
- Metrics extraction (Critical, High, Medium, Low counts)
- Self-validation ensures tool reliability

---

### Quality Assurance (Runs on PR/push)

These workflows validate additional quality metrics.

#### `performance.yml` - Performance Monitoring
**Purpose:** Track performance metrics and prevent regressions
**Trigger:** Push to main, Pull requests (when Rust code changes)
**Jobs:**
- **changes** - Detect Rust/benchmark changes
- **benchmark** - Run Criterion benchmarks with baseline comparison
- **binary-size** - Measure release binary size (threshold: 20MB warning)
- **build-time** - Measure debug and release build times (threshold: 5 min)
- **performance-result** - Aggregated result check

**Thresholds:**
- Binary size: 20MB (warning)
- Release build time: 5 minutes (warning)

**Artifacts:**
- Criterion benchmark results
- Binary size data

---

#### `msrv.yml` - Minimum Supported Rust Version
**Purpose:** Validate compatibility with MSRV and newer versions
**Trigger:** Push to main, Pull requests (when Rust code changes)
**Jobs:**
- **changes** - Detect Rust code changes
- **msrv-check** - Verify MSRV declaration in Cargo.toml
- **msrv-verify** - Build and test on MSRV (1.85.0), stable, and beta
- **msrv-result** - Aggregated result check

**Matrix Testing:**
- Rust 1.85.0 (MSRV, Edition 2024)
- Rust stable
- Rust beta

---

#### `semver.yml` - Semantic Versioning
**Purpose:** Validate API compatibility and CHANGELOG updates
**Trigger:** Push to main, Pull requests, Tag pushes (v*)
**Jobs:**
- **changes** - Detect Rust/Cargo changes
- **semver-check** - API compatibility validation
- **changelog-check** - Verify CHANGELOG.md updates on version changes
- **semver-result** - Aggregated result check

**Validation:**
- Breaking changes detected via cargo-semver-checks
- CHANGELOG.md must be updated when version changes

---

#### `terraform.yml` - Infrastructure as Code
**Purpose:** Validate Terraform configurations
**Trigger:** Push to main, Pull requests (when infrastructure changes)
**Jobs:**
- **changes** - Detect Terraform file changes
- **fmt** - Terraform formatting validation
- **validate** - Configuration syntax validation
- **tflint** - Terraform linting
- **tfsec** - Security scanning for Terraform
- **terraform-result** - Aggregated result check

**Scope:** Infrastructure directory validation

---

### Release Workflows (Triggered by tags/automation)

These workflows handle versioning and distribution.

#### `release-please.yml` - Automated Versioning
**Purpose:** Automated semantic versioning and CHANGELOG generation
**Trigger:** Push to main, Manual dispatch
**Features:**
- Analyzes conventional commits
- Creates release PRs automatically
- Updates version numbers
- Generates CHANGELOG.md
- Auto-merges release PRs (when enabled)

**Automation:**
- Detects commit types (feat, fix, chore, etc.)
- Determines version bumps (major, minor, patch)
- Creates GitHub releases

---

#### `release.yml` - Multi-Platform Build
**Purpose:** Build and publish release binaries
**Trigger:** Tag push (v*), Release workflow completion
**Jobs:**
- Multi-platform binary compilation (Linux, macOS, Windows)
- Cross-compilation for various architectures
- Binary compression and optimization
- GitHub Release attachment
- crates.io publication

**Platforms:**
- Linux (x86_64, aarch64)
- macOS (x86_64, aarch64)
- Windows (x86_64)

---

#### `npm-publish.yml` - NPM Distribution
**Purpose:** Publish npm packages for Node.js integration
**Trigger:** Release workflow completion
**Packages:**
- Platform-specific binaries
- Universal wrapper package

---

#### `homebrew-update.yml` - Homebrew Formula
**Purpose:** Update Homebrew formula after releases
**Trigger:** Release workflow completion
**Actions:**
- Updates formula with new version
- Updates SHA256 checksums
- Creates PR to homebrew-tap

---

### Periodic Workflows (Scheduled execution)

These workflows run on a schedule to maintain code quality.

#### `mutation.yml` - Mutation Testing
**Purpose:** Test quality validation via mutation testing
**Trigger:** Weekly (schedule), Manual dispatch, PR with `mutation` label
**Tool:** cargo-mutants
**Frequency:** Weekly or on-demand

---

#### `fuzz.yml` - Fuzz Testing
**Purpose:** Discover edge cases via fuzzing
**Trigger:** Weekly (schedule), Manual dispatch
**Tool:** cargo-fuzz
**Frequency:** Weekly or on-demand

---

#### `cve-update.yml` - CVE Database Updates
**Purpose:** Keep CVE database current and create update PRs
**Trigger:** Daily (schedule), Manual dispatch
**Actions:**
- Updates internal CVE database
- Creates automated PR with changes
- Bumps patch version if CVEs added

---

### Maintenance Workflows

Automated repository maintenance.

#### `stale.yml` - Issue/PR Management
**Purpose:** Auto-close stale issues and PRs
**Trigger:** Daily (schedule)
**Criteria:**
- Issues: 90 days inactive → stale label → 14 days → close
- PRs: 60 days inactive → stale label → 7 days → close

---

#### `commitlint.yml` - Commit Message Validation
**Purpose:** Enforce Conventional Commits format
**Trigger:** Pull request (opened, edited, synchronized)
**Validation:**
- Commit message format
- Type prefixes (feat, fix, docs, etc.)
- Scope validation

---

## Workflow Dependency Graph

```
┌─────────────────────────────────────────────────────────┐
│                      Code Push                          │
└────────────┬────────────────────────────────────────────┘
             │
    ┌────────┼────────┐
    ▼        ▼        ▼
┌────────┐ ┌──────────┐ ┌─────────────┐
│   CI   │ │ Security │ │ Self-Audit  │
└────────┘ └──────────┘ └─────────────┘
    │            │              │
    └────────────┼──────────────┘
                 │
         [Merge to main]
                 │
                 ▼
        ┌─────────────────┐
        │ Release-Please  │
        └────────┬────────┘
                 │
          [Tag created]
                 │
                 ▼
        ┌─────────────────┐
        │    Release      │
        └────────┬────────┘
                 │
         ┌───────┼───────┐
         ▼       ▼       ▼
    ┌────────┐ ┌────┐ ┌──────────┐
    │  NPM   │ │CRAN│ │Homebrew  │
    └────────┘ └────┘ └──────────┘
```

---

## Composite Actions

Reusable workflow components stored in `.github/actions/`.

### `check-results`
**Purpose:** Standardized result checking for workflow jobs
**Usage:** Applied to all result jobs across workflows
**Benefits:**
- Consistent error handling
- Reduced code duplication (147 lines saved)
- Automatic summary table generation

**Example:**
```yaml
- uses: ./.github/actions/check-results
  with:
    workflow-name: 'CI'
    skip-condition: ${{ needs.changes.outputs.rust != 'true' && 'No changes' || '' }}
    jobs: |
      [
        {"name": "test", "result": "${{ needs.test.result }}"},
        {"name": "lint", "result": "${{ needs.lint.result }}"}
      ]
```

---

## Workflow Communication Patterns

### Change Detection
Most workflows use `paths-filter` to skip unnecessary work:

```yaml
changes:
  outputs:
    rust: ${{ steps.filter.outputs.rust }}
  steps:
    - uses: dorny/paths-filter@v3
      with:
        filters: |
          rust:
            - 'src/**'
            - 'Cargo.toml'
            - 'Cargo.lock'
```

### Artifact Sharing
Workflows share data via artifacts:
- **Benchmark results** (performance.yml)
- **Coverage reports** (ci.yml → Codecov)
- **Self-audit reports** (self-audit.yml → 28 files)
- **Binary builds** (release.yml → GitHub Releases)

### Cross-Workflow Triggers
Some workflows trigger others:
- `release-please.yml` → `release.yml` (via tag)
- `release.yml` → `npm-publish.yml`, `homebrew-update.yml`

---

## Caching Strategy

All Rust workflows use `Swatinem/rust-cache@v2` for dependency caching:
- Cached per OS and Rust toolchain
- Automatically invalidates on Cargo.lock changes
- Shared across jobs in the same workflow

---

## Security Considerations

### Permissions
Most workflows use minimal permissions:
```yaml
permissions:
  contents: read
```

**Exceptions:**
- `self-audit.yml`: `security-events: write` (for SARIF upload)
- `release.yml`: `contents: write` (for release creation)

### Secrets
Used secrets:
- `GITHUB_TOKEN` - Automatically provided by GitHub Actions
- `CODECOV_TOKEN` - For coverage upload (optional)
- `CARGO_REGISTRY_TOKEN` - For crates.io publication
- `NPM_TOKEN` - For npm publication

---

## Performance Optimization

### Parallelization
- Jobs run in parallel when possible
- Matrix strategies for multi-OS testing
- Independent checks execute concurrently

### Conditional Execution
- `paths-filter` skips unchanged areas
- `if` conditions prevent unnecessary work
- Result jobs always run (`if: always()`)

### Resource Usage
- Rust cache reduces build times by ~70%
- Incremental compilation enabled
- Artifacts cleaned up after 30 days

---

## Monitoring and Observability

### GitHub Actions Summary
All workflows contribute to step summary:
- Result tables
- Metrics and statistics
- Links to artifacts and reports

### GitHub Security Tab
SARIF reports from `self-audit.yml`:
- 7 scan categories
- Integrated with code scanning alerts
- Filterable by severity

### Artifacts
Long-term storage for:
- Test results
- Performance data
- Security scan reports
- Build artifacts

---

## Troubleshooting

### Common Issues

**Issue:** Workflow skipped unexpectedly
**Solution:** Check `paths-filter` configuration and file changes

**Issue:** Result job fails but all checks passed
**Solution:** Verify `check-results` action receives correct job results

**Issue:** Cache not working
**Solution:** Ensure Cargo.lock is committed and rust-cache version is current

**Issue:** SARIF upload fails
**Solution:** Verify `security-events: write` permission is set

---

## Best Practices

1. **Always use `check-results` action** for result jobs
2. **Apply `paths-filter`** to skip unnecessary work
3. **Document thresholds** in comments (binary size, build time, etc.)
4. **Use descriptive job names** that explain purpose
5. **Cache aggressively** but invalidate correctly
6. **Minimize permissions** to least privilege required
7. **Provide actionable error messages** with guidance
8. **Test workflows locally** using `act` when possible

---

## Related Documentation

- [CI Error Handling Standards](./ci-error-handling.md)
- [Composite Actions](../.github/actions/README.md)
- [Contributing Guidelines](../CONTRIBUTING.md)

---

## Workflow Statistics

| Category | Count | Total Jobs | Avg Duration |
|----------|-------|------------|--------------|
| Core CI | 3 | 17 | ~8 min |
| Quality Assurance | 4 | 15 | ~12 min |
| Release | 4 | 8 | ~25 min |
| Periodic | 3 | 4 | varies |
| Maintenance | 2 | 2 | <1 min |
| **Total** | **16** | **46** | - |

---

## Future Enhancements

Potential improvements to consider:

1. **Workflow composition** - Extract more composite actions
2. **Self-hosted runners** - For faster execution and cost savings
3. **Matrix optimization** - Smart job distribution based on changes
4. **Progressive rollout** - Canary deployments for releases
5. **Enhanced monitoring** - Metrics dashboard for workflow health
