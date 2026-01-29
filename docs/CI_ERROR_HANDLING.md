# CI Error Handling Standards

This document defines the standard error handling patterns for GitHub Actions workflows in the cc-audit project.

## Decision Tree

When a command fails in a GitHub Actions workflow, follow these standards based on the purpose of the check:

### 1. Build/Test/Lint (CI Critical)

**Characteristics:**
- These checks validate code correctness and quality
- Failures indicate problems that must be fixed before merging
- Results are deterministic and reproducible

**Action:** Fail immediately

**Pattern:** No special handling - let the command fail naturally

**Examples:**
- `cargo test` - Unit and integration tests
- `cargo clippy -- -D warnings` - Linting
- `cargo fmt --check` - Code formatting
- `terraform validate` - Infrastructure validation

**Implementation:**
```yaml
- name: Run tests
  run: cargo test --all-features
```

---

### 2. Audit/Scan/Benchmark (Informational)

**Characteristics:**
- These checks gather information about the codebase
- Results are meant to be reviewed, not to block CI
- May have acceptable variations or false positives

**Action:** Warn only, continue execution

**Pattern:** Use `continue-on-error: true`, then check outcome if needed

**Examples:**
- `cc-audit check` - Security scanning (self-audit)
- `cargo outdated` - Dependency version checks
- `cargo bench` - Performance benchmarks

**Implementation:**
```yaml
- name: Scan with cc-audit
  id: audit
  continue-on-error: true
  run: ./target/release/cc-audit check --type skill .

- name: Report audit status
  if: steps.audit.outcome == 'failure'
  run: echo "::warning::Security issues detected - review scan results"
```

---

### 3. Security Checks (Context-dependent)

**Characteristics:**
- Critical for security but may have legitimate exceptions
- Behavior differs between CI and PR environments
- May require manual review or approval

**Action:** Fail in CI environment, warn in PR environment

**Pattern:** Use `--ci` flag or check environment variables

**Examples:**
- `cargo audit` - CVE database checks
- `cargo vet` - Supply chain verification
- `cargo deny` - License and security policy checks

**Implementation:**
```yaml
# Option 1: Using --ci flag
- name: Security audit
  run: cargo audit --deny warnings

# Option 2: Environment-based
- name: Supply chain check
  id: vet
  continue-on-error: ${{ github.event_name == 'pull_request' }}
  run: cargo vet --locked

- name: Report vet status
  if: steps.vet.outcome == 'failure' && github.event_name == 'pull_request'
  run: echo "::warning::Supply chain audit incomplete - run 'cargo vet' locally"
```

---

### 4. Performance Thresholds (Advisory)

**Characteristics:**
- Monitor performance metrics over time
- Thresholds are guidelines, not strict requirements
- Useful for trend detection and preventing regressions

**Action:** Warn only, track over time

**Pattern:** Set threshold, emit warning if exceeded, but don't fail

**Examples:**
- Binary size monitoring
- Build time tracking
- Benchmark regression detection

**Implementation:**
```yaml
- name: Check binary size
  run: |
    SIZE=$(stat -c%s target/release/cc-audit)
    THRESHOLD=20971520  # 20MB
    if [ "$SIZE" -gt "$THRESHOLD" ]; then
      echo "::warning::Binary size ($SIZE bytes) exceeds threshold ($THRESHOLD bytes)"
      echo "Consider reviewing recent changes for size impact"
    fi
```

---

## Common Patterns

### Pattern: Capture Exit Code for Later Analysis

```yaml
- name: Run command
  run: |
    ./command || COMMAND_EXIT_CODE=$?
    # Continue with other operations
    echo "Command exited with: ${COMMAND_EXIT_CODE:-0}"
    exit ${COMMAND_EXIT_CODE:-0}
```

### Pattern: Conditional Failure Based on Environment

```yaml
- name: Security check
  id: security
  continue-on-error: true
  run: cargo audit

- name: Handle security check result
  if: steps.security.outcome == 'failure'
  run: |
    if [[ "${{ github.event_name }}" == "push" && "${{ github.ref }}" == "refs/heads/main" ]]; then
      echo "::error::Security issues on main branch must be resolved"
      exit 1
    else
      echo "::warning::Security issues detected - please review"
    fi
```

### Pattern: Multiple Failure Conditions

```yaml
- name: Check all results
  run: |
    FAILED_JOBS=""

    [[ "${{ needs.job1.result }}" == "failure" ]] && FAILED_JOBS="$FAILED_JOBS job1"
    [[ "${{ needs.job2.result }}" == "failure" ]] && FAILED_JOBS="$FAILED_JOBS job2"

    if [ -n "$FAILED_JOBS" ]; then
      echo "::error::Failed jobs:$FAILED_JOBS"
      exit 1
    fi
```

---

## Anti-Patterns to Avoid

### ❌ Silencing Errors Without Logging

```yaml
# BAD: Errors are completely hidden
- run: cargo audit || true
```

**Better:**
```yaml
# GOOD: Errors are logged and tracked
- name: Security audit
  id: audit
  continue-on-error: true
  run: cargo audit

- name: Report audit result
  if: steps.audit.outcome == 'failure'
  run: echo "::warning::Security audit found issues"
```

### ❌ Inconsistent Error Handling

```yaml
# BAD: Different patterns in the same workflow
- run: cargo audit || true
- run: cargo vet || echo "::warning::Vet failed"
- run: cargo deny check || exit 1
```

**Better:**
```yaml
# GOOD: Consistent pattern for all security checks
- name: Security audit
  id: audit
  continue-on-error: true
  run: cargo audit

- name: Supply chain verification
  id: vet
  continue-on-error: true
  run: cargo vet --locked

- name: Policy check
  id: deny
  continue-on-error: true
  run: cargo deny check

- name: Evaluate security results
  run: |
    # Centralized error handling logic
    ...
```

### ❌ Hiding Intent with Complex Logic

```yaml
# BAD: Unclear what happens on failure
- run: |
    if ! cargo test; then
      if [ "$CI" = "true" ]; then
        exit 0
      fi
    fi
```

**Better:**
```yaml
# GOOD: Clear intent with descriptive steps
- name: Run tests
  id: test
  continue-on-error: true
  run: cargo test

- name: Evaluate test results
  if: steps.test.outcome == 'failure'
  run: |
    echo "::error::Tests failed - this must be fixed before merging"
    exit 1
```

---

## Best Practices

### 1. Always Log the Reason for Continuing

When using `continue-on-error: true`, always explain why:

```yaml
- name: Benchmark (informational only)
  continue-on-error: true  # Benchmarks should not block CI
  run: cargo bench
```

### 2. Use Descriptive Step Names

Make it clear what each step does:

```yaml
# GOOD
- name: Check binary size threshold (20MB warning)

# BAD
- name: Check size
```

### 3. Provide Actionable Error Messages

```yaml
# GOOD
- run: |
    echo "::error::Binary size exceeded threshold"
    echo "Review recent changes and consider:"
    echo "  - Removing unused dependencies"
    echo "  - Enabling link-time optimization"
    echo "  - Splitting large features into separate binaries"

# BAD
- run: echo "Size too big"
```

### 4. Document Threshold Values

```yaml
- name: Check binary size threshold
  run: |
    SIZE=$(stat -c%s target/release/cc-audit)
    THRESHOLD=20971520  # 20MB - based on package distribution limits

    if [ "$SIZE" -gt "$THRESHOLD" ]; then
      echo "::warning::Binary size: $(($SIZE / 1048576))MB exceeds threshold: $(($THRESHOLD / 1048576))MB"
    fi
```

### 5. Use the check-results Composite Action

For result jobs, use the standardized composite action:

```yaml
- uses: ./.github/actions/check-results
  with:
    workflow-name: 'CI'
    skip-condition: ${{ needs.changes.outputs.rust != 'true' && 'No changes detected' || '' }}
    jobs: |
      [
        {"name": "test", "result": "${{ needs.test.result }}"},
        {"name": "lint", "result": "${{ needs.lint.result }}"}
      ]
```

---

## Summary Table

| Check Type | Action | Pattern | Example |
|------------|--------|---------|---------|
| Build/Test/Lint | Fail immediately | No special handling | `cargo test` |
| Audit/Scan | Warn, continue | `continue-on-error: true` | `cc-audit check` |
| Security (CI) | Fail | Use `--ci` flag | `cargo audit --deny warnings` |
| Security (PR) | Warn | Conditional logic | `cargo vet` with warning |
| Performance | Warn | Threshold check | Binary size monitoring |

---

## Migration Guide

If you're updating an existing workflow to follow these standards:

1. **Identify the check type** using the decision tree above
2. **Apply the appropriate pattern** from the examples
3. **Test the behavior** in both success and failure scenarios
4. **Document the rationale** with inline comments
5. **Update this guide** if you discover new patterns or edge cases

---

## Related Documentation

- [GitHub Actions Architecture](./github-actions-architecture.md) - Overall workflow structure
- [Composite Actions](../.github/actions/README.md) - Reusable action components
- [GitHub Actions Annotations](https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#setting-an-error-message) - Official documentation for error messages
