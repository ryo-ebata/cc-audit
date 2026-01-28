---
name: tdd-coach
description: Guide development using Kent Beck's TDD methodology. Use when implementing new features, fixing bugs, or adding rules to cc-audit. Enforces test-first approach with Red-Green-Refactor cycle.
---

# TDD Coach for cc-audit

## Core Principle

**Tests drive implementation, never the reverse.**

## Red-Green-Refactor Cycle

### 1. Red: Write a Failing Test First

```rust
#[test]
fn test_new_feature_behavior() {
    // Arrange: Set up test data
    let input = "malicious pattern here";

    // Act: Call the function (doesn't exist yet)
    let result = detect_new_pattern(input);

    // Assert: Define expected behavior
    assert!(result.is_some());
    assert_eq!(result.unwrap().rule_id, "EX-011");
}
```

**Verify the test fails:**
```bash
cargo test test_new_feature_behavior
```

### 2. Green: Write Minimal Code to Pass

- Implement **only** what's needed to pass the test
- No extra features, no premature optimization
- "Fake it till you make it" is acceptable

### 3. Refactor: Clean Up While Green

- Remove duplication
- Improve naming
- Extract functions if needed
- **Tests must stay green throughout**

## Workflow Commands

```bash
# Run specific test
cargo test <test_name>

# Run with output
cargo test -- --nocapture

# Check coverage (maintain 90%+)
cargo llvm-cov --summary-only

# Format and lint
cargo fmt --all && cargo clippy -- -D warnings
```

## Rules for cc-audit Development

### DO

- Write test BEFORE implementation
- Confirm test fails before writing code
- Make smallest possible change to pass test
- Run full test suite after each green phase
- Use `cargo insta` for snapshot tests

### DO NOT

- Write implementation first, then retrofit tests
- Modify tests to match buggy implementation
- Skip the red phase
- Add multiple features in one cycle
- Use `#[allow(...)]` or `#[cfg(not(coverage))]`

## Example: Adding a New Detection Rule

### Step 1: Write Failing Test

```rust
// tests/rules/exfiltration.rs
#[test]
fn test_ex011_detects_dns_exfiltration() {
    let scanner = ExfiltrationScanner::new(Default::default());
    let malicious = "dns.lookup(base64.encode(secret))";

    let result = scanner.scan(malicious, Path::new("test.js")).unwrap();

    assert!(!result.findings.is_empty());
    assert_eq!(result.findings[0].rule_id, "EX-011");
}

#[test]
fn test_ex011_ignores_normal_dns() {
    let scanner = ExfiltrationScanner::new(Default::default());
    let benign = "dns.lookup('example.com')";

    let result = scanner.scan(benign, Path::new("test.js")).unwrap();

    assert!(result.findings.is_empty());
}
```

### Step 2: Run and Confirm Failure

```bash
cargo test test_ex011
# Expected: FAILED (function/rule doesn't exist)
```

### Step 3: Implement Minimal Solution

```rust
// src/rules/builtin/exfiltration.rs
Rule {
    id: "EX-011",
    name: "DNS Exfiltration",
    patterns: vec![Pattern::new(r"dns\.lookup.*encode")],
    // ... minimal fields
}
```

### Step 4: Run and Confirm Pass

```bash
cargo test test_ex011
# Expected: PASSED
```

### Step 5: Refactor if Needed

- Add edge cases
- Improve pattern specificity
- Update documentation

## Bug Fix Workflow

1. **Write a test that reproduces the bug**
2. Confirm the test fails (proves bug exists)
3. Fix the bug with minimal change
4. Confirm test passes
5. Ensure no regression in other tests

```bash
# Full regression check
cargo test
cargo llvm-cov --summary-only  # Must be 90%+
```

## Coverage Requirements

| Metric | Minimum |
|--------|---------|
| Line coverage | 90% |
| Branch coverage | 85% |
| New code | 100% |

```bash
# Generate HTML report
cargo llvm-cov --all-features --html
open target/llvm-cov/html/index.html
```

## Quick Reference

| Phase | Action | Verify |
|-------|--------|--------|
| Red | Write failing test | `cargo test` fails |
| Green | Minimal implementation | `cargo test` passes |
| Refactor | Clean code | `cargo test` still passes |

**Remember:** If you're writing code before tests, you're doing it wrong.
