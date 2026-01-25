# cc-audit development tasks

# Default recipe: show available commands
default:
    @just --list

# ============================================================================
# Setup
# ============================================================================

# Setup development environment
setup:
    @echo "Installing required tools..."
    rustup component add clippy rustfmt llvm-tools-preview
    cargo install cargo-llvm-cov cargo-audit cargo-deny cargo-vet cargo-outdated \
        cargo-semver-checks cargo-msrv cargo-mutants
    @echo "Setup complete!"

# Setup all tools including nightly-only tools (fuzz)
setup-all: setup
    @echo "Installing nightly tools..."
    rustup install nightly
    cargo +nightly install cargo-fuzz
    @echo "All tools installed!"

# ============================================================================
# Build
# ============================================================================

# Build the project
build:
    cargo build

# Build release version
build-release:
    cargo build --release

# Build with all features
build-all-features:
    cargo build --all-features

# ============================================================================
# Test
# ============================================================================

# Run all tests
test:
    cargo test

# Run all tests with all features (CI equivalent)
test-all:
    cargo test --all-features

# Run tests with verbose output
test-verbose:
    cargo test -- --nocapture

# ============================================================================
# Coverage (CI: coverage job)
# ============================================================================

# Run coverage and show summary
coverage:
    cargo llvm-cov --summary-only

# Run coverage with all features (CI equivalent)
coverage-all:
    cargo llvm-cov --all-features --summary-only

# Generate coverage report in lcov format (CI equivalent)
coverage-lcov:
    cargo llvm-cov --all-features --lcov --output-path lcov.info

# Run coverage and generate HTML report
coverage-html:
    cargo llvm-cov --all-features --html
    @echo "Coverage report: target/llvm-cov/html/index.html"

# ============================================================================
# Lint & Format (CI: fmt, clippy jobs)
# ============================================================================

# Run clippy linter
lint:
    cargo clippy -- -D warnings

# Run clippy with all targets and features (CI equivalent)
lint-all:
    cargo clippy --all-targets --all-features -- -D warnings

# Format code
fmt:
    cargo fmt --all

# Check formatting without modifying (CI equivalent)
fmt-check:
    cargo fmt --all --check

# ============================================================================
# Documentation (CI: doc job)
# ============================================================================

# Build documentation (CI equivalent)
doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features

# Build and open documentation
doc-open:
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features --open

# ============================================================================
# CI Main Checks (ci.yml equivalent)
# ============================================================================

# Run all CI main checks (fmt + clippy + test + doc)
ci-main: fmt-check lint-all test-all doc
    @echo "All CI main checks passed!"

# Quick CI check (fmt + lint only, fastest)
ci-quick: fmt-check lint-all
    @echo "Quick CI checks passed!"

# ============================================================================
# Security Checks (security.yml equivalent)
# ============================================================================

# Run cargo-audit for security vulnerabilities
security-audit:
    cargo audit

# Run cargo-deny for dependency checks (CI equivalent)
security-deny:
    cargo deny check all

# Run cargo-vet for supply chain security
security-vet:
    cargo vet --locked || echo "Supply chain audit incomplete - run 'cargo vet' to complete"

# Check for outdated dependencies
security-outdated:
    cargo outdated --root-deps-only

# Run all security checks (security.yml equivalent)
ci-security: security-audit security-deny security-vet
    @echo "All security checks passed!"

# ============================================================================
# Performance Checks (performance.yml equivalent)
# ============================================================================

# Run benchmarks (CI equivalent)
bench:
    cargo bench --bench scan_benchmark -- --noplot

# Run benchmarks and save baseline
bench-baseline name="local":
    cargo bench --bench scan_benchmark -- --noplot --save-baseline {{name}}

# Compare benchmarks against baseline
bench-compare baseline="main":
    cargo bench --bench scan_benchmark -- --noplot --baseline {{baseline}}

# Measure binary size
binary-size: build-release
    #!/usr/bin/env bash
    set -e
    if [[ "$OSTYPE" == "darwin"* ]]; then
        SIZE=$(stat -f%z target/release/cc-audit)
    else
        SIZE=$(stat -c%s target/release/cc-audit)
    fi
    SIZE_MB=$(echo "scale=2; $SIZE / 1048576" | bc)
    echo "Binary size: ${SIZE_MB}MB ($SIZE bytes)"
    # Threshold: 20MB
    if [ "$SIZE" -gt 20971520 ]; then
        echo "Warning: Binary size exceeds 20MB threshold"
    fi

# Measure build time (debug)
build-time-debug:
    #!/usr/bin/env bash
    cargo clean
    START=$(date +%s)
    cargo build 2>&1
    END=$(date +%s)
    echo "Debug build time: $((END - START))s"

# Measure build time (release)
build-time-release:
    #!/usr/bin/env bash
    cargo clean
    START=$(date +%s)
    cargo build --release 2>&1
    END=$(date +%s)
    echo "Release build time: $((END - START))s"

# Run all performance checks
ci-performance: bench binary-size
    @echo "Performance checks completed!"

# ============================================================================
# Self Audit (self-audit.yml equivalent)
# ============================================================================

# Run self audit on all types
self-audit: build-release
    @echo "=== Skill Scan ===" && ./target/release/cc-audit --type skill . || true
    @echo ""
    @echo "=== Hook Scan ===" && ./target/release/cc-audit --type hook . || true
    @echo ""
    @echo "=== MCP Scan ===" && ./target/release/cc-audit --type mcp . || true
    @echo ""
    @echo "=== Command Scan ===" && ./target/release/cc-audit --type command . || true
    @echo ""
    @echo "=== Docker Scan ===" && ./target/release/cc-audit --type docker . || true
    @echo ""
    @echo "=== Dependency Scan ===" && ./target/release/cc-audit --type dependency . || true

# Run self audit in strict/CI mode
self-audit-strict: build-release
    ./target/release/cc-audit --type skill --ci .

# ============================================================================
# MSRV Check (msrv.yml equivalent)
# ============================================================================

# Find minimum supported Rust version
msrv-find:
    cargo msrv find --min 1.75.0

# Verify build with MSRV (1.85.0)
msrv-verify:
    rustup run 1.85.0 cargo check --all-features
    rustup run 1.85.0 cargo build --all-features
    rustup run 1.85.0 cargo test --all-features

# Verify build with stable
msrv-stable:
    rustup run stable cargo check --all-features
    rustup run stable cargo build --all-features
    rustup run stable cargo test --all-features

# Verify build with beta
msrv-beta:
    rustup run beta cargo check --all-features
    rustup run beta cargo build --all-features
    rustup run beta cargo test --all-features

# ============================================================================
# Semver Check (semver.yml equivalent)
# ============================================================================

# Check semver compatibility against latest tag
semver-check:
    #!/usr/bin/env bash
    LATEST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "")
    if [ -z "$LATEST_TAG" ]; then
        echo "No previous tags found, skipping semver check"
        exit 0
    fi
    echo "Checking API compatibility against $LATEST_TAG"
    cargo semver-checks check-release --baseline-rev "$LATEST_TAG"

# ============================================================================
# Mutation Testing (mutation.yml equivalent)
# ============================================================================

# Run mutation testing
mutation:
    cargo mutants --timeout 60 --jobs 2

# Run quick mutation testing (limited)
mutation-quick:
    cargo mutants --timeout 30 --jobs 2 --in-place

# ============================================================================
# Fuzz Testing (fuzz.yml equivalent) - Requires nightly
# ============================================================================

# List fuzz targets
fuzz-list:
    cargo +nightly fuzz list 2>/dev/null || echo "No fuzz targets found. Run 'cargo fuzz init' to setup."

# Run fuzz testing (default 60 seconds)
fuzz target duration="60":
    cargo +nightly fuzz run {{target}} -- -max_total_time={{duration}}

# ============================================================================
# Combined CI Commands
# ============================================================================

# Run ALL CI checks locally (equivalent to all GitHub Actions)
ci-all: ci-main ci-security self-audit
    @echo ""
    @echo "============================================"
    @echo "All CI checks passed!"
    @echo "============================================"

# Run full CI with performance (slower)
ci-full: ci-all ci-performance
    @echo ""
    @echo "============================================"
    @echo "Full CI checks (including performance) passed!"
    @echo "============================================"

# Run extended CI (includes mutation testing, slower)
ci-extended: ci-full mutation
    @echo ""
    @echo "============================================"
    @echo "Extended CI checks passed!"
    @echo "============================================"

# ============================================================================
# Development Utilities
# ============================================================================

# Run the tool on examples
run-examples:
    @echo "=== clean ===" && cargo run --quiet -- ./examples/clean/ || true
    @echo ""
    @echo "=== exfiltration ===" && cargo run --quiet -- ./examples/exfiltration/ || true
    @echo ""
    @echo "=== privilege-escalation ===" && cargo run --quiet -- ./examples/privilege-escalation/ || true
    @echo ""
    @echo "=== persistence ===" && cargo run --quiet -- ./examples/persistence/ || true
    @echo ""
    @echo "=== prompt-injection ===" && cargo run --quiet -- ./examples/prompt-injection/ || true
    @echo ""
    @echo "=== overpermission ===" && cargo run --quiet -- ./examples/overpermission/ || true

# Run the tool on a specific path
run path:
    cargo run -- {{path}}

# Run with JSON output
run-json path:
    cargo run -- --format json {{path}}

# Run with verbose output
run-verbose path:
    cargo run -- --verbose {{path}}

# Clean build artifacts
clean:
    cargo clean

# Watch for changes and run tests
watch:
    cargo watch -x test

# Install the tool locally
install:
    cargo install --path .

# Uninstall the tool
uninstall:
    cargo uninstall cc-audit

# ============================================================================
# CI Local Testing with act
# ============================================================================

# List available CI jobs
act-list:
    act -l --workflows .github/workflows/ci.yml

# Run CI locally (dry run)
act-dry:
    act push -n --workflows .github/workflows/ci.yml

# Run all CI jobs locally via act (ubuntu only, skips macOS/Windows)
act-ci:
    act push --workflows .github/workflows/ci.yml

# Run specific CI job (e.g., just act-job fmt)
act-job job:
    act -j {{job}} --workflows .github/workflows/ci.yml

# Run security workflow via act
act-security:
    act push --workflows .github/workflows/security.yml

# Run performance workflow via act
act-performance:
    act push --workflows .github/workflows/performance.yml

# Run self-audit workflow via act
act-self-audit:
    act push --workflows .github/workflows/self-audit.yml

# ============================================================================
# Snapshot Testing
# ============================================================================

# Run snapshot tests
test-snapshot:
    cargo test snapshot_ -- --nocapture

# Review pending snapshot changes
snapshot-review:
    cargo insta review

# Accept all pending snapshots
snapshot-accept:
    cargo insta accept

# ============================================================================
# Code Generation (xtask)
# ============================================================================

# Create a new security rule
# Usage: just new-rule <category> <id> <name>
# Example: just new-rule privilege PE-006 "Setuid bit manipulation"
new-rule category id name:
    cargo xtask new-rule --category {{category}} --id {{id}} --name "{{name}}"
