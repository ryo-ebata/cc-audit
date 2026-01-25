# cc-audit development tasks

# Default recipe: show available commands
default:
    @just --list

# Setup development environment
setup:
    @echo "Installing required tools..."
    rustup component add clippy rustfmt llvm-tools-preview
    cargo install cargo-llvm-cov
    @echo "Setup complete!"

# Build the project
build:
    cargo build

# Build release version
build-release:
    cargo build --release

# Run all tests
test:
    cargo test

# Run tests with verbose output
test-verbose:
    cargo test -- --nocapture

# Run coverage and show summary
coverage:
    cargo llvm-cov --summary-only

# Run coverage and generate HTML report
coverage-html:
    cargo llvm-cov --html
    @echo "Coverage report: target/llvm-cov/html/index.html"

# Run clippy linter
lint:
    cargo clippy -- -D warnings

# Format code
fmt:
    cargo fmt

# Check formatting without modifying
fmt-check:
    cargo fmt -- --check

# Run all checks (for CI)
check: fmt-check lint test
    @echo "All checks passed!"

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

# === CI Local Testing (act) ===

# List available CI jobs
ci-list:
    act -l --workflows .github/workflows/ci.yml

# Run CI locally (dry run)
ci-dry:
    act push -n --workflows .github/workflows/ci.yml

# Run all CI jobs locally (ubuntu only, skips macOS/Windows)
ci:
    act push --workflows .github/workflows/ci.yml

# Run specific CI job (e.g., just ci-job fmt)
ci-job job:
    act -j {{job}} --workflows .github/workflows/ci.yml

# Run fmt job only (fastest check)
ci-fmt:
    act -j fmt --workflows .github/workflows/ci.yml

# Run clippy job only
ci-clippy:
    act -j clippy --workflows .github/workflows/ci.yml

# Run test job only (ubuntu)
ci-test:
    act -j test --workflows .github/workflows/ci.yml

# === Snapshot Testing ===

# Run snapshot tests
test-snapshot:
    cargo test snapshot_ -- --nocapture

# Review pending snapshot changes
snapshot-review:
    cargo insta review

# Accept all pending snapshots
snapshot-accept:
    cargo insta accept

# === Code Generation (xtask) ===

# Create a new security rule
# Usage: just new-rule <category> <id> <name>
# Example: just new-rule privilege PE-006 "Setuid bit manipulation"
new-rule category id name:
    cargo xtask new-rule --category {{category}} --id {{id}} --name "{{name}}"
