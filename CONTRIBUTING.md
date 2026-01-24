# Contributing to cc-audit

Thank you for your interest in contributing to cc-audit! This document provides guidelines and instructions for contributing.

## Getting Started

### Prerequisites

- [Rust](https://rustup.rs/) (latest stable)
- [just](https://github.com/casey/just) (command runner)

### Setup

```bash
# Clone the repository
git clone https://github.com/ryo-ebata/cc-audit.git
cd cc-audit

# Install development tools
just setup

# Verify everything works
just check
```

## Development Workflow

### Building

```bash
just build          # Debug build
just build-release  # Release build
```

### Testing

```bash
just test           # Run all tests
just test-verbose   # Run tests with output
just coverage       # Run coverage report
```

### Linting and Formatting

```bash
just fmt            # Format code
just lint           # Run clippy
just check          # Run all checks (fmt + lint + test)
```

### Running Examples

```bash
just run-examples              # Run all examples
just run ./examples/clean/     # Run specific example
just run-json ./examples/clean/ # Run with JSON output
```

## Code Style

- Follow Rust standard formatting (`cargo fmt`)
- All clippy warnings must be resolved
- Write tests for new functionality
- Maintain test coverage above 80%

## Adding New Rules

Rules are defined in `src/rules/builtin/`. You can add a new rule manually or use the code generator.

### Quick Start (Recommended)

Use the `new-rule` command to generate a rule template:

```bash
# Usage: just new-rule <category> <id> <name>
just new-rule privilege PE-006 "Setuid bit manipulation"
just new-rule exfiltration EX-010 "DNS exfiltration"
just new-rule injection PI-003 "Unicode obfuscation"
```

This will:
1. Add the rule function template to the appropriate file
2. Register it in the category's `rules()` function
3. Add a test template

After running the command:
1. Edit the patterns in the generated function
2. Update the test cases
3. Run `just test` to verify

### Manual Steps

If you prefer to add rules manually:

1. Identify the category (exfiltration, privilege, persistence, injection, permission, obfuscation)
2. Add the rule function in the appropriate file (`src/rules/builtin/<category>.rs`)
3. Register it in the category's `rules()` function
4. Add unit tests for the rule
5. Add an example in `examples/` directory (optional)
6. Update documentation

### Rule Structure

```rust
fn xx_001() -> Rule {
    Rule {
        id: "XX-001",
        name: "Rule name",
        description: "What this rule detects",
        severity: Severity::Critical, // Critical, High, Medium, Low
        category: Category::Exfiltration,
        patterns: vec![
            Regex::new(r"pattern").unwrap(),
        ],
        exclusions: vec![
            Regex::new(r"false_positive_pattern").unwrap(),
        ],
        message: "Message shown to user",
        recommendation: "How to fix",
    }
}
```

### Rule ID Convention

| Prefix | Category             |
| ------ | -------------------- |
| EX-xxx | Exfiltration         |
| PE-xxx | Privilege Escalation |
| PS-xxx | Persistence          |
| PI-xxx | Prompt Injection     |
| OP-xxx | Overpermission       |
| OB-xxx | Obfuscation          |
| SC-xxx | Supply Chain         |

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run `just check` to ensure all checks pass
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### PR Requirements

- [ ] All tests pass (`just test`)
- [ ] No clippy warnings (`just lint`)
- [ ] Code is formatted (`just fmt`)
- [ ] New features have tests
- [ ] Documentation is updated if needed

## Reporting Issues

When reporting issues, please include:

- cc-audit version (`cc-audit --version`)
- Rust version (`rustc --version`)
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Relevant error messages or output

## Security Vulnerabilities

If you discover a security vulnerability, please do NOT open a public issue. Instead, email the maintainers directly.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
