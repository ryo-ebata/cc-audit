# Reporter Module

Output formatters for scan results.

## Overview

This module provides different output formats for scan results, implementing the `Reporter` trait.

## Files

| File | Reporter | Description |
|------|----------|-------------|
| `mod.rs` | `Reporter` trait | Module exports |
| `terminal.rs` | `TerminalReporter` | Colored CLI output |
| `json.rs` | `JsonReporter` | JSON format |
| `sarif.rs` | `SarifReporter` | SARIF for IDE integration |
| `html.rs` | `HtmlReporter` | HTML report |
| `markdown.rs` | `MarkdownReporter` | Markdown report |

## Reporter Trait

```rust
pub trait Reporter {
    fn report(&self, result: &ScanResult) -> String;
}
```

## Reporters

### TerminalReporter

Colored terminal output with severity indicators:

```rust
let reporter = TerminalReporter::new();
println!("{}", reporter.report(&result));
```

Features:
- Colored severity labels (CRITICAL=red, HIGH=yellow, etc.)
- Risk score visualization
- File location links
- Summary statistics

### JsonReporter

Machine-readable JSON output:

```rust
let reporter = JsonReporter::new();
let json = reporter.report(&result);
```

Output structure:
```json
{
  "passed": false,
  "summary": { "total": 5, "critical": 1, "high": 2, ... },
  "findings": [ ... ],
  "risk_score": { "score": 75, "level": "high" }
}
```

### SarifReporter

SARIF (Static Analysis Results Interchange Format) for IDE integration:

```rust
let reporter = SarifReporter::new();
let sarif = reporter.report(&result);
fs::write("results.sarif", sarif)?;
```

Compatible with:
- VS Code SARIF Viewer
- GitHub Code Scanning
- Azure DevOps

### HtmlReporter

Standalone HTML report:

```rust
let reporter = HtmlReporter::new();
let html = reporter.report(&result);
fs::write("report.html", html)?;
```

Features:
- Self-contained (embedded CSS)
- Interactive severity filtering
- Sortable findings table
- Print-friendly

### MarkdownReporter

Markdown report for documentation:

```rust
let reporter = MarkdownReporter::new();
let md = reporter.report(&result);
```

Features:
- GitHub-compatible markdown
- Table formatting
- Code block highlighting

## Usage Example

```rust
use cc_audit::reporter::{Reporter, TerminalReporter, JsonReporter};

// Terminal output
let terminal = TerminalReporter::new();
println!("{}", terminal.report(&result));

// JSON output
let json = JsonReporter::new();
fs::write("results.json", json.report(&result))?;
```

## Output Format Selection

Typically controlled via CLI:

```bash
# Terminal (default)
cc-audit .

# JSON
cc-audit --format json .

# SARIF
cc-audit --format sarif --output results.sarif .

# HTML
cc-audit --format html --output report.html .
```
