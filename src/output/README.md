# Output Module (L7)

The output layer handles formatting and reporting of scan results.

## Architecture Layer

**Layer 7 (Output)** - Receives `ScanResult` from L6 (Aggregator) and produces formatted output.

## Responsibilities

- Terminal output with colored severity indicators
- JSON output for machine consumption
- SARIF output for IDE integration
- HTML reports for browser viewing
- Markdown reports for documentation

## Files

| File | Description |
|------|-------------|
| `mod.rs` | Module exports and re-exports |
| `formatter.rs` | `OutputFormatter` - Format selection and output |

## Key Types

### OutputFormatter

Coordinates output formatting:

```rust
pub struct OutputFormatter {
    format: OutputFormat,
    output_path: Option<PathBuf>,
}

impl OutputFormatter {
    pub fn format(&self, result: &ScanResult) -> String;
    pub fn write(&self, result: &ScanResult) -> Result<()>;
}
```

## Re-exported Reporters

```rust
// From crate::reporter
pub use Reporter;               // Trait
pub use TerminalReporter;       // Colored terminal output
pub use JsonReporter;           // JSON format
pub use SarifReporter;          // SARIF format
pub use HtmlReporter;           // HTML report
pub use MarkdownReporter;       // Markdown report
```

### Reporter Trait

```rust
pub trait Reporter {
    fn report(&self, result: &ScanResult) -> String;
}
```

## Output Formats

| Format | Use Case | File Extension |
|--------|----------|----------------|
| Terminal | Interactive CLI | - |
| JSON | CI/CD, scripting | `.json` |
| SARIF | IDE integration | `.sarif` |
| HTML | Browser viewing | `.html` |
| Markdown | Documentation | `.md` |

## Data Flow

```
┌─────────────────┐
│ Aggregator (L6) │
│   ScanResult    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│     Output      │
│  (This Module)  │
│   - Formatter   │
│   - Reporters   │
└────────┬────────┘
         │
    ┌────┴────┐
    ▼         ▼
 stdout    file.json
           file.sarif
           report.html
```

## Usage Example

```rust
use cc_audit::output::{OutputFormatter, TerminalReporter, Reporter};

// Using OutputFormatter
let formatter = OutputFormatter::new(OutputFormat::Json, None);
let output = formatter.format(&result);

// Using individual reporters
let reporter = TerminalReporter::new();
let output = reporter.report(&result);
println!("{}", output);

// SARIF for IDE integration
let sarif_reporter = SarifReporter::new();
let sarif_output = sarif_reporter.report(&result);
fs::write("results.sarif", sarif_output)?;
```

## Terminal Output Example

```
┌─────────────────────────────────────────────────────────────────┐
│ cc-audit Security Scan Results                                  │
├─────────────────────────────────────────────────────────────────┤
│ Files scanned: 12                                               │
│ Findings: 3 (1 critical, 1 high, 1 medium)                      │
│ Risk Score: 75/100 (HIGH)                                       │
├─────────────────────────────────────────────────────────────────┤
│ [CRITICAL] EX-001: Data exfiltration detected                   │
│   File: SKILL.md:15                                             │
│   Pattern: curl -d $API_KEY https://...                         │
└─────────────────────────────────────────────────────────────────┘
```
