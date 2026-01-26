# Aggregator Module (L6)

The aggregation layer collects findings from the detection engine and produces a comprehensive scan result.

## Architecture Layer

**Layer 6 (Aggregation)** - Aggregates findings from L5 (Detection Engine) and produces `ScanResult` for L7 (Output).

## Responsibilities

- Collect findings from multiple scanner sources
- Calculate risk scores and severity breakdowns
- Generate summary statistics
- Handle baseline comparison for drift detection

## Files

| File | Description |
|------|-------------|
| `mod.rs` | Module exports and re-exports |
| `collector.rs` | `FindingCollector` - Aggregates findings from scanners |
| `summary.rs` | `SummaryBuilder` - Builds scan result summaries |

## Key Types

### Re-exported Types

```rust
// From crate::baseline
pub use Baseline, DriftEntry, DriftReport;

// From crate::rules
pub use ScanResult, Summary;

// From crate::scoring
pub use CategoryScore, RiskLevel, RiskScore, SeverityBreakdown;
```

### Local Types

- `FindingCollector` - Accumulates findings during a scan
- `SummaryBuilder` - Constructs scan summaries with statistics

## Data Flow

```
┌─────────────────┐
│ Detection (L5)  │
│   - Scanners    │
│   - Rules       │
└────────┬────────┘
         │ Findings
         ▼
┌─────────────────┐
│  Aggregator     │
│  (This Module)  │
│   - Collect     │
│   - Score       │
│   - Summarize   │
└────────┬────────┘
         │ ScanResult
         ▼
┌─────────────────┐
│   Output (L7)   │
│   - Terminal    │
│   - JSON/SARIF  │
└─────────────────┘
```

## Usage Example

```rust
use cc_audit::aggregator::{FindingCollector, SummaryBuilder};

let mut collector = FindingCollector::new();
collector.add_finding(finding);

let summary = SummaryBuilder::new()
    .with_findings(&collector.findings())
    .build();
```
