# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0](https://github.com/ryo-ebata/cc-audit/compare/v0.4.1...v1.0.0) (2026-01-25)


### ⚠ BREAKING CHANGES

* Default behavior now returns exit code 1 for ANY finding. Previously only critical/high findings caused CI failure.

### Features

* add rule severity configuration for CI exit code control ([efe8802](https://github.com/ryo-ebata/cc-audit/commit/efe880214bf89bd5b0b3da1f6b0595544d3c4281))
* CI automation, rule severity, and documentation improvements ([a3047b8](https://github.com/ryo-ebata/cc-audit/commit/a3047b8f74b26d9b2cbd6918ef49a398cf46754e))


### Bug Fixes

* **ci:** add Self Audit Result job for required status check ([817cf74](https://github.com/ryo-ebata/cc-audit/commit/817cf7481e812ff27057bd775d22b7a0b971e722))
* **ci:** allow uppercase in commit subject ([18e4d9f](https://github.com/ryo-ebata/cc-audit/commit/18e4d9f70cfcc8689ea6193c1d99e31f8ccda090))
* **ci:** use explicit SHA instead of git checkout - in benchmark comparison ([61f69f2](https://github.com/ryo-ebata/cc-audit/commit/61f69f288bf97f8178a2bb46f76096b512d67a19))
* **ci:** use fetch-depth 0 and proper branch checkout for benchmark comparison ([efcf001](https://github.com/ryo-ebata/cc-audit/commit/efcf0012709743951802e4a25350f3d8fec2072f))
* **ci:** use PAT for release-please to bypass GITHUB_TOKEN restrictions ([71513ad](https://github.com/ryo-ebata/cc-audit/commit/71513ad04aefbb6414281a236d544d5871bd078e))

## [Unreleased]

### Added
- **Multi-Client Support**: Auto-detect and scan AI coding client configurations
  - Supported clients: Claude Code, Cursor, Windsurf, VS Code
  - `--all-clients`: Scan all installed clients
  - `--client <name>`: Scan a specific client (claude, cursor, windsurf, vscode)
  - Findings now include client attribution in output
- **CVE Vulnerability Scanning**: Built-in database of known CVEs affecting MCP and AI tools
  - Scans for 7 known CVEs (CVE-2025-52882, CVE-2025-49596, CVE-2025-54135, etc.)
  - Checks package.json, mcp.json, and extensions.json for vulnerable versions
  - `--cve-db <path>`: Use a custom CVE database
  - `--no-cve-scan`: Disable CVE scanning

### Changed
- `src/client.rs`: New module for client detection
- `src/cve_db.rs`: New module for CVE database handling
- `data/cve-database.json`: Built-in CVE database with 7 entries
- Finding struct now includes optional `client` field

## [0.5.0] - 2026-01-25

### Added
- **Rule Severity Levels**: New `RuleSeverity` (error/warn) to control CI exit codes independently of detection severity
- **Severity Configuration**: Configure per-rule severity in `.cc-audit.yaml`:
  ```yaml
  severity:
    default: error
    warn:
      - PI-001  # Report but don't fail CI
    ignore:
      - OP-001  # Completely skip
  ```
- **New CLI Options**:
  - `--warn-only`: Treat all findings as warnings (exit 0) - useful for initial baseline scans
  - `--min-severity <level>`: Filter findings by severity (critical/high/medium/low)
  - `--min-rule-severity <level>`: Filter by rule severity (error/warn)
- **Enhanced Output**: Terminal output now shows `[ERROR]`/`[WARN]` labels per finding
- **Summary with errors/warnings**: Summary line now shows error and warning counts

### Changed
- **BREAKING**: Default behavior now returns exit code 1 for ANY finding (previously only critical/high)
  - Migration: Use `--warn-only` to restore previous behavior
- **BREAKING**: Summary's `passed` field is now based on `errors == 0` instead of `critical == 0 && high == 0`
- **SARIF Output**: Level now reflects rule severity (error/warning) instead of detection severity
- **JSON Output**: Findings now include `rule_severity` field
- Summary now includes `errors` and `warnings` counts

### Fixed
- Integration tests updated for new exit code behavior

## [0.4.1] - 2026-01-25

### Fixed
- Updated SECURITY.md with correct vulnerability reporting process
- Updated SECURITY.md supported versions to reflect current release

### Changed
- CHANGELOG.md now includes v0.4.0 release notes

## [0.4.0] - 2026-01-25

### Added
- Baseline/Drift detection for rug pull attack prevention (`--baseline`, `--check-drift`, `--save-baseline`, `--baseline-file`)
- Auto-fix functionality (`--fix`, `--fix-dry-run`)
- Deep scan with deobfuscation (`--deep-scan`)
- MCP server mode (`--mcp-server`)
- Profile management (`--profile`, `--save-profile`)
- HTML output format (`--format html`)
- Path comparison (`--compare`)
- Subagent scanning (`--type subagent`)
- Plugin/marketplace scanning (`--type plugin`)
- Risk scoring system (0-100 scale)
- 30+ new detection rules (50+ total)
- LICENSE file in project root
- CHANGELOG.md following Keep a Changelog format
- CODE_OF_CONDUCT.md (Contributor Covenant)

### Changed
- Improved terminal output with risk score visualization
- Enhanced SARIF output with CWE mappings

## [0.3.0] - 2025-01-25

### Added
- MCP server configuration scanning
- Slash commands scanning
- Custom rules scanning
- Docker configuration scanning
- Supply chain attack detection rules
- Secret leak detection (API keys, tokens, credentials)
- Malware signature database
- Watch mode (`--watch`) for real-time scanning
- Pre-commit hooks integration
- Snapshot testing infrastructure
- Cross-platform git hook support

### Changed
- Upgraded notify crate from v7 to v8

### Fixed
- Replaced `unwrap()` with `expect()` in all builtin rules for better error messages
- Cross-platform support for git hook permissions
- Resolved RUSTSEC-2024-0384 security advisory

## [0.2.0] - 2025-01-20

### Added
- Hooks scanning (`settings.json` support)
- SARIF output format for CI/CD integration
- 5 additional built-in security rules (17 total)
- Comprehensive security scanning features

## [0.1.0] - 2025-01-15

### Added
- Initial release
- Skills file scanning
- 12 built-in security rules
- Terminal output with colored severity levels
- JSON output format
- Basic CLI interface

[Unreleased]: https://github.com/ryo-ebata/cc-audit/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/ryo-ebata/cc-audit/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/ryo-ebata/cc-audit/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/ryo-ebata/cc-audit/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/ryo-ebata/cc-audit/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ryo-ebata/cc-audit/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ryo-ebata/cc-audit/releases/tag/v0.1.0
