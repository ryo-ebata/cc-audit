# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.2.4](https://github.com/ryo-ebata/cc-audit/compare/v3.2.3...v3.2.4) (2026-01-29)


### Bug Fixes

* **ux:** improve Japanese text, minified files, long lines, and progress bar ([#61](https://github.com/ryo-ebata/cc-audit/issues/61)) ([f76b44b](https://github.com/ryo-ebata/cc-audit/commit/f76b44b245492f52733cd51abb517d4ce730dd16))

## [3.2.3](https://github.com/ryo-ebata/cc-audit/compare/v3.2.2...v3.2.3) (2026-01-29)


### Bug Fixes

* **config:** change ignore patterns from regex to glob ([#59](https://github.com/ryo-ebata/cc-audit/issues/59)) ([3d941b4](https://github.com/ryo-ebata/cc-audit/commit/3d941b4502392e5b3cefa5a6419db1dacb0fe81d))

## [3.2.2](https://github.com/ryo-ebata/cc-audit/compare/v3.2.1...v3.2.2) (2026-01-29)


### Bug Fixes

* **config:** canonicalize project root path for proper parent directory traversal ([#57](https://github.com/ryo-ebata/cc-audit/issues/57)) ([bb0d842](https://github.com/ryo-ebata/cc-audit/commit/bb0d842502a85e959adeff607f64ce6aee3693eb))

## [3.2.1](https://github.com/ryo-ebata/cc-audit/compare/v3.2.0...v3.2.1) (2026-01-28)


### Bug Fixes

* **test:** strengthen scanner tests to verify detection accuracy ([#55](https://github.com/ryo-ebata/cc-audit/issues/55)) ([f06f72c](https://github.com/ryo-ebata/cc-audit/commit/f06f72cec074bbb7b8746a45fa3f637fe9ea6f50))

## [3.2.0](https://github.com/ryo-ebata/cc-audit/compare/v3.1.7...v3.2.0) (2026-01-28)


### Features

* refactor CLI to subcommand-based structure ([#53](https://github.com/ryo-ebata/cc-audit/issues/53)) ([b3d3d80](https://github.com/ryo-ebata/cc-audit/commit/b3d3d80a767d50a8996f7506805195d72f34a524))

## [3.1.7](https://github.com/ryo-ebata/cc-audit/compare/v3.1.6...v3.1.7) (2026-01-28)


### Bug Fixes

* implement recursive setting in scanner configuration ([#50](https://github.com/ryo-ebata/cc-audit/issues/50)) ([4ff8ffa](https://github.com/ryo-ebata/cc-audit/commit/4ff8ffa645e42f07d5edde2720cfc2d9b7ded9d4))

## [3.1.6](https://github.com/ryo-ebata/cc-audit/compare/v3.1.5...v3.1.6) (2026-01-27)


### Bug Fixes

* respect config file settings in all handlers ([#47](https://github.com/ryo-ebata/cc-audit/issues/47)) ([b76ae4c](https://github.com/ryo-ebata/cc-audit/commit/b76ae4c1353d648371918cadf12bd153d0d51d17))

## [3.1.5](https://github.com/ryo-ebata/cc-audit/compare/v3.1.4...v3.1.5) (2026-01-27)


### Bug Fixes

* **deps:** update criterion from 0.5 to 0.8 ([#45](https://github.com/ryo-ebata/cc-audit/issues/45)) ([07549ec](https://github.com/ryo-ebata/cc-audit/commit/07549ec6400e086bee954e6da85d3897a13047c9))

## [3.1.4](https://github.com/ryo-ebata/cc-audit/compare/v3.1.3...v3.1.4) (2026-01-27)


### Bug Fixes

* **terminal:** improve error display with lint-style output format ([#43](https://github.com/ryo-ebata/cc-audit/issues/43)) ([d36885e](https://github.com/ryo-ebata/cc-audit/commit/d36885e62c671b7fdae39a96baa70de4417e8fee))

## [3.1.4](https://github.com/ryo-ebata/cc-audit/compare/v3.1.3...v3.1.4) (2026-01-27)


### Bug Fixes

* **terminal:** improve error display with lint-style output format

Add lint-style output format similar to ESLint, Clippy for better readability:
- Shows code with line number gutter and caret pointer (^)
- Structured labels: why, ref, fix, example
- Add --compact option for traditional output format
- Document new output format in CLI.md and CLI.ja.md

## [3.1.3](https://github.com/ryo-ebata/cc-audit/compare/v3.1.2...v3.1.3) (2026-01-27)


### Bug Fixes

* **cve:** Update CVE database (+5 entries) [v3.1.3] ([#39](https://github.com/ryo-ebata/cc-audit/issues/39)) ([bc1fba1](https://github.com/ryo-ebata/cc-audit/commit/bc1fba1605c718b136938af9777e4cbd0f15e54c))

## [3.1.2](https://github.com/ryo-ebata/cc-audit/compare/v3.1.1...v3.1.2) (2026-01-27)


### Bug Fixes

* improve detection rules and reduce false positives/negatives ([#40](https://github.com/ryo-ebata/cc-audit/issues/40)) ([72f5edb](https://github.com/ryo-ebata/cc-audit/commit/72f5edb4988d315af0514f094d2c324020d3011e))

## [3.1.1](https://github.com/ryo-ebata/cc-audit/compare/v3.1.0...v3.1.1) (2026-01-26)


### Bug Fixes

* 誤検知(False Positive)の削減 ([#35](https://github.com/ryo-ebata/cc-audit/issues/35)) ([8303692](https://github.com/ryo-ebata/cc-audit/commit/83036923cbb66129e63826c48679faae2e98552f))

## [3.1.0](https://github.com/ryo-ebata/cc-audit/compare/v3.0.0...v3.1.0) (2026-01-26)


### Features

* release v3.1.0 ([#33](https://github.com/ryo-ebata/cc-audit/issues/33)) ([a5cfdee](https://github.com/ryo-ebata/cc-audit/commit/a5cfdeefcc41bbbbab56e7c8de231d724844e126))

## [3.0.0](https://github.com/ryo-ebata/cc-audit/compare/v2.0.0...v3.0.0) (2026-01-26)


### ⚠ BREAKING CHANGES

* Major architecture refactoring with module reorganization.
* Default behavior now returns exit code 1 for ANY finding. Previously only critical/high findings caused CI failure.

### Features

* add comprehensive configuration, HTML reports, baseline drift detection, and scoring system ([c2d2ddb](https://github.com/ryo-ebata/cc-audit/commit/c2d2ddb7ddaa39e47d476b12316a608932e81e49))
* add comprehensive configuration, HTML reports, baseline drift detection, and scoring system ([5cf067a](https://github.com/ryo-ebata/cc-audit/commit/5cf067a72cce56b2a468ef8cacd41a1c22d50554))
* add comprehensive security scanning features for v0.2.0 ([8c9b8cd](https://github.com/ryo-ebata/cc-audit/commit/8c9b8cd6665410a33e2b6b040f0f421f11c3f0db))
* add comprehensive security scanning features for v0.2.0 ([18b421c](https://github.com/ryo-ebata/cc-audit/commit/18b421c1f3718b3248b19512df23ac73ca4d9e1a))
* add multi-client support and CVE vulnerability scanning ([0b351fc](https://github.com/ryo-ebata/cc-audit/commit/0b351fc2333a54546a4a08b61c96beff85fb295f))
* add multi-platform distribution support ([f9b437c](https://github.com/ryo-ebata/cc-audit/commit/f9b437ca16e78b798a49f142ad9a8fdd1c80f5c4))
* add multi-platform distribution support ([70c78ae](https://github.com/ryo-ebata/cc-audit/commit/70c78aec263cca74aa7847d1bfbc0bacd9fa0f2d))
* add rule severity configuration for CI exit code control ([efe8802](https://github.com/ryo-ebata/cc-audit/commit/efe880214bf89bd5b0b3da1f6b0595544d3c4281))
* add snapshot testing infrastructure and git hooks for CI parity ([74f7589](https://github.com/ryo-ebata/cc-audit/commit/74f75893e5f33a0b578232911f39bb16d47de79c))
* add Terraform configuration for GitHub repository protection ([13c9c9c](https://github.com/ryo-ebata/cc-audit/commit/13c9c9c2861584a469d05b52dedea39de4de01a7))
* add Terraform configuration for GitHub repository protection ([736e450](https://github.com/ryo-ebata/cc-audit/commit/736e450d641bd0e9557398ff2e62a6f9faca90e3))
* add v0.4.0 major features - auto-fix, deobfuscation, MCP server, plugin/subagent scanning ([22db6bf](https://github.com/ryo-ebata/cc-audit/commit/22db6bf7efbc9c9ef860e55d23868dd0792f982a))
* CI automation, rule severity, and documentation improvements ([a3047b8](https://github.com/ryo-ebata/cc-audit/commit/a3047b8f74b26d9b2cbd6918ef49a398cf46754e))
* implement 7-layer architecture refactoring ([c8026b0](https://github.com/ryo-ebata/cc-audit/commit/c8026b0d79d4caa0b661e0444045da9eaa8ce23f))
* implement 7-layer architecture refactoring with improved test coverage ([0ff70aa](https://github.com/ryo-ebata/cc-audit/commit/0ff70aa7139fe22284711725927e73e5ceebd2c9))
* initial project setup with v0.2.0 implementation ([31bcdb1](https://github.com/ryo-ebata/cc-audit/commit/31bcdb1603431e8dd3230d289616f9dfc1ca6234))


### Bug Fixes

* add cross-platform support for git hook permissions ([e758006](https://github.com/ryo-ebata/cc-audit/commit/e758006f160b19819413cca3e0291e71f6d662db))
* add last-release-sha to reset release-please versioning ([#24](https://github.com/ryo-ebata/cc-audit/issues/24)) ([678e707](https://github.com/ryo-ebata/cc-audit/commit/678e707c2b5484e27bc26d56dcb04a198bcccd01))
* **ci:** add GITHUB_TOKEN to tfsec-action to prevent rate limiting ([acc4788](https://github.com/ryo-ebata/cc-audit/commit/acc4788b9aa0ac66f6cc2f337166ca9020fdbc3a))
* **ci:** add Self Audit Result job for required status check ([817cf74](https://github.com/ryo-ebata/cc-audit/commit/817cf7481e812ff27057bd775d22b7a0b971e722))
* **ci:** allow uppercase in commit subject ([18e4d9f](https://github.com/ryo-ebata/cc-audit/commit/18e4d9f70cfcc8689ea6193c1d99e31f8ccda090))
* **ci:** use explicit SHA instead of git checkout - in benchmark comparison ([61f69f2](https://github.com/ryo-ebata/cc-audit/commit/61f69f288bf97f8178a2bb46f76096b512d67a19))
* **ci:** use fetch-depth 0 and proper branch checkout for benchmark comparison ([efcf001](https://github.com/ryo-ebata/cc-audit/commit/efcf0012709743951802e4a25350f3d8fec2072f))
* **ci:** use PAT for release-please to bypass GITHUB_TOKEN restrictions ([71513ad](https://github.com/ryo-ebata/cc-audit/commit/71513ad04aefbb6414281a236d544d5871bd078e))
* correct version to 1.1.0 (was incorrectly released as 2.0.0) ([07e4bf9](https://github.com/ryo-ebata/cc-audit/commit/07e4bf9a7b5944ea47965220a839bb4327df7954))
* **infra:** make required_status_checks block conditional ([f2b37b6](https://github.com/ryo-ebata/cc-audit/commit/f2b37b6962134f414048d72d35a58b4dfbd014d9))
* **infra:** remove default required status checks ([983e67c](https://github.com/ryo-ebata/cc-audit/commit/983e67ca7f653ea25e5606307b9dcd9060b00fa9))
* **release:** force release version to 1.2.0 ([#28](https://github.com/ryo-ebata/cc-audit/issues/28)) ([9fe9e61](https://github.com/ryo-ebata/cc-audit/commit/9fe9e61607a09cebd38b99e6cd7b011ddb31b1e5))
* upgrade notify v7 to v8 to resolve RUSTSEC-2024-0384 ([aca5eca](https://github.com/ryo-ebata/cc-audit/commit/aca5eca8a305e73916b575d22ac1ee680655f00c))

## [1.1.0](https://github.com/ryo-ebata/cc-audit/compare/v1.0.0...v1.1.0) (2026-01-26)


### Features

* add multi-client support and CVE vulnerability scanning ([0b351fc](https://github.com/ryo-ebata/cc-audit/commit/0b351fc2333a54546a4a08b61c96beff85fb295f))

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
