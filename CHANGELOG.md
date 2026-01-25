# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- LICENSE file in project root
- CHANGELOG.md following Keep a Changelog format
- CODE_OF_CONDUCT.md (Contributor Covenant)

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

[Unreleased]: https://github.com/ryo-ebata/cc-audit/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/ryo-ebata/cc-audit/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ryo-ebata/cc-audit/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ryo-ebata/cc-audit/releases/tag/v0.1.0
