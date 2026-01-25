# CLI リファレンス

[English](./CLI.md)

## 使用方法

```
cc-audit [OPTIONS] <PATHS>...
```

## 引数

| 引数 | 説明 |
|------|------|
| `<PATHS>...` | スキャンするパス（ファイルまたはディレクトリ） |

## オプション

### 出力オプション

| オプション | 説明 |
|------------|------|
| `-f, --format <FORMAT>` | 出力形式: `terminal`（デフォルト）, `json`, `sarif`, `html` |
| `-o, --output <FILE>` | 出力ファイルパス（HTML/JSON出力用） |
| `-v, --verbose` | 詳細出力 |
| `--ci` | CIモード: 非インタラクティブ出力 |

### スキャンオプション

| オプション | 説明 |
|------------|------|
| `-t, --type <SCAN_TYPE>` | スキャンタイプ（[スキャンタイプ](#スキャンタイプ)参照） |
| `-s, --strict` | 厳格モード: medium/low重大度の検出を表示 |
| `-r, --recursive` | 再帰スキャン |
| `--min-confidence <LEVEL>` | 最小信頼度レベル: `tentative`（デフォルト）, `firm`, `certain` |
| `--skip-comments` | コメント行をスキップ |
| `--deep-scan` | 難読化解除付き深いスキャン |

### 含める/除外するオプション

| オプション | 説明 |
|------------|------|
| `--include-tests` | テストディレクトリを含める |
| `--include-node-modules` | node_modulesディレクトリを含める |
| `--include-vendor` | vendorディレクトリを含める |

### 修正オプション

| オプション | 説明 |
|------------|------|
| `--fix-hint` | ターミナル出力に修正ヒントを表示 |
| `--fix` | 自動修正（可能な場合） |
| `--fix-dry-run` | 自動修正のプレビュー（適用なし） |

### ウォッチモード

| オプション | 説明 |
|------------|------|
| `-w, --watch` | ウォッチモード: ファイル変更を監視 |

### Gitフック

| オプション | 説明 |
|------------|------|
| `--init-hook` | pre-commitフックをインストール |
| `--remove-hook` | pre-commitフックを削除 |

### カスタムルール & マルウェア

| オプション | 説明 |
|------------|------|
| `--custom-rules <PATH>` | カスタムルールファイルのパス（YAML形式） |
| `--malware-db <PATH>` | カスタムマルウェアシグネチャDBのパス |
| `--no-malware-scan` | マルウェアスキャンを無効化 |

### ベースライン & ドリフト検出

| オプション | 説明 |
|------------|------|
| `--baseline` | ドリフト検出用ベースラインスナップショットを作成 |
| `--check-drift` | 保存されたベースラインとのドリフトをチェック |
| `--save-baseline <FILE>` | ベースラインを指定ファイルに保存 |
| `--baseline-file <FILE>` | ベースラインファイルと比較（新規検出のみ表示） |
| `--compare <PATH1> <PATH2>` | 2つのパスを比較して差分を表示 |

### プロファイル

| オプション | 説明 |
|------------|------|
| `--profile <NAME>` | 名前付きプロファイルから設定を読み込む |
| `--save-profile <NAME>` | 現在の設定を名前付きプロファイルとして保存 |

### その他のオプション

| オプション | 説明 |
|------------|------|
| `--init` | デフォルト設定ファイルテンプレートを生成 |
| `--mcp-server` | MCPサーバーとして実行 |
| `-h, --help` | ヘルプを表示 |
| `-V, --version` | バージョンを表示 |

## スキャンタイプ

| タイプ | 説明 | 対象ファイル |
|--------|------|--------------|
| `skill` | Claude Codeスキル定義（デフォルト） | `SKILL.md`、frontmatter付き`*.md` |
| `hook` | フック設定 | `settings.json`、フックスクリプト |
| `mcp` | MCPサーバー設定 | `mcp.json`、サーバー定義 |
| `command` | スラッシュコマンド定義 | `.claude/commands/*.md` |
| `rules` | カスタムルールファイル | `*.yaml`、`*.yml`ルール定義 |
| `docker` | Docker設定 | `Dockerfile`、`docker-compose.yml` |
| `dependency` | パッケージ依存関係 | `package.json`、`Cargo.toml`、`requirements.txt` |
| `subagent` | サブエージェント定義 | `.claude/agents/*.md`、`agent.md` |
| `plugin` | プラグインマーケットプレイス定義 | `marketplace.json`、`plugin.json` |

## 終了コード

| コード | 意味 | アクション |
|--------|------|------------|
| 0 | 問題なし | 安全に続行可能 |
| 1 | critical/high重大度の問題を検出 | インストール前に検出結果を確認 |
| 2 | スキャンエラー（ファイルが見つからない等） | ファイルパスと権限を確認 |

## 例

```bash
# 基本スキャン
cc-audit ./my-skill/

# JSON出力をファイルに保存
cc-audit ./skill/ --format json --output results.json

# HTMLレポート出力
cc-audit ./skill/ --format html --output report.html

# 厳格モードと詳細出力
cc-audit --strict --verbose ./skill/

# MCP設定をスキャン
cc-audit --type mcp ~/.claude/mcp.json

# 開発時のウォッチモード
cc-audit --watch ./my-skill/

# CIパイプラインスキャン
cc-audit --ci --format sarif --strict ./

# 高信頼度のみ
cc-audit --min-confidence certain ./skill/
```
