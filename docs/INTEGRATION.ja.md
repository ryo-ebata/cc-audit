# CI/CD統合

[English](./INTEGRATION.md)

## GitHub Actions

`.github/workflows/cc-audit.yml`を作成：

```yaml
name: cc-audit セキュリティスキャン

on:
  push:
    branches: [main]
    paths:
      - '.claude/**'
      - 'mcp.json'
      - 'package.json'
      - 'Cargo.toml'
  pull_request:
    paths:
      - '.claude/**'
      - 'mcp.json'

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: cc-auditをインストール
        run: cargo install cc-audit

      - name: Skillsをスキャン
        run: cc-audit check --type skill --ci --format sarif .claude/skills/ > skills.sarif
        continue-on-error: true

      - name: MCP設定をスキャン
        run: cc-audit check --type mcp --ci mcp.json
        continue-on-error: true

      - name: 依存関係をスキャン
        run: cc-audit check --type dependency --ci ./

      - name: SARIFをGitHub Securityにアップロード
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: skills.sarif
        if: always()
```

## GitLab CI

```yaml
cc-audit:
  stage: security
  image: rust:latest
  before_script:
    - cargo install cc-audit
  script:
    - cc-audit check --type skill --ci .claude/
    - cc-audit check --type mcp --ci mcp.json
    - cc-audit check --type dependency --ci ./
  allow_failure: false
```

## Pre-commitフック

```bash
# プロジェクトにフックをインストール
cc-audit hook init

# フックを削除
cc-audit hook remove
```

pre-commitフックはコミット前にステージされたファイルを自動的にスキャンします。

---

# トラブルシューティング

## よくある問題

### 「スキャンするファイルが見つかりません」

```bash
# パスが存在し、スキャン可能なファイルが含まれているか確認
ls -la ./my-skill/

# 再帰スキャンはデフォルトで有効です。無効にするには --no-recursive を使用
cc-audit check ./my-skill/
cc-audit check --no-recursive ./my-skill/
```

### 「権限が拒否されました」

```bash
# 対象ファイルの読み取り権限を確認
chmod -R +r ./my-skill/
```

### 誤検知が多い

```bash
# 最小信頼度レベルを上げる
cc-audit check --min-confidence firm ./my-skill/

# 最高精度にはcertainを使用
cc-audit check --min-confidence certain ./my-skill/

# コメント行をスキップ
cc-audit check --skip-comments ./my-skill/
```

### スキャンが遅い

```bash
# 一般的なディレクトリ（node_modules, .gitなど）はデフォルトパターンで除外
# .cc-audit.yamlで無視パターンを設定

# 例: カスタム無視パターンを追加（Glob構文）
# ignore:
#   patterns:
#     - "**/large_directory/**"
#     - "**/*.generated.*"
```

### カスタムルールが読み込まれない

```bash
# YAML構文を検証
cat ./my-rules.yaml | python -c "import yaml, sys; yaml.safe_load(sys.stdin)"

# 必須フィールド: id, name, severity, category, patterns, message, recommendation
```

---

# FAQ

**Q: cc-auditは外部にデータを送信しますか？**

A: デフォルトでは送信しません。スキャン結果はローカルに保持されます。ただし、以下のオプション機能はネットワーク接続が必要です：
- `--remote` / `--awesome-claude-code`: gitでリポジトリをクローン
- `--report-fp`: 偽陽性レポートを送信（`--no-telemetry`で無効化可能）

**Q: エアギャップ環境で使用できますか？**

A: ローカルスキャンは可能です。リポジトリを手動でクローンしてからスキャンしてください。`--remote`機能はエアギャップ環境では使用できません。

**Q: 特定のルールを抑制するにはどうすればよいですか？**

A: `.cc-audit.yaml`の`disabled_rules`にルールIDを追加してください：

```yaml
disabled_rules:
  - "PE-001"
  - "EX-002"
```

**Q: cc-auditはバイナリファイルをスキャンしますか？**

A: いいえ。テキストベースのファイル（スクリプト、設定、Markdown、JSON、YAMLなど）のみです。

**Q: リモートリポジトリを直接スキャンできますか？**

A: はい！`--remote <URL>`で単一リポジトリを、`--remote-list <FILE>`で複数リポジトリを、`--awesome-claude-code`でawesome-claude-codeの全リポジトリをスキャンできます。詳細は[リモートリポジトリスキャン](./FEATURES.ja.md#リモートリポジトリスキャン)を参照してください。

**Q: `--strict`とデフォルトモードの違いは？**

A: デフォルトモードはcriticalとhigh重大度のみを報告します。`--strict`はmediumとlowも含めます。

**Q: マルウェアシグネチャDBはどのくらいの頻度で更新されますか？**

A: 各リリースで更新されます。`--malware-db`でカスタムシグネチャを補完できます。

**Q: 新しい検出ルールを貢献できますか？**

A: はい！[Contributing Guide](../CONTRIBUTING.md)を参照してください。
