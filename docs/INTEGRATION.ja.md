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
        run: cc-audit --type skill --ci --format sarif .claude/skills/ > skills.sarif
        continue-on-error: true

      - name: MCP設定をスキャン
        run: cc-audit --type mcp --ci mcp.json
        continue-on-error: true

      - name: 依存関係をスキャン
        run: cc-audit --type dependency --ci ./

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
    - cc-audit --type skill --ci .claude/
    - cc-audit --type mcp --ci mcp.json
    - cc-audit --type dependency --ci ./
  allow_failure: false
```

## Pre-commitフック

```bash
# プロジェクトにフックをインストール
cc-audit --init-hook .

# フックを削除
cc-audit --remove-hook .
```

pre-commitフックはコミット前にステージされたファイルを自動的にスキャンします。

---

# トラブルシューティング

## よくある問題

### 「スキャンするファイルが見つかりません」

```bash
# パスが存在し、スキャン可能なファイルが含まれているか確認
ls -la ./my-skill/

# ネストされたディレクトリには再帰モードを使用
cc-audit --recursive ./my-skill/
```

### 「権限が拒否されました」

```bash
# 対象ファイルの読み取り権限を確認
chmod -R +r ./my-skill/
```

### 誤検知が多い

```bash
# 最小信頼度レベルを上げる
cc-audit --min-confidence firm ./my-skill/

# 最高精度にはcertainを使用
cc-audit --min-confidence certain ./my-skill/

# コメント行をスキップ
cc-audit --skip-comments ./my-skill/
```

### スキャンが遅い

```bash
# テストはデフォルトで除外
cc-audit ./my-skill/

# 必要な場合は明示的に含める
cc-audit --include-tests ./my-skill/
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

A: いいえ。cc-auditは完全にローカルで動作します。外部サーバーへのデータ送信は一切ありません。

**Q: エアギャップ環境で使用できますか？**

A: はい。インストール後、cc-auditは完全にオフラインで動作します。

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

A: まだできません。最初にクローンしてからローカルでスキャンしてください。リモートスキャンはv1.0.0で予定しています。

**Q: `--strict`とデフォルトモードの違いは？**

A: デフォルトモードはcriticalとhigh重大度のみを報告します。`--strict`はmediumとlowも含めます。

**Q: マルウェアシグネチャDBはどのくらいの頻度で更新されますか？**

A: 各リリースで更新されます。`--malware-db`でカスタムシグネチャを補完できます。

**Q: 新しい検出ルールを貢献できますか？**

A: はい！[Contributing Guide](../CONTRIBUTING.md)を参照してください。
