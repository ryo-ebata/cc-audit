# 高度な機能

[English](./FEATURES.md)

## ベースライン & ドリフト検出

スキャン間の変更（「ドリフト」）を検出し、ラグプル攻撃を防止します。

### ベースラインの作成

```bash
cc-audit --save-baseline baseline.json ./my-skill/
```

### ドリフトのチェック

```bash
cc-audit --baseline-file baseline.json ./my-skill/
```

出力には以下が表示されます：
- **新規検出**: ベースライン以降に出現した問題
- **解決済み検出**: 修正された問題
- **変更された検出**: 深刻度が変更された問題

### 2つのバージョンを比較

```bash
cc-audit --compare ./skill-v1.0/ ./skill-v1.1/
```

---

## 自動修正

特定の問題を自動的に修正：

```bash
# 修正のプレビュー（適用なし）
cc-audit --fix-dry-run ./my-skill/

# 自動修正を適用
cc-audit --fix ./my-skill/
```

**修正可能な問題:**
- `OP-001`: ワイルドカード権限 → 特定のツールを提案
- `PE-003`: `chmod 777` → `chmod 755`または`chmod 644`を推奨

---

## 難読化解除付き深いスキャン

エンコードまたは難読化された悪意のあるパターンを検出：

```bash
cc-audit --deep-scan ./my-skill/
```

**検出可能なエンコーディング:**
- Base64エンコードされたコマンド
- 16進/8進エンコードされた文字列
- Unicodeエスケープシーケンス
- 文字列連結トリック

---

## MCPサーバーモード

cc-auditをMCPサーバーとして実行し、Claude Codeと統合：

```bash
cc-audit --mcp-server ./
```

これにより、スキャン機能がClaude Codeが呼び出せるMCPツールとして公開されます。

---

## プロファイル

スキャン設定を保存して再利用：

```bash
# 現在の設定をプロファイルとして保存
cc-audit --save-profile strict-ci --strict --ci --format sarif ./

# プロファイルから設定を読み込む
cc-audit --profile strict-ci ./my-skill/
```

プロファイルは`~/.config/cc-audit/profiles/`に保存されます。

---

## ウォッチモード

ファイルを継続的に監視し、変更時に再スキャン：

```bash
cc-audit --watch ./my-skill/
```

スキル開発時に問題を即座に検出するのに便利です。

---

## 出力フォーマット

### Terminal（デフォルト）

リスクスコアの視覚化を含む人間が読みやすいカラー出力。

### JSON

プログラム的な処理のための機械可読フォーマット：

```bash
cc-audit ./skill/ --format json --output results.json
```

### SARIF

CI/CD統合用の静的解析結果交換フォーマット：

```bash
cc-audit ./skill/ --format sarif --output results.sarif
```

### HTML

セキュリティレビュー用のインタラクティブなHTMLレポート：

```bash
cc-audit ./skill/ --format html --output report.html
```

含まれる内容：
- リスクスコアの視覚化を含むエグゼクティブサマリー
- 深刻度とカテゴリでグループ化された検出結果
- インタラクティブなフィルタリングと検索
- シンタックスハイライト付きコードスニペット
- 修正推奨事項

### Markdown

ドキュメントやレポート用のプレーンMarkdown形式：

```bash
cc-audit ./skill/ --format markdown --output report.md
```

---

## クライアントスキャン

インストール済みAIコーディングクライアントの設定を自動スキャン：

```bash
# 全クライアントをスキャン
cc-audit --all-clients

# 特定のクライアントをスキャン
cc-audit --client claude
cc-audit --client cursor
cc-audit --client windsurf
cc-audit --client vscode
```

検出・スキャン対象：
- MCPサーバー設定
- フック設定
- カスタムコマンド
- インストール済みスキルとプラグイン

---

## リモートリポジトリスキャン

手動クローンなしでリモートGitHubリポジトリをスキャン：

```bash
# 単一リポジトリをスキャン
cc-audit --remote https://github.com/user/awesome-skill

# 特定のブランチ/タグ/コミットでスキャン
cc-audit --remote https://github.com/user/repo --git-ref v1.0.0

# 認証付きスキャン（プライベートリポジトリ用）
cc-audit --remote https://github.com/org/private-repo --remote-auth $GITHUB_TOKEN

# ファイルから複数リポジトリをスキャン
cc-audit --remote-list repos.txt --parallel-clones 8

# awesome-claude-codeの全リポジトリをスキャン
cc-audit --awesome-claude-code --summary
```

---

## セキュリティバッジ

プロジェクト用のセキュリティバッジを生成：

```bash
# Markdownバッジを生成
cc-audit ./skill/ --badge --badge-format markdown

# HTMLバッジを生成
cc-audit ./skill/ --badge --badge-format html

# shields.io URLのみを生成
cc-audit ./skill/ --badge --badge-format url
```

出力例：
```markdown
[![Security: A](https://img.shields.io/badge/security-A-brightgreen)](...)
```

---

## MCPピンニング（ラグプル検出）

不正な変更を検出するためにMCPツール設定をピン留め：

```bash
# 現在の設定をピン留め
cc-audit --type mcp ~/.claude/mcp.json --pin

# ピンが変更されていないことを検証
cc-audit --type mcp ~/.claude/mcp.json --pin-verify

# 承認済み変更後にピンを更新
cc-audit --type mcp ~/.claude/mcp.json --pin-update

# 既存のピンを強制上書き
cc-audit --type mcp ~/.claude/mcp.json --pin-update --pin-force
```

ピン留め対象：
- ツール名と説明
- 設定スキーマ
- 権限要件
- サーバーエンドポイント

---

## フックモード

リアルタイムスキャン用にClaude Codeフックとしてcc-auditを実行：

```bash
cc-audit --hook-mode
```

Claude Code設定で構成：
```json
{
  "hooks": {
    "pre-tool-call": {
      "command": "cc-audit --hook-mode"
    }
  }
}
```

---

## SBOM生成

ソフトウェア部品表を生成（CycloneDXフォーマット）：

```bash
# CycloneDX SBOMを生成
cc-audit ./skill/ --sbom --sbom-format cyclonedx --output sbom.json

# 特定のエコシステムを含める
cc-audit ./skill/ --sbom --sbom-npm --sbom-cargo
```

---

## プロキシモード

透過プロキシによるMCPランタイム監視：

```bash
# プロキシを起動
cc-audit --proxy --proxy-port 8080 --proxy-target localhost:9000

# TLS終端付き
cc-audit --proxy --proxy-port 8443 --proxy-target localhost:9000 --proxy-tls

# ブロックモード（検出結果のあるメッセージを停止）
cc-audit --proxy --proxy-port 8080 --proxy-target localhost:9000 --proxy-block

# 全トラフィックをログ
cc-audit --proxy --proxy-port 8080 --proxy-target localhost:9000 --proxy-log traffic.jsonl
```

---

## 偽陽性報告

検出精度向上のために偽陽性を報告：

```bash
# 偽陽性を報告
cc-audit ./skill/ --report-fp

# 送信せずにプレビュー
cc-audit ./skill/ --report-fp --report-fp-dry-run

# カスタムエンドポイントを使用
cc-audit ./skill/ --report-fp --report-fp-endpoint https://api.example.com/fp

# テレメトリを完全に無効化
cc-audit ./skill/ --no-telemetry
```

---

## CVEデータベース

cc-auditには、AIコーディングツール、MCPサーバー、および関連製品に影響する既知のCVEのデータベースが組み込まれています。

### 検出対象製品

- Claude Code（VSCode、JetBrains拡張機能）
- MCP（Model Context Protocol）ツール
- Cursor IDE
- GitHub Copilot
- その他

### 仕組み

スキャン時、cc-auditは検出された製品とバージョンの既知の脆弱性を自動的にチェックします。脆弱なバージョンが見つかった場合、CVEと修正アドバイスを報告します。

### 自動更新

CVEデータベースはGitHub Actionsを通じて毎日自動更新されます。新しいCVEは[NVD API](https://nvd.nist.gov/developers/vulnerabilities)から取得され、プルリクエストとして提出されます。

更新プロセスの詳細は[CVE-UPDATE.ja.md](./CVE-UPDATE.ja.md)を参照してください。
