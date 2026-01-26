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
