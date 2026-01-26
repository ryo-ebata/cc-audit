# CVEデータベース自動更新

[English](./CVE-UPDATE.md)

このドキュメントでは、GitHub Actionsを使用したcc-auditのCVEデータベース自動更新について説明します。

## 概要

cc-auditは、AIコーディングツールとMCP関連製品に影響する既知のCVEのデータベースを管理しています。このデータベースは、[NVD（National Vulnerability Database）API](https://nvd.nist.gov/developers/vulnerabilities)から新しい脆弱性を取得することで毎日自動更新されます。

## 仕組み

### 日次Cronジョブ

GitHub Actionsワークフローは毎日**09:00 UTC（18:00 JST）**に実行されます：

```yaml
on:
  schedule:
    - cron: '0 9 * * *'
```

### 更新プロセス

1. **CVEの取得**: スクリプトは以下に関連するCVEをNVD APIにクエリします：
   - MCP（Model Context Protocol）
   - Claude Code
   - Cursor IDE
   - GitHub Copilot
   - Codeium、Tabnine、その他のAIコーディングツール

2. **関連CVEのフィルタリング**: 既知のAIコーディングツールベンダー/製品に影響するCVEのみが含まれます

3. **既存データとのマージ**: 新しいCVEは既存のデータベースとマージされ、重複を回避します

4. **プルリクエストの作成**: 新しいCVEが見つかった場合、レビュー用のPRが自動的に作成されます

### 手動トリガー

GitHub Actionsからワークフローを手動でトリガーすることもできます：

1. **Actions** → **CVE Database Update**に移動
2. **Run workflow**をクリック
3. オプションで遡る日数を指定（デフォルト：90日）

## 設定

### NVD APIキー（推奨）

NVD APIキーを設定すると、レート制限が5リクエスト/30秒から50リクエスト/30秒に増加します。

1. [NVD APIキーリクエスト](https://nvd.nist.gov/developers/request-an-api-key)でAPIキーを申請
2. GitHub Secretとしてキーを追加：
   - **Settings** → **Secrets and variables** → **Actions**に移動
   - `NVD_API_KEY`という名前で新しいシークレットを作成

### ワークフロー権限

ワークフローには以下が必要です：
- `contents: write` - データベース更新をコミットするため
- `pull-requests: write` - PRを作成するため

## データベース構造

CVEデータベースは`data/cve-database.json`に保存されます：

```json
{
  "version": "1.0.0",
  "updated_at": "2025-01-26T00:00:00Z",
  "entries": [
    {
      "id": "CVE-2025-XXXXX",
      "title": "脆弱性のタイトル",
      "description": "詳細な説明...",
      "severity": "critical",
      "cvss_score": 9.8,
      "affected_products": [
        {
          "vendor": "anthropic",
          "product": "claude-code",
          "version_affected": "< 1.5.0",
          "version_fixed": "1.5.0"
        }
      ],
      "cwe_ids": ["CWE-78"],
      "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-XXXXX"],
      "published_at": "2025-01-15T00:00:00Z"
    }
  ]
}
```

## プルリクエストレビュー

PRが作成されたら、レビュアーは以下を確認する必要があります：

- [ ] 新しいCVEエントリがAIコーディングツールに関連している
- [ ] 深刻度の評価が正確である
- [ ] 影響を受けるバージョン範囲が正しい
- [ ] 修正バージョンが適切に指定されている

## CVEの手動追加

CVEを手動で追加するには：

1. `data/cve-database.json`を編集
2. 上記の構造に従って新しいエントリを追加
3. `version`のパッチ番号をインクリメント
4. `updated_at`タイムスタンプを更新
5. PRを提出

## トラブルシューティング

### レート制限

レート制限エラーが表示される場合：
- NVD APIキーを追加（上記の設定を参照）
- 待機して後で再試行

### 新しいCVEが見つからない

以下の場合は正常です：
- 新しいAIコーディングツールのCVEが公開されていない
- 見つかったCVEが既知のベンダー/製品名と一致しない

### スクリプトエラー

詳細はGitHub Actionsのログを確認してください。一般的な問題：
- ネットワーク接続の問題
- NVD APIの一時的な停止
- JSONパースエラー（不正なCVEデータ）

## 関連ドキュメント

- [FEATURES.ja.md](./FEATURES.ja.md) - CVEデータベース機能の概要
- [NVD APIドキュメント](https://nvd.nist.gov/developers/vulnerabilities)
