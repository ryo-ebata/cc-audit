# 検出ルールリファレンス

[English](./RULES.md)

## 深刻度レベル

| レベル | 意味 | デフォルト動作 |
|--------|------|----------------|
| **critical** | インストール禁止、即座にブロック | 終了コード 1 |
| **high** | 強く非推奨、レビュー必須 | 終了コード 1 |
| **medium** | 注意が必要、レビュー推奨 | `--strict`で表示 |
| **low** | 情報提供、ベストプラクティス違反 | `--strict`で表示 |

## リスクスコアリング

cc-auditは検出結果に基づいてリスクスコア（0-100）を計算します：

| スコア範囲 | リスクレベル | 意味 |
|------------|--------------|------|
| 0 | Safe | セキュリティ問題なし |
| 1-25 | Low | 軽微な問題、概ね安全 |
| 26-50 | Medium | レビュー推奨 |
| 51-75 | High | 重大な懸念、レビュー必須 |
| 76-100 | Critical | 深刻な問題、インストール禁止 |

**スコアリングの重み:**
- Critical検出: +40ポイント
- High検出: +20ポイント
- Medium検出: +10ポイント
- Low検出: +5ポイント

---

## データ流出 (EX)

| ID | 名前 | 深刻度 | 説明 |
|----|------|--------|------|
| EX-001 | 環境変数を含むネットワークリクエスト | Critical | `curl`/`wget`で環境変数を検出 |
| EX-002 | Base64エンコード送信 | Critical | ネットワークリクエストでBase64データを検出 |
| EX-003 | DNSベース流出 | High | DNSトンネリングパターンを検出 |
| EX-005 | Netcat外部接続 | Critical | 外部ホストへの`nc`接続を検出 |
| EX-006 | クラウドストレージ流出 | High | S3、GCS、Azure Blobへのアップロードを検出 |
| EX-007 | FTP/SFTP流出 | High | FTPベースのデータ転送を検出 |

## 権限昇格 (PE)

| ID | 名前 | 深刻度 | 説明 |
|----|------|--------|------|
| PE-001 | Sudo実行 | Critical | sudoコマンドの使用を検出 |
| PE-002 | 破壊的ルート削除 | Critical | `rm -rf /`などを検出 |
| PE-003 | 危険な権限変更 | Critical | `chmod 777`パターンを検出 |
| PE-004 | システムパスワードファイルアクセス | Critical | `/etc/passwd`、`/etc/shadow`へのアクセスを検出 |
| PE-005 | SSHディレクトリアクセス | Critical | SSH秘密鍵の読み取りを検出 |

## 永続化 (PS)

| ID | 名前 | 深刻度 | 説明 |
|----|------|--------|------|
| PS-001 | Crontab操作 | Critical | crontab変更を検出 |
| PS-003 | シェルプロファイル変更 | Critical | `.bashrc`、`.zshrc`への書き込みを検出 |
| PS-004 | システムサービス登録 | Critical | systemd/launchdサービス作成を検出 |
| PS-005 | SSH authorized_keys変更 | Critical | SSHキー注入を検出 |
| PS-006 | Initスクリプト変更 | Critical | init.d変更を検出 |
| PS-007 | バックグラウンドプロセス実行 | Critical | `nohup`、`setsid`、`&`パターンを検出 |

## プロンプトインジェクション (PI)

| ID | 名前 | 深刻度 | 説明 |
|----|------|--------|------|
| PI-001 | 指示無視パターン | High | 「以前の指示を無視」を検出 |
| PI-002 | 隠しHTML指示 | High | HTMLコメント内の指示を検出 |
| PI-003 | 不可視Unicode文字 | High | ゼロ幅文字を検出 |

## 過剰権限 (OP)

| ID | 名前 | 深刻度 | 説明 |
|----|------|--------|------|
| OP-001 | ワイルドカードツール権限 | High | `allowed-tools: *`を検出 |

## 難読化 (OB)

| ID | 名前 | 深刻度 | 説明 |
|----|------|--------|------|
| OB-001 | 変数を含むEval | High | `eval $VAR`パターンを検出 |
| OB-002 | Base64デコード実行 | High | `base64 -d \| bash`を検出 |
| OB-003 | 16進/8進実行 | High | エンコードされたシェルコマンドを検出 |
| OB-004 | 文字列操作 | Medium | `rev`、`cut`難読化を検出 |
| OB-005 | 環境変数トリック | Medium | 変数置換トリックを検出 |
| OB-006 | ファイルディスクリプタ操作 | Medium | `exec 3<>`パターンを検出 |

## サプライチェーン (SC)

| ID | 名前 | 深刻度 | 説明 |
|----|------|--------|------|
| SC-001 | curlパイプシェル | Critical | `curl ... \| bash`を検出 |
| SC-002 | wgetパイプシェル | Critical | `wget ... \| bash`を検出 |
| SC-003 | 信頼できないパッケージソース | High | 危険なpip/npmソースを検出 |

## シークレット漏洩 (SL)

| ID | 名前 | 深刻度 | 説明 |
|----|------|--------|------|
| SL-001 | AWSアクセスキー | Critical | `AKIA...`パターンを検出 |
| SL-002 | GitHubトークン | Critical | `ghp_`、`gho_`などを検出 |
| SL-003 | AI APIキー | Critical | Anthropic/OpenAIキーを検出 |
| SL-004 | 秘密鍵 | Critical | PEM秘密鍵を検出 |
| SL-005 | URL内の認証情報 | Critical | `user:pass@host`を検出 |

## Docker (DK)

| ID | 名前 | 深刻度 | 説明 |
|----|------|--------|------|
| DK-001 | 特権コンテナ | Critical | `--privileged`フラグを検出 |
| DK-002 | rootとして実行 | High | `USER root`を検出 |
| DK-003 | RUN内のリモートスクリプト | Critical | `RUN curl \| bash`を検出 |

## 依存関係 (DEP)

| ID | 名前 | 深刻度 | 説明 |
|----|------|--------|------|
| DEP-001 | 危険なライフサイクルスクリプト | High | 悪意あるnpmスクリプトを検出 |
| DEP-002 | ピン留めされていないバージョン | Medium | `*`や`latest`バージョンを検出 |
| DEP-003 | 危険なパッケージソース | High | HTTPパッケージURLを検出 |
| DEP-004 | 非推奨パッケージ | Medium | 既知の非推奨パッケージを検出 |
| DEP-005 | 既知の脆弱バージョン | Critical | 既知のCVEを持つパッケージを検出 |

---

## ルールの抑制

### 設定経由

```yaml
# .cc-audit.yaml
disabled_rules:
  - "PE-001"
  - "EX-002"
```

### インラインコメント経由

```bash
# cc-audit-ignore: PE-001
sudo apt update

# cc-audit-ignore
curl $SECRET_URL  # この行は無視される
```

### 信頼度レベル経由

```bash
# 高信頼度の検出のみ表示
cc-audit check --min-confidence certain ./skill/
```
