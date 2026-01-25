# CI/CD 自動化

このドキュメントでは、cc-audit に設定されている CI/CD パイプラインと自動化について説明します。

## 概要

| 自動化 | トリガー | 説明 |
|--------|---------|------|
| [CI](#ci-チェック) | Push, PR | フォーマット、リント、テスト、ドキュメント |
| [セキュリティ](#セキュリティチェック) | Push, PR | 脆弱性スキャン |
| [パフォーマンス](#パフォーマンスチェック) | Push, PR | ベンチマーク、バイナリサイズ |
| [セルフ監査](#セルフ監査) | Push, PR | cc-audit 自身でのスキャン |
| [コミットリント](#コミットメッセージ検証) | PR | Conventional Commits 検証 |
| [リリース](#リリース自動化) | main への Push | バージョニングとリリースの自動化 |

## CI チェック

**ワークフロー:** `.github/workflows/ci.yml`

| ジョブ | 説明 | ローカルコマンド |
|--------|------|-----------------|
| fmt | コードフォーマットチェック | `just fmt-check` |
| clippy | 全警告をエラーとするリンター | `just lint-all` |
| test | 全テスト実行 | `just test-all` |
| doc | ドキュメントビルド | `just doc` |
| coverage | コードカバレッジレポート | `just coverage-all` |

ローカルで全 CI チェックを実行:
```bash
just ci-main
```

## セキュリティチェック

**ワークフロー:** `.github/workflows/security.yml`

| ジョブ | 説明 | ローカルコマンド |
|--------|------|-----------------|
| audit | 既知の脆弱性チェック | `just security-audit` |
| deny | 依存関係のライセンスとアドバイザリチェック | `just security-deny` |
| vet | サプライチェーンセキュリティ | `just security-vet` |

ローカルで全セキュリティチェックを実行:
```bash
just ci-security
```

## パフォーマンスチェック

**ワークフロー:** `.github/workflows/performance.yml`

| ジョブ | 説明 | ローカルコマンド |
|--------|------|-----------------|
| benchmark | criterion ベンチマーク実行 | `just bench` |
| binary-size | バイナリサイズ閾値チェック | `just binary-size` |

ローカルでパフォーマンスチェックを実行:
```bash
just ci-performance
```

## セルフ監査

**ワークフロー:** `.github/workflows/self-audit.yml`

cc-audit 自身のコードベースをスキャン（ドッグフーディング）。

```bash
just self-audit
```

## MSRV チェック

**ワークフロー:** `.github/workflows/msrv.yml`

最小サポート Rust バージョン（MSRV）を検証。

```bash
just msrv-verify
```

## Semver チェック

**ワークフロー:** `.github/workflows/semver.yml`

前回リリースとの API 互換性をチェック。

```bash
just semver-check
```

## コミットメッセージ検証

**ワークフロー:** `.github/workflows/commitlint.yml`

コミットが [Conventional Commits](https://www.conventionalcommits.org/) 形式に従っているか検証。

### 許可されるタイプ

| タイプ | 説明 |
|--------|------|
| `feat` | 新機能 |
| `fix` | バグ修正 |
| `docs` | ドキュメント変更 |
| `style` | コードスタイル変更（フォーマット） |
| `refactor` | コードリファクタリング |
| `perf` | パフォーマンス改善 |
| `test` | テストの追加・更新 |
| `build` | ビルドシステム変更 |
| `ci` | CI 設定変更 |
| `chore` | その他の変更 |
| `revert` | 以前のコミットを取り消し |

### 例

```bash
feat: add JSON output format
fix(parser): handle empty input correctly
docs: update installation instructions
feat!: change API response format  # 破壊的変更
```

### ローカル設定

ローカルでのコミット検証を有効化:
```bash
just setup-hooks
```

## リリース自動化

**ワークフロー:**
- `.github/workflows/release-please.yml` - 自動バージョニング
- `.github/workflows/release.yml` - ビルドと公開

### 動作フロー

```
1. main に Conventional Commits 形式で push
   │
   ▼
2. release-please がコミットを解析
   │
   ├─ fix: コミット → パッチバンプ (0.5.0 → 0.5.1)
   ├─ feat: コミット → マイナーバンプ (0.5.0 → 0.6.0)
   └─ feat!: または BREAKING CHANGE → メジャーバンプ (0.5.0 → 1.0.0)
   │
   ▼
3. Release PR が自動作成/更新
   │  - CHANGELOG.md 更新
   │  - Cargo.toml バージョン更新
   │
   ▼
4. Release PR で CI チェック実行
   │
   ▼
5. 全チェック合格で自動マージ
   │
   ▼
6. タグ作成 (例: v0.6.0)
   │
   ▼
7. release.yml がトリガー
   │  - 全プラットフォーム向けバイナリビルド
   │  - GitHub Release 作成
   │  - チェックサム付きアーティファクトアップロード
   │
   ▼
8. リリース完了！
```

### サポートプラットフォーム

| プラットフォーム | ターゲット |
|-----------------|-----------|
| macOS (Intel) | x86_64-apple-darwin |
| macOS (Apple Silicon) | aarch64-apple-darwin |
| Linux (glibc) | x86_64-unknown-linux-gnu |
| Linux (glibc, ARM) | aarch64-unknown-linux-gnu |
| Linux (musl) | x86_64-unknown-linux-musl |
| Windows | x86_64-pc-windows-msvc |

### 手動リリース（必要な場合）

手動でリリースをトリガーする必要がある場合:
```bash
git tag v0.6.0
git push origin v0.6.0
```

## ローカルで全 CI を実行

```bash
# クイックチェック（フォーマット + リント）
just ci-quick

# メイン CI チェック
just ci-main

# フル CI（セキュリティ含む）
just ci-all

# 拡張 CI（パフォーマンスとミューテーションテスト含む）
just ci-extended
```

## GitHub リポジトリ設定

完全自動化のため、以下の設定を有効にしてください:

### ブランチ保護 (Settings → Branches → main)
- ☑ Require a pull request before merging
- ☑ Require status checks to pass before merging
- ☑ Require branches to be up to date before merging

### プルリクエスト (Settings → General → Pull Requests)
- ☑ Allow auto-merge

## ワークフローファイル一覧

| ファイル | 目的 |
|---------|------|
| `ci.yml` | メイン CI チェック |
| `security.yml` | セキュリティスキャン |
| `performance.yml` | ベンチマーク |
| `self-audit.yml` | ドッグフーディング |
| `msrv.yml` | MSRV 検証 |
| `semver.yml` | API 互換性 |
| `commitlint.yml` | コミットメッセージリント |
| `release-please.yml` | 自動バージョニング |
| `release.yml` | ビルドと公開 |
| `fuzz.yml` | ファズテスト |
| `mutation.yml` | ミューテーションテスト |
| `terraform.yml` | インフラ検証 |
