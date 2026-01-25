# 配布チャネル

cc-auditは複数のパッケージマネージャーを通じて配布されています。

## インストール方法

| チャネル | 対象 | コマンド |
|----------|------|----------|
| [crates.io](https://crates.io/crates/cc-audit) | Rust開発者 | `cargo install cc-audit` |
| [Homebrew](https://github.com/ryo-ebata/homebrew-tap) | macOS/Linux | `brew install ryo-ebata/tap/cc-audit` |
| [npm](https://www.npmjs.com/org/cc-audit) | Node.js開発者 | `npx @cc-audit/cc-audit` |
| GitHub Releases | 直接ダウンロード | [Releases](https://github.com/ryo-ebata/cc-audit/releases) |

## サポートプラットフォーム

| プラットフォーム | アーキテクチャ | パッケージ |
|------------------|----------------|------------|
| macOS | Apple Silicon (arm64) | 全チャネル |
| macOS | Intel (x64) | 全チャネル |
| Linux | x64 (glibc) | 全チャネル |
| Linux | arm64 (glibc) | 全チャネル |
| Linux | x64 (musl/Alpine) | npm, GitHub Releases |
| Windows | x64 | npm, GitHub Releases |

## リリース自動化

新しいバージョンタグがpushされると、3つのGitHub Actionsワークフローが自動実行されます：

```
git tag vX.Y.Z
git push origin vX.Y.Z
    │
    ├── release.yml        → GitHub Release + バイナリ
    ├── npm-publish.yml    → 7つのnpmパッケージ公開
    └── homebrew-update.yml → Homebrew Formula更新
```

### ワークフロー詳細

#### 1. release.yml

タグpush（`v*`）でトリガー。全プラットフォーム向けバイナリをビルドし、SHA256チェックサムとともにGitHub Releasesにアップロード。

**ターゲット:**
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`
- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`
- `x86_64-unknown-linux-musl`
- `x86_64-pc-windows-msvc`

#### 2. npm-publish.yml

リリース公開でトリガー。GitHub Releaseからバイナリをダウンロードしてnpmに公開。

**パッケージ:**
- `@cc-audit/cc-audit` - メインラッパーパッケージ
- `@cc-audit/darwin-arm64`
- `@cc-audit/darwin-x64`
- `@cc-audit/linux-arm64`
- `@cc-audit/linux-x64`
- `@cc-audit/linux-x64-musl`
- `@cc-audit/win32-x64`

**必要なSecret:** `NPM_TOKEN`

#### 3. homebrew-update.yml

リリース公開でトリガー。新バージョンとSHA256でHomebrew Formulaを更新。

**必要なSecret:** `HOMEBREW_TAP_TOKEN`（homebrew-tapへのrepoアクセス権を持つPAT）

## npmパッケージアーキテクチャ

**optionalDependencies**パターンを採用（Biome、esbuild、SWCと同様）：

```
@cc-audit/cc-audit (メインパッケージ)
├── bin/cc-audit        # CLIラッパー (Node.js)
├── src/index.js        # バイナリ解決ロジック
└── optionalDependencies:
    ├── @cc-audit/darwin-arm64
    ├── @cc-audit/darwin-x64
    ├── @cc-audit/linux-arm64
    ├── @cc-audit/linux-x64
    ├── @cc-audit/linux-x64-musl
    └── @cc-audit/win32-x64
```

npmはユーザーのOS/アーキテクチャに一致するプラットフォーム固有パッケージのみを自動インストール。

## Homebrew Tap

リポジトリ: [ryo-ebata/homebrew-tap](https://github.com/ryo-ebata/homebrew-tap)

```
homebrew-tap/
└── Formula/
    └── cc-audit.rb
```

FormulaはGitHub Releasesからビルド済みバイナリをダウンロード。

## 手動リリース手順

自動化が失敗した場合の手順：

### 1. crates.io

```bash
cargo login
cargo publish
```

### 2. GitHub Release

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
# release.ymlの完了を待つ
```

### 3. npm（手動）

```bash
# バイナリダウンロード
gh release download vX.Y.Z --pattern "*.tar.gz" --pattern "*.zip" --dir /tmp/release

# npmパッケージに展開
cd /tmp/release
tar -xzf cc-audit-vX.Y.Z-aarch64-apple-darwin.tar.gz
mv cc-audit /path/to/npm/darwin-arm64/bin/
# 他のプラットフォームも同様...

# 公開（プラットフォームパッケージ→メインの順）
cd npm/darwin-arm64 && npm publish --access public
cd ../darwin-x64 && npm publish --access public
cd ../linux-arm64 && npm publish --access public
cd ../linux-x64 && npm publish --access public
cd ../linux-x64-musl && npm publish --access public
cd ../win32-x64 && npm publish --access public
cd ../cc-audit && npm publish --access public
```

### 4. Homebrew（手動）

```bash
# SHA256取得
curl -sL https://github.com/ryo-ebata/cc-audit/releases/download/vX.Y.Z/cc-audit-vX.Y.Z-aarch64-apple-darwin.tar.gz | shasum -a 256

# Formula更新
cd homebrew-tap
# Formula/cc-audit.rbを新バージョンとSHA256で編集
git add . && git commit -m "Update cc-audit to X.Y.Z" && git push
```

## 必要なGitHub Secrets

| Secret | 用途 |
|--------|------|
| `NPM_TOKEN` | npm公開アクセス（bypass 2FA付きgranular token） |
| `HOMEBREW_TAP_TOKEN` | homebrew-tapリポジトリへのpush（Contents write権限付きPAT） |

## バージョンアップチェックリスト

1. `Cargo.toml`のバージョン更新
2. CHANGELOG.md更新
3. mainにコミット・push
4. タグ作成・push: `git tag vX.Y.Z && git push origin vX.Y.Z`
5. 全ワークフローの完了を確認
6. 各チャネルからのインストールをテスト
