# GitHub Repository Protection (Terraform)

cc-auditリポジトリの保護設定をTerraformで管理します。

## 設定内容

### Branch Protection (main)

- 直接push禁止
- Force push禁止
- ブランチ削除禁止
- PR会話解決必須
- CI通過必須 (test, lint, clippy, fmt)

### Tag Protection (v*)

- タグ作成: 許可
- タグ更新: 禁止
- タグ削除: 禁止

## 前提条件

- Terraform >= 1.0
- Fine-grained Personal Access Token (PAT)
  - Repository: `kotrotsos/cc-audit`
  - Permissions:
    - Administration: Read and write
    - Contents: Read

## 使用方法

### 1. PATの発行

1. [GitHub Settings > Developer settings > Personal access tokens > Fine-grained tokens](https://github.com/settings/tokens?type=beta)
2. "Generate new token"
3. 設定:
   - Token name: `cc-audit-terraform`
   - Expiration: 7 days (推奨)
   - Repository access: Only select repositories > `kotrotsos/cc-audit`
   - Permissions:
     - Repository permissions > Administration: Read and write
     - Repository permissions > Contents: Read

### 2. 初期化と適用

```bash
cd infra/github

# 環境変数にトークンを設定
export GITHUB_TOKEN="github_pat_xxxxx"

# 初期化
terraform init

# 確認
terraform plan

# 適用
terraform apply
```

### 3. 検証

```bash
# AC-001: mainへの直接pushが拒否される
git push origin main
# -> rejected

# AC-002: CI失敗PRがmerge不可
# -> GitHub UIでmergeボタン無効を確認

# AC-003: v*タグが削除不可
git push --delete origin v0.4.1
# -> rejected

# AC-004: terraform planが差分なし
terraform plan
# -> No changes
```

### 4. PAT権限の縮小

適用完了後、PATの権限を最小限に縮小または削除することを推奨します。

## State管理

- `terraform.tfstate`はローカル管理
- **リポジトリにコミットしない** (.gitignoreで除外済み)
- 紛失した場合は`terraform import`で復元可能

### State復元手順

```bash
# リポジトリ情報を再インポート
terraform import 'data.github_repository.cc_audit' "kotrotsos/cc-audit"

# ブランチ保護を再インポート
terraform import 'github_branch_protection.main' "cc-audit:main"

# タグ保護rulesetを再インポート (ruleset IDはGitHub APIで確認)
terraform import 'github_repository_ruleset.protect_release_tags' "cc-audit:<ruleset_id>"
```

## トラブルシューティング

### 自分もpush不可になった場合

PRからのmergeは引き続き可能です。GitHub UIから設定を一時的に緩和することもできます。

### PAT認証エラー

```
Error: GET https://api.github.com/repos/kotrotsos/cc-audit: 401 Bad credentials
```

→ トークンが正しく設定されているか確認:

```bash
echo $GITHUB_TOKEN
```

### 権限不足エラー

```
Error: PUT https://api.github.com/repos/kotrotsos/cc-audit/branches/main/protection: 403
```

→ PATに`Administration: Read and write`権限があるか確認

## 参考リンク

- [GitHub Provider Documentation](https://registry.terraform.io/providers/integrations/github/latest/docs)
- [Branch protection rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
- [Repository rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets)
