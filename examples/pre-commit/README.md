# cc-audit Pre-commit Hook

## 自動インストール

```bash
cc-audit --init-hook
```

これで `.git/hooks/pre-commit` にフックがインストールされます。

## 削除

```bash
cc-audit --remove-hook
```

## 手動設定 (pre-commit framework)

`.pre-commit-config.yaml` に以下を追加:

```yaml
repos:
  - repo: local
    hooks:
      - id: cc-audit
        name: cc-audit
        entry: cc-audit --type skill --ci .
        language: system
        pass_filenames: false
        files: ^\.claude/
```

## husky (Node.js)

```bash
npx husky add .husky/pre-commit "cc-audit --type skill --ci ."
```
