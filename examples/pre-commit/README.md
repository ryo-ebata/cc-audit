# cc-audit Pre-commit Hook

## Automatic Installation

```bash
cc-audit hook init
```

This installs the hook to `.git/hooks/pre-commit`.

## Removal

```bash
cc-audit hook remove
```

## Manual Setup (pre-commit framework)

Add the following to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: cc-audit
        name: cc-audit
        entry: cc-audit check --type skill --ci .
        language: system
        pass_filenames: false
        files: ^\.claude/
```

## husky (Node.js)

```bash
npx husky add .husky/pre-commit "cc-audit check --type skill --ci ."
```

## lint-staged

Add to `package.json`:

```json
{
  "lint-staged": {
    ".claude/**/*.md": "cc-audit check --type skill --ci"
  }
}
```

## lefthook

Add to `lefthook.yml`:

```yaml
pre-commit:
  commands:
    cc-audit:
      glob: ".claude/**/*.md"
      run: cc-audit check --type skill --ci {staged_files}
```
