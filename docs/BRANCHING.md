# Branching Strategy

This project follows **GitHub Flow** - a simple, lightweight branching model suitable for small to medium-sized OSS projects.

## Branch Structure

```
main (always deployable)
  │
  ├── feature/add-mcp-scanning     # New features
  ├── fix/false-positive-ex001     # Bug fixes
  ├── docs/improve-readme          # Documentation
  └── refactor/rule-engine         # Code improvements
```

## Branch Naming Convention

| Prefix | Purpose | Example |
|--------|---------|---------|
| `feature/` | New functionality | `feature/sarif-output` |
| `fix/` | Bug fixes | `fix/unicode-handling` |
| `docs/` | Documentation only | `docs/add-japanese-readme` |
| `refactor/` | Code refactoring | `refactor/scanner-module` |
| `test/` | Test additions | `test/integration-mcp` |
| `ci/` | CI/CD changes | `ci/add-coverage` |

## Workflow

### For Contributors

```bash
# 1. Fork and clone
git clone https://github.com/YOUR_USERNAME/cc-audit.git
cd cc-audit

# 2. Create feature branch from main
git checkout main
git pull origin main
git checkout -b feature/your-feature

# 3. Make changes and commit
git add .
git commit -m "Add your feature"

# 4. Push to your fork
git push origin feature/your-feature

# 5. Open Pull Request on GitHub
```

### For Maintainers

```bash
# 1. Create branch directly (no fork needed)
git checkout main
git pull origin main
git checkout -b feature/new-feature

# 2. Make changes and push
git add .
git commit -m "Add new feature"
git push origin feature/new-feature

# 3. Open Pull Request, get review, merge
```

## Rules

### Main Branch

- **Always deployable** - `main` should never be broken
- **No direct pushes** - All changes go through Pull Requests
- **CI must pass** - PRs can only be merged if all checks pass

### Pull Requests

- One feature/fix per PR (keep it focused)
- Write descriptive PR titles
- Reference related issues (`Fixes #123`)
- Request review from maintainers
- Squash commits when merging (keeps history clean)

## Release Process

Releases are triggered by Git tags:

```bash
# 1. Ensure main is ready for release
git checkout main
git pull origin main

# 2. Create and push tag
git tag v0.1.0
git push origin v0.1.0

# 3. CI automatically:
#    - Builds binaries for all platforms
#    - Creates GitHub Release
#    - Uploads artifacts
```

### Version Format

Follow [Semantic Versioning](https://semver.org/):

```
v{MAJOR}.{MINOR}.{PATCH}

MAJOR: Breaking changes
MINOR: New features (backward compatible)
PATCH: Bug fixes (backward compatible)
```

Examples:
- `v0.1.0` - Initial release
- `v0.1.1` - Bug fix
- `v0.2.0` - New feature added
- `v1.0.0` - Stable release / Breaking change

### Pre-release Tags

```
v0.2.0-alpha.1   # Early testing
v0.2.0-beta.1    # Feature complete, testing
v0.2.0-rc.1      # Release candidate
```

## GitHub Repository Settings

### Branch Protection (Settings > Branches)

Apply to `main` branch:

| Setting | Value | Reason |
|---------|-------|--------|
| Require a pull request before merging | ON | No direct pushes |
| Require status checks to pass | ON | CI must pass |
| Required checks | `fmt`, `clippy`, `test` | Core quality gates |
| Require conversation resolution | ON | All comments addressed |
| Include administrators | ON | No exceptions |

### Merge Settings (Settings > General)

| Setting | Recommended |
|---------|-------------|
| Allow squash merging | ON (default) |
| Allow merge commits | OFF |
| Allow rebase merging | OFF |
| Automatically delete head branches | ON |

### Actions Settings (Settings > Actions > General)

| Setting | Value |
|---------|-------|
| Fork pull request workflows | Require approval for first-time contributors |
| Fork pull request workflows from outside collaborators | Require approval for all |

## FAQ

### Why GitHub Flow instead of Git Flow?

Git Flow (with `develop`, `release/*`, `hotfix/*` branches) is designed for projects with scheduled releases. For cc-audit:

- We release when features are ready (not on a schedule)
- We have a small team
- Simpler is better

### When should I create a new branch?

Always. Even for small changes. This ensures:
- Changes are reviewed before merging
- CI runs on all changes
- History is traceable

### Can I push directly to main?

No. Even maintainers must go through Pull Requests. This is enforced by branch protection rules.
