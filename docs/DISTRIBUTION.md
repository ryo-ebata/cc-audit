# Distribution Channels

cc-audit is distributed through multiple package managers to reach different developer communities.

## Installation Methods

| Channel | Target | Command |
|---------|--------|---------|
| [crates.io](https://crates.io/crates/cc-audit) | Rust developers | `cargo install cc-audit` |
| [Homebrew](https://github.com/ryo-ebata/homebrew-tap) | macOS/Linux | `brew install ryo-ebata/tap/cc-audit` |
| [npm](https://www.npmjs.com/org/cc-audit) | Node.js developers | `npx @cc-audit/cc-audit` |
| GitHub Releases | Direct download | [Releases](https://github.com/ryo-ebata/cc-audit/releases) |

## Supported Platforms

| Platform | Architecture | Package |
|----------|--------------|---------|
| macOS | Apple Silicon (arm64) | All channels |
| macOS | Intel (x64) | All channels |
| Linux | x64 (glibc) | All channels |
| Linux | arm64 (glibc) | All channels |
| Linux | x64 (musl/Alpine) | npm, GitHub Releases |
| Windows | x64 | npm, GitHub Releases |

## Release Automation

When a new version tag is pushed, three GitHub Actions workflows run automatically:

```
git tag vX.Y.Z
git push origin vX.Y.Z
    │
    ├── release.yml        → GitHub Release + platform binaries
    ├── npm-publish.yml    → Publish 7 npm packages
    └── homebrew-update.yml → Update Homebrew formula
```

### Workflow Details

#### 1. release.yml

Triggers on tag push (`v*`). Builds binaries for all platforms and uploads to GitHub Releases with SHA256 checksums.

**Targets:**
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`
- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`
- `x86_64-unknown-linux-musl`
- `x86_64-pc-windows-msvc`

#### 2. npm-publish.yml

Triggers on release published. Downloads binaries from GitHub Release and publishes to npm.

**Packages:**
- `@cc-audit/cc-audit` - Main wrapper package
- `@cc-audit/darwin-arm64`
- `@cc-audit/darwin-x64`
- `@cc-audit/linux-arm64`
- `@cc-audit/linux-x64`
- `@cc-audit/linux-x64-musl`
- `@cc-audit/win32-x64`

**Required Secret:** `NPM_TOKEN`

#### 3. homebrew-update.yml

Triggers on release published. Updates the Homebrew formula with new version and SHA256 checksums.

**Required Secret:** `HOMEBREW_TAP_TOKEN` (PAT with repo access to homebrew-tap)

## npm Package Architecture

Uses the **optionalDependencies** pattern (same as Biome, esbuild, SWC):

```
@cc-audit/cc-audit (main package)
├── bin/cc-audit        # CLI wrapper (Node.js)
├── src/index.js        # Binary resolution logic
└── optionalDependencies:
    ├── @cc-audit/darwin-arm64
    ├── @cc-audit/darwin-x64
    ├── @cc-audit/linux-arm64
    ├── @cc-audit/linux-x64
    ├── @cc-audit/linux-x64-musl
    └── @cc-audit/win32-x64
```

npm automatically installs only the platform-specific package matching the user's OS/architecture.

## Homebrew Tap

Repository: [ryo-ebata/homebrew-tap](https://github.com/ryo-ebata/homebrew-tap)

```
homebrew-tap/
└── Formula/
    └── cc-audit.rb
```

The formula downloads pre-built binaries from GitHub Releases.

## Manual Release Process

If automation fails, follow these steps:

### 1. crates.io

```bash
cargo login
cargo publish
```

### 2. GitHub Release

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
# Wait for release.yml to complete
```

### 3. npm (manual)

```bash
# Download binaries
gh release download vX.Y.Z --pattern "*.tar.gz" --pattern "*.zip" --dir /tmp/release

# Extract to npm packages
cd /tmp/release
tar -xzf cc-audit-vX.Y.Z-aarch64-apple-darwin.tar.gz
mv cc-audit /path/to/npm/darwin-arm64/bin/
# Repeat for other platforms...

# Publish (platform packages first, then main)
cd npm/darwin-arm64 && npm publish --access public
cd ../darwin-x64 && npm publish --access public
cd ../linux-arm64 && npm publish --access public
cd ../linux-x64 && npm publish --access public
cd ../linux-x64-musl && npm publish --access public
cd ../win32-x64 && npm publish --access public
cd ../cc-audit && npm publish --access public
```

### 4. Homebrew (manual)

```bash
# Get SHA256
curl -sL https://github.com/ryo-ebata/cc-audit/releases/download/vX.Y.Z/cc-audit-vX.Y.Z-aarch64-apple-darwin.tar.gz | shasum -a 256

# Update Formula
cd homebrew-tap
# Edit Formula/cc-audit.rb with new version and SHA256
git add . && git commit -m "Update cc-audit to X.Y.Z" && git push
```

## Required GitHub Secrets

| Secret | Purpose |
|--------|---------|
| `NPM_TOKEN` | npm publish access (granular token with bypass 2FA) |
| `HOMEBREW_TAP_TOKEN` | Push to homebrew-tap repository (PAT with Contents write) |

## Version Bump Checklist

1. Update version in `Cargo.toml`
2. Update CHANGELOG.md
3. Commit and push to main
4. Create and push tag: `git tag vX.Y.Z && git push origin vX.Y.Z`
5. Verify all workflows complete successfully
6. Test installation from each channel
