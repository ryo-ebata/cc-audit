# Homebrew Formula for cc-audit
# Copy this file to homebrew-tap/Formula/cc-audit.rb after updating SHA256 values
#
# To calculate SHA256 from release assets:
#   curl -sL https://github.com/ryo-ebata/cc-audit/releases/download/vX.Y.Z/cc-audit-vX.Y.Z-TARGET.tar.gz | shasum -a 256
#
class CcAudit < Formula
  desc "Security auditor for Claude Code skills, hooks, and MCP servers"
  homepage "https://github.com/ryo-ebata/cc-audit"
  version "0.4.1"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/ryo-ebata/cc-audit/releases/download/v#{version}/cc-audit-v#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_ACTUAL_SHA256_DARWIN_ARM64"
    end
    on_intel do
      url "https://github.com/ryo-ebata/cc-audit/releases/download/v#{version}/cc-audit-v#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_ACTUAL_SHA256_DARWIN_X64"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/ryo-ebata/cc-audit/releases/download/v#{version}/cc-audit-v#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "REPLACE_WITH_ACTUAL_SHA256_LINUX_ARM64"
    end
    on_intel do
      url "https://github.com/ryo-ebata/cc-audit/releases/download/v#{version}/cc-audit-v#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "REPLACE_WITH_ACTUAL_SHA256_LINUX_X64"
    end
  end

  def install
    bin.install "cc-audit"
  end

  test do
    assert_match "cc-audit", shell_output("#{bin}/cc-audit --version")
  end
end
