const path = require('path');
const fs = require('fs');

const PLATFORMS = {
  'darwin-arm64': '@cc-audit/darwin-arm64',
  'darwin-x64': '@cc-audit/darwin-x64',
  'linux-arm64': '@cc-audit/linux-arm64',
  'linux-x64': '@cc-audit/linux-x64',
  'win32-x64': '@cc-audit/win32-x64',
};

function isMusl() {
  if (process.platform !== 'linux') return false;

  try {
    const output = require('child_process').execSync('ldd --version 2>&1', {
      encoding: 'utf8',
    });
    return output.includes('musl');
  } catch {
    try {
      const release = fs.readFileSync('/etc/os-release', 'utf8');
      return release.includes('Alpine');
    } catch {
      return false;
    }
  }
}

function getPlatformPackage() {
  const platform = process.platform;
  const arch = process.arch;

  if (platform === 'linux' && arch === 'x64' && isMusl()) {
    return '@cc-audit/linux-x64-musl';
  }

  const key = `${platform}-${arch}`;
  const pkg = PLATFORMS[key];

  if (!pkg) {
    throw new Error(
      `Unsupported platform: ${platform}-${arch}\n` +
        `Supported platforms: ${Object.keys(PLATFORMS).join(', ')}, linux-x64-musl`
    );
  }

  return pkg;
}

function getBinaryPath() {
  const pkg = getPlatformPackage();

  try {
    const pkgPath = require.resolve(`${pkg}/package.json`);
    const pkgDir = path.dirname(pkgPath);
    const binaryName =
      process.platform === 'win32' ? 'cc-audit.exe' : 'cc-audit';
    const binaryPath = path.join(pkgDir, 'bin', binaryName);

    if (!fs.existsSync(binaryPath)) {
      throw new Error(`Binary not found: ${binaryPath}`);
    }

    return binaryPath;
  } catch (error) {
    if (error.code === 'MODULE_NOT_FOUND') {
      throw new Error(
        `Platform package not installed: ${pkg}\n` + `Run: npm install ${pkg}`
      );
    }
    throw error;
  }
}

module.exports = { getBinaryPath, getPlatformPackage };
