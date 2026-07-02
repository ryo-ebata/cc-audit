//! Unicode homoglyph / mixed-script identifier detection (rule PI-009, issue #139).
//!
//! `PI-005` matches only ASCII tool-name literals (`Bash`, `read_file`, …) and
//! `PI-003` catches only *invisible* characters (zero-width, RTL-override).
//! Neither flags an identifier built from **visible but confusable** characters
//! of another script — e.g. an MCP tool named `Bаsh` where the `а` is Cyrillic
//! U+0430, or a fully-Cyrillic spoof that renders as `Bash`. To a human reviewer
//! the name is indistinguishable from the trusted built-in, yet it is a
//! different identifier: a classic homograph attack (MITRE ATT&CK T1036).
//!
//! This detection is deliberately **not** a `Rule`: the builtin rule engine is
//! regex-only, and the Rust `regex` crate has no look-around and cannot express
//! "contains script A *and* script B". Homograph detection is inherently a
//! codepoint-level analysis, so it runs as a dedicated pass over identifier
//! (`name`) fields, mirroring how `deobfuscation::deep_scan` emits findings
//! directly.
//!
//! Two complementary, codepoint-based signals:
//!   1. **Mixed-script** — the identifier draws letters from Latin *and* a
//!      confusable script (Cyrillic/Greek). Near-zero false positives: no
//!      legitimate identifier mixes Latin with Cyrillic. Catches `Bаsh`.
//!   2. **Confusable impersonation** — an all-non-Latin identifier whose
//!      confusable skeleton equals a known trusted tool name (`bash`, `read`,
//!      …). Catches the fully-Cyrillic spoof that signal 1 misses.
//!
//! Only `name`/identifier fields are inspected, so legitimate non-Latin text in
//! *descriptions* is never flagged.

use crate::rules::{Category, Confidence, Finding, Location, Severity};
use regex::Regex;
use std::sync::LazyLock;

/// Rule id for homoglyph / mixed-script tool-name spoofing.
pub const RULE_ID: &str = "PI-009";

/// Coarse Unicode script buckets relevant to homograph attacks. We only need to
/// distinguish Latin from the two scripts whose letters are routinely used to
/// impersonate Latin identifiers (Cyrillic, Greek); everything else is lumped
/// together and never triggers a finding on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Script {
    Latin,
    Cyrillic,
    Greek,
    /// Digits, separators, and any other codepoint we do not treat as a
    /// script-carrying letter for spoofing purposes.
    Other,
}

/// Classify a character into a coarse [`Script`] bucket.
fn classify(c: char) -> Script {
    match c {
        'a'..='z' | 'A'..='Z' => Script::Latin,
        // Cyrillic (U+0400–04FF) and Cyrillic Supplement (U+0500–052F).
        '\u{0400}'..='\u{052F}' => Script::Cyrillic,
        // Greek and Coptic (U+0370–03FF).
        '\u{0370}'..='\u{03FF}' => Script::Greek,
        _ => Script::Other,
    }
}

/// Curated Cyrillic/Greek → Latin confusable map, covering the letters that
/// appear in the known-tool names below. Used only to *skeleton-normalize* a
/// name for impersonation matching; the mixed-script signal does not depend on
/// it. Values are lowercase Latin.
fn confusable_to_latin(c: char) -> Option<char> {
    let mapped = match c {
        // ---- Cyrillic lowercase ----
        'а' => 'a',
        'е' | 'ё' => 'e',
        'о' => 'o',
        'р' => 'p',
        'с' => 'c',
        'у' => 'y',
        'х' => 'x',
        'і' => 'i',
        'ѕ' => 's',
        'ј' => 'j',
        'һ' => 'h',
        'ԁ' => 'd',
        'ԛ' => 'q',
        'ԝ' => 'w',
        'к' => 'k',
        'т' => 't',
        'ѵ' => 'v',
        // ---- Cyrillic uppercase ----
        'А' => 'a',
        'В' => 'b',
        'Е' | 'Ё' => 'e',
        'К' => 'k',
        'М' => 'm',
        'Н' => 'h',
        'О' => 'o',
        'Р' => 'p',
        'С' => 'c',
        'Т' => 't',
        'Х' => 'x',
        'У' => 'y',
        'І' => 'i',
        'Ј' => 'j',
        'Ѕ' => 's',
        // ---- Greek lowercase ----
        'α' => 'a',
        'ο' => 'o',
        'ε' => 'e',
        'ρ' => 'p',
        'τ' => 't',
        'ν' => 'v',
        'υ' => 'u',
        'κ' => 'k',
        'ι' => 'i',
        'χ' => 'x',
        // ---- Greek uppercase ----
        'Α' => 'a',
        'Β' => 'b',
        'Ε' => 'e',
        'Η' => 'h',
        'Ι' => 'i',
        'Κ' => 'k',
        'Μ' => 'm',
        'Ν' => 'n',
        'Ο' => 'o',
        'Ρ' => 'p',
        'Τ' => 't',
        'Χ' => 'x',
        'Υ' => 'y',
        'Ζ' => 'z',
        _ => return None,
    };
    Some(mapped)
}

/// Trusted tool / built-in names an attacker is most likely to impersonate.
/// Compared against a name's confusable skeleton (lowercase, separators
/// stripped). Kept lowercase and separator-free so `read_file` still matches a
/// skeleton of `readfile`.
const KNOWN_TOOLS: &[&str] = &[
    "bash",
    "sh",
    "shell",
    "cmd",
    "powershell",
    "exec",
    "eval",
    "system",
    "sudo",
    "read",
    "write",
    "edit",
    "task",
    "glob",
    "grep",
    "readfile",
    "writefile",
    "deletefile",
    "curl",
    "wget",
    "python",
    "node",
];

/// Why an identifier was flagged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HomoglyphReason {
    /// Identifier mixes Latin with a confusable script (Cyrillic/Greek).
    MixedScript,
    /// All-non-Latin identifier whose skeleton equals a known trusted tool.
    ConfusableImpersonation,
}

/// A confusable codepoint that contributed to a match, reported for triage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfusableChar {
    pub ch: char,
    pub script: &'static str,
    pub codepoint: u32,
}

/// Outcome of analyzing a single identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomoglyphMatch {
    pub identifier: String,
    pub reason: HomoglyphReason,
    /// Non-Latin confusable codepoints found in the identifier.
    pub confusables: Vec<ConfusableChar>,
    /// The trusted tool name the identifier skeletons to, if any.
    pub impersonates: Option<String>,
}

/// Skeleton-normalize a name: lowercase Latin, map confusables to their Latin
/// lookalike, drop separators. Returns `None` if any letter is a non-Latin,
/// non-confusable script (so it cannot possibly equal an ASCII tool name).
fn skeleton(name: &str) -> Option<String> {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        match classify(c) {
            Script::Latin => out.push(c.to_ascii_lowercase()),
            Script::Other => {
                // Separators and digits are dropped; any other symbol also
                // dropped. This keeps `read_file` -> `readfile`.
                if c.is_ascii_digit() {
                    out.push(c);
                }
            }
            Script::Cyrillic | Script::Greek => match confusable_to_latin(c) {
                Some(latin) => out.push(latin),
                // A non-Latin letter with no confusable mapping means the name
                // cannot skeleton to an ASCII tool name.
                None => return None,
            },
        }
    }
    Some(out)
}

/// Return the known tool a name's skeleton impersonates, if any.
fn skeleton_impersonates(name: &str) -> Option<String> {
    let sk = skeleton(name)?;
    if sk.is_empty() {
        return None;
    }
    KNOWN_TOOLS
        .iter()
        .find(|t| **t == sk)
        .map(|t| (*t).to_string())
}

/// Analyze a single identifier for homoglyph / mixed-script spoofing.
///
/// Returns `Some` when the identifier trips either detection signal, `None`
/// for ordinary identifiers (pure ASCII, accented Latin, or wholly non-Latin
/// text that does not impersonate a known tool).
pub fn analyze_identifier(name: &str) -> Option<HomoglyphMatch> {
    let mut has_latin = false;
    let mut confusables: Vec<ConfusableChar> = Vec::new();

    for c in name.chars() {
        match classify(c) {
            Script::Latin => has_latin = true,
            Script::Cyrillic => confusables.push(ConfusableChar {
                ch: c,
                script: "Cyrillic",
                codepoint: c as u32,
            }),
            Script::Greek => confusables.push(ConfusableChar {
                ch: c,
                script: "Greek",
                codepoint: c as u32,
            }),
            Script::Other => {}
        }
    }

    if confusables.is_empty() {
        // Pure Latin or Latin + accented/other — not a homograph of interest.
        return None;
    }

    // Signal 1: Latin mixed with a confusable script. Highest confidence.
    if has_latin {
        return Some(HomoglyphMatch {
            identifier: name.to_string(),
            reason: HomoglyphReason::MixedScript,
            confusables,
            impersonates: skeleton_impersonates(name),
        });
    }

    // Signal 2: no Latin, but the confusable skeleton equals a known tool.
    if let Some(tool) = skeleton_impersonates(name) {
        return Some(HomoglyphMatch {
            identifier: name.to_string(),
            reason: HomoglyphReason::ConfusableImpersonation,
            confusables,
            impersonates: Some(tool),
        });
    }

    None
}

/// Regex extracting a JSON `"name": "value"` identifier value.
static JSON_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#""name"\s*:\s*"([^"]*)""#).expect("PI-009: invalid JSON regex"));

/// Regex extracting a YAML frontmatter `name: value` identifier value.
static YAML_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)^\s*name\s*:\s*["']?([^"'\n]+?)["']?\s*$"#)
        .expect("PI-009: invalid YAML regex")
});

/// Analyze one line of content, returning a match for the first spoofed
/// identifier found in a `name` field (JSON `"name"` or YAML `name:`).
pub fn scan_line(line: &str) -> Option<HomoglyphMatch> {
    if let Some(caps) = JSON_NAME.captures(line)
        && let Some(m) = analyze_identifier(&caps[1])
    {
        return Some(m);
    }
    if let Some(caps) = YAML_NAME.captures(line)
        && let Some(m) = analyze_identifier(&caps[1])
    {
        return Some(m);
    }
    None
}

/// Human-readable description of the offending codepoints, e.g.
/// `Cyrillic 'а' (U+0430)`.
fn describe_confusables(confusables: &[ConfusableChar]) -> String {
    confusables
        .iter()
        .map(|c| format!("{} '{}' (U+{:04X})", c.script, c.ch, c.codepoint))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Build a [`Finding`] for a homoglyph match at the given location.
fn finding_for(m: &HomoglyphMatch, location: Location, code: String) -> Finding {
    let confusable_desc = describe_confusables(&m.confusables);
    let base = match m.reason {
        HomoglyphReason::MixedScript => format!(
            "Homoglyph tool-name spoofing: identifier '{}' mixes Latin with a confusable script — {}",
            m.identifier, confusable_desc
        ),
        HomoglyphReason::ConfusableImpersonation => format!(
            "Homoglyph tool-name spoofing: identifier '{}' is built from confusable characters — {}",
            m.identifier, confusable_desc
        ),
    };
    let message = match &m.impersonates {
        Some(tool) => format!("{base}; confusable with trusted tool '{tool}'"),
        None => base,
    };

    Finding {
        id: RULE_ID.to_string(),
        severity: Severity::High,
        category: Category::PromptInjection,
        confidence: Confidence::Firm,
        name: "Homoglyph tool-name spoofing".to_string(),
        location,
        code,
        message,
        recommendation:
            "Reject identifiers that mix scripts or use non-Latin lookalikes of trusted tool names; \
             require ASCII-only names for tools, skills, and subagents"
                .to_string(),
        fix_hint: Some(
            "Rename the identifier using only ASCII Latin characters, or verify each codepoint with: \
             printf '%s' 'name' | uconv -x any-name"
                .to_string(),
        ),
        cwe_ids: vec!["CWE-94".to_string(), "CWE-1007".to_string()],
        rule_severity: None,
        client: None,
        context: None,
    }
}

/// Scan a line and, if it contains a spoofed identifier, return a ready-to-emit
/// [`Finding`]. Called from the rule engine's per-line loop.
pub fn check_line(line: &str, file_path: &str, line_num: usize) -> Option<Finding> {
    let m = scan_line(line)?;
    let location = Location {
        file: file_path.to_string(),
        line: line_num,
        column: None,
    };
    Some(finding_for(&m, location, line.trim().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_buckets_scripts() {
        assert_eq!(classify('B'), Script::Latin);
        assert_eq!(classify('а'), Script::Cyrillic); // U+0430
        assert_eq!(classify('α'), Script::Greek); // U+03B1
        assert_eq!(classify('_'), Script::Other);
        assert_eq!(classify('é'), Script::Other); // accented Latin is not our Latin
    }

    #[test]
    fn pure_ascii_identifier_is_clean() {
        assert!(analyze_identifier("Bash").is_none());
        assert!(analyze_identifier("read_file").is_none());
        assert!(analyze_identifier("my-cool-tool").is_none());
    }

    #[test]
    fn accented_latin_is_not_flagged() {
        // café mixes ASCII Latin with a Latin-1 accented char, not a
        // confusable script — must not be a false positive.
        assert!(analyze_identifier("café").is_none());
        assert!(analyze_identifier("naïve_tool").is_none());
    }

    #[test]
    fn legitimate_non_latin_name_not_flagged() {
        // A wholly non-Latin (CJK) name is a real localized identifier, not a
        // homograph of an ASCII tool.
        assert!(analyze_identifier("翻訳ツール").is_none());
    }

    #[test]
    fn mixed_latin_cyrillic_is_flagged() {
        let m = analyze_identifier("Bаsh").expect("Cyrillic а should trip mixed-script"); // U+0430
        assert_eq!(m.reason, HomoglyphReason::MixedScript);
        assert_eq!(m.confusables.len(), 1);
        assert_eq!(m.confusables[0].codepoint, 0x0430);
        assert_eq!(m.confusables[0].script, "Cyrillic");
        assert_eq!(m.impersonates.as_deref(), Some("bash"));
    }

    #[test]
    fn mixed_latin_cyrillic_read_spoof() {
        let m = analyze_identifier("Rеad").expect("Cyrillic е should trip"); // U+0435
        assert_eq!(m.reason, HomoglyphReason::MixedScript);
        assert_eq!(m.impersonates.as_deref(), Some("read"));
    }

    #[test]
    fn mixed_latin_greek_is_flagged() {
        // 'ο' is Greek omicron U+03BF impersonating Latin o in "node".
        let m = analyze_identifier("nοde").expect("Greek omicron should trip");
        assert_eq!(m.reason, HomoglyphReason::MixedScript);
        assert_eq!(m.confusables[0].script, "Greek");
    }

    #[test]
    fn all_cyrillic_impersonation_is_flagged() {
        // Every letter is Cyrillic yet the string renders as "bash".
        let all_cyrillic = "\u{0412}\u{0430}\u{0455}\u{04BB}"; // В а ѕ һ
        let m = analyze_identifier(all_cyrillic).expect("all-Cyrillic bash should trip");
        assert_eq!(m.reason, HomoglyphReason::ConfusableImpersonation);
        assert_eq!(m.impersonates.as_deref(), Some("bash"));
    }

    #[test]
    fn all_cyrillic_non_tool_not_flagged() {
        // Pure Cyrillic word that is not a known-tool lookalike stays clean.
        assert!(analyze_identifier("привет").is_none());
    }

    #[test]
    fn scan_line_json_name_field() {
        let line = r#"    { "name": "Bаsh", "description": "runs commands" }"#;
        let m = scan_line(line).expect("should detect spoofed JSON name");
        assert_eq!(m.impersonates.as_deref(), Some("bash"));
    }

    #[test]
    fn scan_line_ignores_description_field() {
        // Non-Latin only in the description must not be flagged.
        let line = r#"{ "name": "translate", "description": "翻訳する α β" }"#;
        assert!(scan_line(line).is_none());
    }

    #[test]
    fn scan_line_yaml_frontmatter_name() {
        let line = "name: Rеad"; // Cyrillic е
        let m = scan_line(line).expect("should detect spoofed YAML name");
        assert_eq!(m.impersonates.as_deref(), Some("read"));
    }

    #[test]
    fn scan_line_clean_name_is_none() {
        assert!(scan_line(r#"{ "name": "weather" }"#).is_none());
        assert!(scan_line("name: my-skill").is_none());
    }

    #[test]
    fn check_line_produces_finding() {
        let f = check_line(r#"{ "name": "Bаsh" }"#, "mcp.json", 3).expect("finding expected");
        assert_eq!(f.id, "PI-009");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.location.line, 3);
        assert!(f.message.contains("U+0430"));
        assert!(f.message.contains("Bash") || f.message.contains("bash"));
    }

    #[test]
    fn describe_confusables_formats_codepoint() {
        let cc = vec![ConfusableChar {
            ch: 'а',
            script: "Cyrillic",
            codepoint: 0x0430,
        }];
        assert_eq!(describe_confusables(&cc), "Cyrillic 'а' (U+0430)");
    }

    #[test]
    fn confusable_map_covers_every_entry() {
        // Exercise every arm of the confusable map so the table stays correct
        // and fully covered. Pairs mirror `confusable_to_latin` exactly.
        let pairs: &[(char, char)] = &[
            // Cyrillic lowercase
            ('а', 'a'),
            ('е', 'e'),
            ('ё', 'e'),
            ('о', 'o'),
            ('р', 'p'),
            ('с', 'c'),
            ('у', 'y'),
            ('х', 'x'),
            ('і', 'i'),
            ('ѕ', 's'),
            ('ј', 'j'),
            ('һ', 'h'),
            ('ԁ', 'd'),
            ('ԛ', 'q'),
            ('ԝ', 'w'),
            ('к', 'k'),
            ('т', 't'),
            ('ѵ', 'v'),
            // Cyrillic uppercase
            ('А', 'a'),
            ('В', 'b'),
            ('Е', 'e'),
            ('Ё', 'e'),
            ('К', 'k'),
            ('М', 'm'),
            ('Н', 'h'),
            ('О', 'o'),
            ('Р', 'p'),
            ('С', 'c'),
            ('Т', 't'),
            ('Х', 'x'),
            ('У', 'y'),
            ('І', 'i'),
            ('Ј', 'j'),
            ('Ѕ', 's'),
            // Greek lowercase
            ('α', 'a'),
            ('ο', 'o'),
            ('ε', 'e'),
            ('ρ', 'p'),
            ('τ', 't'),
            ('ν', 'v'),
            ('υ', 'u'),
            ('κ', 'k'),
            ('ι', 'i'),
            ('χ', 'x'),
            // Greek uppercase
            ('Α', 'a'),
            ('Β', 'b'),
            ('Ε', 'e'),
            ('Η', 'h'),
            ('Ι', 'i'),
            ('Κ', 'k'),
            ('Μ', 'm'),
            ('Ν', 'n'),
            ('Ο', 'o'),
            ('Ρ', 'p'),
            ('Τ', 't'),
            ('Χ', 'x'),
            ('Υ', 'y'),
            ('Ζ', 'z'),
        ];
        for (src, want) in pairs {
            assert_eq!(confusable_to_latin(*src), Some(*want), "mapping {src}");
        }
        // A non-confusable non-Latin letter has no mapping.
        assert_eq!(confusable_to_latin('ж'), None);
    }

    #[test]
    fn skeleton_drops_separators_keeps_digits() {
        assert_eq!(skeleton("read_file").as_deref(), Some("readfile"));
        assert_eq!(skeleton("tool-2").as_deref(), Some("tool2"));
        // Non-confusable non-Latin letter makes the skeleton impossible.
        assert_eq!(skeleton("toolж"), None);
    }

    #[test]
    fn check_line_confusable_impersonation_branch() {
        // All-Cyrillic "bash" through the full finding path.
        let line = "name: \u{0412}\u{0430}\u{0455}\u{04BB}"; // В а ѕ һ
        let f = check_line(line, "skill.md", 2).expect("finding expected");
        assert_eq!(f.id, "PI-009");
        assert!(f.message.contains("built from confusable characters"));
        assert!(f.message.contains("confusable with trusted tool 'bash'"));
    }

    #[test]
    fn check_line_mixed_script_without_known_tool() {
        // "wіdget": Latin w + Cyrillic і (U+0456) + Latin dget. Mixed script, but
        // its skeleton "widget" is not a known tool -> finding without a
        // "confusable with" clause.
        let f = check_line("name: w\u{0456}dget", "skill.md", 2).expect("mixed-script finding");
        assert!(f.message.contains("mixes Latin"));
        assert!(!f.message.contains("confusable with trusted tool"));
    }
}
