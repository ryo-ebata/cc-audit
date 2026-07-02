//! Shared normalization of shell backslash line-continuations into logical lines.
//!
//! Line-based scanners test each physical line independently, so a payload split
//! across lines with a trailing `\` evades detection even though the single-line
//! form fires. Joining continuations before matching closes this evasion class
//! for both the rule engine (#126) and the malware signature database (#151),
//! from a single source of truth.

/// Join shell-style backslash line-continuations into logical lines.
///
/// A physical line ending in an **odd** number of backslashes continues onto the
/// next line; the trailing `\` is stripped and the lines are concatenated. An
/// **even** count is an escaped literal backslash, not a continuation.
///
/// Returns `(start, logical_line)` pairs where `start` is the 0-based index of
/// the first physical line of the logical line, so findings keep reporting the
/// original line number. Content with no continuations yields exactly its
/// physical lines with unchanged indices.
pub fn logical_lines(content: &str) -> Vec<(usize, String)> {
    let mut result = Vec::new();
    let mut pending: Option<(usize, String)> = None;

    for (idx, line) in content.lines().enumerate() {
        let continued = ends_with_continuation(line);
        // Strip the single trailing backslash that marks the continuation.
        let segment = if continued {
            &line[..line.len() - 1]
        } else {
            line
        };
        match pending {
            Some((_, ref mut buf)) => buf.push_str(segment),
            None => pending = Some((idx, segment.to_string())),
        }
        if !continued && let Some(joined) = pending.take() {
            result.push(joined);
        }
    }

    // A file whose last physical line ends on a continuation still yields its
    // accumulated logical line.
    if let Some(joined) = pending.take() {
        result.push(joined);
    }

    result
}

/// Whether `line` ends with an odd number of backslashes — a shell line
/// continuation. An even count is an escaped literal backslash.
fn ends_with_continuation(line: &str) -> bool {
    let trailing = line.bytes().rev().take_while(|&b| b == b'\\').count();
    trailing % 2 == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_continuation_preserves_lines_and_indices() {
        let lines = logical_lines("a\nb\nc");
        assert_eq!(
            lines,
            vec![
                (0, "a".to_string()),
                (1, "b".to_string()),
                (2, "c".to_string())
            ]
        );
    }

    #[test]
    fn test_backslash_continuation_joins_with_start_index() {
        // Physical lines 0-1 join; line 2 stays separate at index 2.
        let lines = logical_lines("foo \\\n  bar\nbaz");
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], (0, "foo   bar".to_string()));
        assert_eq!(lines[1], (2, "baz".to_string()));
    }

    #[test]
    fn test_even_backslashes_are_not_a_continuation() {
        // Two trailing backslashes = one escaped literal backslash, not a join.
        let lines = logical_lines("foo\\\\\nbar");
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], (0, "foo\\\\".to_string()));
    }

    #[test]
    fn test_trailing_continuation_at_eof_still_emitted() {
        let lines = logical_lines("foo \\");
        assert_eq!(lines, vec![(0, "foo ".to_string())]);
    }

    #[test]
    fn test_empty_content_yields_no_lines() {
        assert!(logical_lines("").is_empty());
    }

    #[test]
    fn test_multiple_consecutive_continuations() {
        let lines = logical_lines("a \\\nb \\\nc");
        assert_eq!(lines, vec![(0, "a b c".to_string())]);
    }
}
