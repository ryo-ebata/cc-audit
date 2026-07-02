//! Frontmatter parsing for skill files.
//!
//! Re-exports the canonical [`crate::parser::FrontmatterParser`] so there is a
//! single, line-aware implementation of frontmatter extraction rather than a
//! divergent copy. The previous duplicate used a raw `find("---")` substring
//! search that truncated on a `---` inside a value, letting `allowed-tools: *`
//! escape the scanned frontmatter and evade OP-001 (issue #131).

pub use crate::parser::FrontmatterParser;
