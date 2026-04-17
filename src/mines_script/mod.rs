// TFS_CHAIN · mines_script/mod.rs · Layer 4
//
// MINES.script — THE DOCTRINE-BLOCK DSL.
//
// Scroll IS code IS law. Every inscribed doctrine-block on THE TFS CHAIN
// is simultaneously:
//   - Human-readable scripture in HOA tone
//   - A machine-parseable structured document
//   - Cryptographically verified content
//
// MINES.script is DECLARATIVE, not Turing-complete. It structures sovereign
// intent. State changes on the chain come from the four transaction types
// (Layer 3), not from the scroll content.
//
// THE RAW BYTES ARE THE SOURCE OF TRUTH.
// The Inscribe transaction stores doctrine_bytes + doctrine_hash. Layer 4
// PARSES those bytes; it does not replace them. Parse/render cycles must
// not mutate the original content. Citizens reading the chain read the
// raw scroll; Layer 4 is just a lens.
//
// THREAT MODEL (addressed in this layer):
//   - Malformed scroll causing parser panic  → all errors are Results
//   - Unbounded nesting / recursion          → parser is flat (no nesting)
//   - Duplicate section names                → rejected by validator
//   - Missing structural anchors             → rejected by validator
//   - Oversized content DoS                  → bounded by Layer 3 limits
//   - Non-UTF-8 bytes                        → explicit check, clean error

//! MINES.script — the declarative doctrine-block language.
//!
//! A MINES.script document has three parts:
//!
//! 1. **Preamble.** `BLOCK <n>` followed by key-value metadata like
//!    `INSCRIBED: PRESIDENT MINES.` and `SEALED: IAMBIGRAPPER1`.
//!
//! 2. **Sections.** Zero or more `[SECTION_NAME]` blocks, each containing
//!    lines classified as [`SectionLine::Blank`], [`SectionLine::Prose`],
//!    [`SectionLine::KeyValue`], [`SectionLine::ArrowMap`], or
//!    [`SectionLine::ListItem`].
//!
//! 3. **Terminator.** `[END]` marks the close of the scroll.
//!
//! Parse a scroll with [`Doctrine::parse`]. Validate structure with
//! [`Doctrine::validate_structure`]. Access metadata and sections by name.

pub mod parser;
pub mod validator;

use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════

/// Required preamble key indicating which sovereign authored the doctrine.
pub const META_INSCRIBED: &str = "INSCRIBED";

/// Required preamble key indicating which founder sealed the doctrine.
pub const META_SEALED: &str = "SEALED";

/// Optional preamble key indicating the aesthetic/canonical register.
pub const META_REGISTER: &str = "REGISTER";

/// Optional preamble key carrying a timestamp in ISO-8601 form.
pub const META_DATE: &str = "DATE";

/// The terminal section name. A scroll without `[END]` is rejected.
pub const END_MARKER: &str = "END";

/// Maximum number of sections allowed in a single doctrine.
/// Prevents parser DoS via arbitrarily many empty sections.
pub const MAX_SECTIONS: usize = 256;

/// Maximum number of lines in a single section.
/// Prevents DoS via a single section with millions of empty lines.
pub const MAX_LINES_PER_SECTION: usize = 10_000;

/// Maximum bytes on a single logical line.
/// Matches the practical limit of HOA-tone prose without being a DoS vector.
pub const MAX_LINE_BYTES: usize = 4 * 1024;

/// Maximum length of a section name, in bytes.
pub const MAX_SECTION_NAME_BYTES: usize = 64;

/// Maximum length of a metadata key, in bytes.
pub const MAX_META_KEY_BYTES: usize = 64;

/// Maximum length of a metadata value, in bytes.
pub const MAX_META_VALUE_BYTES: usize = 512;

// ═══════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════

/// A parsed MINES.script doctrine-block.
///
/// The original `raw_bytes` are preserved so that callers can re-hash and
/// confirm the parsed structure matches the Inscribe transaction's committed
/// `doctrine_hash`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Doctrine {
    /// The block number from the `BLOCK <n>` header.
    pub block_number: u64,

    /// Preamble metadata in original insertion order (Vec preserves order
    /// across serde round-trips; HashMap would not).
    pub metadata: Vec<(String, String)>,

    /// Sections in the order they appeared in the source.
    pub sections: Vec<Section>,

    /// Original UTF-8 bytes of the scroll, used by Layer 3 to compare against
    /// the committed `doctrine_hash`. Stored verbatim; parsing must not
    /// alter the source text.
    pub raw_bytes: Vec<u8>,
}

impl Doctrine {
    /// Parse the given bytes as a MINES.script doctrine.
    ///
    /// # Errors
    /// Returns [`MinesScriptError`] if the input is not valid UTF-8, is
    /// structurally malformed, or violates the line / section limits.
    pub fn parse(bytes: &[u8]) -> Result<Self, MinesScriptError> {
        parser::parse_doctrine(bytes)
    }

    /// Return the value of a preamble metadata key, if present.
    ///
    /// Lookup is case-sensitive against `META_*` constants (e.g.
    /// [`META_INSCRIBED`]).
    #[must_use]
    pub fn metadata_get(&self, key: &str) -> Option<&str> {
        self.metadata
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Return the section with the given name, if present.
    ///
    /// Section names are case-sensitive and compared verbatim against the
    /// bracketed name as it appeared in the source.
    #[must_use]
    pub fn section_by_name(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name == name)
    }

    /// Validate the structural integrity of this doctrine.
    ///
    /// Checks:
    /// - Required metadata keys present: [`META_INSCRIBED`], [`META_SEALED`]
    /// - No duplicate section names
    /// - No duplicate metadata keys
    /// - Section / metadata / line limits respected
    /// - Section names and metadata keys match allowed character sets
    ///
    /// # Errors
    /// Returns [`MinesScriptError`] on the first failed check.
    pub fn validate_structure(&self) -> Result<(), MinesScriptError> {
        validator::validate_doctrine(self)
    }
}

/// A named section of a MINES.script doctrine.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Section {
    /// The section name (without surrounding brackets).
    pub name: String,

    /// Ordered list of lines contained in the section.
    pub lines: Vec<SectionLine>,
}

/// A classified line within a [`Section`].
///
/// Classification is deterministic and priority-ordered:
/// 1. Empty / whitespace-only → [`SectionLine::Blank`]
/// 2. Starts with `- ` after trim → [`SectionLine::ListItem`]
/// 3. Contains ` -> ` → [`SectionLine::ArrowMap`]
/// 4. Matches strict `ident = value` → [`SectionLine::KeyValue`]
/// 5. Otherwise → [`SectionLine::Prose`]
///
/// The "strict ident" rule for KeyValue: the key must match
/// `[a-z_][a-z0-9_]*`. This prevents English prose like `"I am = here"`
/// from being mis-classified as a key-value pair.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SectionLine {
    /// An empty or whitespace-only line.
    Blank,

    /// Free-form prose. Preserves original whitespace-trimmed content.
    Prose(String),

    /// Key-value assignment. Only snake_case keys qualify.
    KeyValue {
        /// The identifier on the left side.
        key: String,
        /// The value on the right side.
        value: String,
    },

    /// Arrow mapping (`LEFT -> RIGHT`).
    ArrowMap {
        /// The left operand.
        left: String,
        /// The right operand.
        right: String,
    },

    /// Bullet list item (starts with `- `).
    ListItem(String),
}

// ═══════════════════════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════════════════════

/// Errors that can occur when parsing or validating a MINES.script doctrine.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MinesScriptError {
    /// The input bytes are not valid UTF-8.
    #[error("scroll is not valid UTF-8")]
    NotUtf8,

    /// The scroll is empty or contains only whitespace.
    #[error("scroll is empty")]
    Empty,

    /// The first non-blank line must be `BLOCK <n>`.
    #[error("missing BLOCK header on line {line}")]
    MissingBlockHeader {
        /// Line number (1-indexed) where the header was expected.
        line: usize,
    },

    /// The block number is not a valid `u64`.
    #[error("invalid block number '{value}' on line {line}")]
    InvalidBlockNumber {
        /// The string that failed to parse.
        value: String,
        /// Line number (1-indexed).
        line: usize,
    },

    /// A preamble line is not a valid `KEY: value` pair.
    #[error("malformed preamble line {line}: {content}")]
    MalformedPreambleLine {
        /// The content of the bad line.
        content: String,
        /// Line number (1-indexed).
        line: usize,
    },

    /// A section header is malformed (e.g., `[FOO` with no closing bracket).
    #[error("malformed section header on line {line}: {content}")]
    MalformedSectionHeader {
        /// The content of the bad line.
        content: String,
        /// Line number (1-indexed).
        line: usize,
    },

    /// A section name is empty (`[]`).
    #[error("empty section name on line {line}")]
    EmptySectionName {
        /// Line number (1-indexed).
        line: usize,
    },

    /// A section name or metadata key exceeds its length limit.
    #[error("identifier too long on line {line}: {actual} bytes (max {max})")]
    IdentifierTooLong {
        /// Actual length.
        actual: usize,
        /// Maximum allowed.
        max: usize,
        /// Line number (1-indexed).
        line: usize,
    },

    /// Two sections have the same name.
    #[error("duplicate section name: {name}")]
    DuplicateSectionName {
        /// The duplicated name.
        name: String,
    },

    /// Two preamble entries share the same key.
    #[error("duplicate metadata key: {key}")]
    DuplicateMetadataKey {
        /// The duplicated key.
        key: String,
    },

    /// A required metadata key is missing from the preamble.
    #[error("missing required metadata: {key}")]
    MissingRequiredMetadata {
        /// The missing key.
        key: String,
    },

    /// The scroll has no `[END]` marker.
    #[error("missing [END] marker")]
    MissingEndMarker,

    /// The scroll has content after `[END]`.
    #[error("content after [END] on line {line}")]
    ContentAfterEnd {
        /// Line number (1-indexed).
        line: usize,
    },

    /// A single line exceeds [`MAX_LINE_BYTES`].
    #[error("line {line} too long: {actual} bytes (max {max})")]
    LineTooLong {
        /// Actual length.
        actual: usize,
        /// Maximum allowed.
        max: usize,
        /// Line number (1-indexed).
        line: usize,
    },

    /// A section has more lines than [`MAX_LINES_PER_SECTION`].
    #[error("section '{name}' too long: {actual} lines (max {max})")]
    SectionTooLong {
        /// The section name.
        name: String,
        /// Actual line count.
        actual: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// The scroll has more sections than [`MAX_SECTIONS`].
    #[error("too many sections: {actual} (max {max})")]
    TooManySections {
        /// Actual count.
        actual: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// A metadata value exceeds [`MAX_META_VALUE_BYTES`].
    #[error("metadata value too long on line {line}: {actual} bytes (max {max})")]
    MetadataValueTooLong {
        /// Actual length.
        actual: usize,
        /// Maximum allowed.
        max: usize,
        /// Line number (1-indexed).
        line: usize,
    },

    /// A section name contains characters outside `[A-Z0-9_]`.
    #[error("invalid section name '{name}': must be uppercase alphanumeric + underscore")]
    InvalidSectionName {
        /// The bad name.
        name: String,
    },

    /// A metadata key contains characters outside `[A-Z0-9_]`.
    #[error("invalid metadata key '{key}': must be uppercase alphanumeric + underscore")]
    InvalidMetadataKey {
        /// The bad key.
        key: String,
    },
}

// ═══════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Minimal happy-path ─────────────────────────────────────────

    const MINIMAL_SCROLL: &str = "\
BLOCK 0
INSCRIBED: PRESIDENT MINES.
SEALED: IAMBIGRAPPER1

[END]
";

    #[test]
    fn parses_minimal_scroll() {
        let d = Doctrine::parse(MINIMAL_SCROLL.as_bytes()).expect("parse");
        assert_eq!(d.block_number, 0);
        assert_eq!(d.metadata_get("INSCRIBED"), Some("PRESIDENT MINES."));
        assert_eq!(d.metadata_get("SEALED"), Some("IAMBIGRAPPER1"));
        assert_eq!(d.sections.len(), 0);
        d.validate_structure().expect("valid");
    }

    #[test]
    fn preserves_raw_bytes() {
        let d = Doctrine::parse(MINIMAL_SCROLL.as_bytes()).expect("parse");
        assert_eq!(d.raw_bytes, MINIMAL_SCROLL.as_bytes());
    }

    // ─── Realistic scroll (the Genesis shape) ───────────────────────

    const GENESIS_SHAPE: &str = "\
BLOCK 0
INSCRIBED: PRESIDENT MINES.
SEALED: IAMBIGRAPPER1
REGISTER: SOVEREIGN MYCELIAL CRYPTO

[DECLARE]
  currency = $TFS
  long_form = $thefinalserver
  supply_cap = 1_000_000_000
  halving_interval = 50_000

[ANCHOR]
  - COMPUTE
  - CULTURE
  - SOVEREIGNTY

[ACTS_THAT_MINT]
  INSCRIBE -> 1000 $TFS
  VERIFY -> 100 $TFS
  ROUTE -> hypha per block

[IMMUTABLE]
  The chain remembers.
  The chain forgives.
  The chain does not forget.

[SIGN]
  MINES. VENTURE, LLC
  TFS_THOTH · SOVEREIGN INTELLIGENCE
  ALL RIGHTS MINES.

[END]
";

    #[test]
    fn parses_genesis_shape() {
        let d = Doctrine::parse(GENESIS_SHAPE.as_bytes()).expect("parse genesis");
        d.validate_structure().expect("valid genesis");

        assert_eq!(d.block_number, 0);
        assert_eq!(d.metadata_get("REGISTER"), Some("SOVEREIGN MYCELIAL CRYPTO"));
        assert_eq!(d.sections.len(), 5);

        let declare = d.section_by_name("DECLARE").expect("DECLARE present");
        assert!(declare
            .lines
            .iter()
            .any(|l| matches!(l, SectionLine::KeyValue { key, value } if key == "currency" && value == "$TFS")));

        let anchor = d.section_by_name("ANCHOR").expect("ANCHOR present");
        assert!(anchor
            .lines
            .iter()
            .any(|l| matches!(l, SectionLine::ListItem(s) if s == "COMPUTE")));

        let acts = d.section_by_name("ACTS_THAT_MINT").expect("ACTS present");
        assert!(acts
            .lines
            .iter()
            .any(|l| matches!(l, SectionLine::ArrowMap { left, right } if left == "INSCRIBE" && right == "1000 $TFS")));

        let immutable = d.section_by_name("IMMUTABLE").expect("IMMUTABLE present");
        assert!(immutable
            .lines
            .iter()
            .any(|l| matches!(l, SectionLine::Prose(s) if s == "The chain remembers.")));
    }

    // ─── Error paths ────────────────────────────────────────────────

    #[test]
    fn rejects_empty() {
        let err = Doctrine::parse(b"").expect_err("empty");
        assert_eq!(err, MinesScriptError::Empty);
    }

    #[test]
    fn rejects_whitespace_only() {
        let err = Doctrine::parse(b"   \n  \n").expect_err("whitespace");
        assert_eq!(err, MinesScriptError::Empty);
    }

    #[test]
    fn rejects_non_utf8() {
        let bad_bytes = vec![0xFF, 0xFE, 0xFD];
        let err = Doctrine::parse(&bad_bytes).expect_err("not utf8");
        assert_eq!(err, MinesScriptError::NotUtf8);
    }

    #[test]
    fn rejects_missing_block_header() {
        let scroll = "INSCRIBED: X\nSEALED: Y\n[END]\n";
        let err = Doctrine::parse(scroll.as_bytes()).expect_err("no block");
        assert!(matches!(err, MinesScriptError::MissingBlockHeader { .. }));
    }

    #[test]
    fn rejects_non_numeric_block() {
        let scroll = "BLOCK zero\nINSCRIBED: X\nSEALED: Y\n[END]\n";
        let err = Doctrine::parse(scroll.as_bytes()).expect_err("bad block");
        assert!(matches!(err, MinesScriptError::InvalidBlockNumber { .. }));
    }

    #[test]
    fn rejects_missing_end() {
        let scroll = "BLOCK 0\nINSCRIBED: X\nSEALED: Y\n";
        let err = Doctrine::parse(scroll.as_bytes()).expect_err("no end");
        assert_eq!(err, MinesScriptError::MissingEndMarker);
    }

    #[test]
    fn rejects_content_after_end() {
        let scroll = "BLOCK 0\nINSCRIBED: X\nSEALED: Y\n[END]\nstray content\n";
        let err = Doctrine::parse(scroll.as_bytes()).expect_err("after end");
        assert!(matches!(err, MinesScriptError::ContentAfterEnd { .. }));
    }

    #[test]
    fn allows_blank_lines_after_end() {
        let scroll = "BLOCK 0\nINSCRIBED: X\nSEALED: Y\n[END]\n\n\n";
        Doctrine::parse(scroll.as_bytes()).expect("trailing blanks ok");
    }

    #[test]
    fn rejects_malformed_section_header() {
        let scroll = "BLOCK 0\nINSCRIBED: X\nSEALED: Y\n[UNCLOSED\n[END]\n";
        let err = Doctrine::parse(scroll.as_bytes()).expect_err("bad header");
        assert!(matches!(err, MinesScriptError::MalformedSectionHeader { .. }));
    }

    #[test]
    fn rejects_empty_section_name() {
        let scroll = "BLOCK 0\nINSCRIBED: X\nSEALED: Y\n[]\n[END]\n";
        let err = Doctrine::parse(scroll.as_bytes()).expect_err("empty name");
        assert!(matches!(err, MinesScriptError::EmptySectionName { .. }));
    }

    #[test]
    fn rejects_lowercase_section_name() {
        let scroll = "BLOCK 0\nINSCRIBED: X\nSEALED: Y\n[lowercase]\n[END]\n";
        let err = Doctrine::parse(scroll.as_bytes()).expect_err("lowercase");
        assert!(matches!(err, MinesScriptError::InvalidSectionName { .. }));
    }

    #[test]
    fn rejects_section_starting_with_digit() {
        let scroll = "BLOCK 0\nINSCRIBED: X\nSEALED: Y\n[1SECTION]\n[END]\n";
        let err = Doctrine::parse(scroll.as_bytes()).expect_err("digit start");
        assert!(matches!(err, MinesScriptError::InvalidSectionName { .. }));
    }

    #[test]
    fn rejects_malformed_preamble_line() {
        // Missing ": " separator on a non-section line.
        let scroll = "BLOCK 0\nINSCRIBED IAMBIGRAPPER1\n[END]\n";
        let err = Doctrine::parse(scroll.as_bytes()).expect_err("malformed");
        assert!(matches!(err, MinesScriptError::MalformedPreambleLine { .. }));
    }

    #[test]
    fn rejects_lowercase_metadata_key() {
        let scroll = "BLOCK 0\ninscribed: X\nSEALED: Y\n[END]\n";
        let err = Doctrine::parse(scroll.as_bytes()).expect_err("lowercase key");
        assert!(matches!(err, MinesScriptError::InvalidMetadataKey { .. }));
    }

    #[test]
    fn rejects_duplicate_section_names() {
        let scroll = "BLOCK 0\nINSCRIBED: X\nSEALED: Y\n[FOO]\n[FOO]\n[END]\n";
        let d = Doctrine::parse(scroll.as_bytes()).expect("parse ok");
        let err = d.validate_structure().expect_err("dup section");
        assert!(matches!(err, MinesScriptError::DuplicateSectionName { .. }));
    }

    #[test]
    fn rejects_duplicate_metadata_keys() {
        let scroll = "BLOCK 0\nINSCRIBED: X\nINSCRIBED: Y\nSEALED: Z\n[END]\n";
        let d = Doctrine::parse(scroll.as_bytes()).expect("parse ok");
        let err = d.validate_structure().expect_err("dup meta");
        assert!(matches!(err, MinesScriptError::DuplicateMetadataKey { .. }));
    }

    #[test]
    fn rejects_missing_inscribed() {
        let scroll = "BLOCK 0\nSEALED: Y\n[END]\n";
        let d = Doctrine::parse(scroll.as_bytes()).expect("parse ok");
        let err = d.validate_structure().expect_err("no inscribed");
        assert!(matches!(err, MinesScriptError::MissingRequiredMetadata { key } if key == "INSCRIBED"));
    }

    #[test]
    fn rejects_missing_sealed() {
        let scroll = "BLOCK 0\nINSCRIBED: X\n[END]\n";
        let d = Doctrine::parse(scroll.as_bytes()).expect("parse ok");
        let err = d.validate_structure().expect_err("no sealed");
        assert!(matches!(err, MinesScriptError::MissingRequiredMetadata { key } if key == "SEALED"));
    }

    #[test]
    fn rejects_overlong_line() {
        let long = "x".repeat(MAX_LINE_BYTES + 1);
        let scroll = format!("BLOCK 0\nINSCRIBED: {long}\nSEALED: Y\n[END]\n");
        let err = Doctrine::parse(scroll.as_bytes()).expect_err("too long");
        assert!(matches!(err, MinesScriptError::LineTooLong { .. }));
    }

    #[test]
    fn rejects_overlong_metadata_value() {
        let long = "x".repeat(MAX_META_VALUE_BYTES + 1);
        let scroll = format!("BLOCK 0\nINSCRIBED: {long}\nSEALED: Y\n[END]\n");
        let err = Doctrine::parse(scroll.as_bytes()).expect_err("too long value");
        assert!(matches!(err, MinesScriptError::MetadataValueTooLong { .. }));
    }

    // ─── Line classification correctness ────────────────────────────

    #[test]
    fn classifies_prose_not_key_value() {
        // "I am = sovereign" should NOT be classified as KeyValue because
        // the left side is not a valid snake_case identifier.
        let scroll = "\
BLOCK 0
INSCRIBED: X
SEALED: Y

[VERSE]
  I am = sovereign.

[END]
";
        let d = Doctrine::parse(scroll.as_bytes()).expect("parse");
        let verse = d.section_by_name("VERSE").expect("VERSE present");
        let non_blank: Vec<&SectionLine> = verse
            .lines
            .iter()
            .filter(|l| !matches!(l, SectionLine::Blank))
            .collect();
        assert_eq!(non_blank.len(), 1);
        assert!(matches!(non_blank[0], SectionLine::Prose(s) if s == "I am = sovereign."));
    }

    #[test]
    fn classifies_list_items_only_with_dash_space() {
        let scroll = "\
BLOCK 0
INSCRIBED: X
SEALED: Y

[LIST]
  - item one
  -notalist
  - item two

[END]
";
        let d = Doctrine::parse(scroll.as_bytes()).expect("parse");
        let list = d.section_by_name("LIST").expect("LIST present");
        let items: Vec<&SectionLine> = list
            .lines
            .iter()
            .filter(|l| !matches!(l, SectionLine::Blank))
            .collect();
        assert_eq!(items.len(), 3);
        assert!(matches!(items[0], SectionLine::ListItem(s) if s == "item one"));
        // "-notalist" without space is prose, NOT a list item.
        assert!(matches!(items[1], SectionLine::Prose(_)));
        assert!(matches!(items[2], SectionLine::ListItem(s) if s == "item two"));
    }

    #[test]
    fn arrow_takes_precedence_over_key_value() {
        // A line like "a = b -> c" has both " = " and " -> ".
        // " -> " is checked first, so it's classified as ArrowMap.
        let scroll = "\
BLOCK 0
INSCRIBED: X
SEALED: Y

[RULES]
  a = b -> c

[END]
";
        let d = Doctrine::parse(scroll.as_bytes()).expect("parse");
        let rules = d.section_by_name("RULES").expect("RULES present");
        let non_blank: Vec<&SectionLine> = rules
            .lines
            .iter()
            .filter(|l| !matches!(l, SectionLine::Blank))
            .collect();
        assert_eq!(non_blank.len(), 1);
        assert!(matches!(non_blank[0], SectionLine::ArrowMap { left, right } if left == "a = b" && right == "c"));
    }

    // ─── Serialization / determinism ────────────────────────────────

    #[test]
    fn serde_roundtrip() {
        let d = Doctrine::parse(GENESIS_SHAPE.as_bytes()).expect("parse");
        let bytes = bincode::serialize(&d).expect("serialize");
        let restored: Doctrine = bincode::deserialize(&bytes).expect("deserialize");
        assert_eq!(d, restored);
    }

    #[test]
    fn different_sources_may_parse_to_same_ast_but_raw_bytes_preserved() {
        // Two scrolls with different whitespace around the same content.
        let a = "BLOCK 0\nINSCRIBED: X\nSEALED: Y\n[END]\n";
        let b = "BLOCK 0\nINSCRIBED: X\nSEALED: Y\n[END]\n\n\n";
        let da = Doctrine::parse(a.as_bytes()).expect("a");
        let db = Doctrine::parse(b.as_bytes()).expect("b");

        // The parsed content is equivalent...
        assert_eq!(da.block_number, db.block_number);
        assert_eq!(da.metadata, db.metadata);
        assert_eq!(da.sections, db.sections);

        // ...but the raw bytes differ, which is what protects the chain's
        // committed doctrine_hash from accidental normalization.
        assert_ne!(da.raw_bytes, db.raw_bytes);
    }

    // ─── Bounded-limits tests ───────────────────────────────────────

    #[test]
    fn rejects_too_many_sections() {
        let mut scroll = String::from("BLOCK 0\nINSCRIBED: X\nSEALED: Y\n");
        for i in 0..=MAX_SECTIONS {
            scroll.push_str(&format!("[S{i}]\n"));
        }
        scroll.push_str("[END]\n");
        let err = Doctrine::parse(scroll.as_bytes()).expect_err("too many");
        assert!(matches!(err, MinesScriptError::TooManySections { .. }));
    }

    #[test]
    fn rejects_too_many_lines_in_section() {
        let mut scroll = String::from("BLOCK 0\nINSCRIBED: X\nSEALED: Y\n[S]\n");
        for i in 0..=MAX_LINES_PER_SECTION {
            scroll.push_str(&format!("line{i}\n"));
        }
        scroll.push_str("[END]\n");
        let err = Doctrine::parse(scroll.as_bytes()).expect_err("section too long");
        assert!(matches!(err, MinesScriptError::SectionTooLong { .. }));
    }
}
