// TFS_CHAIN · mines_script/parser.rs · Layer 4
//
// Line-by-line state machine for MINES.script doctrines.
//
// The parser is intentionally simple:
//   - No lookahead
//   - No backtracking
//   - No recursive descent (sections are flat, never nested)
//
// Every error path returns a Result with line-number context so that
// doctrine authors can find their mistake at a glance.

//! Parser for MINES.script doctrine-blocks.
//!
//! See [`parse_doctrine`] for the entry point. The parser preserves the
//! original bytes verbatim in [`Doctrine::raw_bytes`] so that cryptographic
//! commitments over the source text remain valid.

use super::{
    Doctrine, MinesScriptError, Section, SectionLine, END_MARKER, MAX_LINES_PER_SECTION,
    MAX_LINE_BYTES, MAX_META_KEY_BYTES, MAX_META_VALUE_BYTES, MAX_SECTIONS,
    MAX_SECTION_NAME_BYTES,
};

/// Parser states.
#[derive(Debug)]
enum State {
    /// Expecting the `BLOCK <n>` header or leading blank lines.
    ExpectingBlock,

    /// Inside the preamble, reading `KEY: value` metadata lines (or blank,
    /// or a section header which transitions to `InSection`).
    Preamble,

    /// Inside a named section, reading content lines. Transitions to another
    /// `InSection` on the next section header or to `AfterEnd` on `[END]`.
    InSection,

    /// Saw `[END]`. Any further non-blank content is an error.
    AfterEnd,
}

/// Parse a MINES.script doctrine from raw bytes.
///
/// # Errors
/// Returns [`MinesScriptError`] on any parse failure.
pub fn parse_doctrine(bytes: &[u8]) -> Result<Doctrine, MinesScriptError> {
    // 1. Decode as UTF-8.
    let text = std::str::from_utf8(bytes).map_err(|_| MinesScriptError::NotUtf8)?;

    if text.trim().is_empty() {
        return Err(MinesScriptError::Empty);
    }

    // 2. Line-by-line state machine.
    let mut state = State::ExpectingBlock;
    let mut block_number: Option<u64> = None;
    let mut metadata: Vec<(String, String)> = Vec::new();
    let mut sections: Vec<Section> = Vec::new();
    let mut current_section: Option<Section> = None;

    for (idx, raw_line) in text.lines().enumerate() {
        let line_no = idx + 1;

        // Bound line length.
        if raw_line.len() > MAX_LINE_BYTES {
            return Err(MinesScriptError::LineTooLong {
                actual: raw_line.len(),
                max: MAX_LINE_BYTES,
                line: line_no,
            });
        }

        let trimmed = raw_line.trim();

        match state {
            State::ExpectingBlock => {
                // Allow leading blank lines before the header.
                if trimmed.is_empty() {
                    continue;
                }
                // Expect exactly "BLOCK <n>".
                block_number = Some(parse_block_header(trimmed, line_no)?);
                state = State::Preamble;
            }

            State::Preamble => {
                if trimmed.is_empty() {
                    continue;
                }

                if let Some(section_name) = parse_section_header(trimmed, line_no)? {
                    // First section header ends the preamble.
                    if section_name == END_MARKER {
                        // A scroll with no sections is valid; finalize here.
                        finalize_current_section(&mut current_section, &mut sections)?;
                        state = State::AfterEnd;
                        continue;
                    }
                    enforce_section_count(&sections)?;
                    current_section = Some(Section {
                        name: section_name,
                        lines: Vec::new(),
                    });
                    state = State::InSection;
                    continue;
                }

                // Otherwise, expect a `KEY: value` preamble line.
                let (key, value) = parse_preamble_line(trimmed, line_no)?;
                if key.len() > MAX_META_KEY_BYTES {
                    return Err(MinesScriptError::IdentifierTooLong {
                        actual: key.len(),
                        max: MAX_META_KEY_BYTES,
                        line: line_no,
                    });
                }
                if value.len() > MAX_META_VALUE_BYTES {
                    return Err(MinesScriptError::MetadataValueTooLong {
                        actual: value.len(),
                        max: MAX_META_VALUE_BYTES,
                        line: line_no,
                    });
                }
                if !is_valid_identifier(&key) {
                    return Err(MinesScriptError::InvalidMetadataKey { key });
                }
                metadata.push((key, value));
            }

            State::InSection => {
                // A section header (or [END]) ends the current section.
                if let Some(section_name) = parse_section_header(trimmed, line_no)? {
                    finalize_current_section(&mut current_section, &mut sections)?;

                    if section_name == END_MARKER {
                        state = State::AfterEnd;
                        continue;
                    }

                    enforce_section_count(&sections)?;
                    current_section = Some(Section {
                        name: section_name,
                        lines: Vec::new(),
                    });
                    continue;
                }

                // Otherwise it's a content line for the current section.
                let section = current_section
                    .as_mut()
                    .expect("InSection state implies a current_section is set");
                if section.lines.len() >= MAX_LINES_PER_SECTION {
                    return Err(MinesScriptError::SectionTooLong {
                        name: section.name.clone(),
                        actual: section.lines.len() + 1,
                        max: MAX_LINES_PER_SECTION,
                    });
                }
                section.lines.push(classify_line(raw_line));
            }

            State::AfterEnd => {
                if !trimmed.is_empty() {
                    return Err(MinesScriptError::ContentAfterEnd { line: line_no });
                }
            }
        }
    }

    // Must have seen [END].
    if !matches!(state, State::AfterEnd) {
        return Err(MinesScriptError::MissingEndMarker);
    }

    // Unwrap the block number; unreachable otherwise because we transitioned
    // through ExpectingBlock only after setting it.
    let block_number = block_number.ok_or(MinesScriptError::MissingBlockHeader { line: 1 })?;

    Ok(Doctrine {
        block_number,
        metadata,
        sections,
        raw_bytes: bytes.to_vec(),
    })
}

/// Flush the in-progress section into the sections vector.
fn finalize_current_section(
    current: &mut Option<Section>,
    sections: &mut Vec<Section>,
) -> Result<(), MinesScriptError> {
    if let Some(s) = current.take() {
        sections.push(s);
    }
    Ok(())
}

/// Enforce the global section-count limit.
fn enforce_section_count(sections: &[Section]) -> Result<(), MinesScriptError> {
    if sections.len() >= MAX_SECTIONS {
        return Err(MinesScriptError::TooManySections {
            actual: sections.len() + 1,
            max: MAX_SECTIONS,
        });
    }
    Ok(())
}

/// Parse the `BLOCK <n>` header line. Expects no leading/trailing whitespace.
fn parse_block_header(line: &str, line_no: usize) -> Result<u64, MinesScriptError> {
    let rest = line
        .strip_prefix("BLOCK ")
        .ok_or(MinesScriptError::MissingBlockHeader { line: line_no })?;
    rest.trim()
        .parse::<u64>()
        .map_err(|_| MinesScriptError::InvalidBlockNumber {
            value: rest.trim().to_string(),
            line: line_no,
        })
}

/// If the line is a section header `[NAME]`, return `Some(name)`. Otherwise
/// return `Ok(None)` so the caller can try other parse strategies.
///
/// Returns `Err` only if the line LOOKS LIKE a section header (starts with
/// `[`) but is malformed — preventing silent misclassification.
fn parse_section_header(
    line: &str,
    line_no: usize,
) -> Result<Option<String>, MinesScriptError> {
    if !line.starts_with('[') {
        return Ok(None);
    }
    // Must end with a closing bracket.
    let stripped = line.strip_suffix(']').ok_or_else(|| {
        MinesScriptError::MalformedSectionHeader {
            content: line.to_string(),
            line: line_no,
        }
    })?;
    let name = &stripped[1..]; // drop leading '['
    if name.is_empty() {
        return Err(MinesScriptError::EmptySectionName { line: line_no });
    }
    if name.len() > MAX_SECTION_NAME_BYTES {
        return Err(MinesScriptError::IdentifierTooLong {
            actual: name.len(),
            max: MAX_SECTION_NAME_BYTES,
            line: line_no,
        });
    }
    if !is_valid_section_name(name) {
        return Err(MinesScriptError::InvalidSectionName {
            name: name.to_string(),
        });
    }
    Ok(Some(name.to_string()))
}

/// Parse a preamble line: `KEY: value`. The key must be `UPPER_SNAKE_CASE`.
fn parse_preamble_line(line: &str, line_no: usize) -> Result<(String, String), MinesScriptError> {
    // Find the first ": " separator.
    let sep = line.find(": ").ok_or_else(|| {
        MinesScriptError::MalformedPreambleLine {
            content: line.to_string(),
            line: line_no,
        }
    })?;
    let key = line[..sep].trim().to_string();
    let value = line[sep + 2..].trim().to_string();
    if key.is_empty() || value.is_empty() {
        return Err(MinesScriptError::MalformedPreambleLine {
            content: line.to_string(),
            line: line_no,
        });
    }
    Ok((key, value))
}

/// Classify a section content line into one of the five kinds.
fn classify_line(raw: &str) -> SectionLine {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return SectionLine::Blank;
    }
    if let Some(rest) = trimmed.strip_prefix("- ") {
        return SectionLine::ListItem(rest.trim().to_string());
    }
    if let Some((left, right)) = split_once_substr(trimmed, " -> ") {
        return SectionLine::ArrowMap {
            left: left.trim().to_string(),
            right: right.trim().to_string(),
        };
    }
    if let Some((key, value)) = split_once_substr(trimmed, " = ") {
        let key_t = key.trim();
        let value_t = value.trim();
        if is_valid_snake_case(key_t) && !value_t.is_empty() {
            return SectionLine::KeyValue {
                key: key_t.to_string(),
                value: value_t.to_string(),
            };
        }
    }
    // Fallback: treat as prose, preserving trimmed content.
    SectionLine::Prose(trimmed.to_string())
}

/// Split a string at the first occurrence of `sep` (a multi-byte substring),
/// returning `(before, after)` or `None` if not found.
///
/// Used instead of `str::split_once` in older MSRVs and to be explicit
/// about what we accept.
fn split_once_substr<'a>(s: &'a str, sep: &str) -> Option<(&'a str, &'a str)> {
    s.find(sep).map(|i| (&s[..i], &s[i + sep.len()..]))
}

/// An identifier for a section name. ASCII uppercase letters, digits, and
/// underscores. Must start with a letter or underscore (not a digit).
fn is_valid_section_name(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_uppercase() || first == '_') {
        return false;
    }
    for c in chars {
        if !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_') {
            return false;
        }
    }
    true
}

/// An identifier for a metadata key. Same rules as section names.
fn is_valid_identifier(s: &str) -> bool {
    is_valid_section_name(s)
}

/// A snake_case identifier for a KeyValue left-side: ASCII lowercase letters,
/// digits, and underscores. Must start with a letter or underscore.
fn is_valid_snake_case(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_lowercase() || first == '_') {
        return false;
    }
    for c in chars {
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
            return false;
        }
    }
    true
}
