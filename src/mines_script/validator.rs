// TFS_CHAIN · mines_script/validator.rs · Layer 4
//
// Structural validation for parsed doctrines.
//
// The parser enforces syntactic rules (line shapes, brackets, identifiers).
// The validator enforces SEMANTIC STRUCTURE: required metadata present,
// no duplicates, section names unique. Everything here operates on an
// already-parsed [`Doctrine`].

//! Validator for parsed MINES.script doctrines.
//!
//! Call [`validate_doctrine`] (or equivalently [`Doctrine::validate_structure`])
//! after successful parsing to confirm the scroll carries the required
//! metadata and has internally consistent structure.

use super::{Doctrine, MinesScriptError, META_INSCRIBED, META_SEALED};

/// Validate the structural integrity of a parsed doctrine.
///
/// # Errors
/// Returns [`MinesScriptError`] on the first failed check:
/// - Duplicate section names
/// - Duplicate metadata keys
/// - Missing required metadata ([`META_INSCRIBED`], [`META_SEALED`])
pub fn validate_doctrine(doctrine: &Doctrine) -> Result<(), MinesScriptError> {
    check_no_duplicate_sections(doctrine)?;
    check_no_duplicate_metadata(doctrine)?;
    check_required_metadata(doctrine)?;
    Ok(())
}

/// Verify no two sections share a name.
fn check_no_duplicate_sections(doctrine: &Doctrine) -> Result<(), MinesScriptError> {
    let mut seen: Vec<&str> = Vec::with_capacity(doctrine.sections.len());
    for section in &doctrine.sections {
        if seen.contains(&section.name.as_str()) {
            return Err(MinesScriptError::DuplicateSectionName {
                name: section.name.clone(),
            });
        }
        seen.push(section.name.as_str());
    }
    Ok(())
}

/// Verify no two preamble keys are the same.
fn check_no_duplicate_metadata(doctrine: &Doctrine) -> Result<(), MinesScriptError> {
    let mut seen: Vec<&str> = Vec::with_capacity(doctrine.metadata.len());
    for (key, _) in &doctrine.metadata {
        if seen.contains(&key.as_str()) {
            return Err(MinesScriptError::DuplicateMetadataKey {
                key: key.clone(),
            });
        }
        seen.push(key.as_str());
    }
    Ok(())
}

/// Verify all required metadata keys are present.
fn check_required_metadata(doctrine: &Doctrine) -> Result<(), MinesScriptError> {
    for required in [META_INSCRIBED, META_SEALED] {
        if doctrine.metadata_get(required).is_none() {
            return Err(MinesScriptError::MissingRequiredMetadata {
                key: required.to_string(),
            });
        }
    }
    Ok(())
}
