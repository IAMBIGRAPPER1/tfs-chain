// TFS_CHAIN · tx/sigil.rs · Layer 3
//
// SIGIL BIND · the entry act.
//
// A citizen claims a sigil on the chain. One sigil per citizen, one citizen
// per sigil. The chain enforces uniqueness — the first to inscribe a given
// sigil holds it forever. This is the mechanism behind the Citizen Covenant
// promise ("the first citizen to inscribe a sigil holds it forever"): the
// inscription is a signed SigilBind transaction, and the signature is proof
// of the keychain that owns the sigil from that block onward.
//
// At GENESIS the SigilBind also draws the era-adjusted inscribe reward from
// the treasury — the citizen's onboarding allowance. After enough halvings
// the reward goes to 0 but the binding still succeeds.

//! Sigil-binding transactions (the citizen-entry act).

use serde::{Deserialize, Serialize};

use super::TxError;
use crate::crypto::address::Address;

/// Maximum length of a sigil in bytes.
/// The Citizen Covenant: "Sixteen characters or fewer. Monospace. No whitespace."
pub const MAX_SIGIL_LEN: usize = 16;

/// Bind a sigil to an address on the chain.
///
/// Invariants checked at Layer 3:
/// - `sigil.len() > 0` and `sigil.len() <= MAX_SIGIL_LEN`
/// - Every char is ASCII alphanumeric, `-`, or `_`
/// - No whitespace anywhere
///
/// NOT checked at Layer 3 (Layer 5 enforces):
/// - Has this sigil already been claimed? (uniqueness)
/// - Does `claimant` already have a different sigil? (one-per-address)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SigilBindPayload {
    /// The sigil being claimed. UTF-8 bytes; must pass the charset check.
    pub sigil: String,

    /// Address of the citizen claiming the sigil (who receives the binding
    /// and the onboarding reward).
    pub claimant: Address,

    /// Replay-protection nonce. Typically 0 for a first-time citizen
    /// (their address has no prior history); non-zero if an existing
    /// address chooses to claim a sigil retroactively.
    pub nonce: u64,

    /// Unix milliseconds when the binding was constructed.
    pub timestamp_ms: i64,
}

impl SigilBindPayload {
    /// Construct a new SigilBind payload.
    #[must_use]
    pub const fn new(sigil: String, claimant: Address, nonce: u64, timestamp_ms: i64) -> Self {
        Self {
            sigil,
            claimant,
            nonce,
            timestamp_ms,
        }
    }

    /// Validate structural invariants.
    ///
    /// # Errors
    /// Returns [`TxError`] if:
    /// - Sigil is empty
    /// - Sigil exceeds [`MAX_SIGIL_LEN`] bytes
    /// - Sigil contains any character outside `[A-Za-z0-9_-]`
    pub fn validate_invariants(&self) -> Result<(), TxError> {
        if self.sigil.is_empty() {
            return Err(TxError::EmptySigil);
        }
        if self.sigil.len() > MAX_SIGIL_LEN {
            return Err(TxError::SigilTooLong {
                actual: self.sigil.len(),
                max: MAX_SIGIL_LEN,
            });
        }
        for c in self.sigil.chars() {
            if !is_valid_sigil_char(c) {
                return Err(TxError::InvalidSigilChar(c));
            }
        }
        Ok(())
    }
}

/// Whether a character is a valid sigil character per the Citizen Covenant.
/// Allowed: ASCII letters, ASCII digits, hyphen, underscore. Nothing else —
/// no whitespace, no punctuation, no emoji, no non-ASCII.
#[must_use]
pub const fn is_valid_sigil_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}
