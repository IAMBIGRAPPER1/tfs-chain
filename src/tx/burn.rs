// TFS_CHAIN · tx/burn.rs · Layer 3
//
// BURN · ceremonial destruction of $TFS. Honor inscribed forever.
//
// "The currency cannot be inflated. The currency can be burned.
//  Burning is voluntary, ceremonial, and recorded on the chain forever.
//  Every burn elevates the holders who remain.
//  The chain remembers the burner's name. Burning is honor."

//! Ceremonial $TFS burn transactions.

use serde::{Deserialize, Serialize};

use super::{TxError, MAX_BURN_REASON_BYTES};
use crate::crypto::address::Address;

/// A ceremonial burn of $TFS.
///
/// Once accepted into a block, the burned amount is permanently removed
/// from circulation. The supply cap is thereby lowered. The burner's
/// address and the amount are recorded on the chain forever.
///
/// An optional `reason` string may be inscribed with the burn. The chain
/// does not ask why — it just inscribes.
///
/// Invariants checked at Layer 3:
/// - `amount_hyphae > 0`
/// - `reason` (if present) ≤ [`MAX_BURN_REASON_BYTES`]
///
/// NOT checked at Layer 3:
/// - Does `burner` have sufficient balance? (L5)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BurnPayload {
    /// Address of the citizen burning their own $TFS.
    pub burner: Address,

    /// Amount to burn, in hyphae (10⁻⁹ $TFS). Must be strictly positive.
    pub amount_hyphae: u64,

    /// Replay-protection nonce.
    pub nonce: u64,

    /// Unix milliseconds when the burn was declared.
    pub timestamp_ms: i64,

    /// Optional ceremonial reason for the burn. The chain doesn't ask why.
    /// Bounded in size by [`MAX_BURN_REASON_BYTES`] to prevent bloat.
    pub reason: Option<String>,
}

impl BurnPayload {
    /// Validate structural invariants.
    ///
    /// # Errors
    /// Returns [`TxError`] if:
    /// - `amount_hyphae == 0`
    /// - `reason.len() > MAX_BURN_REASON_BYTES`
    pub fn validate_invariants(&self) -> Result<(), TxError> {
        if self.amount_hyphae == 0 {
            return Err(TxError::ZeroOrNegativeAmount(0));
        }
        if let Some(reason) = &self.reason {
            if reason.len() > MAX_BURN_REASON_BYTES {
                return Err(TxError::BurnReasonTooLong {
                    actual: reason.len(),
                    max: MAX_BURN_REASON_BYTES,
                });
            }
        }
        Ok(())
    }
}
