// TFS_CHAIN · tx/transfer.rs · Layer 3
//
// TRANSFER · citizen-to-citizen $TFS movement.

//! Citizen-to-citizen $TFS transfers.

use serde::{Deserialize, Serialize};

use super::TxError;
use crate::crypto::address::Address;

/// A $TFS transfer from one citizen to another.
///
/// Invariants checked at Layer 3:
/// - `amount_hyphae > 0`
/// - `from != to`
///
/// NOT checked at Layer 3 (state-dependent — Layer 5's job):
/// - Does `from` have sufficient balance?
/// - Is `nonce` the next expected for `from`?
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransferPayload {
    /// Sending address.
    pub from: Address,

    /// Receiving address.
    pub to: Address,

    /// Amount in hyphae (10⁻⁹ $TFS).
    pub amount_hyphae: u64,

    /// Replay-protection nonce. Layer 5 enforces per-account monotonicity.
    pub nonce: u64,

    /// Unix milliseconds when the transfer was created.
    pub timestamp_ms: i64,
}

impl TransferPayload {
    /// Validate structural invariants.
    ///
    /// # Errors
    /// Returns [`TxError`] if an invariant is violated.
    pub fn validate_invariants(&self) -> Result<(), TxError> {
        if self.amount_hyphae == 0 {
            return Err(TxError::ZeroOrNegativeAmount(0));
        }
        if self.from == self.to {
            return Err(TxError::TransferToSelf(self.from));
        }
        Ok(())
    }
}
