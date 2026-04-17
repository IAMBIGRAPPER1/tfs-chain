// TFS_CHAIN · tx/verify.rs · Layer 3
//
// VERIFY · the hyphal-neighbor attestation.
//
// A citizen is verified by a quorum of 3+ peers signing the same Verify
// payload. The verified citizen receives a fixed mint (100 $TFS at genesis).
// This is the mycelial model: trust propagates through the weave, not
// through a central authority.

//! Peer-verification transactions (3-peer quorum mint event).

use serde::{Deserialize, Serialize};

use super::TxError;
use crate::crypto::address::Address;

/// A peer-verification transaction.
///
/// The payload itself carries only the verified citizen's address, the
/// nonce, and the timestamp. The signer set (the verifier quorum) lives in
/// the containing [`crate::tx::SignedTransaction`]'s `signatures` field.
///
/// Invariants checked at Layer 3 (on the containing SignedTransaction):
/// - ≥ [`crate::tx::MIN_VERIFICATION_QUORUM`] signatures
/// - ≤ [`crate::tx::MAX_VERIFICATION_SIGNERS`] signatures
/// - Every signer's address ≠ `verified` (no self-verification)
/// - All signer addresses distinct (no stuffing with duplicates)
///
/// NOT checked at Layer 3:
/// - Have any of the signers already verified `verified` in a prior tx? (L5)
/// - Are the signers themselves verified citizens? (L5 — TOFU or mandatory)
/// - Is `verified` already verified? (L5 — idempotent rule)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifyPayload {
    /// The citizen being verified (who receives the 100 $TFS mint).
    pub verified: Address,

    /// Replay-protection nonce.
    pub nonce: u64,

    /// Unix milliseconds when the verification was created.
    pub timestamp_ms: i64,
}

impl VerifyPayload {
    /// Validate structural invariants.
    ///
    /// For Verify, the body itself has no invariants beyond a valid
    /// timestamp — the signer-set constraints are enforced by the
    /// containing [`crate::tx::SignedTransaction`]. This method exists to
    /// keep the API uniform with the other payload types.
    ///
    /// # Errors
    /// Always `Ok` currently. Returns [`TxError`] for future extensions.
    pub const fn validate_invariants(&self) -> Result<(), TxError> {
        Ok(())
    }
}
