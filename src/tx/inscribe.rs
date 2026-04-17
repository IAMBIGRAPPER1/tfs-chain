// TFS_CHAIN · tx/inscribe.rs · Layer 3
//
// INSCRIBE · the minting act.
//
// A citizen inscribes a doctrine-block on the chain. At GENESIS the issuance
// is 1,000 $TFS per inscription, halving every 50,000 doctrine-blocks until
// the supply cap is reached. This is the primary mint event.

//! Doctrine-block inscription transactions (the primary $TFS mint event).

use serde::{Deserialize, Serialize};

use super::{doctrine_content_hash, TxError, MAX_INSCRIPTION_BYTES};
use crate::crypto::{address::Address, hash::Hash};

/// A doctrine-block inscription.
///
/// Contains both the raw doctrine bytes (for future MINES.script parsing at
/// Layer 4) and a stored `doctrine_hash` that must equal `BLAKE3(doctrine_bytes)`.
/// The chain refuses to accept an inscription whose stated hash doesn't match
/// its actual content — this is a defense-in-depth against tampering during
/// transaction propagation.
///
/// Invariants checked at Layer 3:
/// - `doctrine_bytes.len() > 0`
/// - `doctrine_bytes.len() <= MAX_INSCRIPTION_BYTES`
/// - `doctrine_hash == BLAKE3(doctrine_bytes)`
///
/// NOT checked at Layer 3:
/// - Is `doctrine_bytes` valid MINES.script? (Layer 4)
/// - Is `inscriber` authorized to inscribe? (Layer 5)
/// - Has this doctrine_hash already been inscribed? (Layer 5)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InscribePayload {
    /// Address of the citizen inscribing (who receives the mint).
    pub inscriber: Address,

    /// Raw bytes of the doctrine being inscribed.
    /// Layer 4 will parse this as MINES.script. At Layer 3 it is opaque.
    pub doctrine_bytes: Vec<u8>,

    /// BLAKE3 hash of `doctrine_bytes`. Must match or the inscription is
    /// rejected. Stored explicitly (rather than recomputed on demand) so
    /// that block indexers and light clients can reference doctrines by
    /// hash without downloading the full content.
    pub doctrine_hash: Hash,

    /// Replay-protection nonce.
    pub nonce: u64,

    /// Unix milliseconds when the inscription was created.
    pub timestamp_ms: i64,
}

impl InscribePayload {
    /// Build a new inscription payload, computing `doctrine_hash` from content.
    #[must_use]
    pub fn new(
        inscriber: Address,
        doctrine_bytes: Vec<u8>,
        nonce: u64,
        timestamp_ms: i64,
    ) -> Self {
        let doctrine_hash = doctrine_content_hash(&doctrine_bytes);
        Self {
            inscriber,
            doctrine_bytes,
            doctrine_hash,
            nonce,
            timestamp_ms,
        }
    }

    /// Validate structural invariants.
    ///
    /// # Errors
    /// Returns [`TxError`] if:
    /// - Content is empty
    /// - Content exceeds [`MAX_INSCRIPTION_BYTES`]
    /// - `doctrine_hash` doesn't match BLAKE3 of the content
    pub fn validate_invariants(&self) -> Result<(), TxError> {
        if self.doctrine_bytes.is_empty() {
            return Err(TxError::EmptyInscription);
        }
        if self.doctrine_bytes.len() > MAX_INSCRIPTION_BYTES {
            return Err(TxError::InscriptionTooLarge {
                actual: self.doctrine_bytes.len(),
                max: MAX_INSCRIPTION_BYTES,
            });
        }
        let computed = doctrine_content_hash(&self.doctrine_bytes);
        if computed != self.doctrine_hash {
            return Err(TxError::DoctrineHashMismatch {
                claimed: self.doctrine_hash.to_hex(),
                computed: computed.to_hex(),
            });
        }
        Ok(())
    }
}
