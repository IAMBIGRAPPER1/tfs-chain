// TFS_CHAIN · tx/mod.rs · Layer 3
//
// THE FOUR ACTS OF THE NATION.
//
// Transfer · Inscribe · Verify · Burn.
//
// Each transaction is a signed intent to change the chain's state.
// Layer 3 validates the STRUCTURE and SIGNATURES of transactions.
// Layer 5 will validate the SEMANTICS (balances, nonce ordering, quorum rules)
// against the chain's state machine.
//
// ┌──────────────── SignedTransaction ────────────────┐
// │                                                    │
// │   Transaction (enum)                               │
// │   ├─ Transfer  (TransferPayload)                   │
// │   ├─ Inscribe  (InscribePayload)                   │
// │   ├─ Verify    (VerifyPayload)                     │
// │   └─ Burn      (BurnPayload)                       │
// │                                                    │
// │   signatures: Vec<TxSignature>                     │
// │                                                    │
// └────────────────────────────────────────────────────┘
//
// Each TxSignature carries BOTH the signer's PublicKey AND the Signature.
// Validators verify:
//   1. BLAKE3(pubkey) == claimed_address (binding)
//   2. Signature valid over body_hash (authentication)
//
// THREAT MODEL (addressed in this layer):
//   - Signature forgery         → ed25519 strict verification
//   - Address/pubkey mismatch   → explicit hash check
//   - Replay attacks            → nonce field (enforced at Layer 5)
//   - Self-verification         → Verify rejects verifier == verified
//   - Duplicate verifiers       → unique-by-pubkey check in quorum
//   - Insufficient quorum       → >= MIN_VERIFICATION_QUORUM
//   - Zero-amount transfers     → amount > 0 check
//   - Zero-amount burns         → amount > 0 check
//   - Oversized inscriptions    → MAX_INSCRIPTION_BYTES
//   - Mismatched doctrine hash  → self-check on InscribePayload
//   - Long reason string DoS    → MAX_BURN_REASON_BYTES

//! Transaction types and signing for THE TFS CHAIN.
//!
//! The four acts of the nation:
//! - [`transfer::TransferPayload`]  — citizen-to-citizen $TFS movement
//! - [`inscribe::InscribePayload`]  — inscribe doctrine on-chain (mints 1,000 $TFS)
//! - [`verify::VerifyPayload`]      — 3-peer quorum verifies a citizen (mints 100 $TFS)
//! - [`burn::BurnPayload`]          — ceremonial burn (honor inscribed forever)
//!
//! Wrap a payload in [`SignedTransaction`] after signing with the owning
//! keypair(s). Validate with [`SignedTransaction::validate_structure`].

pub mod burn;
pub mod inscribe;
pub mod sigil;
pub mod transfer;
pub mod verify;

pub use burn::BurnPayload;
pub use inscribe::InscribePayload;
pub use sigil::{SigilBindPayload, MAX_SIGIL_LEN};
pub use transfer::TransferPayload;
pub use verify::VerifyPayload;

use serde::{Deserialize, Serialize};

use crate::crypto::{
    address::Address,
    hash::{hash_bytes, hash_serialized, Hash, HashError},
    keypair::{Keypair, PublicKey, Signature, VerifyError},
};

// ═══════════════════════════════════════════════════════════════════
// CONSTANTS · economic and structural
// ═══════════════════════════════════════════════════════════════════

/// Number of hyphae (the smallest unit) per $TFS.
///
/// 1 $TFS = 1,000,000,000 hyphae = 10⁹ hyphae.
/// This matches the scroll's declaration that `one hypha equals 0.000000001 $TFS`.
pub const HYPHAE_PER_TFS: u64 = 1_000_000_000;

/// Maximum circulating supply in hyphae.
/// Equals 1,000,000,000 $TFS × 10⁹ hyphae/$TFS = 10¹⁸ hyphae.
/// Fits in u64 (max ~1.84 × 10¹⁹) with ~18× headroom.
pub const MAX_SUPPLY_HYPHAE: u64 = 1_000_000_000 * HYPHAE_PER_TFS;

/// Minimum quorum of distinct peers for a Verify transaction.
/// The scroll: "a quorum of three or more peers signs the verification."
pub const MIN_VERIFICATION_QUORUM: usize = 3;

/// Maximum number of verifiers in a single Verify transaction.
/// Prevents vector-length DoS. 128 is far more than the scroll's 3 minimum.
pub const MAX_VERIFICATION_SIGNERS: usize = 128;

/// Maximum inscribed doctrine size in bytes.
/// 512 KiB. Enough for long scrolls, small enough to limit block bloat.
pub const MAX_INSCRIPTION_BYTES: usize = 512 * 1024;

/// Maximum length of an optional burn reason, in bytes.
/// 1024 bytes ≈ 200 English words. The chain inscribes honor; it doesn't
/// host essays.
pub const MAX_BURN_REASON_BYTES: usize = 1024;

// ═══════════════════════════════════════════════════════════════════
// TRANSACTION ENUM · the four acts
// ═══════════════════════════════════════════════════════════════════

/// A transaction body on THE TFS CHAIN. One of the four sovereign acts.
///
/// Wrap in a [`SignedTransaction`] after signing with the owning keypair(s).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Transaction {
    /// Citizen-to-citizen $TFS transfer.
    Transfer(TransferPayload),

    /// Inscribe a doctrine-block on the chain. Mints 1,000 $TFS to the inscriber.
    Inscribe(InscribePayload),

    /// Verify a citizen via 3-peer quorum. Mints 100 $TFS to the verified citizen.
    Verify(VerifyPayload),

    /// Ceremonial burn of $TFS. Permanently reduces supply.
    Burn(BurnPayload),

    /// Claim a sigil on the chain. One sigil per citizen. First to inscribe
    /// holds it forever. Draws the era-adjusted inscribe reward from treasury
    /// as the citizen's onboarding allowance.
    SigilBind(SigilBindPayload),
}

impl Transaction {
    /// Return the canonical hash of this transaction body.
    ///
    /// This is what signers sign. Changing ANY byte of the body — including
    /// the transaction variant, the payload fields, the nonce, or the timestamp —
    /// produces a different hash, invalidating all existing signatures.
    ///
    /// # Errors
    /// Returns [`HashError`] if serialization fails (should be impossible
    /// given the structure of the types).
    pub fn body_hash(&self) -> Result<Hash, HashError> {
        hash_serialized(self)
    }

    /// Return the nonce associated with this transaction.
    ///
    /// Used by Layer 5 to enforce per-account transaction ordering and
    /// prevent replay attacks.
    #[must_use]
    pub const fn nonce(&self) -> u64 {
        match self {
            Self::Transfer(t) => t.nonce,
            Self::Inscribe(i) => i.nonce,
            Self::Verify(v) => v.nonce,
            Self::Burn(b) => b.nonce,
            Self::SigilBind(s) => s.nonce,
        }
    }

    /// Return the transaction's timestamp in milliseconds since Unix epoch.
    #[must_use]
    pub const fn timestamp_ms(&self) -> i64 {
        match self {
            Self::Transfer(t) => t.timestamp_ms,
            Self::Inscribe(i) => i.timestamp_ms,
            Self::Verify(v) => v.timestamp_ms,
            Self::Burn(b) => b.timestamp_ms,
            Self::SigilBind(s) => s.timestamp_ms,
        }
    }

    /// Return the primary (originating) address for this transaction.
    ///
    /// - Transfer: `from`
    /// - Inscribe: `inscriber`
    /// - Verify: `verified` (the citizen receiving the mint; verifiers are in the signatures)
    /// - Burn: `burner`
    /// - SigilBind: `claimant`
    #[must_use]
    pub const fn primary_address(&self) -> &Address {
        match self {
            Self::Transfer(t) => &t.from,
            Self::Inscribe(i) => &i.inscriber,
            Self::Verify(v) => &v.verified,
            Self::Burn(b) => &b.burner,
            Self::SigilBind(s) => &s.claimant,
        }
    }

    /// Validate the internal invariants of the transaction body.
    ///
    /// This is the Layer 3 structural check — does NOT consult any on-chain
    /// state. Checks:
    /// - Amounts are strictly positive where required (Transfer, Burn).
    /// - Addresses are distinct where required (Transfer from != to).
    /// - Inscription content within size limit and its hash is consistent.
    /// - Burn reason within size limit.
    /// - Timestamps are not in the obviously-invalid past (negative).
    ///
    /// # Errors
    /// Returns [`TxError`] describing the invariant that failed.
    pub fn validate_invariants(&self) -> Result<(), TxError> {
        if self.timestamp_ms() < 0 {
            return Err(TxError::InvalidTimestamp(self.timestamp_ms()));
        }

        match self {
            Self::Transfer(t) => t.validate_invariants(),
            Self::Inscribe(i) => i.validate_invariants(),
            Self::Verify(v) => v.validate_invariants(),
            Self::Burn(b) => b.validate_invariants(),
            Self::SigilBind(s) => s.validate_invariants(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// TX SIGNATURE · one signer's commitment to a body_hash
// ═══════════════════════════════════════════════════════════════════

/// A single signature on a transaction.
///
/// Contains both the signer's [`PublicKey`] and their [`Signature`].
/// The public key is required because addresses on THE TFS CHAIN are
/// BLAKE3(pubkey) — the address alone is insufficient to verify a signature.
///
/// Validators check two things:
/// 1. `BLAKE3(signer_pubkey)` equals the address claimed by the transaction
///    (or is in the verifier set, for Verify transactions).
/// 2. `signer_pubkey.verify(body_hash, signature)` succeeds.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxSignature {
    /// The signer's public key.
    pub signer_pubkey: PublicKey,

    /// The ed25519 signature over the transaction body hash.
    pub signature: Signature,
}

impl TxSignature {
    /// Create a signature by signing `body_hash` with `keypair`.
    #[must_use]
    pub fn sign(keypair: &Keypair, body_hash: &Hash) -> Self {
        Self {
            signer_pubkey: keypair.public_key(),
            signature: keypair.sign(body_hash.as_bytes()),
        }
    }

    /// Return the address derived from the signer's public key.
    ///
    /// This is the address the chain will credit or debit when processing
    /// a transaction containing this signature.
    #[must_use]
    pub fn signer_address(&self) -> Address {
        Address::from_public_key(&self.signer_pubkey)
    }

    /// Verify this signature against a specific body hash.
    ///
    /// # Errors
    /// Returns [`VerifyError`] if the signature is invalid.
    pub fn verify(&self, body_hash: &Hash) -> Result<(), VerifyError> {
        self.signer_pubkey.verify(body_hash.as_bytes(), &self.signature)
    }
}

// ═══════════════════════════════════════════════════════════════════
// SIGNED TRANSACTION · body + signatures
// ═══════════════════════════════════════════════════════════════════

/// A transaction with one or more attached signatures.
///
/// - [`Transaction::Transfer`]: exactly 1 signature from `from`.
/// - [`Transaction::Inscribe`]: exactly 1 signature from `inscriber`.
/// - [`Transaction::Verify`]: ≥ [`MIN_VERIFICATION_QUORUM`] signatures from
///   distinct verifiers, none of whom is the verified citizen.
/// - [`Transaction::Burn`]: exactly 1 signature from `burner`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedTransaction {
    /// The transaction body.
    pub tx: Transaction,

    /// Signatures over `tx.body_hash()`.
    pub signatures: Vec<TxSignature>,
}

impl SignedTransaction {
    /// Sign a single-signer transaction (Transfer, Inscribe, Burn) with the
    /// given keypair.
    ///
    /// # Errors
    /// Returns [`TxError`] if:
    /// - The transaction is a Verify (use [`SignedTransaction::sign_verify`]).
    /// - The keypair's address doesn't match the primary address of the transaction.
    /// - Hashing fails.
    pub fn sign_single(tx: Transaction, keypair: &Keypair) -> Result<Self, TxError> {
        if matches!(tx, Transaction::Verify(_)) {
            return Err(TxError::WrongSigningMethod {
                expected: "sign_verify (multi-sig)",
                got: "sign_single",
            });
        }

        let signer_addr = Address::from_public_key(&keypair.public_key());
        if signer_addr != *tx.primary_address() {
            return Err(TxError::SignerAddressMismatch {
                expected: *tx.primary_address(),
                actual: signer_addr,
            });
        }

        let body_hash = tx.body_hash()?;
        let sig = TxSignature::sign(keypair, &body_hash);
        Ok(Self {
            tx,
            signatures: vec![sig],
        })
    }

    /// Sign a Verify transaction with a quorum of verifier keypairs.
    ///
    /// # Errors
    /// Returns [`TxError`] if:
    /// - The transaction is not a Verify.
    /// - Fewer than [`MIN_VERIFICATION_QUORUM`] keypairs provided.
    /// - Any keypair's address equals the `verified` address (self-verification).
    /// - Any two keypairs have the same address (duplicate verifier).
    /// - Hashing fails.
    pub fn sign_verify(tx: Transaction, verifier_keypairs: &[&Keypair]) -> Result<Self, TxError> {
        let Transaction::Verify(ref payload) = tx else {
            return Err(TxError::WrongSigningMethod {
                expected: "sign_single",
                got: "sign_verify",
            });
        };

        if verifier_keypairs.len() < MIN_VERIFICATION_QUORUM {
            return Err(TxError::InsufficientQuorum {
                provided: verifier_keypairs.len(),
                required: MIN_VERIFICATION_QUORUM,
            });
        }

        if verifier_keypairs.len() > MAX_VERIFICATION_SIGNERS {
            return Err(TxError::TooManyVerifiers {
                provided: verifier_keypairs.len(),
                max: MAX_VERIFICATION_SIGNERS,
            });
        }

        // Check distinct and no-self-verification.
        let verified_addr = payload.verified;
        let mut seen: Vec<Address> = Vec::with_capacity(verifier_keypairs.len());
        for kp in verifier_keypairs {
            let addr = Address::from_public_key(&kp.public_key());
            if addr == verified_addr {
                return Err(TxError::SelfVerification(addr));
            }
            if seen.contains(&addr) {
                return Err(TxError::DuplicateVerifier(addr));
            }
            seen.push(addr);
        }

        let body_hash = tx.body_hash()?;
        let signatures: Vec<TxSignature> = verifier_keypairs
            .iter()
            .map(|kp| TxSignature::sign(kp, &body_hash))
            .collect();

        Ok(Self { tx, signatures })
    }

    /// Return this transaction's ID — BLAKE3 over the entire signed structure.
    ///
    /// Two transactions with identical bodies but different signature orderings
    /// produce different IDs. If deterministic transaction IDs are required
    /// regardless of signature ordering (for Verify with permuted verifiers),
    /// use [`Transaction::body_hash`] as the logical identity.
    ///
    /// # Errors
    /// Returns [`HashError`] if serialization fails.
    pub fn tx_id(&self) -> Result<Hash, HashError> {
        hash_serialized(self)
    }

    /// Return the canonical serialized bytes of this signed transaction.
    /// Used for inclusion in blocks.
    ///
    /// # Errors
    /// Returns [`HashError`] if serialization fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, HashError> {
        bincode::serialize(self).map_err(|e| HashError::Serialize(e.to_string()))
    }

    /// Parse a signed transaction from its serialized bytes.
    ///
    /// # Errors
    /// Returns [`TxError`] if deserialization fails.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TxError> {
        bincode::deserialize(bytes).map_err(|e| TxError::Deserialize(e.to_string()))
    }

    /// Validate the structural correctness of this signed transaction.
    ///
    /// Checks:
    /// 1. Internal invariants of the body (amount > 0, etc.) via
    ///    [`Transaction::validate_invariants`].
    /// 2. Exactly 1 signature for Transfer/Inscribe/Burn;
    ///    [`MIN_VERIFICATION_QUORUM`]..= [`MAX_VERIFICATION_SIGNERS`] for Verify.
    /// 3. Each signature's `signer_pubkey` hashes to a required address:
    ///    - Transfer/Inscribe/Burn: matches the primary address.
    ///    - Verify: does NOT equal `verified`, and is distinct from other signers.
    /// 4. Each signature verifies against `body_hash`.
    ///
    /// # Errors
    /// Returns [`TxError`] on the first failed check.
    pub fn validate_structure(&self) -> Result<(), TxError> {
        self.tx.validate_invariants()?;

        let body_hash = self.tx.body_hash()?;

        match &self.tx {
            Transaction::Transfer(_)
            | Transaction::Inscribe(_)
            | Transaction::Burn(_)
            | Transaction::SigilBind(_) => self.validate_single_signer(&body_hash),
            Transaction::Verify(payload) => self.validate_quorum(&body_hash, &payload.verified),
        }
    }

    fn validate_single_signer(&self, body_hash: &Hash) -> Result<(), TxError> {
        if self.signatures.len() != 1 {
            return Err(TxError::WrongSignatureCount {
                expected: 1,
                actual: self.signatures.len(),
            });
        }

        let sig = &self.signatures[0];
        let signer_addr = sig.signer_address();
        let expected_addr = self.tx.primary_address();

        if signer_addr != *expected_addr {
            return Err(TxError::SignerAddressMismatch {
                expected: *expected_addr,
                actual: signer_addr,
            });
        }

        sig.verify(body_hash)?;
        Ok(())
    }

    fn validate_quorum(&self, body_hash: &Hash, verified: &Address) -> Result<(), TxError> {
        if self.signatures.len() < MIN_VERIFICATION_QUORUM {
            return Err(TxError::InsufficientQuorum {
                provided: self.signatures.len(),
                required: MIN_VERIFICATION_QUORUM,
            });
        }
        if self.signatures.len() > MAX_VERIFICATION_SIGNERS {
            return Err(TxError::TooManyVerifiers {
                provided: self.signatures.len(),
                max: MAX_VERIFICATION_SIGNERS,
            });
        }

        // Check each signature's validity, that its signer is not `verified`,
        // and that all signers are distinct.
        let mut seen: Vec<Address> = Vec::with_capacity(self.signatures.len());
        for sig in &self.signatures {
            let addr = sig.signer_address();
            if addr == *verified {
                return Err(TxError::SelfVerification(addr));
            }
            if seen.contains(&addr) {
                return Err(TxError::DuplicateVerifier(addr));
            }
            seen.push(addr);

            sig.verify(body_hash)?;
        }

        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════════════════════

/// Errors that can occur when constructing or validating transactions.
#[derive(Debug, thiserror::Error)]
pub enum TxError {
    /// A transfer or burn specified a zero or negative amount.
    #[error("amount must be strictly positive (got {0})")]
    ZeroOrNegativeAmount(u64),

    /// Transfer where `from == to`.
    #[error("transfer from-address equals to-address: {0}")]
    TransferToSelf(Address),

    /// Inscription content is empty.
    #[error("inscription content is empty")]
    EmptyInscription,

    /// Inscription content exceeds [`MAX_INSCRIPTION_BYTES`].
    #[error("inscription too large: {actual} bytes, max is {max}")]
    InscriptionTooLarge {
        /// Actual content size.
        actual: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Inscription's stored `doctrine_hash` doesn't match BLAKE3 of content.
    #[error("doctrine hash mismatch: claimed {claimed}, computed {computed}")]
    DoctrineHashMismatch {
        /// Hash claimed in the payload.
        claimed: String,
        /// Hash computed from the content.
        computed: String,
    },

    /// Burn reason exceeds [`MAX_BURN_REASON_BYTES`].
    #[error("burn reason too long: {actual} bytes, max is {max}")]
    BurnReasonTooLong {
        /// Actual reason length.
        actual: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// SigilBind with an empty sigil string.
    #[error("sigil is empty")]
    EmptySigil,

    /// SigilBind whose sigil exceeds [`MAX_SIGIL_LEN`].
    #[error("sigil too long: {actual} bytes, max is {max}")]
    SigilTooLong {
        /// Actual sigil length.
        actual: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// SigilBind contains a character outside the allowed set `[A-Za-z0-9_-]`.
    #[error("invalid sigil character: {0:?}")]
    InvalidSigilChar(char),

    /// Number of signatures doesn't match expectations for this tx type.
    #[error("wrong signature count: expected {expected}, got {actual}")]
    WrongSignatureCount {
        /// Expected count.
        expected: usize,
        /// Actual count.
        actual: usize,
    },

    /// A signer's derived address doesn't match the transaction's primary address.
    #[error("signer address mismatch: expected {expected}, got {actual}")]
    SignerAddressMismatch {
        /// Expected address.
        expected: Address,
        /// Actual address (derived from signer pubkey).
        actual: Address,
    },

    /// Verify transaction received fewer than [`MIN_VERIFICATION_QUORUM`] signatures.
    #[error("insufficient quorum: {provided} signers, need at least {required}")]
    InsufficientQuorum {
        /// Number of signers provided.
        provided: usize,
        /// Minimum required.
        required: usize,
    },

    /// Verify transaction received more than [`MAX_VERIFICATION_SIGNERS`].
    #[error("too many verifiers: {provided}, max {max}")]
    TooManyVerifiers {
        /// Number provided.
        provided: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// A verifier's address equals the verified citizen's address (self-verification attempt).
    #[error("self-verification not permitted for address {0}")]
    SelfVerification(Address),

    /// Two verifiers in the same Verify transaction have the same address.
    #[error("duplicate verifier address in quorum: {0}")]
    DuplicateVerifier(Address),

    /// Called the wrong signing method for this transaction type.
    #[error("wrong signing method: expected {expected}, called {got}")]
    WrongSigningMethod {
        /// The method that should have been called.
        expected: &'static str,
        /// The method that was called.
        got: &'static str,
    },

    /// Timestamp is negative (pre-1970).
    #[error("invalid timestamp: {0}")]
    InvalidTimestamp(i64),

    /// Deserialization of a signed transaction failed.
    #[error("deserialization failed: {0}")]
    Deserialize(String),

    /// Underlying hash/serialize error.
    #[error("hash error: {0}")]
    Hash(#[from] HashError),

    /// Signature verification failed.
    #[error("signature verification failed: {0}")]
    Signature(#[from] VerifyError),
}

// ═══════════════════════════════════════════════════════════════════
// INTERNAL UTILITIES (used by submodules)
// ═══════════════════════════════════════════════════════════════════

/// Compute BLAKE3 of the given bytes (re-export for submodules).
pub(crate) fn doctrine_content_hash(bytes: &[u8]) -> Hash {
    hash_bytes(bytes)
}

// ═══════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn kp() -> Keypair {
        Keypair::generate()
    }

    fn addr(kp: &Keypair) -> Address {
        Address::from_public_key(&kp.public_key())
    }

    fn now_ms() -> i64 {
        1_700_000_000_000
    }

    // ─── TRANSFER ───────────────────────────────────────────────────

    #[test]
    fn transfer_happy_path() {
        let alice = kp();
        let bob = kp();
        let tx = Transaction::Transfer(TransferPayload {
            from: addr(&alice),
            to: addr(&bob),
            amount_hyphae: 1_000_000_000, // 1 $TFS
            nonce: 0,
            timestamp_ms: now_ms(),
        });
        let signed = SignedTransaction::sign_single(tx, &alice).expect("sign");
        signed.validate_structure().expect("valid");
    }

    #[test]
    fn transfer_rejects_zero_amount() {
        let alice = kp();
        let bob = kp();
        let tx = Transaction::Transfer(TransferPayload {
            from: addr(&alice),
            to: addr(&bob),
            amount_hyphae: 0,
            nonce: 0,
            timestamp_ms: now_ms(),
        });
        let signed = SignedTransaction::sign_single(tx, &alice).expect("sign ok");
        let err = signed.validate_structure().expect_err("zero amount rejected");
        assert!(matches!(err, TxError::ZeroOrNegativeAmount(_)));
    }

    #[test]
    fn transfer_rejects_to_self() {
        let alice = kp();
        let tx = Transaction::Transfer(TransferPayload {
            from: addr(&alice),
            to: addr(&alice),
            amount_hyphae: 1,
            nonce: 0,
            timestamp_ms: now_ms(),
        });
        let signed = SignedTransaction::sign_single(tx, &alice).expect("sign ok");
        let err = signed.validate_structure().expect_err("self transfer rejected");
        assert!(matches!(err, TxError::TransferToSelf(_)));
    }

    #[test]
    fn transfer_rejects_wrong_signer() {
        let alice = kp();
        let bob = kp();
        let mallory = kp();
        let tx = Transaction::Transfer(TransferPayload {
            from: addr(&alice),
            to: addr(&bob),
            amount_hyphae: 1,
            nonce: 0,
            timestamp_ms: now_ms(),
        });
        // Mallory tries to sign Alice's transfer.
        let err = SignedTransaction::sign_single(tx, &mallory).expect_err("rejected");
        assert!(matches!(err, TxError::SignerAddressMismatch { .. }));
    }

    #[test]
    fn transfer_rejects_tampered_signature() {
        let alice = kp();
        let bob = kp();
        let tx = Transaction::Transfer(TransferPayload {
            from: addr(&alice),
            to: addr(&bob),
            amount_hyphae: 1,
            nonce: 0,
            timestamp_ms: now_ms(),
        });
        let mut signed = SignedTransaction::sign_single(tx, &alice).expect("sign");

        // Tamper with the body after signing. The signature no longer verifies.
        if let Transaction::Transfer(ref mut payload) = signed.tx {
            payload.amount_hyphae = 999_999_999;
        }

        let err = signed.validate_structure().expect_err("tampered");
        assert!(matches!(err, TxError::Signature(_)));
    }

    // ─── INSCRIBE ───────────────────────────────────────────────────

    #[test]
    fn inscribe_happy_path() {
        let president = kp();
        let doctrine = "SCROLL OF GENESIS · the supply is capped at one billion."
            .as_bytes()
            .to_vec();
        let payload = InscribePayload::new(addr(&president), doctrine, 0, now_ms());
        let tx = Transaction::Inscribe(payload);
        let signed = SignedTransaction::sign_single(tx, &president).expect("sign");
        signed.validate_structure().expect("valid");
    }

    #[test]
    fn inscribe_rejects_empty_content() {
        let president = kp();
        let payload = InscribePayload {
            inscriber: addr(&president),
            doctrine_bytes: Vec::new(),
            doctrine_hash: Hash::ZERO,
            nonce: 0,
            timestamp_ms: now_ms(),
        };
        let tx = Transaction::Inscribe(payload);
        let signed = SignedTransaction::sign_single(tx, &president).expect("sign");
        let err = signed.validate_structure().expect_err("empty");
        assert!(matches!(err, TxError::EmptyInscription));
    }

    #[test]
    fn inscribe_rejects_oversized() {
        let president = kp();
        let big = vec![0u8; MAX_INSCRIPTION_BYTES + 1];
        let payload = InscribePayload::new(addr(&president), big, 0, now_ms());
        let tx = Transaction::Inscribe(payload);
        let signed = SignedTransaction::sign_single(tx, &president).expect("sign");
        let err = signed.validate_structure().expect_err("oversized");
        assert!(matches!(err, TxError::InscriptionTooLarge { .. }));
    }

    #[test]
    fn inscribe_rejects_hash_mismatch() {
        let president = kp();
        // Manually construct a payload with a WRONG hash.
        let payload = InscribePayload {
            inscriber: addr(&president),
            doctrine_bytes: b"real doctrine".to_vec(),
            doctrine_hash: Hash::from_bytes([0xFF; 32]), // fake
            nonce: 0,
            timestamp_ms: now_ms(),
        };
        let tx = Transaction::Inscribe(payload);
        let signed = SignedTransaction::sign_single(tx, &president).expect("sign");
        let err = signed.validate_structure().expect_err("hash mismatch");
        assert!(matches!(err, TxError::DoctrineHashMismatch { .. }));
    }

    // ─── VERIFY ─────────────────────────────────────────────────────

    #[test]
    fn verify_happy_path() {
        let verified = kp();
        let v1 = kp();
        let v2 = kp();
        let v3 = kp();
        let tx = Transaction::Verify(VerifyPayload {
            verified: addr(&verified),
            nonce: 0,
            timestamp_ms: now_ms(),
        });
        let signed =
            SignedTransaction::sign_verify(tx, &[&v1, &v2, &v3]).expect("sign quorum");
        signed.validate_structure().expect("valid");
    }

    #[test]
    fn verify_rejects_insufficient_quorum() {
        let verified = kp();
        let v1 = kp();
        let v2 = kp();
        let tx = Transaction::Verify(VerifyPayload {
            verified: addr(&verified),
            nonce: 0,
            timestamp_ms: now_ms(),
        });
        // Only 2 verifiers — below quorum.
        let err =
            SignedTransaction::sign_verify(tx, &[&v1, &v2]).expect_err("quorum fail");
        assert!(matches!(err, TxError::InsufficientQuorum { .. }));
    }

    #[test]
    fn verify_rejects_self_verification() {
        let verified = kp();
        let v1 = kp();
        let v2 = kp();
        let tx = Transaction::Verify(VerifyPayload {
            verified: addr(&verified),
            nonce: 0,
            timestamp_ms: now_ms(),
        });
        // `verified` is one of the verifiers — not allowed.
        let err = SignedTransaction::sign_verify(tx, &[&v1, &v2, &verified])
            .expect_err("self-verify");
        assert!(matches!(err, TxError::SelfVerification(_)));
    }

    #[test]
    fn verify_rejects_duplicate_verifier() {
        let verified = kp();
        let v1 = kp();
        let v2 = kp();
        let tx = Transaction::Verify(VerifyPayload {
            verified: addr(&verified),
            nonce: 0,
            timestamp_ms: now_ms(),
        });
        // v1 signs twice — duplicate.
        let err = SignedTransaction::sign_verify(tx, &[&v1, &v2, &v1])
            .expect_err("duplicate");
        assert!(matches!(err, TxError::DuplicateVerifier(_)));
    }

    #[test]
    fn verify_rejects_tampered_post_signing() {
        let verified = kp();
        let v1 = kp();
        let v2 = kp();
        let v3 = kp();
        let tx = Transaction::Verify(VerifyPayload {
            verified: addr(&verified),
            nonce: 0,
            timestamp_ms: now_ms(),
        });
        let mut signed =
            SignedTransaction::sign_verify(tx, &[&v1, &v2, &v3]).expect("sign");

        // Change the verified address post-signing. All signatures invalidate.
        if let Transaction::Verify(ref mut payload) = signed.tx {
            payload.verified = addr(&kp()); // different victim
        }
        let err = signed.validate_structure().expect_err("tampered verify");
        assert!(matches!(err, TxError::Signature(_)));
    }

    #[test]
    fn verify_rejects_wrong_signing_method_for_verify() {
        let verified = kp();
        let random_kp = kp();
        let tx = Transaction::Verify(VerifyPayload {
            verified: addr(&verified),
            nonce: 0,
            timestamp_ms: now_ms(),
        });
        // Can't use sign_single on a Verify.
        let err = SignedTransaction::sign_single(tx, &random_kp).expect_err("wrong method");
        assert!(matches!(err, TxError::WrongSigningMethod { .. }));
    }

    #[test]
    fn verify_rejects_wrong_signing_method_for_single() {
        let alice = kp();
        let bob = kp();
        let tx = Transaction::Transfer(TransferPayload {
            from: addr(&alice),
            to: addr(&bob),
            amount_hyphae: 1,
            nonce: 0,
            timestamp_ms: now_ms(),
        });
        // Can't use sign_verify on a Transfer.
        let err = SignedTransaction::sign_verify(tx, &[&alice, &bob, &kp()])
            .expect_err("wrong method");
        assert!(matches!(err, TxError::WrongSigningMethod { .. }));
    }

    // ─── BURN ───────────────────────────────────────────────────────

    #[test]
    fn burn_happy_path() {
        let citizen = kp();
        let tx = Transaction::Burn(BurnPayload {
            burner: addr(&citizen),
            amount_hyphae: HYPHAE_PER_TFS, // burn 1 $TFS
            nonce: 0,
            timestamp_ms: now_ms(),
            reason: Some("for the nation".to_string()),
        });
        let signed = SignedTransaction::sign_single(tx, &citizen).expect("sign");
        signed.validate_structure().expect("valid");
    }

    #[test]
    fn burn_allows_no_reason() {
        let citizen = kp();
        let tx = Transaction::Burn(BurnPayload {
            burner: addr(&citizen),
            amount_hyphae: 1,
            nonce: 0,
            timestamp_ms: now_ms(),
            reason: None,
        });
        let signed = SignedTransaction::sign_single(tx, &citizen).expect("sign");
        signed.validate_structure().expect("valid");
    }

    #[test]
    fn burn_rejects_zero_amount() {
        let citizen = kp();
        let tx = Transaction::Burn(BurnPayload {
            burner: addr(&citizen),
            amount_hyphae: 0,
            nonce: 0,
            timestamp_ms: now_ms(),
            reason: None,
        });
        let signed = SignedTransaction::sign_single(tx, &citizen).expect("sign");
        let err = signed.validate_structure().expect_err("zero amount");
        assert!(matches!(err, TxError::ZeroOrNegativeAmount(_)));
    }

    #[test]
    fn burn_rejects_oversized_reason() {
        let citizen = kp();
        let long_reason = "M".repeat(MAX_BURN_REASON_BYTES + 1);
        let tx = Transaction::Burn(BurnPayload {
            burner: addr(&citizen),
            amount_hyphae: 1,
            nonce: 0,
            timestamp_ms: now_ms(),
            reason: Some(long_reason),
        });
        let signed = SignedTransaction::sign_single(tx, &citizen).expect("sign");
        let err = signed.validate_structure().expect_err("reason too long");
        assert!(matches!(err, TxError::BurnReasonTooLong { .. }));
    }

    // ─── SIGIL BIND ─────────────────────────────────────────────────

    fn sigil_payload(s: &str, k: &Keypair) -> Transaction {
        Transaction::SigilBind(SigilBindPayload::new(
            s.to_string(),
            addr(k),
            0,
            now_ms(),
        ))
    }

    #[test]
    fn sigil_bind_happy_path() {
        let citizen = kp();
        let tx = sigil_payload("IAMBIGRAPPER1", &citizen);
        let signed = SignedTransaction::sign_single(tx, &citizen).expect("sign");
        signed.validate_structure().expect("valid");
    }

    #[test]
    fn sigil_bind_rejects_empty() {
        let citizen = kp();
        let tx = sigil_payload("", &citizen);
        let signed = SignedTransaction::sign_single(tx, &citizen).expect("sign");
        let err = signed.validate_structure().expect_err("empty sigil");
        assert!(matches!(err, TxError::EmptySigil));
    }

    #[test]
    fn sigil_bind_rejects_oversized() {
        let citizen = kp();
        let long = "a".repeat(MAX_SIGIL_LEN + 1);
        let tx = sigil_payload(&long, &citizen);
        let signed = SignedTransaction::sign_single(tx, &citizen).expect("sign");
        let err = signed.validate_structure().expect_err("too long");
        assert!(matches!(err, TxError::SigilTooLong { .. }));
    }

    #[test]
    fn sigil_bind_rejects_whitespace() {
        let citizen = kp();
        let tx = sigil_payload("big rapper", &citizen);
        let signed = SignedTransaction::sign_single(tx, &citizen).expect("sign");
        let err = signed.validate_structure().expect_err("whitespace");
        assert!(matches!(err, TxError::InvalidSigilChar(' ')));
    }

    #[test]
    fn sigil_bind_rejects_punctuation() {
        let citizen = kp();
        let tx = sigil_payload("big.rapper", &citizen);
        let signed = SignedTransaction::sign_single(tx, &citizen).expect("sign");
        let err = signed.validate_structure().expect_err("punctuation");
        assert!(matches!(err, TxError::InvalidSigilChar('.')));
    }

    #[test]
    fn sigil_bind_accepts_hyphens_and_underscores() {
        let citizen = kp();
        let tx = sigil_payload("big-rapper_001", &citizen);
        let signed = SignedTransaction::sign_single(tx, &citizen).expect("sign");
        signed.validate_structure().expect("valid");
    }

    #[test]
    fn sigil_bind_rejects_wrong_signer() {
        let citizen = kp();
        let impostor = kp();
        let tx = sigil_payload("IAMBIGRAPPER1", &citizen);
        let err = SignedTransaction::sign_single(tx, &impostor).expect_err("wrong signer");
        assert!(matches!(err, TxError::SignerAddressMismatch { .. }));
    }

    #[test]
    fn sigil_bind_body_hash_is_deterministic() {
        let citizen = kp();
        let t1 = sigil_payload("IAMBIGRAPPER1", &citizen);
        let t2 = t1.clone();
        assert_eq!(t1.body_hash().unwrap(), t2.body_hash().unwrap());
    }

    // ─── CROSS-VARIANT INVARIANTS ───────────────────────────────────

    #[test]
    fn body_hash_is_deterministic_across_variants() {
        // Two identical payloads produce identical body hashes.
        let alice = kp();
        let bob = kp();
        let tx1 = Transaction::Transfer(TransferPayload {
            from: addr(&alice),
            to: addr(&bob),
            amount_hyphae: 42,
            nonce: 7,
            timestamp_ms: now_ms(),
        });
        let tx2 = tx1.clone();
        assert_eq!(tx1.body_hash().expect("h1"), tx2.body_hash().expect("h2"));
    }

    #[test]
    fn different_variants_produce_different_hashes() {
        // Even with identical field values where possible, different variants
        // must produce different hashes (enum tag is part of the serialization).
        let alice = kp();
        let t = Transaction::Transfer(TransferPayload {
            from: addr(&alice),
            to: addr(&kp()),
            amount_hyphae: 1,
            nonce: 0,
            timestamp_ms: now_ms(),
        });
        let b = Transaction::Burn(BurnPayload {
            burner: addr(&alice),
            amount_hyphae: 1,
            nonce: 0,
            timestamp_ms: now_ms(),
            reason: None,
        });
        assert_ne!(
            t.body_hash().expect("th"),
            b.body_hash().expect("bh")
        );
    }

    #[test]
    fn nonce_change_changes_body_hash() {
        let alice = kp();
        let bob = kp();
        let mut payload = TransferPayload {
            from: addr(&alice),
            to: addr(&bob),
            amount_hyphae: 1,
            nonce: 0,
            timestamp_ms: now_ms(),
        };
        let h0 = Transaction::Transfer(payload.clone())
            .body_hash()
            .expect("h0");
        payload.nonce = 1;
        let h1 = Transaction::Transfer(payload).body_hash().expect("h1");
        assert_ne!(h0, h1);
    }

    #[test]
    fn signed_tx_serialization_roundtrip() {
        let alice = kp();
        let bob = kp();
        let tx = Transaction::Transfer(TransferPayload {
            from: addr(&alice),
            to: addr(&bob),
            amount_hyphae: 100,
            nonce: 3,
            timestamp_ms: now_ms(),
        });
        let signed = SignedTransaction::sign_single(tx, &alice).expect("sign");
        let bytes = signed.to_bytes().expect("serialize");
        let restored = SignedTransaction::from_bytes(&bytes).expect("deserialize");
        assert_eq!(signed, restored);
        assert_eq!(
            signed.tx_id().expect("id1"),
            restored.tx_id().expect("id2")
        );
        restored.validate_structure().expect("restored still valid");
    }

    #[test]
    fn tx_id_changes_when_signatures_change() {
        let verified = kp();
        let v1 = kp();
        let v2 = kp();
        let v3 = kp();
        let v4 = kp();
        let tx = Transaction::Verify(VerifyPayload {
            verified: addr(&verified),
            nonce: 0,
            timestamp_ms: now_ms(),
        });
        let signed_a = SignedTransaction::sign_verify(tx.clone(), &[&v1, &v2, &v3])
            .expect("sign a");
        let signed_b = SignedTransaction::sign_verify(tx, &[&v1, &v2, &v4]).expect("sign b");
        // Different verifier sets → different tx IDs.
        assert_ne!(
            signed_a.tx_id().expect("id_a"),
            signed_b.tx_id().expect("id_b")
        );
        // But the BODY hash is the same (the payload is unchanged).
        assert_eq!(
            signed_a.tx.body_hash().expect("body_a"),
            signed_b.tx.body_hash().expect("body_b")
        );
    }

    #[test]
    fn primary_address_matches_variant() {
        let alice = kp();
        let bob = kp();

        let t = Transaction::Transfer(TransferPayload {
            from: addr(&alice),
            to: addr(&bob),
            amount_hyphae: 1,
            nonce: 0,
            timestamp_ms: now_ms(),
        });
        assert_eq!(*t.primary_address(), addr(&alice));

        let i = Transaction::Inscribe(InscribePayload::new(
            addr(&alice),
            b"x".to_vec(),
            0,
            now_ms(),
        ));
        assert_eq!(*i.primary_address(), addr(&alice));

        let v = Transaction::Verify(VerifyPayload {
            verified: addr(&bob),
            nonce: 0,
            timestamp_ms: now_ms(),
        });
        assert_eq!(*v.primary_address(), addr(&bob));

        let b = Transaction::Burn(BurnPayload {
            burner: addr(&alice),
            amount_hyphae: 1,
            nonce: 0,
            timestamp_ms: now_ms(),
            reason: None,
        });
        assert_eq!(*b.primary_address(), addr(&alice));
    }

    #[test]
    fn rejects_negative_timestamp() {
        let alice = kp();
        let bob = kp();
        let tx = Transaction::Transfer(TransferPayload {
            from: addr(&alice),
            to: addr(&bob),
            amount_hyphae: 1,
            nonce: 0,
            timestamp_ms: -1,
        });
        let signed = SignedTransaction::sign_single(tx, &alice).expect("sign");
        let err = signed.validate_structure().expect_err("negative ts");
        assert!(matches!(err, TxError::InvalidTimestamp(_)));
    }

    #[test]
    fn sanity_supply_cap_fits_in_u64() {
        // The entire supply in hyphae must fit in u64 with room.
        assert!(MAX_SUPPLY_HYPHAE < u64::MAX / 2);
        // And it must equal exactly 10^18.
        assert_eq!(MAX_SUPPLY_HYPHAE, 1_000_000_000_000_000_000);
    }

    #[test]
    fn verify_rejects_too_many_signers() {
        let verified = kp();
        // Keypairs live in a Vec so the references stay valid.
        let kps: Vec<Keypair> = (0..=MAX_VERIFICATION_SIGNERS).map(|_| kp()).collect();
        let refs: Vec<&Keypair> = kps.iter().collect();
        let tx = Transaction::Verify(VerifyPayload {
            verified: addr(&verified),
            nonce: 0,
            timestamp_ms: now_ms(),
        });
        let err = SignedTransaction::sign_verify(tx, &refs).expect_err("too many");
        assert!(matches!(err, TxError::TooManyVerifiers { .. }));
    }
}
