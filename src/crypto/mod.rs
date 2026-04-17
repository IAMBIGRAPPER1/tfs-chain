// TFS_CHAIN · crypto · Layer 1 · MINES. VENTURE, LLC · ALL RIGHTS MINES.
//
// The cryptographic foundation. Every other layer depends on these primitives.
// Adversarial threat model:
//   - Attacker may try to forge signatures → defended by ed25519 + constant-time verify
//   - Attacker may try to predict keys     → defended by OS-provided CSPRNG
//   - Attacker may try timing side-channels → defended by constant-time subtle crate
//   - Attacker may try memory forensics    → defended by zeroize-on-drop
//   - Attacker may try hash collisions     → defended by BLAKE3 (256-bit)
//   - Attacker may try address typos       → defended by bech32 checksum

//! Cryptographic primitives for THE TFS CHAIN.
//!
//! This module is the foundation. If anything in here is wrong, the entire
//! chain is wrong.
//!
//! - [`hash`]: BLAKE3 hashing (the chain's fingerprint primitive)
//! - [`keypair`]: ed25519 signing keypairs (the sovereignty primitive)
//! - [`address`]: bech32-encoded addresses (the identity primitive)

pub mod address;
pub mod hash;
pub mod keypair;

// Convenient re-exports
pub use address::Address;
pub use hash::{Hash, Hasher};
pub use keypair::{Keypair, PublicKey, Signature, VerifyError};

/// Top-level cryptographic errors for the TFS_CHAIN crypto layer.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// Signature verification failed. The transaction or block is not authentic.
    #[error("signature verification failed: {0}")]
    SignatureInvalid(#[from] VerifyError),

    /// Address encoding or decoding failed (e.g., checksum mismatch, bad length).
    #[error("address error: {0}")]
    AddressError(#[from] address::AddressError),

    /// Hash input could not be serialized deterministically.
    #[error("hash error: {0}")]
    HashError(String),
}
