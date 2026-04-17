// TFS_CHAIN · crypto/hash.rs · Layer 1
//
// The fingerprint primitive. BLAKE3.
//
// Why BLAKE3 (not SHA-256):
//   - Equally secure (256-bit output, 2^256 preimage resistance)
//   - Significantly faster (~4x faster than SHA-256 on modern CPUs)
//   - Built-in keyed hashing, XOF, and derive_key modes
//   - Designed by the authors of Bao, ed25519-dalek authors reviewed it
//   - Used by Solana, Iroh, and modern rust crypto projects
//
// SAFETY INVARIANTS:
//   - Hash outputs are exactly 32 bytes. Always. Never other lengths.
//   - Hashing is deterministic: identical bytes in → identical hash out.
//   - Serialization (via bincode) is canonical: the same struct produces the
//     same bytes every time, on every platform, forever.

//! BLAKE3 hashing primitives for THE TFS CHAIN.
//!
//! Use [`Hasher`] when streaming multiple inputs into a single hash.
//! Use [`hash_bytes`] for a one-shot hash of a byte slice.
//! Use [`hash_serialized`] to hash any `Serialize`-implementing value.

use serde::{Deserialize, Serialize};
use std::fmt;

/// The length of a TFS_CHAIN hash, in bytes. Always 32.
pub const HASH_LEN: usize = 32;

/// A cryptographic hash in THE TFS CHAIN.
///
/// This is a fixed-size 32-byte BLAKE3 digest. Used for:
/// - Block hashes (linking blocks together)
/// - Transaction IDs (uniquely identifying transactions)
/// - Address derivation (deriving addresses from public keys)
/// - Merkle roots (commitment to sets of transactions)
/// - Content addressing (pointing to doctrine-blocks by content)
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
pub struct Hash(pub [u8; HASH_LEN]);

impl Hash {
    /// The zero hash. Used as the `previous_hash` of the genesis block.
    ///
    /// This is the ONLY block in the entire chain that has this value.
    /// All other blocks must have a non-zero `previous_hash`.
    pub const ZERO: Self = Self([0u8; HASH_LEN]);

    /// Construct a [`Hash`] from a 32-byte array.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; HASH_LEN]) -> Self {
        Self(bytes)
    }

    /// Return the underlying 32-byte array.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    /// Return the hash as a hex string (64 chars, lowercase).
    /// Used for human-readable display and for block explorer URLs.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse a hex string into a [`Hash`].
    ///
    /// # Errors
    /// Returns an error if the input is not exactly 64 hex characters
    /// or contains invalid hex digits.
    pub fn from_hex(s: &str) -> Result<Self, HashDecodeError> {
        let bytes = hex::decode(s).map_err(|_| HashDecodeError::InvalidHex)?;
        if bytes.len() != HASH_LEN {
            return Err(HashDecodeError::WrongLength {
                expected: HASH_LEN,
                actual: bytes.len(),
            });
        }
        let mut out = [0u8; HASH_LEN];
        out.copy_from_slice(&bytes);
        Ok(Self(out))
    }

    /// Return `true` if this is the zero hash (only valid for genesis).
    #[must_use]
    pub fn is_zero(&self) -> bool {
        // Use constant-time comparison to avoid timing side-channels.
        // (Not strictly necessary for this check, but habit of the craft.)
        use subtle::ConstantTimeEq;
        self.0.ct_eq(&[0u8; HASH_LEN]).into()
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({})", self.to_hex())
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Display shows first 8 hex chars + ellipsis + last 8 hex chars
        // This matches the block explorer convention: "a1b2c3d4...e5f6g7h8"
        let hex = self.to_hex();
        #[allow(clippy::string_slice)]
        {
            write!(f, "{}...{}", &hex[..8], &hex[hex.len() - 8..])
        }
    }
}

/// Errors that can occur when decoding a hash from hex.
#[derive(Debug, thiserror::Error)]
pub enum HashDecodeError {
    /// The input is not a valid hex string.
    #[error("invalid hex encoding")]
    InvalidHex,

    /// The decoded bytes are not the correct length (32 bytes).
    #[error("wrong hash length: expected {expected} bytes, got {actual}")]
    WrongLength {
        /// Expected length in bytes (always 32).
        expected: usize,
        /// Actual length received.
        actual: usize,
    },
}

/// A streaming BLAKE3 hasher.
///
/// Used when building up a hash from multiple inputs without allocating
/// an intermediate buffer. Critical for hashing large blocks efficiently.
#[derive(Clone)]
pub struct Hasher {
    inner: blake3::Hasher,
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher {
    /// Create a new, empty hasher.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: blake3::Hasher::new(),
        }
    }

    /// Feed bytes into the hasher.
    pub fn update(&mut self, bytes: &[u8]) -> &mut Self {
        self.inner.update(bytes);
        self
    }

    /// Finalize the hasher and return the resulting [`Hash`].
    ///
    /// This consumes the hasher. To hash more data, create a new hasher.
    #[must_use]
    pub fn finalize(self) -> Hash {
        let output = self.inner.finalize();
        Hash(*output.as_bytes())
    }
}

/// Hash a byte slice in one shot.
///
/// Equivalent to `Hasher::new().update(bytes).finalize()`.
#[must_use]
pub fn hash_bytes(bytes: &[u8]) -> Hash {
    let mut hasher = Hasher::new();
    hasher.update(bytes);
    hasher.finalize()
}

/// Hash any `Serialize`-implementing value by first serializing it
/// canonically with bincode, then hashing the bytes.
///
/// This is the standard way to hash structured data in THE TFS CHAIN.
/// Because bincode is deterministic, identical values produce identical hashes
/// on every platform, forever.
///
/// # Errors
/// Returns an error if serialization fails (extremely rare; usually indicates
/// a bug or an unrepresentable value).
pub fn hash_serialized<T: Serialize>(value: &T) -> Result<Hash, HashError> {
    let bytes = bincode::serialize(value).map_err(|e| HashError::Serialize(e.to_string()))?;
    Ok(hash_bytes(&bytes))
}

/// Errors that can occur during hashing of structured data.
#[derive(Debug, thiserror::Error)]
pub enum HashError {
    /// Serialization of the input failed.
    #[error("failed to serialize for hashing: {0}")]
    Serialize(String),
}

// ────────────────────────────────────────────────────────────────────
// TESTS
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_hash_is_zero() {
        assert!(Hash::ZERO.is_zero());
        assert_eq!(Hash::ZERO.as_bytes(), &[0u8; HASH_LEN]);
    }

    #[test]
    fn hash_bytes_is_deterministic() {
        let a = hash_bytes(b"MINES.");
        let b = hash_bytes(b"MINES.");
        assert_eq!(a, b);
    }

    #[test]
    fn hash_different_inputs_differ() {
        let a = hash_bytes(b"MINES.");
        let b = hash_bytes(b"MINES");
        assert_ne!(a, b);
    }

    #[test]
    fn hex_roundtrip() {
        let h = hash_bytes(b"THE FINAL SERVER");
        let hex = h.to_hex();
        let decoded = Hash::from_hex(&hex).expect("roundtrip");
        assert_eq!(h, decoded);
    }

    #[test]
    fn hex_rejects_wrong_length() {
        assert!(matches!(
            Hash::from_hex("abcd"),
            Err(HashDecodeError::WrongLength { .. })
        ));
    }

    #[test]
    fn hex_rejects_invalid_chars() {
        let bad = "z".repeat(64);
        assert!(matches!(
            Hash::from_hex(&bad),
            Err(HashDecodeError::InvalidHex)
        ));
    }

    #[test]
    fn display_is_truncated() {
        let h = hash_bytes(b"ALL RIGHTS MINES.");
        let display = format!("{h}");
        assert!(display.contains("..."));
        assert_eq!(display.len(), 8 + 3 + 8); // "xxxxxxxx...xxxxxxxx"
    }

    #[test]
    fn hash_serialized_is_deterministic() {
        #[derive(Serialize)]
        struct Doctrine {
            name: String,
            supply_cap: u64,
        }
        let a = Doctrine {
            name: "$TFS".to_string(),
            supply_cap: 1_000_000_000,
        };
        let b = Doctrine {
            name: "$TFS".to_string(),
            supply_cap: 1_000_000_000,
        };
        let ha = hash_serialized(&a).expect("hash a");
        let hb = hash_serialized(&b).expect("hash b");
        assert_eq!(ha, hb);
    }

    #[test]
    fn streaming_equals_one_shot() {
        let mut h = Hasher::new();
        h.update(b"THE FINAL ");
        h.update(b"SERVER");
        let streamed = h.finalize();
        let one_shot = hash_bytes(b"THE FINAL SERVER");
        assert_eq!(streamed, one_shot);
    }
}
