// TFS_CHAIN · crypto/address.rs · Layer 1
//
// The identity primitive. bech32-encoded addresses.
//
// Addresses are what humans see. Public keys are what the chain sees.
// An address is a bech32 encoding of a 32-byte BLAKE3 hash of the public key.
//
//   PublicKey (32 bytes)
//        │
//        ▼  BLAKE3
//   AddressHash (32 bytes)
//        │
//        ▼  bech32 encode with "tfs" HRP
//   Address: "tfs1q9p8m...checksum"
//
// Why hash the public key instead of encoding it directly?
//   - Public keys leak info (quantum-computer preparedness: quantum attacks
//     need the public key, not just the address; unused addresses stay quantum-safe)
//   - Shorter addresses in some encodings
//   - Separation of identity (address) from signing authority (pubkey)
//
// Why bech32 (not base58 like Bitcoin legacy addresses)?
//   - Built-in checksum detects up to 6 typos per 90 characters
//   - Lowercase-only encoding (no confusing capital-O vs zero)
//   - Human-readable prefix ("tfs1...") makes origin obvious
//   - Same encoding Bitcoin SegWit + Cosmos use
//   - Specified in BIP-0173, battle-tested since 2017

//! bech32-encoded sovereign identities for THE TFS CHAIN.
//!
//! Addresses look like `tfs1q9p8m...checksum`:
//! - `tfs` is the human-readable prefix ([`crate::ADDRESS_HRP`]).
//! - `1` is the bech32 separator.
//! - The remaining characters encode the 32-byte address hash plus a checksum.
//!
//! Derive an address from a public key with [`Address::from_public_key`].
//! Parse a string into an address with [`Address::parse`].

use bech32::{Bech32m, Hrp};
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::crypto::{hash::hash_bytes, hash::Hash, keypair::PublicKey};
use crate::ADDRESS_HRP;

/// A sovereign citizen address on THE TFS CHAIN.
///
/// Internally, an address is a 32-byte BLAKE3 hash of a public key.
/// Externally, it is displayed as a bech32 string: `tfs1...`.
///
/// Two public keys with different bytes produce different addresses
/// (preimage resistance of BLAKE3 guarantees this).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address {
    /// The 32-byte address hash (BLAKE3 of the public key).
    hash: Hash,
}

impl Address {
    /// Derive an address from a public key.
    ///
    /// This is the canonical way to create an address for a citizen.
    /// The derivation is: `address = BLAKE3(public_key_bytes)`.
    #[must_use]
    pub fn from_public_key(pk: &PublicKey) -> Self {
        let pk_bytes = pk.to_bytes();
        let hash = hash_bytes(&pk_bytes);
        Self { hash }
    }

    /// Construct an address directly from a 32-byte hash.
    ///
    /// This is primarily for internal use and for deserialization from storage.
    /// Citizens should use [`Address::from_public_key`] for normal operation.
    #[must_use]
    pub const fn from_hash(hash: Hash) -> Self {
        Self { hash }
    }

    /// Return the underlying 32-byte address hash.
    #[must_use]
    pub const fn as_hash(&self) -> &Hash {
        &self.hash
    }

    /// Return the underlying 32 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.hash.as_bytes()
    }

    /// Encode this address as a bech32m string (`tfs1...`).
    ///
    /// bech32m is the improved bech32 variant specified in BIP-0350.
    /// It fixes a minor mutation issue in the original bech32 checksum.
    #[must_use]
    pub fn to_bech32(&self) -> String {
        // Construct the HRP. Unwrap is safe because ADDRESS_HRP is a
        // compile-time constant that we control and know is valid.
        let hrp = Hrp::parse(ADDRESS_HRP)
            .expect("ADDRESS_HRP is a valid bech32 HRP (compile-time invariant)");
        // Encoding is infallible for a valid HRP + byte slice.
        bech32::encode::<Bech32m>(hrp, self.as_bytes())
            .expect("bech32m encoding is infallible for 32 bytes")
    }

    /// Parse an address from its bech32m string representation.
    ///
    /// # Errors
    /// Returns [`AddressError`] if:
    /// - The string is not valid bech32 / bech32m
    /// - The human-readable prefix is not `tfs`
    /// - The decoded data is not exactly 32 bytes
    /// - The checksum is invalid (indicates a typo or corruption)
    pub fn parse(s: &str) -> Result<Self, AddressError> {
        // bech32::decode validates:
        //   - Character set (lowercase bech32 alphabet)
        //   - Checksum (detects up to 6 typos per 90 chars)
        //   - Max length
        let (hrp, data) = bech32::decode(s).map_err(|_| AddressError::InvalidBech32)?;

        // Reject addresses with wrong prefix.
        if hrp.as_str() != ADDRESS_HRP {
            return Err(AddressError::WrongHrp {
                expected: ADDRESS_HRP.to_string(),
                actual: hrp.as_str().to_string(),
            });
        }

        // Reject addresses with wrong byte length.
        if data.len() != 32 {
            return Err(AddressError::WrongLength {
                expected: 32,
                actual: data.len(),
            });
        }

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&data);
        Ok(Self {
            hash: Hash::from_bytes(bytes),
        })
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({})", self.to_bech32())
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_bech32())
    }
}

/// Errors that can occur when parsing or constructing an address.
#[derive(Debug, thiserror::Error)]
pub enum AddressError {
    /// The input is not a valid bech32 / bech32m string.
    /// Most commonly this means the checksum is wrong (indicating a typo).
    #[error("invalid bech32 encoding (check for typos)")]
    InvalidBech32,

    /// The address has the wrong human-readable prefix.
    /// A `tfs1...` address was expected, but something else was provided.
    #[error("wrong address prefix: expected {expected}, got {actual}")]
    WrongHrp {
        /// The prefix we expected (always `tfs`).
        expected: String,
        /// The prefix we actually received.
        actual: String,
    },

    /// The decoded address has the wrong byte length.
    /// Addresses on THE TFS CHAIN are always exactly 32 bytes.
    #[error("wrong address length: expected {expected} bytes, got {actual}")]
    WrongLength {
        /// Expected length (always 32).
        expected: usize,
        /// Actual length decoded.
        actual: usize,
    },
}

// ────────────────────────────────────────────────────────────────────
// TESTS
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keypair::Keypair;

    #[test]
    fn address_from_public_key_is_deterministic() {
        let kp = Keypair::generate();
        let a1 = Address::from_public_key(&kp.public_key());
        let a2 = Address::from_public_key(&kp.public_key());
        // Same public key → same address, always.
        assert_eq!(a1, a2);
    }

    #[test]
    fn different_pubkeys_produce_different_addresses() {
        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();
        let a1 = Address::from_public_key(&kp1.public_key());
        let a2 = Address::from_public_key(&kp2.public_key());
        assert_ne!(a1, a2);
    }

    #[test]
    fn bech32_roundtrip() {
        let kp = Keypair::generate();
        let a = Address::from_public_key(&kp.public_key());
        let encoded = a.to_bech32();
        // Addresses start with "tfs1" (HRP + bech32 separator).
        assert!(encoded.starts_with("tfs1"));
        let decoded = Address::parse(&encoded).expect("valid address");
        assert_eq!(a, decoded);
    }

    #[test]
    fn parse_rejects_typo() {
        let kp = Keypair::generate();
        let a = Address::from_public_key(&kp.public_key());
        let mut encoded = a.to_bech32();

        // Flip one character in the data portion.
        // bech32 alphabet is "qpzry9x8gf2tvdw0s3jn54khce6mua7l".
        // We flip a 'q' to 'p' (or whatever) to create a typo.
        let last_char = encoded.pop().expect("non-empty address");
        let replacement = if last_char == 'q' { 'p' } else { 'q' };
        encoded.push(replacement);

        // The checksum should catch the typo.
        let result = Address::parse(&encoded);
        assert!(matches!(result, Err(AddressError::InvalidBech32)));
    }

    #[test]
    fn parse_rejects_wrong_prefix() {
        // A valid bech32 string with the wrong HRP ("btc" instead of "tfs").
        // This would be a Bitcoin-style address; our chain must reject it.
        let wrong_hrp = "btc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
        let result = Address::parse(wrong_hrp);
        assert!(matches!(result, Err(_)));
    }

    #[test]
    fn parse_rejects_empty_string() {
        let result = Address::parse("");
        assert!(matches!(result, Err(AddressError::InvalidBech32)));
    }

    #[test]
    fn parse_rejects_mixed_case() {
        // bech32 is specified as single-case. Mixed case (some upper, some
        // lower) is invalid per BIP-173 and must be rejected.
        //
        // NOTE: we must uppercase a LETTER, not a digit. The bech32 alphabet
        // includes digits (0, 2-9), which have no case distinction, so
        // uppercasing a digit leaves it unchanged and the test would become
        // flaky. We find the first letter after the separator and uppercase
        // that, guaranteeing a genuine case change.
        let kp = Keypair::generate();
        let a = Address::from_public_key(&kp.public_key());
        let encoded = a.to_bech32();

        let sep_pos = encoded.find('1').expect("bech32 has separator");
        let target_pos = encoded[sep_pos + 1..]
            .char_indices()
            .find(|(_, c)| c.is_ascii_alphabetic())
            .map(|(i, _)| sep_pos + 1 + i)
            .expect("address must contain at least one letter after the separator");

        let mut chars: Vec<char> = encoded.chars().collect();
        chars[target_pos] = chars[target_pos].to_ascii_uppercase();
        let mangled: String = chars.into_iter().collect();

        // Sanity check: we must have actually changed something.
        assert_ne!(mangled, encoded, "test setup failure: no case change occurred");

        assert!(
            Address::parse(&mangled).is_err(),
            "mixed-case address should be rejected: {mangled}"
        );
    }

    #[test]
    fn display_equals_bech32() {
        let kp = Keypair::generate();
        let a = Address::from_public_key(&kp.public_key());
        assert_eq!(format!("{a}"), a.to_bech32());
    }

    #[test]
    fn address_is_32_bytes() {
        let kp = Keypair::generate();
        let a = Address::from_public_key(&kp.public_key());
        assert_eq!(a.as_bytes().len(), 32);
    }
}
