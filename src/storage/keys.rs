// TFS_CHAIN · storage/keys.rs · Layer 6
//
// KEY ENCODING.
//
// RocksDB sorts keys lexicographically by byte value. To get numeric
// ordering for u64 heights (so "height 10" > "height 9"), we MUST
// encode u64 big-endian. little-endian would put 10 before 9.
//
// This file is the single source of truth for byte layout of keys
// that cross between Rust types and disk. If you add a new key type,
// add its codec HERE.

//! Key encoding helpers for the storage layer.
//!
//! All keys crossing the Rust/disk boundary go through these functions.

use crate::crypto::{address::Address, hash::Hash};

// ═══════════════════════════════════════════════════════════════════
// u64 ↔ BIG-ENDIAN BYTES
// ═══════════════════════════════════════════════════════════════════

/// Encode a `u64` as 8 big-endian bytes.
///
/// Big-endian preserves numeric order under lexicographic byte
/// comparison, which is what RocksDB uses. `u64_to_be(10)` sorts AFTER
/// `u64_to_be(9)`, as expected.
#[must_use]
pub const fn u64_to_be(n: u64) -> [u8; 8] {
    n.to_be_bytes()
}

/// Decode 8 big-endian bytes into a `u64`.
///
/// # Errors
/// Returns [`KeyError::BadU64Length`] if `bytes.len() != 8`.
pub fn u64_from_be(bytes: &[u8]) -> Result<u64, KeyError> {
    let arr: [u8; 8] = bytes
        .try_into()
        .map_err(|_| KeyError::BadU64Length(bytes.len()))?;
    Ok(u64::from_be_bytes(arr))
}

// ═══════════════════════════════════════════════════════════════════
// HASH (32 bytes)
// ═══════════════════════════════════════════════════════════════════

/// Return the 32-byte representation of a [`Hash`] as the key bytes.
#[must_use]
pub fn hash_key(h: &Hash) -> [u8; 32] {
    *h.as_bytes()
}

/// Decode 32 bytes into a [`Hash`].
///
/// # Errors
/// Returns [`KeyError::BadHashLength`] if `bytes.len() != 32`.
pub fn hash_from_key(bytes: &[u8]) -> Result<Hash, KeyError> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| KeyError::BadHashLength(bytes.len()))?;
    Ok(Hash::from_bytes(arr))
}

// ═══════════════════════════════════════════════════════════════════
// ADDRESS (32 bytes, internally a Hash)
// ═══════════════════════════════════════════════════════════════════

/// Return the 32-byte representation of an [`Address`] as the key bytes.
#[must_use]
pub fn address_key(addr: &Address) -> [u8; 32] {
    *addr.as_hash().as_bytes()
}

/// Decode 32 bytes into an [`Address`].
///
/// # Errors
/// Returns [`KeyError::BadAddressLength`] if `bytes.len() != 32`.
pub fn address_from_key(bytes: &[u8]) -> Result<Address, KeyError> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| KeyError::BadAddressLength(bytes.len()))?;
    Ok(Address::from_hash(Hash::from_bytes(arr)))
}

// ═══════════════════════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════════════════════

/// Errors that can occur decoding on-disk key or value bytes.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    /// A u64 value wasn't 8 bytes.
    #[error("bad u64 length: expected 8 bytes, got {0}")]
    BadU64Length(usize),

    /// A hash value wasn't 32 bytes.
    #[error("bad hash length: expected 32 bytes, got {0}")]
    BadHashLength(usize),

    /// An address value wasn't 32 bytes.
    #[error("bad address length: expected 32 bytes, got {0}")]
    BadAddressLength(usize),
}

// ═══════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keypair::Keypair;

    #[test]
    fn u64_encoding_is_big_endian() {
        assert_eq!(u64_to_be(0), [0; 8]);
        assert_eq!(u64_to_be(1), [0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(
            u64_to_be(0x0102_0304_0506_0708),
            [1, 2, 3, 4, 5, 6, 7, 8]
        );
    }

    #[test]
    fn u64_roundtrips() {
        for n in [0u64, 1, 42, 1_000_000, u64::MAX / 2, u64::MAX] {
            let bytes = u64_to_be(n);
            let back = u64_from_be(&bytes).expect("decode");
            assert_eq!(n, back);
        }
    }

    #[test]
    fn u64_decode_rejects_wrong_length() {
        let err = u64_from_be(&[1, 2, 3]).expect_err("short");
        assert!(matches!(err, KeyError::BadU64Length(3)));
    }

    #[test]
    fn u64_lex_order_matches_numeric_order() {
        // The whole point of big-endian.
        let small = u64_to_be(9);
        let big = u64_to_be(10);
        assert!(small < big);
    }

    #[test]
    fn hash_roundtrips() {
        let h = Hash::from_bytes([0x42; 32]);
        let bytes = hash_key(&h);
        let back = hash_from_key(&bytes).expect("decode");
        assert_eq!(h, back);
    }

    #[test]
    fn address_roundtrips() {
        let kp = Keypair::generate();
        let a = Address::from_public_key(&kp.public_key());
        let bytes = address_key(&a);
        let back = address_from_key(&bytes).expect("decode");
        assert_eq!(a, back);
    }
}
