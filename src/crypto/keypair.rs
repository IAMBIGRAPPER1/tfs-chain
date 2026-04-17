// TFS_CHAIN · crypto/keypair.rs · Layer 1
//
// The sovereignty primitive. ed25519.
//
// Every citizen has a keypair. The private key signs transactions. The public
// key verifies them. This is how the chain knows who did what.
//
// Why ed25519 (not secp256k1):
//   - Constant-time operations BY DEFAULT (timing-attack resistant)
//   - 32-byte public keys, 64-byte signatures (compact)
//   - Faster signing and verification than secp256k1
//   - What Solana, Near, modern sovereign chains use
//   - Deterministic nonce generation (no bad RNG = no leaked keys)
//
// Why ed25519-dalek specifically:
//   - Audited Rust implementation
//   - Built-in zeroize support (private keys wiped on drop)
//   - Strict verification mode (rejects malleable signatures — critical)
//   - Used by Solana, Zcash, Filecoin
//
// SECURITY INVARIANTS:
//   - SecretKey bytes are ZEROED on Drop (zeroize)
//   - Public keys are 32 bytes, signatures are 64 bytes — no other sizes
//   - Verification uses strict mode — rejects non-canonical signatures
//   - Random key generation uses OsRng (OS-provided CSPRNG)

//! Signing keypairs for THE TFS CHAIN.
//!
//! - Generate a new [`Keypair`] with [`Keypair::generate`].
//! - Sign a message with [`Keypair::sign`].
//! - Verify a signature with [`PublicKey::verify`].
//!
//! Private keys are automatically wiped from memory when dropped.

use ed25519_dalek::{
    Signature as DalekSignature, Signer, SigningKey, VerifyingKey, SECRET_KEY_LENGTH,
    SIGNATURE_LENGTH,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fmt;

/// The length of a public key, in bytes. Always 32 for ed25519.
pub const PUBLIC_KEY_LEN: usize = 32;

/// The length of a secret key seed, in bytes. Always 32 for ed25519.
pub const SECRET_KEY_LEN: usize = SECRET_KEY_LENGTH;

/// The length of a signature, in bytes. Always 64 for ed25519.
pub const SIGNATURE_LEN: usize = SIGNATURE_LENGTH;

// ────────────────────────────────────────────────────────────────────
// PUBLIC KEY — safe to share, safe to log, safe to print
// ────────────────────────────────────────────────────────────────────

/// A public key. Safe to share publicly.
///
/// Public keys are used to:
/// - Verify signatures on transactions
/// - Derive the citizen's [`crate::crypto::Address`]
///
/// Every public key has exactly one corresponding private key, held only by
/// the owner of the keypair.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey(VerifyingKey);

impl PublicKey {
    /// Reconstruct a public key from its 32-byte representation.
    ///
    /// # Errors
    /// Returns an error if the bytes do not represent a valid ed25519 point,
    /// OR if they represent a cryptographically **weak** point (the identity
    /// element, or any low-order subgroup element).
    ///
    /// # Why reject weak keys at construction?
    ///
    /// ed25519-dalek accepts low-order points at construction time by default,
    /// deferring the rejection to `verify_strict`. For a sovereign chain, we
    /// want a stronger posture: a weak key can't even be used to derive an
    /// address. This prevents:
    /// - "Nothing-up-my-sleeve" attacks where a malicious party claims
    ///   ownership of an address they cannot actually control.
    /// - Signature-malleability attacks that rely on the identity element.
    /// - Spam addresses that can never produce a valid signature.
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_LEN]) -> Result<Self, VerifyError> {
        let vk = VerifyingKey::from_bytes(bytes).map_err(|_| VerifyError::MalformedPublicKey)?;
        // Reject weak keys at construction — stronger posture than dalek's default.
        if vk.is_weak() {
            return Err(VerifyError::WeakPublicKey);
        }
        Ok(Self(vk))
    }

    /// Return the 32-byte representation of this public key.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.0.to_bytes()
    }

    /// Return the public key as a hex string (64 chars, lowercase).
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Verify a signature over a message against this public key.
    ///
    /// Uses ed25519-dalek's strict verification mode, which rejects
    /// non-canonical signatures (a source of malleability attacks in
    /// permissive implementations).
    ///
    /// # Errors
    /// Returns [`VerifyError::InvalidSignature`] if the signature is not
    /// valid for this message under this public key.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), VerifyError> {
        self.0
            .verify_strict(message, &signature.0)
            .map_err(|_| VerifyError::InvalidSignature)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.to_hex())
    }
}

// Serde: serialize as 32 raw bytes, same on every platform.
impl Serialize for PublicKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct PublicKeyVisitor;
        impl<'de> serde::de::Visitor<'de> for PublicKeyVisitor {
            type Value = PublicKey;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a 32-byte ed25519 public key")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<PublicKey, E> {
                if v.len() != PUBLIC_KEY_LEN {
                    return Err(E::custom(format!(
                        "wrong public key length: expected {PUBLIC_KEY_LEN}, got {}",
                        v.len()
                    )));
                }
                let mut arr = [0u8; PUBLIC_KEY_LEN];
                arr.copy_from_slice(v);
                PublicKey::from_bytes(&arr).map_err(E::custom)
            }
            fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<PublicKey, E> {
                self.visit_bytes(&v)
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<PublicKey, A::Error> {
                let mut arr = [0u8; PUBLIC_KEY_LEN];
                for (i, slot) in arr.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                PublicKey::from_bytes(&arr).map_err(serde::de::Error::custom)
            }
        }
        d.deserialize_bytes(PublicKeyVisitor)
    }
}

// ────────────────────────────────────────────────────────────────────
// SIGNATURE — safe to share, safe to log
// ────────────────────────────────────────────────────────────────────

/// An ed25519 signature. 64 bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature(DalekSignature);

impl Signature {
    /// Reconstruct a signature from its 64-byte representation.
    ///
    /// # Errors
    /// Returns an error if the bytes are not exactly 64 bytes or if they
    /// represent a signature that is structurally malformed.
    pub fn from_bytes(bytes: &[u8; SIGNATURE_LEN]) -> Result<Self, VerifyError> {
        // Signature::from_bytes is infallible for 64 bytes in dalek 2.x,
        // but we keep the Result signature for forward compatibility.
        Ok(Self(DalekSignature::from_bytes(bytes)))
    }

    /// Return the 64-byte representation of this signature.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LEN] {
        self.0.to_bytes()
    }

    /// Return the signature as a hex string (128 chars, lowercase).
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({})", self.to_hex())
    }
}

impl Serialize for Signature {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        // Serialize as bytes. This is the canonical encoding for
        // cryptographic primitives — produces identical bytes across all
        // serde formats (bincode, JSON base64, etc.).
        s.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct SignatureVisitor;
        impl<'de> serde::de::Visitor<'de> for SignatureVisitor {
            type Value = Signature;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a 64-byte ed25519 signature")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Signature, E> {
                if v.len() != SIGNATURE_LEN {
                    return Err(E::custom(format!(
                        "wrong signature length: expected {SIGNATURE_LEN}, got {}",
                        v.len()
                    )));
                }
                let mut arr = [0u8; SIGNATURE_LEN];
                arr.copy_from_slice(v);
                Signature::from_bytes(&arr).map_err(E::custom)
            }
            fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Signature, E> {
                self.visit_bytes(&v)
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Signature, A::Error> {
                // Some formats (bincode with default config) serialize
                // `serialize_bytes` as a length-prefixed sequence rather
                // than a dedicated bytes payload. Handle that path too.
                let mut arr = [0u8; SIGNATURE_LEN];
                for (i, slot) in arr.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Signature::from_bytes(&arr).map_err(serde::de::Error::custom)
            }
        }
        d.deserialize_bytes(SignatureVisitor)
    }
}

// ────────────────────────────────────────────────────────────────────
// KEYPAIR — contains SECRET key material; ZEROIZED on drop
// ────────────────────────────────────────────────────────────────────

/// A signing keypair. Contains both the private signing key and the
/// corresponding public verifying key.
///
/// # SECURITY
///
/// The private key is **zeroized from memory when this struct is dropped**.
/// This means:
/// - Do NOT log a `Keypair` (its Debug impl shows only the public key).
/// - Do NOT clone a `Keypair` casually (each clone is another copy of the
///   private key that must be protected).
/// - Store keypairs in hardware wallets, cold storage, or encrypted at rest.
///
/// Generating a keypair uses the OS-provided CSPRNG (`OsRng`). This is the
/// same source used by Bitcoin Core, OpenSSH, and all sovereign crypto.
///
/// Zeroization is handled by `ed25519_dalek::SigningKey`'s own `Drop` impl
/// (enabled via the `zeroize` feature in Cargo.toml). When a `Keypair` is
/// dropped, Rust drops the inner `SigningKey`, which wipes its secret bytes.
pub struct Keypair {
    /// The ed25519 signing key. Its bytes are wiped on drop via
    /// ed25519-dalek's built-in zeroization.
    signing_key: SigningKey,
}

impl Keypair {
    /// Generate a new random keypair using the OS's cryptographically
    /// secure random number generator.
    #[must_use]
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Reconstruct a keypair from its 32-byte secret seed.
    ///
    /// This is how you restore a keypair from cold storage or a backup phrase.
    ///
    /// # SECURITY
    /// The caller MUST ensure the seed was generated with a CSPRNG and is
    /// protected with the same care as the keypair itself.
    #[must_use]
    pub fn from_secret_bytes(seed: &[u8; SECRET_KEY_LEN]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        Self { signing_key }
    }

    /// Return the 32-byte secret seed.
    ///
    /// # SECURITY
    /// The returned bytes are the private key. Handle with extreme care.
    /// The returned `[u8; 32]` is NOT zeroized — it is the caller's
    /// responsibility to zeroize it after use if appropriate.
    #[must_use]
    pub fn secret_bytes(&self) -> [u8; SECRET_KEY_LEN] {
        self.signing_key.to_bytes()
    }

    /// Return the public key for this keypair.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.signing_key.verifying_key())
    }

    /// Sign a message with this keypair's private key.
    ///
    /// ed25519 is deterministic — signing the same message with the same
    /// keypair always produces the same signature. No randomness is needed
    /// (and none is used). This eliminates an entire class of RNG-related
    /// key-leakage bugs that plague ECDSA implementations.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Signature {
        Signature(self.signing_key.sign(message))
    }
}

impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // NEVER log the private key. Show only the public key for identification.
        write!(f, "Keypair(public: {})", self.public_key().to_hex())
    }
}

// ────────────────────────────────────────────────────────────────────
// ERRORS
// ────────────────────────────────────────────────────────────────────

/// Errors that can occur during signature verification or public key parsing.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifyError {
    /// The signature is not valid for the given message and public key.
    ///
    /// This is the most common error. Either the signature was forged, the
    /// message was tampered with, or the signer used a different key.
    #[error("signature verification failed")]
    InvalidSignature,

    /// The bytes do not represent a valid ed25519 public key encoding.
    ///
    /// The encoding is wrong: not a valid curve point, not canonical, or
    /// wrong length. Distinct from [`VerifyError::WeakPublicKey`], which
    /// rejects structurally-valid-but-cryptographically-useless points.
    #[error("malformed public key")]
    MalformedPublicKey,

    /// The public key is structurally valid but cryptographically weak.
    ///
    /// It represents a low-order curve point (the identity element or
    /// points of small subgroup order). Such keys cannot produce valid
    /// signatures and are rejected here to prevent dead-end addresses and
    /// signature-malleability attacks.
    #[error("weak public key (low-order point rejected)")]
    WeakPublicKey,
}

// ────────────────────────────────────────────────────────────────────
// TESTS
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_unique_keypairs() {
        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();
        // Different calls produce different keys (probability of collision
        // is effectively zero for a CSPRNG).
        assert_ne!(kp1.public_key(), kp2.public_key());
    }

    #[test]
    fn sign_and_verify_succeeds() {
        let kp = Keypair::generate();
        let msg = b"THE CHAIN REMEMBERS";
        let sig = kp.sign(msg);
        assert!(kp.public_key().verify(msg, &sig).is_ok());
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let kp = Keypair::generate();
        let sig = kp.sign(b"MINES.");
        // Changing even one byte invalidates the signature.
        let result = kp.public_key().verify(b"MINES!", &sig);
        assert_eq!(result, Err(VerifyError::InvalidSignature));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();
        let msg = b"sovereign";
        let sig = kp1.sign(msg);
        // Different keypair cannot verify kp1's signature.
        let result = kp2.public_key().verify(msg, &sig);
        assert_eq!(result, Err(VerifyError::InvalidSignature));
    }

    #[test]
    fn signing_is_deterministic() {
        // ed25519 signatures are deterministic — same message + key → same sig.
        let kp = Keypair::generate();
        let sig1 = kp.sign(b"PRESIDENT MINES.");
        let sig2 = kp.sign(b"PRESIDENT MINES.");
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn roundtrip_secret_bytes() {
        let kp1 = Keypair::generate();
        let seed = kp1.secret_bytes();
        let kp2 = Keypair::from_secret_bytes(&seed);
        // Restoring from the seed yields the same public key.
        assert_eq!(kp1.public_key(), kp2.public_key());
        // And the same signatures.
        let msg = b"ALL RIGHTS MINES.";
        assert_eq!(kp1.sign(msg), kp2.sign(msg));
    }

    #[test]
    fn public_key_roundtrips_bytes() {
        let kp = Keypair::generate();
        let pk = kp.public_key();
        let bytes = pk.to_bytes();
        let pk2 = PublicKey::from_bytes(&bytes).expect("valid key");
        assert_eq!(pk, pk2);
    }

    #[test]
    fn public_key_rejects_weak_point() {
        // The all-zero public key is the identity element (a low-order point)
        // and must be rejected at construction time. This is a stronger
        // posture than ed25519-dalek's default, which accepts it at
        // construction and only rejects during verify_strict.
        let zero = [0u8; PUBLIC_KEY_LEN];
        let result = PublicKey::from_bytes(&zero);
        assert_eq!(result, Err(VerifyError::WeakPublicKey));
    }

    #[test]
    fn signature_roundtrips_bytes() {
        let kp = Keypair::generate();
        let sig = kp.sign(b"inscribed");
        let bytes = sig.to_bytes();
        let sig2 = Signature::from_bytes(&bytes).expect("valid sig");
        assert_eq!(sig, sig2);
    }

    #[test]
    fn debug_impl_hides_private_key() {
        let kp = Keypair::generate();
        let debug_str = format!("{kp:?}");
        // The debug output must NOT contain the secret key bytes.
        let secret_hex = hex::encode(kp.secret_bytes());
        assert!(
            !debug_str.contains(&secret_hex),
            "Keypair Debug impl leaked the secret key!"
        );
        // But it should contain the public key for identification.
        let public_hex = kp.public_key().to_hex();
        assert!(debug_str.contains(&public_hex));
    }
}
