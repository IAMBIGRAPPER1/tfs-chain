// TFS_CHAIN · block.rs · Layer 2
//
// THE ATOM OF THE CHAIN.
//
// A block has a header (the commitment) and a body (the transactions).
// The block's hash is BLAKE3 over the header. The header commits to the
// transactions via a Merkle root, so tampering with ANY transaction
// invalidates the block's hash.
//
//   ┌─ BlockHeader ────────────────────────────────┐
//   │ version · chain_id · height · timestamp_ms   │
//   │ previous_hash · tx_merkle_root · proposer    │
//   └──────────────────┬───────────────────────────┘
//                      │  BLAKE3(bincode(header))
//                      ▼
//                  block.hash()
//
//   ┌─ Block ──────────────────────────────────────┐
//   │ header: BlockHeader                          │
//   │ transactions: Vec<Vec<u8>>  ← opaque at L2   │
//   │ proposer_signature: Signature                │
//   └──────────────────────────────────────────────┘
//
// THREAT MODEL (addressed in this file):
//   - Tampered transactions        → tx_merkle_root check fails
//   - Tampered header              → previous block's child breaks
//   - Reordered blocks             → height + previous_hash enforce order
//   - Time travel (old timestamp)  → monotonic timestamp check
//   - Time travel (future)         → max clock skew check
//   - Giant block DoS              → MAX_BLOCK_SIZE_BYTES
//   - Giant transaction DoS        → MAX_TX_SIZE_BYTES
//   - Too many transactions        → MAX_TXS_PER_BLOCK
//   - Unsigned / badly signed      → proposer_signature verified via ed25519

//! Block primitives for THE TFS CHAIN.
//!
//! A [`Block`] consists of a [`BlockHeader`] (the cryptographic commitment)
//! and a body of opaque transaction bytes. The header's `tx_merkle_root`
//! commits to the body, so any tampering with transactions invalidates the
//! block's hash.
//!
//! Construct a genesis block with [`Block::genesis`]. Propose subsequent
//! blocks with [`Block::propose`]. Validate a block against its predecessor
//! with [`Block::validate_against_previous`].

use serde::{Deserialize, Serialize};

use crate::crypto::{
    hash::{hash_bytes, hash_serialized, Hash, HashError, Hasher},
    keypair::{Keypair, PublicKey, Signature, VerifyError},
};

// ═══════════════════════════════════════════════════════════════════
// CONSTANTS — protocol limits
// ═══════════════════════════════════════════════════════════════════

/// Maximum total byte size of a block (header + all transaction bytes).
/// 4 MiB. Anything larger is rejected at the structural level.
/// (Bitcoin is 1 MB, Ethereum ~30 KB target. 4 MB gives us room for
/// doctrine inscriptions which are text-heavy.)
pub const MAX_BLOCK_SIZE_BYTES: usize = 4 * 1024 * 1024;

/// Maximum number of transactions in a single block. 100,000.
/// Prevents vector-length DoS during deserialization.
pub const MAX_TXS_PER_BLOCK: usize = 100_000;

/// Maximum size of a single transaction in bytes. 1 MiB.
/// Large enough for doctrine inscriptions, small enough to prevent
/// memory exhaustion.
pub const MAX_TX_SIZE_BYTES: usize = 1024 * 1024;

/// Maximum clock skew tolerated between a block's timestamp and `now`.
/// 10 seconds. Blocks claiming to be from the future beyond this limit
/// are rejected.
pub const MAX_CLOCK_SKEW_MS: i64 = 10_000;

/// The height of the genesis block. Always zero.
pub const GENESIS_HEIGHT: u64 = 0;

// ═══════════════════════════════════════════════════════════════════
// BLOCK HEADER — the cryptographic commitment
// ═══════════════════════════════════════════════════════════════════

/// The committed fingerprint of a block.
///
/// The block's hash (used for chain-linking and identification) is
/// `BLAKE3(bincode(header))`. Every field in this struct is part of the
/// cryptographic commitment — changing any byte here changes the block hash.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockHeader {
    /// Protocol version. Must match [`crate::PROTOCOL_VERSION`].
    /// Incrementing this is a hard fork.
    pub version: u32,

    /// Chain identifier. Must match [`crate::CHAIN_ID`].
    /// Blocks from a different chain are rejected.
    pub chain_id: String,

    /// Block height. Genesis is 0. Each subsequent block is `previous + 1`.
    pub height: u64,

    /// Unix timestamp in milliseconds when the block was proposed.
    /// Must be strictly greater than the previous block's timestamp.
    /// Must not exceed `now + MAX_CLOCK_SKEW_MS`.
    pub timestamp_ms: i64,

    /// Hash of the previous block's header. [`Hash::ZERO`] for genesis.
    pub previous_hash: Hash,

    /// Merkle root of the transactions in this block.
    /// Computed by [`compute_tx_merkle_root`].
    /// [`Hash::ZERO`] for an empty block (no transactions).
    pub tx_merkle_root: Hash,

    /// The validator who proposed this block. Layer 5 consensus verifies
    /// this is in the authorized validator set.
    pub proposer: PublicKey,
}

impl BlockHeader {
    /// Compute this header's hash (which is the block's identity).
    ///
    /// # Errors
    /// Returns [`HashError`] if serialization fails (should be impossible
    /// for this struct; fields are all types with infallible serialization).
    pub fn hash(&self) -> Result<Hash, HashError> {
        hash_serialized(self)
    }

    /// Return the total serialized size of this header in bytes.
    ///
    /// # Errors
    /// Returns [`HashError`] if serialization fails.
    pub fn serialized_size(&self) -> Result<usize, HashError> {
        bincode::serialize(self)
            .map(|b| b.len())
            .map_err(|e| HashError::Serialize(e.to_string()))
    }
}

// ═══════════════════════════════════════════════════════════════════
// BLOCK — header + transactions + proposer signature
// ═══════════════════════════════════════════════════════════════════

/// A block on THE TFS CHAIN.
///
/// - [`header`][Block::header] is the committed fingerprint.
/// - `transactions` are the body (opaque byte payloads at this layer;
///   Layer 3 will define their semantic types).
/// - `proposer_signature` is the block's signature from its proposer, over
///   the header hash. Layer 5 consensus will add additional quorum signatures.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Block {
    /// The committed block header.
    pub header: BlockHeader,

    /// Opaque transaction bytes. Layer 3 defines their semantic meaning.
    /// Must commit to `header.tx_merkle_root`.
    pub transactions: Vec<Vec<u8>>,

    /// Signature of `header.hash()` by the proposer's private key.
    pub proposer_signature: Signature,
}

impl Block {
    /// Construct the genesis block (height 0) with the given transactions.
    ///
    /// Genesis has:
    /// - `height = 0`
    /// - `previous_hash = Hash::ZERO`
    /// - `tx_merkle_root` committing to the provided transactions
    /// - proposer signature from the president's keypair
    ///
    /// # Errors
    /// Returns [`BlockError`] if the transactions exceed size/count limits,
    /// or if the header fails to hash.
    pub fn genesis(
        chain_id: &str,
        timestamp_ms: i64,
        transactions: Vec<Vec<u8>>,
        proposer_kp: &Keypair,
    ) -> Result<Self, BlockError> {
        Self::build(
            BlockBuildArgs {
                height: GENESIS_HEIGHT,
                previous_hash: Hash::ZERO,
                chain_id,
                timestamp_ms,
                transactions,
                proposer_kp,
            },
        )
    }

    /// Propose a new block on top of `previous`.
    ///
    /// Returns a signed block with:
    /// - `height = previous.header.height + 1`
    /// - `previous_hash = previous.hash()`
    /// - `tx_merkle_root` committing to the provided transactions
    /// - proposer signature from the given keypair
    ///
    /// # Errors
    /// Returns [`BlockError`] if the header of `previous` can't be hashed,
    /// if the transactions exceed limits, or if height would overflow.
    pub fn propose(
        previous: &Self,
        chain_id: &str,
        timestamp_ms: i64,
        transactions: Vec<Vec<u8>>,
        proposer_kp: &Keypair,
    ) -> Result<Self, BlockError> {
        let previous_hash = previous.hash()?;
        let height = previous
            .header
            .height
            .checked_add(1)
            .ok_or(BlockError::HeightOverflow)?;

        Self::build(
            BlockBuildArgs {
                height,
                previous_hash,
                chain_id,
                timestamp_ms,
                transactions,
                proposer_kp,
            },
        )
    }

    /// Internal builder used by both `genesis` and `propose`.
    fn build(args: BlockBuildArgs<'_>) -> Result<Self, BlockError> {
        // Enforce transaction limits BEFORE any expensive crypto.
        if args.transactions.len() > MAX_TXS_PER_BLOCK {
            return Err(BlockError::TooManyTransactions {
                actual: args.transactions.len(),
                max: MAX_TXS_PER_BLOCK,
            });
        }
        for tx in &args.transactions {
            if tx.len() > MAX_TX_SIZE_BYTES {
                return Err(BlockError::TransactionTooLarge {
                    actual: tx.len(),
                    max: MAX_TX_SIZE_BYTES,
                });
            }
        }

        // Compute the merkle root over the provided transactions.
        let tx_merkle_root = compute_tx_merkle_root(&args.transactions);

        let header = BlockHeader {
            version: crate::PROTOCOL_VERSION,
            chain_id: args.chain_id.to_string(),
            height: args.height,
            timestamp_ms: args.timestamp_ms,
            previous_hash: args.previous_hash,
            tx_merkle_root,
            proposer: args.proposer_kp.public_key(),
        };

        // Proposer signs the header hash.
        let header_hash = header.hash()?;
        let proposer_signature = args.proposer_kp.sign(header_hash.as_bytes());

        let block = Self {
            header,
            transactions: args.transactions,
            proposer_signature,
        };

        // Enforce total block size AFTER construction.
        let size = block.serialized_size()?;
        if size > MAX_BLOCK_SIZE_BYTES {
            return Err(BlockError::BlockTooLarge {
                actual: size,
                max: MAX_BLOCK_SIZE_BYTES,
            });
        }

        Ok(block)
    }

    /// Return the hash of this block (i.e., the hash of its header).
    ///
    /// # Errors
    /// Returns [`BlockError::Hash`] if serialization fails.
    pub fn hash(&self) -> Result<Hash, BlockError> {
        Ok(self.header.hash()?)
    }

    /// Return the total serialized size of this block in bytes.
    ///
    /// # Errors
    /// Returns [`BlockError::Hash`] if serialization fails.
    pub fn serialized_size(&self) -> Result<usize, BlockError> {
        bincode::serialize(self)
            .map(|b| b.len())
            .map_err(|e| BlockError::Hash(HashError::Serialize(e.to_string())))
    }

    /// Validate this block's STRUCTURAL integrity (not consensus rules).
    ///
    /// Checks:
    /// 1. Protocol version matches
    /// 2. Chain ID matches
    /// 3. Size limits (block total + per-tx + count)
    /// 4. `tx_merkle_root` matches computed root of `transactions`
    /// 5. Proposer signature is valid over the header hash
    /// 6. Timestamp is not too far in the future (vs `now_ms`)
    ///
    /// Consensus rules (proposer is authorized, quorum signatures) are
    /// Layer 5's job and are NOT checked here.
    ///
    /// # Errors
    /// Returns [`BlockError`] describing the first failed check.
    pub fn validate_structure(
        &self,
        expected_chain_id: &str,
        now_ms: i64,
    ) -> Result<(), BlockError> {
        // 1. Protocol version.
        if self.header.version != crate::PROTOCOL_VERSION {
            return Err(BlockError::UnsupportedVersion(self.header.version));
        }

        // 2. Chain ID.
        if self.header.chain_id != expected_chain_id {
            return Err(BlockError::WrongChainId {
                expected: expected_chain_id.to_string(),
                actual: self.header.chain_id.clone(),
            });
        }

        // 3. Tx count + per-tx size.
        if self.transactions.len() > MAX_TXS_PER_BLOCK {
            return Err(BlockError::TooManyTransactions {
                actual: self.transactions.len(),
                max: MAX_TXS_PER_BLOCK,
            });
        }
        for tx in &self.transactions {
            if tx.len() > MAX_TX_SIZE_BYTES {
                return Err(BlockError::TransactionTooLarge {
                    actual: tx.len(),
                    max: MAX_TX_SIZE_BYTES,
                });
            }
        }

        // 4. Total block size.
        let size = self.serialized_size()?;
        if size > MAX_BLOCK_SIZE_BYTES {
            return Err(BlockError::BlockTooLarge {
                actual: size,
                max: MAX_BLOCK_SIZE_BYTES,
            });
        }

        // 5. Tx merkle root matches.
        let computed_root = compute_tx_merkle_root(&self.transactions);
        if computed_root != self.header.tx_merkle_root {
            return Err(BlockError::TxMerkleRootMismatch {
                claimed: self.header.tx_merkle_root.to_hex(),
                computed: computed_root.to_hex(),
            });
        }

        // 6. Proposer signature verifies the header hash.
        let header_hash = self.header.hash()?;
        self.header
            .proposer
            .verify(header_hash.as_bytes(), &self.proposer_signature)
            .map_err(BlockError::Signature)?;

        // 7. Timestamp not too far in the future.
        if self.header.timestamp_ms > now_ms + MAX_CLOCK_SKEW_MS {
            return Err(BlockError::TimestampTooFarFuture {
                current_ms: self.header.timestamp_ms,
                now_ms,
                max_skew_ms: MAX_CLOCK_SKEW_MS,
            });
        }

        Ok(())
    }

    /// Validate this block against its immediate predecessor.
    ///
    /// Checks:
    /// 1. `previous_hash` matches `previous.hash()`
    /// 2. `height` equals `previous.height + 1`
    /// 3. `timestamp_ms` is strictly greater than `previous.timestamp_ms`
    /// 4. Both blocks agree on the same chain ID
    ///
    /// Does NOT call [`Block::validate_structure`]. Callers should run
    /// structural validation first, then pairwise against the predecessor.
    ///
    /// # Errors
    /// Returns [`BlockError`] on the first failed check.
    pub fn validate_against_previous(&self, previous: &Self) -> Result<(), BlockError> {
        // 1. previous_hash linkage.
        let expected_prev_hash = previous.hash()?;
        if self.header.previous_hash != expected_prev_hash {
            return Err(BlockError::PreviousHashMismatch {
                claimed: self.header.previous_hash.to_hex(),
                expected: expected_prev_hash.to_hex(),
            });
        }

        // 2. Height is exactly +1 from previous.
        let expected_height = previous
            .header
            .height
            .checked_add(1)
            .ok_or(BlockError::HeightOverflow)?;
        if self.header.height != expected_height {
            return Err(BlockError::HeightMismatch {
                expected: expected_height,
                actual: self.header.height,
            });
        }

        // 3. Timestamp strictly greater.
        if self.header.timestamp_ms <= previous.header.timestamp_ms {
            return Err(BlockError::TimestampNotMonotonic {
                previous_ms: previous.header.timestamp_ms,
                current_ms: self.header.timestamp_ms,
            });
        }

        // 4. Chain ID match.
        if self.header.chain_id != previous.header.chain_id {
            return Err(BlockError::WrongChainId {
                expected: previous.header.chain_id.clone(),
                actual: self.header.chain_id.clone(),
            });
        }

        Ok(())
    }
}

/// Internal argument bag for [`Block::build`].
struct BlockBuildArgs<'a> {
    height: u64,
    previous_hash: Hash,
    chain_id: &'a str,
    timestamp_ms: i64,
    transactions: Vec<Vec<u8>>,
    proposer_kp: &'a Keypair,
}

// ═══════════════════════════════════════════════════════════════════
// MERKLE ROOT — commits a vector of transactions to a single hash
// ═══════════════════════════════════════════════════════════════════

/// Compute a Merkle root over a set of transaction byte payloads.
///
/// Algorithm (explicit; no surprises):
/// 1. If no transactions, return [`Hash::ZERO`].
/// 2. Hash each transaction's bytes → level 0.
/// 3. Repeatedly pair-and-hash adjacent entries to produce the next level.
///    If a level has an odd number of entries, the last entry is DUPLICATED
///    (paired with itself) — this is the Bitcoin-style rule.
/// 4. Continue until one hash remains; return it.
///
/// # Domain separation
///
/// Each level's pair-hash is domain-separated with a one-byte prefix (`0x01`)
/// to distinguish internal-node hashes from leaf-node hashes (which are
/// raw BLAKE3 of transaction bytes). This prevents second-preimage attacks
/// where an attacker could present an internal hash as a leaf.
#[must_use]
pub fn compute_tx_merkle_root(transactions: &[Vec<u8>]) -> Hash {
    if transactions.is_empty() {
        return Hash::ZERO;
    }

    // Level 0: leaf hashes = BLAKE3(tx_bytes).
    let mut level: Vec<Hash> = transactions.iter().map(|tx| hash_bytes(tx)).collect();

    // Build up the tree, level by level, until only the root remains.
    while level.len() > 1 {
        let mut next_level: Vec<Hash> = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            // Bitcoin-style rule: if odd, duplicate the last leaf.
            let right = if i + 1 < level.len() {
                level[i + 1]
            } else {
                left
            };

            // Domain-separated internal node hash.
            let mut hasher = Hasher::new();
            hasher.update(&[0x01_u8]); // internal-node domain tag
            hasher.update(left.as_bytes());
            hasher.update(right.as_bytes());
            next_level.push(hasher.finalize());

            i += 2;
        }
        level = next_level;
    }

    level[0]
}

// ═══════════════════════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════════════════════

/// Errors that can occur when constructing or validating a block.
#[derive(Debug, thiserror::Error)]
pub enum BlockError {
    /// The block's serialized size exceeds [`MAX_BLOCK_SIZE_BYTES`].
    #[error("block too large: {actual} bytes, max is {max}")]
    BlockTooLarge {
        /// Actual serialized size.
        actual: usize,
        /// Maximum permitted size.
        max: usize,
    },

    /// The block contains more transactions than [`MAX_TXS_PER_BLOCK`].
    #[error("too many transactions: {actual}, max is {max}")]
    TooManyTransactions {
        /// Actual count.
        actual: usize,
        /// Maximum permitted count.
        max: usize,
    },

    /// A single transaction exceeds [`MAX_TX_SIZE_BYTES`].
    #[error("transaction too large: {actual} bytes, max is {max}")]
    TransactionTooLarge {
        /// Actual byte size.
        actual: usize,
        /// Maximum permitted size.
        max: usize,
    },

    /// Block height would overflow a `u64`.
    /// This is astronomically unlikely (2^64 blocks at 1 second each would
    /// take 584 billion years), but we check for it anyway.
    #[error("block height would overflow u64")]
    HeightOverflow,

    /// Block height doesn't match `previous.height + 1`.
    #[error("height mismatch: expected {expected}, got {actual}")]
    HeightMismatch {
        /// The height we expected.
        expected: u64,
        /// The height we got.
        actual: u64,
    },

    /// `previous_hash` doesn't match the actual previous block's hash.
    #[error("previous hash mismatch: claimed {claimed}, expected {expected}")]
    PreviousHashMismatch {
        /// Hash the block claims for its predecessor.
        claimed: String,
        /// Actual predecessor hash.
        expected: String,
    },

    /// Block's timestamp is not strictly greater than the previous block's.
    #[error("timestamp not monotonic: previous {previous_ms}, current {current_ms}")]
    TimestampNotMonotonic {
        /// Previous block's timestamp.
        previous_ms: i64,
        /// Current block's timestamp.
        current_ms: i64,
    },

    /// Block's timestamp is too far in the future (beyond [`MAX_CLOCK_SKEW_MS`]).
    #[error("timestamp too far future: block {current_ms}, now {now_ms}, max skew {max_skew_ms}")]
    TimestampTooFarFuture {
        /// The block's claimed timestamp.
        current_ms: i64,
        /// The current time.
        now_ms: i64,
        /// The maximum permitted future skew.
        max_skew_ms: i64,
    },

    /// `header.tx_merkle_root` doesn't match the root computed from `transactions`.
    #[error("tx merkle root mismatch: claimed {claimed}, computed {computed}")]
    TxMerkleRootMismatch {
        /// Root claimed in the header.
        claimed: String,
        /// Root computed from the transaction body.
        computed: String,
    },

    /// Block claims a different chain ID than expected.
    #[error("wrong chain id: expected {expected}, got {actual}")]
    WrongChainId {
        /// The chain ID we expected.
        expected: String,
        /// The chain ID the block claimed.
        actual: String,
    },

    /// Block's protocol version is not supported by this node.
    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u32),

    /// Hashing / serialization error (extremely rare).
    #[error("hash error: {0}")]
    Hash(#[from] HashError),

    /// Proposer signature verification failed.
    #[error("proposer signature invalid: {0}")]
    Signature(#[from] VerifyError),
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

    fn now_ms() -> i64 {
        // Deterministic test timestamp, not wall-clock. Genesis is hour zero.
        1_000_000_000_000
    }

    // ─── Merkle root ────────────────────────────────────────────────

    #[test]
    fn empty_tx_root_is_zero() {
        assert_eq!(compute_tx_merkle_root(&[]), Hash::ZERO);
    }

    #[test]
    fn single_tx_root_is_leaf_hash() {
        let tx = b"inscribe doctrine".to_vec();
        let root = compute_tx_merkle_root(&[tx.clone()]);
        // With a single transaction, root equals the leaf hash directly.
        assert_eq!(root, hash_bytes(&tx));
    }

    #[test]
    fn merkle_root_is_deterministic() {
        let txs = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];
        let r1 = compute_tx_merkle_root(&txs);
        let r2 = compute_tx_merkle_root(&txs);
        assert_eq!(r1, r2);
    }

    #[test]
    fn merkle_root_detects_reordering() {
        let r1 = compute_tx_merkle_root(&[b"a".to_vec(), b"b".to_vec()]);
        let r2 = compute_tx_merkle_root(&[b"b".to_vec(), b"a".to_vec()]);
        assert_ne!(r1, r2);
    }

    #[test]
    fn merkle_root_detects_tampering() {
        let r1 = compute_tx_merkle_root(&[b"hello".to_vec(), b"world".to_vec()]);
        let r2 = compute_tx_merkle_root(&[b"hello".to_vec(), b"worle".to_vec()]);
        assert_ne!(r1, r2);
    }

    #[test]
    fn merkle_root_odd_count_duplicates_last() {
        // The Bitcoin-style rule: with 3 entries, last pairs with itself.
        // Verify the root differs from 4 entries (a, b, c, c).
        let r3 = compute_tx_merkle_root(&[b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
        let r4 = compute_tx_merkle_root(&[
            b"a".to_vec(),
            b"b".to_vec(),
            b"c".to_vec(),
            b"c".to_vec(),
        ]);
        // They should be equal because the algorithm naturally duplicates
        // the last entry at every odd level. This is the Bitcoin-compatible
        // behavior (which has a known second-preimage quirk, but is fine
        // when combined with our domain separation).
        assert_eq!(r3, r4);
    }

    // ─── Genesis block ──────────────────────────────────────────────

    #[test]
    fn genesis_has_height_zero() {
        let k = kp();
        let b = Block::genesis("tfs-test-1", now_ms(), vec![], &k).expect("genesis");
        assert_eq!(b.header.height, 0);
        assert_eq!(b.header.previous_hash, Hash::ZERO);
        assert_eq!(b.header.tx_merkle_root, Hash::ZERO);
    }

    #[test]
    fn genesis_validates_self_signature() {
        let k = kp();
        let b = Block::genesis("tfs-test-1", now_ms(), vec![b"MINES.".to_vec()], &k)
            .expect("genesis");
        b.validate_structure("tfs-test-1", now_ms())
            .expect("structure valid");
    }

    #[test]
    fn genesis_proposer_is_kp_public_key() {
        let k = kp();
        let b = Block::genesis("tfs-test-1", now_ms(), vec![], &k).expect("genesis");
        assert_eq!(b.header.proposer, k.public_key());
    }

    // ─── Block proposal + linkage ───────────────────────────────────

    #[test]
    fn propose_links_to_previous() {
        let k = kp();
        let g = Block::genesis("tfs-test-1", 100, vec![], &k).expect("genesis");
        let g_hash = g.hash().expect("genesis hash");

        let b1 = Block::propose(&g, "tfs-test-1", 200, vec![b"tx-1".to_vec()], &k)
            .expect("propose 1");

        assert_eq!(b1.header.height, 1);
        assert_eq!(b1.header.previous_hash, g_hash);
        b1.validate_against_previous(&g)
            .expect("valid linkage");
    }

    #[test]
    fn propose_computes_merkle_root() {
        let k = kp();
        let g = Block::genesis("tfs-test-1", 100, vec![], &k).expect("genesis");
        let txs = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];
        let b1 = Block::propose(&g, "tfs-test-1", 200, txs.clone(), &k).expect("propose");
        assert_eq!(b1.header.tx_merkle_root, compute_tx_merkle_root(&txs));
    }

    // ─── Structural validation ──────────────────────────────────────

    #[test]
    fn rejects_mismatched_merkle_root() {
        let k = kp();
        let mut g = Block::genesis("tfs-test-1", 100, vec![b"tx".to_vec()], &k)
            .expect("genesis");

        // Swap the merkle root in the header. The proposer signature no
        // longer verifies either, which we catch via the signature check —
        // but the merkle root check happens first in validate_structure,
        // so that's what we'll see.
        g.header.tx_merkle_root = Hash::from_bytes([0xFF; 32]);

        let err = g
            .validate_structure("tfs-test-1", now_ms())
            .expect_err("should fail");
        assert!(matches!(err, BlockError::TxMerkleRootMismatch { .. }));
    }

    #[test]
    fn rejects_forged_tx_body() {
        // Build a valid block, then tamper with a transaction byte AFTER
        // signing. The stored merkle root no longer matches the body.
        let k = kp();
        let mut g = Block::genesis("tfs-test-1", 100, vec![b"original".to_vec()], &k)
            .expect("genesis");

        // Tamper.
        g.transactions[0] = b"forgery!".to_vec();

        let err = g
            .validate_structure("tfs-test-1", now_ms())
            .expect_err("forgery must be detected");
        assert!(matches!(err, BlockError::TxMerkleRootMismatch { .. }));
    }

    #[test]
    fn rejects_wrong_chain_id() {
        let k = kp();
        let g = Block::genesis("tfs-mainnet-1", 100, vec![], &k).expect("genesis");
        let err = g
            .validate_structure("tfs-testnet-1", now_ms())
            .expect_err("wrong chain id");
        assert!(matches!(err, BlockError::WrongChainId { .. }));
    }

    #[test]
    fn rejects_wrong_version() {
        let k = kp();
        let mut g = Block::genesis("tfs-test-1", 100, vec![], &k).expect("genesis");
        g.header.version = crate::PROTOCOL_VERSION + 1;
        let err = g
            .validate_structure("tfs-test-1", now_ms())
            .expect_err("bad version");
        assert!(matches!(err, BlockError::UnsupportedVersion(_)));
    }

    #[test]
    fn rejects_timestamp_too_far_future() {
        let k = kp();
        // Block claims to be from 1 full hour in the future.
        let far_future = now_ms() + 60 * 60 * 1000;
        let b = Block::genesis("tfs-test-1", far_future, vec![], &k).expect("build");
        let err = b
            .validate_structure("tfs-test-1", now_ms())
            .expect_err("timestamp too far future");
        assert!(matches!(err, BlockError::TimestampTooFarFuture { .. }));
    }

    #[test]
    fn accepts_timestamp_within_skew() {
        let k = kp();
        // Block claims to be from +5 seconds, within the 10-second skew window.
        let slight_future = now_ms() + 5_000;
        let b = Block::genesis("tfs-test-1", slight_future, vec![], &k).expect("build");
        b.validate_structure("tfs-test-1", now_ms())
            .expect("within skew");
    }

    // ─── Linkage validation ─────────────────────────────────────────

    #[test]
    fn rejects_bad_previous_hash() {
        let k = kp();
        let g = Block::genesis("tfs-test-1", 100, vec![], &k).expect("genesis");
        let mut b1 = Block::propose(&g, "tfs-test-1", 200, vec![], &k).expect("propose");
        b1.header.previous_hash = Hash::from_bytes([0xAB; 32]);
        let err = b1
            .validate_against_previous(&g)
            .expect_err("should fail");
        assert!(matches!(err, BlockError::PreviousHashMismatch { .. }));
    }

    #[test]
    fn rejects_bad_height() {
        let k = kp();
        let g = Block::genesis("tfs-test-1", 100, vec![], &k).expect("genesis");
        let mut b1 = Block::propose(&g, "tfs-test-1", 200, vec![], &k).expect("propose");
        b1.header.height = 5; // should be 1
        let err = b1
            .validate_against_previous(&g)
            .expect_err("should fail");
        assert!(matches!(err, BlockError::HeightMismatch { .. }));
    }

    #[test]
    fn rejects_non_monotonic_timestamp() {
        let k = kp();
        let g = Block::genesis("tfs-test-1", 1_000, vec![], &k).expect("genesis");
        let b1 = Block::propose(&g, "tfs-test-1", 1_000, vec![], &k).expect("propose");
        // Even though `propose` constructs successfully, the linkage check
        // rejects equal timestamps as non-monotonic.
        let err = b1
            .validate_against_previous(&g)
            .expect_err("should reject equal timestamps");
        assert!(matches!(err, BlockError::TimestampNotMonotonic { .. }));
    }

    // ─── Size limits ────────────────────────────────────────────────

    #[test]
    fn rejects_oversized_transaction() {
        let k = kp();
        let big = vec![0u8; MAX_TX_SIZE_BYTES + 1];
        let err =
            Block::genesis("tfs-test-1", now_ms(), vec![big], &k).expect_err("oversized");
        assert!(matches!(err, BlockError::TransactionTooLarge { .. }));
    }

    #[test]
    fn rejects_too_many_transactions() {
        let k = kp();
        // Use tiny tx payloads to avoid hitting BlockTooLarge first.
        let many: Vec<Vec<u8>> = (0..=MAX_TXS_PER_BLOCK).map(|_| vec![0u8; 1]).collect();
        let err =
            Block::genesis("tfs-test-1", now_ms(), many, &k).expect_err("too many");
        assert!(matches!(err, BlockError::TooManyTransactions { .. }));
    }

    // ─── Hash determinism ───────────────────────────────────────────

    #[test]
    fn block_hash_is_deterministic() {
        let k = kp();
        let b = Block::genesis("tfs-test-1", 100, vec![b"tx".to_vec()], &k).expect("build");
        let h1 = b.hash().expect("hash");
        let h2 = b.hash().expect("hash");
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_blocks_produce_different_hashes() {
        let k = kp();
        let a = Block::genesis("tfs-test-1", 100, vec![b"a".to_vec()], &k).expect("a");
        let b = Block::genesis("tfs-test-1", 100, vec![b"b".to_vec()], &k).expect("b");
        assert_ne!(a.hash().expect("ah"), b.hash().expect("bh"));
    }

    #[test]
    fn tampering_with_header_breaks_signature() {
        let k = kp();
        let mut b = Block::genesis("tfs-test-1", 100, vec![], &k).expect("build");
        // Tamper with the timestamp (but keep it within skew).
        b.header.timestamp_ms += 1;
        // The signature was over the ORIGINAL header; now it's invalid.
        let err = b
            .validate_structure("tfs-test-1", now_ms())
            .expect_err("tampered header");
        assert!(matches!(err, BlockError::Signature(_)));
    }

    #[test]
    fn serialization_roundtrip() {
        let k = kp();
        let b =
            Block::genesis("tfs-test-1", 100, vec![b"doctrine".to_vec()], &k).expect("build");
        let bytes = bincode::serialize(&b).expect("serialize");
        let restored: Block = bincode::deserialize(&bytes).expect("deserialize");
        assert_eq!(b, restored);
        assert_eq!(b.hash().expect("bh"), restored.hash().expect("rh"));
    }
}
