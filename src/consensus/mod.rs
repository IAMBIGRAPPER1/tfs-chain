// TFS_CHAIN · consensus/mod.rs · Layer 5
//
// THE SOVEREIGN BFT CONSENSUS.
//
// TFS_CHAIN uses PROOF-OF-AUTHORITY + BYZANTINE FAULT TOLERANCE.
// Validators are authorized citizens of the sovereign layer. Each block
// is finalized in a single round when ⅔+1 of authorized validators sign.
//
// This file defines the primitives:
//
//   ┌─ ValidatorSet ───────────────────────────────────────┐
//   │ · ordered, deduplicated set of validator public keys │
//   │ · quorum threshold = floor(2N/3) + 1                 │
//   │ · authorizes proposers + counts votes                │
//   └──────────────────────────────────────────────────────┘
//
//   ┌─ Vote ───────────────────────────────────────────────┐
//   │ · signature over (height, block_hash) by a validator │
//   │ · single-purpose: "I commit to this block at this    │
//   │   height." Both fields included so a vote for the    │
//   │   wrong height at the wrong hash is a distinct       │
//   │   signable object.                                   │
//   └──────────────────────────────────────────────────────┘
//
//   ┌─ QuorumCertificate ──────────────────────────────────┐
//   │ · ≥ quorum_threshold votes on the same (height,      │
//   │   block_hash), all from distinct authorized          │
//   │   validators.                                        │
//   │ · irrefutable proof of finalization.                 │
//   └──────────────────────────────────────────────────────┘
//
//   ┌─ CommittedBlock ─────────────────────────────────────┐
//   │ · Block + its QuorumCertificate                      │
//   │ · chain only stores CommittedBlocks — raw Blocks     │
//   │   are proposals, not history.                        │
//   └──────────────────────────────────────────────────────┘
//
// THREAT MODEL:
//   - Unauthorized proposer            → ValidatorSet::is_authorized
//   - Unauthorized voter               → rejected at QC construction
//   - Quorum forgery (reused sig)      → distinct-signer check
//   - Vote for wrong block             → signed (height, block_hash) pair
//   - Signature replay across heights  → height in signed payload
//   - Byzantine subset ≤ ⅓             → tolerated by BFT math
//   - Validator set mutation mid-quorum→ QC validates against the set that
//                                          was authoritative at its height
//   - Empty validator set              → construction rejects zero
//   - Duplicate validator keys         → BTreeSet dedup at construction

//! Sovereign BFT consensus primitives.
//!
//! The building blocks of THE TFS CHAIN's finalization layer:
//!
//! - [`ValidatorSet`] — the authorized validator roster.
//! - [`Vote`] — one validator's commitment to a specific block at a height.
//! - [`QuorumCertificate`] — `≥ ⅔+1` distinct votes on the same block.
//! - [`CommittedBlock`] — a block paired with its QC; irreversible history.

pub mod bft;

pub use bft::{ConsensusEngine, ConsensusError};

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::block::{Block, BlockError};
use crate::crypto::{
    hash::{hash_serialized, Hash, HashError},
    keypair::{Keypair, PublicKey, Signature, VerifyError},
};

// ═══════════════════════════════════════════════════════════════════
// VALIDATOR SET
// ═══════════════════════════════════════════════════════════════════

/// The authorized validator roster.
///
/// Validators in THIS struct are permitted to propose and vote on blocks.
/// Internally stored as `BTreeSet<PublicKey>` for deterministic iteration
/// and automatic deduplication. Serialization is likewise deterministic.
///
/// **Mutation discipline:** a validator set is associated with a specific
/// height range. Changing the set is a governance act that should be
/// inscribed on-chain (future work). For now the set is fixed at genesis.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSet {
    validators: BTreeSet<PublicKey>,
}

impl ValidatorSet {
    /// Construct a validator set from a list of public keys.
    ///
    /// Duplicates are silently collapsed. Empty sets are rejected.
    ///
    /// # Errors
    /// Returns [`ConsensusError::EmptyValidatorSet`] if `keys` is empty
    /// (or contains only duplicates).
    pub fn new(keys: impl IntoIterator<Item = PublicKey>) -> Result<Self, ConsensusError> {
        let validators: BTreeSet<PublicKey> = keys.into_iter().collect();
        if validators.is_empty() {
            return Err(ConsensusError::EmptyValidatorSet);
        }
        Ok(Self { validators })
    }

    /// Total number of validators.
    #[must_use]
    pub fn len(&self) -> usize {
        self.validators.len()
    }

    /// True if the set has no validators (should be impossible after construction).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    /// The BFT quorum threshold: `floor(2 * N / 3) + 1`.
    ///
    /// This is the minimum number of distinct signatures on a block before
    /// it is considered finalized. Tolerates up to `floor((N-1) / 3)`
    /// Byzantine validators.
    ///
    /// Examples:
    /// - N=1: quorum=1
    /// - N=3: quorum=3 (tolerates 0 faults)
    /// - N=4: quorum=3 (tolerates 1 fault)
    /// - N=7: quorum=5 (tolerates 2 faults)
    /// - N=100: quorum=67 (tolerates 33 faults)
    #[must_use]
    pub fn quorum_threshold(&self) -> usize {
        let n = self.validators.len();
        // We verified `n > 0` at construction, and u64 math is exact here.
        (2 * n) / 3 + 1
    }

    /// True if the given public key is an authorized validator.
    #[must_use]
    pub fn is_authorized(&self, pk: &PublicKey) -> bool {
        self.validators.contains(pk)
    }

    /// Iterate over validators in deterministic (sorted) order.
    pub fn iter(&self) -> impl Iterator<Item = &PublicKey> {
        self.validators.iter()
    }

    /// Compute the canonical hash of this validator set.
    ///
    /// Used by headers/checkpoints to commit to which set was authoritative
    /// at a given height.
    ///
    /// # Errors
    /// Returns [`HashError`] if serialization fails.
    pub fn set_hash(&self) -> Result<Hash, HashError> {
        hash_serialized(self)
    }
}

// ═══════════════════════════════════════════════════════════════════
// VOTE
// ═══════════════════════════════════════════════════════════════════

/// The canonical bytes a validator signs when voting on a block.
///
/// Domain-separated: `b"tfs_vote_v1"` + height + block_hash. Domain
/// separation prevents a block hash signature from being replayed as a
/// vote for a different purpose (or vice versa).
fn vote_signing_payload(height: u64, block_hash: &Hash) -> Vec<u8> {
    const DOMAIN: &[u8] = b"tfs_vote_v1";
    let mut buf = Vec::with_capacity(DOMAIN.len() + 8 + 32);
    buf.extend_from_slice(DOMAIN);
    buf.extend_from_slice(&height.to_be_bytes());
    buf.extend_from_slice(block_hash.as_bytes());
    buf
}

/// A single validator's commitment to a specific block at a specific height.
///
/// A vote is ONE signature. Collecting [`ValidatorSet::quorum_threshold`]
/// distinct votes on the same `(height, block_hash)` yields a
/// [`QuorumCertificate`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vote {
    /// Height of the block being voted on.
    pub height: u64,

    /// Hash of the block being voted on.
    pub block_hash: Hash,

    /// Validator's public key.
    pub validator: PublicKey,

    /// Signature over `vote_signing_payload(height, block_hash)`.
    pub signature: Signature,
}

impl Vote {
    /// Sign a vote for `(height, block_hash)` with the given validator keypair.
    #[must_use]
    pub fn sign(height: u64, block_hash: Hash, kp: &Keypair) -> Self {
        let payload = vote_signing_payload(height, &block_hash);
        let signature = kp.sign(&payload);
        Self {
            height,
            block_hash,
            validator: kp.public_key(),
            signature,
        }
    }

    /// Verify the signature matches `(height, block_hash)` under the given
    /// validator key.
    ///
    /// # Errors
    /// Returns [`VerifyError`] if the signature doesn't verify.
    pub fn verify(&self) -> Result<(), VerifyError> {
        let payload = vote_signing_payload(self.height, &self.block_hash);
        self.validator.verify(&payload, &self.signature)
    }
}

// ═══════════════════════════════════════════════════════════════════
// QUORUM CERTIFICATE
// ═══════════════════════════════════════════════════════════════════

/// Proof that a super-majority of validators have committed to a block.
///
/// A QC is the atomic unit of finalization on THE TFS CHAIN. Once a block
/// has a valid QC, it is committed forever. The QC can be verified
/// independently by anyone with the block hash and the validator set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumCertificate {
    /// Height of the finalized block.
    pub height: u64,

    /// Hash of the finalized block.
    pub block_hash: Hash,

    /// Signatures from distinct authorized validators.
    /// Must contain ≥ [`ValidatorSet::quorum_threshold`] entries.
    pub votes: Vec<Vote>,
}

impl QuorumCertificate {
    /// Build a QC from collected votes.
    ///
    /// All votes must agree on `(height, block_hash)` and be from distinct
    /// validators in the given set. This does NOT check count against the
    /// set's quorum threshold — that is done in [`Self::verify`].
    ///
    /// # Errors
    /// Returns [`ConsensusError`] if:
    /// - Any vote disagrees on height or block hash.
    /// - Any vote's validator is not in `set`.
    /// - Two votes share a validator.
    /// - Any signature fails to verify.
    pub fn new(
        height: u64,
        block_hash: Hash,
        votes: Vec<Vote>,
        set: &ValidatorSet,
    ) -> Result<Self, ConsensusError> {
        let mut seen: BTreeSet<PublicKey> = BTreeSet::new();
        for v in &votes {
            if v.height != height {
                return Err(ConsensusError::VoteHeightMismatch {
                    expected: height,
                    actual: v.height,
                });
            }
            if v.block_hash != block_hash {
                return Err(ConsensusError::VoteBlockMismatch);
            }
            if !set.is_authorized(&v.validator) {
                return Err(ConsensusError::UnauthorizedValidator);
            }
            if !seen.insert(v.validator.clone()) {
                return Err(ConsensusError::DuplicateVoter);
            }
            v.verify().map_err(ConsensusError::Signature)?;
        }
        Ok(Self {
            height,
            block_hash,
            votes,
        })
    }

    /// Verify this QC against a validator set.
    ///
    /// Re-checks every vote's signature, distinct-voter property, authorized-
    /// voter property, and that the number of votes meets
    /// [`ValidatorSet::quorum_threshold`].
    ///
    /// # Errors
    /// Returns [`ConsensusError`] describing the first failed check.
    pub fn verify(&self, set: &ValidatorSet) -> Result<(), ConsensusError> {
        let threshold = set.quorum_threshold();
        if self.votes.len() < threshold {
            return Err(ConsensusError::InsufficientQuorum {
                provided: self.votes.len(),
                required: threshold,
            });
        }

        let mut seen: BTreeSet<PublicKey> = BTreeSet::new();
        for v in &self.votes {
            if v.height != self.height {
                return Err(ConsensusError::VoteHeightMismatch {
                    expected: self.height,
                    actual: v.height,
                });
            }
            if v.block_hash != self.block_hash {
                return Err(ConsensusError::VoteBlockMismatch);
            }
            if !set.is_authorized(&v.validator) {
                return Err(ConsensusError::UnauthorizedValidator);
            }
            if !seen.insert(v.validator.clone()) {
                return Err(ConsensusError::DuplicateVoter);
            }
            v.verify().map_err(ConsensusError::Signature)?;
        }
        Ok(())
    }

    /// Compute the canonical hash of this QC.
    ///
    /// # Errors
    /// Returns [`HashError`] if serialization fails.
    pub fn qc_hash(&self) -> Result<Hash, HashError> {
        hash_serialized(self)
    }
}

// ═══════════════════════════════════════════════════════════════════
// COMMITTED BLOCK
// ═══════════════════════════════════════════════════════════════════

/// A finalized block on THE TFS CHAIN.
///
/// `block` is the proposal, `qc` is the super-majority commitment. The
/// chain stores a sequence of these; they are the permanent record.
///
/// Invariant: `qc.height == block.header.height` and `qc.block_hash ==
/// block.hash()`. Use [`Self::new`] to enforce this at construction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommittedBlock {
    /// The block itself.
    pub block: Block,

    /// Super-majority proof.
    pub qc: QuorumCertificate,
}

impl CommittedBlock {
    /// Construct a [`CommittedBlock`] enforcing the `qc ↔ block` invariant.
    ///
    /// This also runs [`QuorumCertificate::verify`] against `set` to confirm
    /// the QC is valid. Callers who have already verified may use
    /// [`Self::from_parts_unchecked`].
    ///
    /// # Errors
    /// Returns [`ConsensusError`] if:
    /// - QC height doesn't match block height.
    /// - QC block_hash doesn't match computed block hash.
    /// - QC itself fails verification.
    pub fn new(
        block: Block,
        qc: QuorumCertificate,
        set: &ValidatorSet,
    ) -> Result<Self, ConsensusError> {
        let block_hash = block.hash().map_err(ConsensusError::Block)?;
        if qc.height != block.header.height {
            return Err(ConsensusError::QcHeightMismatch {
                qc_height: qc.height,
                block_height: block.header.height,
            });
        }
        if qc.block_hash != block_hash {
            return Err(ConsensusError::QcBlockMismatch);
        }
        qc.verify(set)?;
        Ok(Self { block, qc })
    }

    /// Construct without any verification. For trusted pipelines only
    /// (e.g., reading from verified persistent storage).
    #[must_use]
    pub const fn from_parts_unchecked(block: Block, qc: QuorumCertificate) -> Self {
        Self { block, qc }
    }

    /// Return the block's hash.
    ///
    /// # Errors
    /// Returns [`BlockError`] if serialization fails.
    pub fn block_hash(&self) -> Result<Hash, BlockError> {
        self.block.hash()
    }
}

// ═══════════════════════════════════════════════════════════════════
// DIAGNOSTIC: per-height vote tally (internal use)
// ═══════════════════════════════════════════════════════════════════

/// An in-memory tally of votes grouped by `(height, block_hash)`.
///
/// Used by [`ConsensusEngine`] (in [`bft`]) to aggregate incoming votes
/// and decide when a quorum has been reached. Exposed in `mod.rs` so
/// tests and the engine can share the same structure.
#[derive(Debug, Default, Clone)]
pub(crate) struct VoteTally {
    /// (height, block_hash) → validator → Vote
    by_proposal: BTreeMap<(u64, Hash), BTreeMap<PublicKey, Vote>>,
}

impl VoteTally {
    pub(crate) const fn new() -> Self {
        Self {
            by_proposal: BTreeMap::new(),
        }
    }

    /// Insert a vote. Returns true if the vote was new, false if a prior
    /// vote from the same validator on the same proposal already existed.
    pub(crate) fn record(&mut self, vote: Vote) -> bool {
        let key = (vote.height, vote.block_hash);
        let bucket = self.by_proposal.entry(key).or_default();
        if bucket.contains_key(&vote.validator) {
            return false;
        }
        bucket.insert(vote.validator.clone(), vote);
        true
    }

    /// Return the votes for a specific proposal in deterministic order.
    pub(crate) fn votes_for(&self, height: u64, block_hash: &Hash) -> Vec<Vote> {
        self.by_proposal
            .get(&(height, *block_hash))
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Number of distinct voters for a proposal.
    pub(crate) fn count_for(&self, height: u64, block_hash: &Hash) -> usize {
        self.by_proposal
            .get(&(height, *block_hash))
            .map_or(0, BTreeMap::len)
    }

    /// Drop all votes at or below `height` (called on finalization).
    pub(crate) fn prune_through(&mut self, height: u64) {
        self.by_proposal.retain(|&(h, _), _| h > height);
    }
}

// ═══════════════════════════════════════════════════════════════════
// TESTS — primitives only; engine tests live in bft.rs
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn kp() -> Keypair {
        Keypair::generate()
    }

    // ─── ValidatorSet ────────────────────────────────────────────────

    #[test]
    fn validator_set_rejects_empty() {
        let err = ValidatorSet::new([]).expect_err("empty");
        assert!(matches!(err, ConsensusError::EmptyValidatorSet));
    }

    #[test]
    fn validator_set_dedups() {
        let k = kp();
        let set = ValidatorSet::new([k.public_key(), k.public_key()]).expect("set");
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn quorum_threshold_bft_math() {
        let cases = [
            (1_usize, 1_usize),
            (2, 2),
            (3, 3),
            (4, 3),
            (5, 4),
            (6, 5),
            (7, 5),
            (10, 7),
            (100, 67),
        ];
        for (n, expected) in cases {
            let kps: Vec<Keypair> = (0..n).map(|_| kp()).collect();
            let set =
                ValidatorSet::new(kps.iter().map(Keypair::public_key)).expect("set");
            assert_eq!(
                set.quorum_threshold(),
                expected,
                "quorum for N={n} should be {expected}",
            );
        }
    }

    #[test]
    fn validator_set_hash_is_order_independent() {
        let a = kp();
        let b = kp();
        let c = kp();
        let s1 = ValidatorSet::new([a.public_key(), b.public_key(), c.public_key()]).unwrap();
        let s2 = ValidatorSet::new([c.public_key(), a.public_key(), b.public_key()]).unwrap();
        assert_eq!(s1.set_hash().unwrap(), s2.set_hash().unwrap());
    }

    // ─── Vote ────────────────────────────────────────────────────────

    #[test]
    fn vote_signs_and_verifies() {
        let v = kp();
        let bh = Hash::from_bytes([7u8; 32]);
        let vote = Vote::sign(42, bh, &v);
        vote.verify().expect("vote verifies");
    }

    #[test]
    fn vote_for_wrong_hash_fails() {
        let v = kp();
        let bh = Hash::from_bytes([7u8; 32]);
        let mut vote = Vote::sign(42, bh, &v);
        // Tamper with the vote's block_hash. The signature is over the ORIGINAL.
        vote.block_hash = Hash::from_bytes([0u8; 32]);
        assert!(vote.verify().is_err());
    }

    #[test]
    fn vote_for_wrong_height_fails() {
        let v = kp();
        let bh = Hash::from_bytes([7u8; 32]);
        let mut vote = Vote::sign(42, bh, &v);
        vote.height = 43;
        assert!(vote.verify().is_err());
    }

    // ─── QuorumCertificate ───────────────────────────────────────────

    fn make_set(n: usize) -> (Vec<Keypair>, ValidatorSet) {
        let kps: Vec<Keypair> = (0..n).map(|_| kp()).collect();
        let set = ValidatorSet::new(kps.iter().map(Keypair::public_key)).expect("set");
        (kps, set)
    }

    #[test]
    fn qc_construction_validates_all_votes() {
        let (kps, set) = make_set(4);
        let height = 5;
        let bh = Hash::from_bytes([9u8; 32]);
        let votes: Vec<Vote> = kps.iter().take(3).map(|k| Vote::sign(height, bh, k)).collect();
        let qc = QuorumCertificate::new(height, bh, votes, &set).expect("qc");
        qc.verify(&set).expect("verify");
    }

    #[test]
    fn qc_rejects_insufficient_quorum() {
        let (kps, set) = make_set(4); // threshold = 3
        let height = 5;
        let bh = Hash::from_bytes([9u8; 32]);
        let votes: Vec<Vote> = kps.iter().take(2).map(|k| Vote::sign(height, bh, k)).collect();
        // Construction succeeds — verify is where quorum is enforced.
        let qc = QuorumCertificate::new(height, bh, votes, &set).expect("ok");
        let err = qc.verify(&set).expect_err("insufficient");
        assert!(matches!(err, ConsensusError::InsufficientQuorum { .. }));
    }

    #[test]
    fn qc_rejects_unauthorized_validator() {
        let (kps, set) = make_set(4);
        let imposter = kp();
        let height = 5;
        let bh = Hash::from_bytes([9u8; 32]);
        let mut votes: Vec<Vote> = kps.iter().take(2).map(|k| Vote::sign(height, bh, k)).collect();
        votes.push(Vote::sign(height, bh, &imposter));
        let err = QuorumCertificate::new(height, bh, votes, &set).expect_err("imposter");
        assert!(matches!(err, ConsensusError::UnauthorizedValidator));
    }

    #[test]
    fn qc_rejects_duplicate_voter() {
        let (kps, set) = make_set(4);
        let height = 5;
        let bh = Hash::from_bytes([9u8; 32]);
        let votes = vec![
            Vote::sign(height, bh, &kps[0]),
            Vote::sign(height, bh, &kps[0]), // duplicate
            Vote::sign(height, bh, &kps[1]),
        ];
        let err = QuorumCertificate::new(height, bh, votes, &set).expect_err("dup");
        assert!(matches!(err, ConsensusError::DuplicateVoter));
    }

    #[test]
    fn qc_rejects_vote_for_different_block() {
        let (kps, set) = make_set(4);
        let height = 5;
        let bh1 = Hash::from_bytes([1u8; 32]);
        let bh2 = Hash::from_bytes([2u8; 32]);
        let votes = vec![
            Vote::sign(height, bh1, &kps[0]),
            Vote::sign(height, bh2, &kps[1]), // wrong hash
            Vote::sign(height, bh1, &kps[2]),
        ];
        let err = QuorumCertificate::new(height, bh1, votes, &set).expect_err("mismatch");
        assert!(matches!(err, ConsensusError::VoteBlockMismatch));
    }

    #[test]
    fn qc_rejects_vote_for_different_height() {
        let (kps, set) = make_set(4);
        let bh = Hash::from_bytes([1u8; 32]);
        let votes = vec![
            Vote::sign(5, bh, &kps[0]),
            Vote::sign(6, bh, &kps[1]), // different height
            Vote::sign(5, bh, &kps[2]),
        ];
        let err = QuorumCertificate::new(5, bh, votes, &set).expect_err("mismatch");
        assert!(matches!(err, ConsensusError::VoteHeightMismatch { .. }));
    }

    // ─── VoteTally (internal) ────────────────────────────────────────

    #[test]
    fn tally_records_and_counts() {
        let mut t = VoteTally::new();
        let k = kp();
        let bh = Hash::from_bytes([3u8; 32]);
        assert!(t.record(Vote::sign(1, bh, &k)));
        assert!(!t.record(Vote::sign(1, bh, &k))); // duplicate
        assert_eq!(t.count_for(1, &bh), 1);
    }

    #[test]
    fn tally_prune_removes_old() {
        let mut t = VoteTally::new();
        let k = kp();
        let bh = Hash::from_bytes([3u8; 32]);
        t.record(Vote::sign(1, bh, &k));
        t.record(Vote::sign(2, bh, &k));
        t.prune_through(1);
        assert_eq!(t.count_for(1, &bh), 0);
        assert_eq!(t.count_for(2, &bh), 1);
    }
}
