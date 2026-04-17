// TFS_CHAIN · consensus/bft.rs · Layer 5
//
// THE CONSENSUS ENGINE.
//
// This is the live driver that watches incoming votes, forms quorum
// certificates, and emits finalization decisions. It is intentionally a
// pure state machine — no networking, no time, no disk. Callers (Layer 7)
// feed it votes and ask it when a quorum has formed.
//
// Flow, per block height:
//   1. A validator proposes a Block. Its header is signed by the proposer.
//   2. Every authorized validator (INCLUDING the proposer) signs a Vote
//      over (height, block_hash) and broadcasts it.
//   3. The engine collects votes via `record_vote`. Invalid, unauthorized,
//      or stale votes are rejected at admission.
//   4. When a (height, block_hash) accumulates ≥ quorum_threshold votes,
//      `try_form_quorum_certificate` succeeds and a QuorumCertificate is
//      returned.
//   5. The caller feeds the QC + Block into a CommittedBlock, which is
//      then appended to the chain via Layer 5's Chain struct.
//
// Validator equivocation (signing two conflicting proposals at the same
// height) is DETECTED here but not slashed — slashing is governance,
// handled at a higher layer. The engine refuses to count conflicting
// votes but records the evidence.
//
// THREAT MODEL:
//   - Old-height vote replay           → votes pruned after finalization
//   - Vote signature forgery           → Vote::verify on admission
//   - Unauthorized voter               → ValidatorSet::is_authorized
//   - Duplicate vote from same signer  → BTreeSet dedup, conflicting votes rejected
//   - Equivocation (two-block vote)    → detected via conflicting_votes
//   - Denial of service via vote spam  → per-validator dedup + per-height bound
//   - Quorum hijack on wrong block     → QC construction re-verifies

//! The BFT consensus engine.
//!
//! See [`ConsensusEngine`] — a pure-functional vote aggregator that
//! converts a stream of incoming votes into deterministic finalization
//! decisions.

use std::collections::BTreeMap;

use super::{QuorumCertificate, ValidatorSet, Vote, VoteTally};
use crate::block::BlockError;
use crate::crypto::{
    hash::{Hash, HashError},
    keypair::{PublicKey, VerifyError},
};

// ═══════════════════════════════════════════════════════════════════
// ENGINE
// ═══════════════════════════════════════════════════════════════════

/// Pure-state BFT vote aggregator.
///
/// Feed it votes via [`Self::record_vote`]. Call
/// [`Self::try_form_quorum_certificate`] to check whether any proposal
/// at a given height has reached a quorum. Call [`Self::on_finalized`]
/// after a block is committed, to drop stale votes.
///
/// This struct is deterministic — identical sequences of `record_vote`
/// calls produce identical internal state and identical QC outputs on
/// every node, given the same [`ValidatorSet`].
#[derive(Debug, Clone)]
pub struct ConsensusEngine {
    /// Authorized validators.
    validators: ValidatorSet,

    /// Votes grouped by (height, block_hash) → validator → vote.
    tally: VoteTally,

    /// Per-validator, per-height FIRST vote hash we've seen.
    /// Used to detect equivocation (same validator voting on two
    /// different blocks at the same height).
    first_vote_at_height: BTreeMap<(u64, PublicKey), Hash>,

    /// Validators observed equivocating (voted for two different block
    /// hashes at the same height). Recorded for governance to review;
    /// no slashing is performed here.
    equivocators: BTreeMap<u64, Vec<PublicKey>>,

    /// The last height for which a QC has been emitted. Votes at or
    /// below this height are considered stale and are rejected.
    last_finalized_height: Option<u64>,
}

impl ConsensusEngine {
    /// Create an engine with the given validator set. Starts with no votes.
    #[must_use]
    pub fn new(validators: ValidatorSet) -> Self {
        Self {
            validators,
            tally: VoteTally::new(),
            first_vote_at_height: BTreeMap::new(),
            equivocators: BTreeMap::new(),
            last_finalized_height: None,
        }
    }

    /// Return the validator set this engine is operating over.
    #[must_use]
    pub const fn validators(&self) -> &ValidatorSet {
        &self.validators
    }

    /// The last finalized height (or `None` before any QC has been emitted).
    #[must_use]
    pub const fn last_finalized_height(&self) -> Option<u64> {
        self.last_finalized_height
    }

    /// Record an incoming vote.
    ///
    /// - Rejects unauthorized validators.
    /// - Rejects invalid signatures.
    /// - Rejects votes at or below the last-finalized height (stale).
    /// - Detects equivocation (same validator voting on different block
    ///   hashes at the same height). The second vote is rejected and the
    ///   validator is added to `equivocators[height]`.
    /// - Ignores (idempotently) a repeat of the same vote.
    ///
    /// # Errors
    /// Returns [`ConsensusError`] describing the reason for rejection.
    pub fn record_vote(&mut self, vote: Vote) -> Result<VoteOutcome, ConsensusError> {
        // 1. Authorized voter check.
        if !self.validators.is_authorized(&vote.validator) {
            return Err(ConsensusError::UnauthorizedValidator);
        }

        // 2. Staleness check.
        if let Some(last) = self.last_finalized_height {
            if vote.height <= last {
                return Err(ConsensusError::StaleVote {
                    vote_height: vote.height,
                    last_finalized: last,
                });
            }
        }

        // 3. Signature check.
        vote.verify().map_err(ConsensusError::Signature)?;

        // 4. Equivocation check.
        let key = (vote.height, vote.validator.clone());
        if let Some(prior_hash) = self.first_vote_at_height.get(&key) {
            if *prior_hash != vote.block_hash {
                // Equivocation. Reject and record.
                self.equivocators
                    .entry(vote.height)
                    .or_default()
                    .push(vote.validator.clone());
                return Err(ConsensusError::Equivocation {
                    height: vote.height,
                });
            }
            // Same vote repeated — idempotent.
            return Ok(VoteOutcome::AlreadyRecorded);
        }

        // 5. Record first-seen hash and accept the vote.
        self.first_vote_at_height.insert(key, vote.block_hash);
        let inserted = self.tally.record(vote);
        Ok(if inserted {
            VoteOutcome::Recorded
        } else {
            VoteOutcome::AlreadyRecorded
        })
    }

    /// Return the number of distinct votes recorded for the given
    /// (height, block_hash).
    #[must_use]
    pub fn vote_count(&self, height: u64, block_hash: &Hash) -> usize {
        self.tally.count_for(height, block_hash)
    }

    /// Attempt to form a [`QuorumCertificate`] for the given
    /// (height, block_hash). Succeeds only if the vote count meets the
    /// validator set's quorum threshold.
    ///
    /// Calling this does NOT advance `last_finalized_height`. Call
    /// [`Self::on_finalized`] once the caller has actually committed
    /// the block.
    ///
    /// # Errors
    /// Returns [`ConsensusError::InsufficientQuorum`] if fewer than
    /// `quorum_threshold` votes have been recorded for this proposal.
    pub fn try_form_quorum_certificate(
        &self,
        height: u64,
        block_hash: Hash,
    ) -> Result<QuorumCertificate, ConsensusError> {
        let threshold = self.validators.quorum_threshold();
        let votes = self.tally.votes_for(height, &block_hash);
        if votes.len() < threshold {
            return Err(ConsensusError::InsufficientQuorum {
                provided: votes.len(),
                required: threshold,
            });
        }
        QuorumCertificate::new(height, block_hash, votes, &self.validators)
    }

    /// Notify the engine that a block at `height` has been finalized.
    ///
    /// Drops all stored votes at or below `height` (they are no longer
    /// needed) and advances `last_finalized_height`.
    pub fn on_finalized(&mut self, height: u64) {
        self.last_finalized_height = Some(
            self.last_finalized_height
                .map_or(height, |prev| prev.max(height)),
        );
        self.tally.prune_through(height);
        self.first_vote_at_height
            .retain(|&(h, _), _| h > height);
        self.equivocators.retain(|&h, _| h > height);
    }

    /// Return the list of validators who have equivocated at the given height
    /// (voted for two different block hashes). Empty if none.
    #[must_use]
    pub fn equivocators_at(&self, height: u64) -> Vec<PublicKey> {
        self.equivocators.get(&height).cloned().unwrap_or_default()
    }
}

/// Outcome of [`ConsensusEngine::record_vote`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VoteOutcome {
    /// The vote was new and has been recorded.
    Recorded,
    /// A vote with identical `(height, validator, block_hash)` was already
    /// on file. Nothing changed.
    AlreadyRecorded,
}

// ═══════════════════════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════════════════════

/// Errors that can occur in the consensus layer.
#[derive(Debug, thiserror::Error)]
pub enum ConsensusError {
    /// Validator set was constructed with no validators.
    #[error("validator set cannot be empty")]
    EmptyValidatorSet,

    /// A vote or proposal came from a key not in the validator set.
    #[error("validator not authorized")]
    UnauthorizedValidator,

    /// Two or more votes in a QC came from the same validator.
    #[error("duplicate voter in quorum certificate")]
    DuplicateVoter,

    /// A vote's block_hash doesn't match the QC it's being included in.
    #[error("vote disagrees with QC block hash")]
    VoteBlockMismatch,

    /// A vote's height doesn't match the expected height.
    #[error("vote height mismatch: expected {expected}, got {actual}")]
    VoteHeightMismatch {
        /// The height the vote should have been for.
        expected: u64,
        /// The height the vote claimed.
        actual: u64,
    },

    /// Too few votes collected to form a quorum.
    #[error("insufficient quorum: provided {provided}, required {required}")]
    InsufficientQuorum {
        /// Number of distinct votes provided.
        provided: usize,
        /// Threshold required by the validator set.
        required: usize,
    },

    /// A validator signed two conflicting votes at the same height.
    #[error("equivocation detected at height {height}")]
    Equivocation {
        /// Height at which the equivocation occurred.
        height: u64,
    },

    /// A vote arrived for a height already finalized.
    #[error("stale vote: height {vote_height}, last finalized {last_finalized}")]
    StaleVote {
        /// Height claimed by the vote.
        vote_height: u64,
        /// Last-finalized height the engine is tracking.
        last_finalized: u64,
    },

    /// QC height doesn't match its block's height.
    #[error("qc height {qc_height} doesn't match block height {block_height}")]
    QcHeightMismatch {
        /// The QC's declared height.
        qc_height: u64,
        /// The block's header height.
        block_height: u64,
    },

    /// QC block_hash doesn't match the block it's paired with.
    #[error("qc block hash doesn't match block")]
    QcBlockMismatch,

    /// Signature verification failed.
    #[error("signature verification failed: {0}")]
    Signature(#[from] VerifyError),

    /// Block error (usually hashing).
    #[error("block error: {0}")]
    Block(#[from] BlockError),

    /// Hash/serialization error.
    #[error("hash error: {0}")]
    Hash(#[from] HashError),
}

// ═══════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{CommittedBlock, Vote};
    use crate::crypto::keypair::Keypair;

    fn kp() -> Keypair {
        Keypair::generate()
    }

    fn make_engine(n: usize) -> (Vec<Keypair>, ConsensusEngine) {
        let kps: Vec<Keypair> = (0..n).map(|_| kp()).collect();
        let set = ValidatorSet::new(kps.iter().map(Keypair::public_key)).expect("set");
        (kps, ConsensusEngine::new(set))
    }

    // ─── record_vote admission ──────────────────────────────────────

    #[test]
    fn record_vote_accepts_authorized() {
        let (kps, mut eng) = make_engine(4);
        let bh = Hash::from_bytes([1u8; 32]);
        let vote = Vote::sign(1, bh, &kps[0]);
        let outcome = eng.record_vote(vote).expect("ok");
        assert_eq!(outcome, VoteOutcome::Recorded);
        assert_eq!(eng.vote_count(1, &bh), 1);
    }

    #[test]
    fn record_vote_rejects_unauthorized() {
        let (_kps, mut eng) = make_engine(4);
        let imposter = kp();
        let vote = Vote::sign(1, Hash::from_bytes([1u8; 32]), &imposter);
        let err = eng.record_vote(vote).expect_err("unauthorized");
        assert!(matches!(err, ConsensusError::UnauthorizedValidator));
    }

    #[test]
    fn record_vote_rejects_bad_signature() {
        let (kps, mut eng) = make_engine(4);
        let bh = Hash::from_bytes([1u8; 32]);
        let mut vote = Vote::sign(1, bh, &kps[0]);
        // Tamper post-signing.
        vote.block_hash = Hash::from_bytes([9u8; 32]);
        let err = eng.record_vote(vote).expect_err("bad sig");
        assert!(matches!(err, ConsensusError::Signature(_)));
    }

    #[test]
    fn record_vote_rejects_stale() {
        let (kps, mut eng) = make_engine(4);
        eng.on_finalized(10);
        let vote = Vote::sign(10, Hash::from_bytes([1u8; 32]), &kps[0]);
        let err = eng.record_vote(vote).expect_err("stale");
        assert!(matches!(err, ConsensusError::StaleVote { .. }));
    }

    #[test]
    fn record_vote_is_idempotent_on_same_vote() {
        let (kps, mut eng) = make_engine(4);
        let bh = Hash::from_bytes([1u8; 32]);
        let vote = Vote::sign(1, bh, &kps[0]);
        eng.record_vote(vote.clone()).expect("first");
        let outcome = eng.record_vote(vote).expect("second");
        assert_eq!(outcome, VoteOutcome::AlreadyRecorded);
        assert_eq!(eng.vote_count(1, &bh), 1);
    }

    // ─── equivocation ───────────────────────────────────────────────

    #[test]
    fn record_vote_detects_equivocation() {
        let (kps, mut eng) = make_engine(4);
        let bh1 = Hash::from_bytes([1u8; 32]);
        let bh2 = Hash::from_bytes([2u8; 32]);
        // Validator 0 votes for block 1.
        eng.record_vote(Vote::sign(1, bh1, &kps[0])).expect("first");
        // Then votes for block 2 at the same height — equivocation.
        let err = eng
            .record_vote(Vote::sign(1, bh2, &kps[0]))
            .expect_err("equiv");
        assert!(matches!(err, ConsensusError::Equivocation { height: 1 }));
        assert_eq!(eng.equivocators_at(1).len(), 1);
        // The conflicting second vote must NOT be counted toward the tally.
        assert_eq!(eng.vote_count(1, &bh2), 0);
        assert_eq!(eng.vote_count(1, &bh1), 1);
    }

    // ─── quorum formation ──────────────────────────────────────────

    #[test]
    fn forms_qc_at_threshold() {
        let (kps, mut eng) = make_engine(4); // threshold = 3
        let bh = Hash::from_bytes([7u8; 32]);
        for k in kps.iter().take(3) {
            eng.record_vote(Vote::sign(5, bh, k)).expect("vote");
        }
        let qc = eng
            .try_form_quorum_certificate(5, bh)
            .expect("should form");
        assert_eq!(qc.height, 5);
        assert_eq!(qc.block_hash, bh);
        assert_eq!(qc.votes.len(), 3);
    }

    #[test]
    fn does_not_form_qc_below_threshold() {
        let (kps, mut eng) = make_engine(4);
        let bh = Hash::from_bytes([7u8; 32]);
        for k in kps.iter().take(2) {
            eng.record_vote(Vote::sign(5, bh, k)).expect("vote");
        }
        let err = eng
            .try_form_quorum_certificate(5, bh)
            .expect_err("below");
        assert!(matches!(err, ConsensusError::InsufficientQuorum { .. }));
    }

    #[test]
    fn finalization_clears_old_votes() {
        let (kps, mut eng) = make_engine(3);
        let bh = Hash::from_bytes([7u8; 32]);
        eng.record_vote(Vote::sign(1, bh, &kps[0])).expect("ok");
        eng.record_vote(Vote::sign(2, bh, &kps[0])).expect("ok");
        eng.on_finalized(1);
        assert_eq!(eng.vote_count(1, &bh), 0);
        assert_eq!(eng.vote_count(2, &bh), 1);
        assert_eq!(eng.last_finalized_height(), Some(1));
    }

    // ─── CommittedBlock ─────────────────────────────────────────────

    #[test]
    fn committed_block_enforces_qc_matches_block() {
        use crate::block::Block;
        let (kps, mut eng) = make_engine(4);
        let proposer = &kps[0];
        let block = Block::genesis("tfs-test", 1, vec![], proposer).expect("block");
        let bh = block.hash().expect("hash");
        for k in kps.iter().take(3) {
            eng.record_vote(Vote::sign(block.header.height, bh, k))
                .expect("vote");
        }
        let qc = eng
            .try_form_quorum_certificate(block.header.height, bh)
            .expect("qc");
        let committed = CommittedBlock::new(block, qc, eng.validators()).expect("commit");
        assert_eq!(committed.block.header.height, 0);
    }

    #[test]
    fn committed_block_rejects_qc_for_wrong_block() {
        use crate::block::Block;
        let (kps, mut eng) = make_engine(4);
        let proposer = &kps[0];
        let block = Block::genesis("tfs-test", 1, vec![], proposer).expect("block");
        let wrong_hash = Hash::from_bytes([0xAA; 32]);
        for k in kps.iter().take(3) {
            eng.record_vote(Vote::sign(0, wrong_hash, k)).expect("vote");
        }
        let qc = eng
            .try_form_quorum_certificate(0, wrong_hash)
            .expect("qc");
        let err = CommittedBlock::new(block, qc, eng.validators()).expect_err("bad pair");
        assert!(matches!(err, ConsensusError::QcBlockMismatch));
    }
}
