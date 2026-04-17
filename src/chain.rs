// TFS_CHAIN · chain.rs · Layer 5
//
// THE APPEND-ONLY HISTORY.
//
// The `Chain` is the top-level driver for Layer 5. It knits together:
//
//   - the [`ValidatorSet`]   (who is allowed to propose and vote)
//   - the [`State`]          (the current balance/nonce/supply universe)
//   - the committed history  (sequence of [`CommittedBlock`]s)
//
// On `append_committed_block`, the chain enforces the full validation
// stack:
//
//   1. Block structural integrity       (Layer 2)
//   2. Block linkage to previous         (Layer 2)
//   3. Proposer is an authorized validator (Layer 5)
//   4. Block's QC verifies against the validator set (Layer 5)
//   5. Every transaction applies cleanly to state (Layer 3 + 5 semantics)
//
// If any step fails, the block is rejected and NOTHING changes — no
// state mutation, no history append.
//
// THE CHAIN REMEMBERS.
// THE CHAIN FORGIVES.
// THE CHAIN DOES NOT FORGET.
//
// DESIGN POSTURE:
//   - In-memory Vec<CommittedBlock> for Layer 5. Layer 6 will swap in
//     RocksDB without changing this API.
//   - Clone-and-rollback for state atomicity (same pattern as
//     State::apply_block — if tx application fails mid-block, restore).
//   - No async. Layer 7 will wrap this in a lock for concurrent reads
//     and exclusive writes; the core logic stays synchronous and testable.
//
// THREAT MODEL:
//   - Block skipped / out-of-order       → validate_against_previous
//   - Unauthorized proposer              → ValidatorSet::is_authorized
//   - Forged QC                          → QC::verify
//   - Invalid tx inside otherwise valid  → State::apply_block rolls back
//     block                                 AND the chain refuses to append
//   - Replay of an already-committed     → height mismatch blocks it
//     block                                 (must be prev.height + 1)
//   - Reorg / fork                       → append-only; no rewinding
//   - Genesis block misuse after init    → append checks height > 0

//! The top-level chain object.
//!
//! Construct with [`Chain::genesis`] by supplying the genesis block
//! + its QC + the validator set. Append subsequent blocks with
//! [`Chain::append_committed_block`].

use serde::{Deserialize, Serialize};

use crate::block::{Block, BlockError};
use crate::consensus::{CommittedBlock, ConsensusError, QuorumCertificate, ValidatorSet};
use crate::crypto::hash::{Hash, HashError};
use crate::state::{State, StateError};

// ═══════════════════════════════════════════════════════════════════
// CHAIN
// ═══════════════════════════════════════════════════════════════════

/// The append-only history of THE TFS CHAIN.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Chain {
    /// The chain identifier (e.g. `"tfs-mainnet-1"`).
    chain_id: String,

    /// The authorized validator set. Fixed for Layer 5 (set at genesis).
    /// Future governance protocol will allow epoch rotation.
    validators: ValidatorSet,

    /// Committed blocks in order, index i = height i.
    /// For mainnet, Layer 6 will replace this with RocksDB-backed storage.
    blocks: Vec<CommittedBlock>,

    /// Live state derived from replaying `blocks` from genesis.
    /// Held in memory to avoid re-replaying on each query.
    state: State,
}

impl Chain {
    /// Initialize the chain with the genesis committed block.
    ///
    /// `genesis_block` must be at height 0 with `previous_hash = Hash::ZERO`.
    /// `genesis_qc` must be a valid QC over `genesis_block.hash()` signed
    /// by `validators`.
    ///
    /// # Errors
    /// Returns [`ChainError`] if:
    /// - The block isn't at height 0.
    /// - `previous_hash` isn't zero.
    /// - The chain_id doesn't match.
    /// - The block proposer isn't an authorized validator.
    /// - The QC doesn't verify.
    /// - Any transaction in the genesis block fails to apply.
    pub fn genesis(
        chain_id: &str,
        validators: ValidatorSet,
        genesis_block: Block,
        genesis_qc: QuorumCertificate,
        now_ms: i64,
    ) -> Result<Self, ChainError> {
        // Structural + signature validation at Block level.
        genesis_block
            .validate_structure(chain_id, now_ms)
            .map_err(ChainError::Block)?;

        // Genesis-specific invariants.
        if genesis_block.header.height != 0 {
            return Err(ChainError::GenesisMustBeHeightZero(genesis_block.header.height));
        }
        if genesis_block.header.previous_hash != Hash::ZERO {
            return Err(ChainError::GenesisPreviousHashNotZero);
        }

        // Authorized proposer.
        if !validators.is_authorized(&genesis_block.header.proposer) {
            return Err(ChainError::UnauthorizedProposer);
        }

        // QC validation.
        let committed = CommittedBlock::new(genesis_block, genesis_qc, &validators)
            .map_err(ChainError::Consensus)?;

        // Apply to a fresh state.
        let mut state = State::new();
        state.apply_block(&committed.block).map_err(ChainError::State)?;

        Ok(Self {
            chain_id: chain_id.to_string(),
            validators,
            blocks: vec![committed],
            state,
        })
    }

    /// Append the next committed block on top of the current tip.
    ///
    /// # Errors
    /// Returns [`ChainError`] if:
    /// - Structural validation fails.
    /// - Linkage to previous fails (height, prev_hash, chain_id, timestamp).
    /// - Proposer isn't an authorized validator.
    /// - QC doesn't verify.
    /// - State application fails (insufficient balance, bad nonce, etc.).
    pub fn append_committed_block(
        &mut self,
        committed: CommittedBlock,
        now_ms: i64,
    ) -> Result<(), ChainError> {
        // 1. Structural validation.
        committed
            .block
            .validate_structure(&self.chain_id, now_ms)
            .map_err(ChainError::Block)?;

        // 2. Linkage to previous.
        let prev = self.tip();
        committed
            .block
            .validate_against_previous(&prev.block)
            .map_err(ChainError::Block)?;

        // 3. Authorized proposer.
        if !self.validators.is_authorized(&committed.block.header.proposer) {
            return Err(ChainError::UnauthorizedProposer);
        }

        // 4. QC verification (height + block-hash + signatures + threshold).
        let block_hash = committed.block.hash().map_err(ChainError::Block)?;
        if committed.qc.height != committed.block.header.height {
            return Err(ChainError::Consensus(ConsensusError::QcHeightMismatch {
                qc_height: committed.qc.height,
                block_height: committed.block.header.height,
            }));
        }
        if committed.qc.block_hash != block_hash {
            return Err(ChainError::Consensus(ConsensusError::QcBlockMismatch));
        }
        committed
            .qc
            .verify(&self.validators)
            .map_err(ChainError::Consensus)?;

        // 5. Attempt state application on a CLONE first for atomicity at
        //    this level — `State::apply_block` already rolls back internally
        //    on failure, but we want zero leak of `self.state` mutation if
        //    a later step errors.
        let mut candidate_state = self.state.clone();
        candidate_state
            .apply_block(&committed.block)
            .map_err(ChainError::State)?;

        // All checks passed. Commit.
        self.state = candidate_state;
        self.blocks.push(committed);
        Ok(())
    }

    // ───────────────────────────────────────────────────────────────
    // QUERIES
    // ───────────────────────────────────────────────────────────────

    /// The chain's identifier string.
    #[must_use]
    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }

    /// The currently authorized validator set.
    #[must_use]
    pub const fn validators(&self) -> &ValidatorSet {
        &self.validators
    }

    /// The current chain height (= number of committed blocks − 1).
    #[must_use]
    pub fn height(&self) -> u64 {
        self.state.height
    }

    /// The hash of the most recently committed block.
    ///
    /// # Errors
    /// Returns [`ChainError::Block`] if block serialization fails.
    pub fn last_block_hash(&self) -> Result<Hash, ChainError> {
        self.tip().block.hash().map_err(ChainError::Block)
    }

    /// A reference to the live state.
    #[must_use]
    pub const fn state(&self) -> &State {
        &self.state
    }

    /// A reference to the tip (most recent committed block).
    ///
    /// # Panics
    /// The chain always has at least a genesis block after construction,
    /// so this never panics; the `Vec::last().unwrap()` is justified by
    /// the constructor's invariant.
    #[must_use]
    pub fn tip(&self) -> &CommittedBlock {
        self.blocks
            .last()
            .expect("chain invariant: at least genesis")
    }

    /// Return the committed block at the given height, if present.
    #[must_use]
    pub fn committed_at(&self, height: u64) -> Option<&CommittedBlock> {
        let idx = usize::try_from(height).ok()?;
        self.blocks.get(idx)
    }

    /// Number of committed blocks (= height + 1).
    #[must_use]
    pub fn committed_count(&self) -> usize {
        self.blocks.len()
    }

    /// Compute the hash of the current state. Useful for snapshots and
    /// light-client proofs.
    ///
    /// # Errors
    /// Returns [`HashError`] if serialization fails.
    pub fn state_root(&self) -> Result<Hash, HashError> {
        self.state.state_root()
    }
}

// ═══════════════════════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════════════════════

/// Errors that can occur at the chain layer.
#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    /// Block structural or linkage error.
    #[error("block error: {0}")]
    Block(#[from] BlockError),

    /// Consensus / QC error.
    #[error("consensus error: {0}")]
    Consensus(#[from] ConsensusError),

    /// State application error.
    #[error("state error: {0}")]
    State(#[from] StateError),

    /// Genesis block had a non-zero height.
    #[error("genesis block must be at height 0, got {0}")]
    GenesisMustBeHeightZero(u64),

    /// Genesis block's `previous_hash` wasn't `Hash::ZERO`.
    #[error("genesis block's previous_hash must be Hash::ZERO")]
    GenesisPreviousHashNotZero,

    /// Proposer isn't in the authorized validator set.
    #[error("proposer is not an authorized validator")]
    UnauthorizedProposer,

    /// Hash / serialization error.
    #[error("hash error: {0}")]
    Hash(#[from] HashError),
}

// ═══════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{ConsensusEngine, Vote};
    use crate::crypto::{address::Address, keypair::Keypair};
    use crate::tx::{SignedTransaction, Transaction, TransferPayload};

    fn kp() -> Keypair {
        Keypair::generate()
    }

    fn addr(k: &Keypair) -> Address {
        Address::from_public_key(&k.public_key())
    }

    fn build_qc(
        validator_kps: &[&Keypair],
        height: u64,
        block_hash: Hash,
        set: &ValidatorSet,
    ) -> QuorumCertificate {
        let votes: Vec<Vote> = validator_kps
            .iter()
            .map(|k| Vote::sign(height, block_hash, k))
            .collect();
        QuorumCertificate::new(height, block_hash, votes, set).expect("qc")
    }

    const CHAIN_ID: &str = "tfs-test-1";

    #[test]
    fn genesis_initializes_height_zero() {
        let proposer = kp();
        let v1 = kp();
        let v2 = kp();
        let set = ValidatorSet::new([
            proposer.public_key(),
            v1.public_key(),
            v2.public_key(),
        ])
        .expect("set");
        let block = Block::genesis(CHAIN_ID, 1, vec![], &proposer).expect("block");
        let bh = block.hash().expect("hash");
        let qc = build_qc(&[&proposer, &v1, &v2], 0, bh, &set);

        let chain = Chain::genesis(CHAIN_ID, set, block, qc, 1).expect("chain");
        assert_eq!(chain.height(), 0);
        assert_eq!(chain.committed_count(), 1);
    }

    #[test]
    fn genesis_rejects_non_zero_height() {
        // Build a block with height=5 (illegal for genesis).
        let proposer = kp();
        let v1 = kp();
        let v2 = kp();
        let set = ValidatorSet::new([
            proposer.public_key(),
            v1.public_key(),
            v2.public_key(),
        ])
        .expect("set");
        // Build a real genesis first, then propose on top to get a height-1 block.
        let g = Block::genesis(CHAIN_ID, 1, vec![], &proposer).expect("g");
        let b1 = Block::propose(&g, CHAIN_ID, 2, vec![], &proposer).expect("b1");
        let bh = b1.hash().expect("bh");
        let qc = build_qc(&[&proposer, &v1, &v2], 1, bh, &set);

        let err = Chain::genesis(CHAIN_ID, set, b1, qc, 2).expect_err("height");
        assert!(matches!(err, ChainError::GenesisMustBeHeightZero(1)));
    }

    #[test]
    fn genesis_rejects_unauthorized_proposer() {
        let president = kp();
        let v1 = kp();
        let v2 = kp();
        let imposter = kp();
        // Set does NOT contain imposter.
        let set = ValidatorSet::new([
            president.public_key(),
            v1.public_key(),
            v2.public_key(),
        ])
        .expect("set");
        let block = Block::genesis(CHAIN_ID, 1, vec![], &imposter).expect("block");
        let bh = block.hash().expect("bh");
        // Manufacture QC from the AUTHORIZED validators (so the QC is valid)
        // but the proposer isn't in the set — chain should reject.
        let qc = build_qc(&[&president, &v1, &v2], 0, bh, &set);
        let err = Chain::genesis(CHAIN_ID, set, block, qc, 1).expect_err("unauthed");
        assert!(matches!(err, ChainError::UnauthorizedProposer));
    }

    #[test]
    fn append_committed_block_advances_height_and_state() {
        let proposer = kp();
        let v1 = kp();
        let v2 = kp();
        let alice = kp();
        let bob = kp();

        let set = ValidatorSet::new([
            proposer.public_key(),
            v1.public_key(),
            v2.public_key(),
        ])
        .expect("set");

        // Genesis mints 1000 TFS via inscription from proposer.
        use crate::tx::InscribePayload;
        let inscribe = SignedTransaction::sign_single(
            Transaction::Inscribe(InscribePayload::new(
                addr(&proposer),
                b"GENESIS SCROLL".to_vec(),
                0,
                1,
            )),
            &proposer,
        )
        .expect("sign inscribe");
        let inscribe_bytes = inscribe.to_bytes().expect("bytes");

        let g = Block::genesis(CHAIN_ID, 1, vec![inscribe_bytes], &proposer).expect("g");
        let g_hash = g.hash().expect("g hash");
        let g_qc = build_qc(&[&proposer, &v1, &v2], 0, g_hash, &set);

        let mut chain =
            Chain::genesis(CHAIN_ID, set.clone(), g, g_qc, 1).expect("chain");
        assert_eq!(chain.height(), 0);
        // Proposer now has 1000 TFS.
        assert!(chain.state().balance(&addr(&proposer)) > 0);

        // Next block: proposer transfers to alice.
        let tx = SignedTransaction::sign_single(
            Transaction::Transfer(TransferPayload {
                from: addr(&proposer),
                to: addr(&alice),
                amount_hyphae: 500,
                nonce: 1, // proposer's nonce is 1 after genesis inscribe
                timestamp_ms: 2,
            }),
            &proposer,
        )
        .expect("sign transfer");
        let tx_bytes = tx.to_bytes().expect("bytes");

        let tip_block = chain.tip().block.clone();
        let b1 = Block::propose(&tip_block, CHAIN_ID, 2, vec![tx_bytes], &proposer)
            .expect("b1");
        let b1_hash = b1.hash().expect("b1 hash");
        let b1_qc = build_qc(&[&proposer, &v1, &v2], 1, b1_hash, &set);
        let committed = CommittedBlock::new(b1, b1_qc, &set).expect("commit");

        chain
            .append_committed_block(committed, 2)
            .expect("append");
        assert_eq!(chain.height(), 1);
        assert_eq!(chain.state().balance(&addr(&alice)), 500);
        // Bob is unused — just to confirm the api doesn't pollute state for
        // non-addressed accounts.
        let _ = bob;
    }

    #[test]
    fn append_rejects_skipped_height() {
        let proposer = kp();
        let v1 = kp();
        let v2 = kp();
        let set = ValidatorSet::new([
            proposer.public_key(),
            v1.public_key(),
            v2.public_key(),
        ])
        .expect("set");
        let g = Block::genesis(CHAIN_ID, 1, vec![], &proposer).expect("g");
        let g_hash = g.hash().expect("gh");
        let g_qc = build_qc(&[&proposer, &v1, &v2], 0, g_hash, &set);
        let mut chain =
            Chain::genesis(CHAIN_ID, set.clone(), g, g_qc, 1).expect("chain");

        // Build a height-1 block from genesis.
        let b1 =
            Block::propose(&chain.tip().block, CHAIN_ID, 2, vec![], &proposer).expect("b1");
        // Now build height-2 from b1 WITHOUT appending b1.
        let b2 = Block::propose(&b1, CHAIN_ID, 3, vec![], &proposer).expect("b2");
        let b2_hash = b2.hash().expect("b2 hash");
        let b2_qc = build_qc(&[&proposer, &v1, &v2], 2, b2_hash, &set);
        let committed = CommittedBlock::new(b2, b2_qc, &set).expect("commit");

        let err = chain
            .append_committed_block(committed, 3)
            .expect_err("gap");
        assert!(matches!(err, ChainError::Block(_)));
    }

    #[test]
    fn append_rejects_wrong_qc() {
        let proposer = kp();
        let v1 = kp();
        let v2 = kp();
        let set = ValidatorSet::new([
            proposer.public_key(),
            v1.public_key(),
            v2.public_key(),
        ])
        .expect("set");
        let g = Block::genesis(CHAIN_ID, 1, vec![], &proposer).expect("g");
        let g_hash = g.hash().expect("gh");
        let g_qc = build_qc(&[&proposer, &v1, &v2], 0, g_hash, &set);
        let mut chain =
            Chain::genesis(CHAIN_ID, set.clone(), g, g_qc, 1).expect("chain");

        let b1 =
            Block::propose(&chain.tip().block, CHAIN_ID, 2, vec![], &proposer).expect("b1");
        // QC for the WRONG block hash.
        let wrong_hash = Hash::from_bytes([0xAB; 32]);
        let bad_qc = build_qc(&[&proposer, &v1, &v2], 1, wrong_hash, &set);
        let committed = CommittedBlock::from_parts_unchecked(b1, bad_qc);
        let err = chain
            .append_committed_block(committed, 2)
            .expect_err("bad qc");
        assert!(matches!(err, ChainError::Consensus(_)));
    }

    #[test]
    fn state_root_changes_per_block() {
        let proposer = kp();
        let v1 = kp();
        let v2 = kp();
        let set = ValidatorSet::new([
            proposer.public_key(),
            v1.public_key(),
            v2.public_key(),
        ])
        .expect("set");
        use crate::tx::InscribePayload;
        let inscribe = SignedTransaction::sign_single(
            Transaction::Inscribe(InscribePayload::new(
                addr(&proposer),
                b"g".to_vec(),
                0,
                1,
            )),
            &proposer,
        )
        .expect("sign");
        let g = Block::genesis(
            CHAIN_ID,
            1,
            vec![inscribe.to_bytes().expect("b")],
            &proposer,
        )
        .expect("g");
        let g_hash = g.hash().expect("gh");
        let g_qc = build_qc(&[&proposer, &v1, &v2], 0, g_hash, &set);
        let mut chain = Chain::genesis(CHAIN_ID, set.clone(), g, g_qc, 1).expect("chain");

        let r0 = chain.state_root().expect("r0");

        let inscribe2 = SignedTransaction::sign_single(
            Transaction::Inscribe(InscribePayload::new(
                addr(&proposer),
                b"second".to_vec(),
                1,
                2,
            )),
            &proposer,
        )
        .expect("sign2");
        let b1 = Block::propose(
            &chain.tip().block,
            CHAIN_ID,
            2,
            vec![inscribe2.to_bytes().expect("b")],
            &proposer,
        )
        .expect("b1");
        let b1_hash = b1.hash().expect("bh");
        let b1_qc = build_qc(&[&proposer, &v1, &v2], 1, b1_hash, &set);
        let committed = CommittedBlock::new(b1, b1_qc, &set).expect("commit");
        chain.append_committed_block(committed, 2).expect("append");
        let r1 = chain.state_root().expect("r1");
        assert_ne!(r0, r1);
    }

    // ─── Consensus engine <-> Chain integration smoke test ──────────

    #[test]
    fn engine_produces_qc_that_chain_accepts() {
        let proposer = kp();
        let v1 = kp();
        let v2 = kp();
        let set = ValidatorSet::new([
            proposer.public_key(),
            v1.public_key(),
            v2.public_key(),
        ])
        .expect("set");
        let g = Block::genesis(CHAIN_ID, 1, vec![], &proposer).expect("g");
        let g_hash = g.hash().expect("gh");
        let mut engine = ConsensusEngine::new(set.clone());
        engine
            .record_vote(Vote::sign(0, g_hash, &proposer))
            .expect("v0");
        engine.record_vote(Vote::sign(0, g_hash, &v1)).expect("v1");
        engine.record_vote(Vote::sign(0, g_hash, &v2)).expect("v2");
        let g_qc = engine
            .try_form_quorum_certificate(0, g_hash)
            .expect("form");
        let _chain = Chain::genesis(CHAIN_ID, set, g, g_qc, 1).expect("chain");
    }
}

