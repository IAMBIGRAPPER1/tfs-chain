// TFS_CHAIN · node/proposer.rs · Layer 7
//
// THE VALIDATOR LOOP.
//
// This module implements the four actions a validator performs:
//
//   1. LEADER CHECK. At height H, validator[H mod N] is the proposer.
//      Deterministic round-robin. No leader-election protocol needed.
//
//   2. PROPOSE. If we're the leader for the NEXT height, drain up to
//      MAX_TXS_PER_BLOCK transactions from the mempool (via
//      `Mempool::select_for_block`) and build a block on top of the
//      current tip. Sign and broadcast.
//
//   3. VOTE. When a block proposal arrives, validate it structurally
//      and against the state machine (speculative apply). If it would
//      apply cleanly, cast a Vote on (height, block_hash). Broadcast.
//
//   4. COMMIT. When the quorum threshold of votes for a given proposal
//      has been collected, form a QuorumCertificate and append the
//      CommittedBlock to the chain (both in-memory + disk via Layer 6).
//
// Each action is a PURE function of the node's current state. This
// module has no I/O of its own — the Node orchestrator wires publish
// outputs into the P2P task.
//
// THREAT MODEL:
//   - Leader skew (no one proposes)   → future: timeout + view change.
//                                       Layer 7: next leader picks up
//                                       at the next height naturally.
//   - Proposal for wrong height       → rejected by validate_against_previous
//   - Proposal with bad state diff    → rejected by speculative apply
//   - Vote on block we never saw      → recorded in tally for future
//                                       CommittedBlock lookup; if block
//                                       never arrives, never finalizes
//   - Double-propose (two blocks at   → our own deterministic code only
//     same height)                      produces one; Byzantine leaders
//                                       are handled by the chain's
//                                       QC-on-single-block rule

//! Validator-loop helpers: leader election, proposal, voting, commit.

#![cfg(feature = "node")]

use crate::block::Block;
use crate::chain::ChainError;
use crate::consensus::{
    CommittedBlock, ConsensusEngine, ConsensusError, QuorumCertificate, ValidatorSet, Vote,
};
use crate::crypto::hash::{Hash, HashError};
use crate::crypto::keypair::{Keypair, PublicKey};
use crate::mempool::Mempool;
use crate::persistent_chain::PersistentChain;
use crate::state::State;

use super::messages::GossipMessage;

// ═══════════════════════════════════════════════════════════════════
// LEADER SELECTION
// ═══════════════════════════════════════════════════════════════════

/// Return the public key of the validator who proposes block at `height`.
///
/// Round-robin over the sorted validator set: `validators[height % N]`.
/// Deterministic — every node agrees on the leader from the same set.
#[must_use]
pub fn leader_at(height: u64, validators: &ValidatorSet) -> PublicKey {
    let n = u64::try_from(validators.len()).unwrap_or(u64::MAX).max(1);
    let idx = (height % n) as usize;
    // BTreeSet iterates in sorted order — deterministic pick.
    validators
        .iter()
        .nth(idx)
        .copied()
        .expect("validators set non-empty by construction")
}

/// True if the given public key is the leader for `height`.
#[must_use]
pub fn is_leader_at(height: u64, pk: &PublicKey, validators: &ValidatorSet) -> bool {
    leader_at(height, validators) == *pk
}

// ═══════════════════════════════════════════════════════════════════
// PROPOSAL
// ═══════════════════════════════════════════════════════════════════

/// Attempt to build and sign a new block on top of the chain's tip.
///
/// Returns `Ok(None)` if this validator is NOT the leader for the next
/// height. Returns `Ok(Some(block))` with a signed proposal if it is.
///
/// `max_txs` caps how many transactions to pull from the mempool. The
/// caller may set this smaller than Layer 2's `MAX_TXS_PER_BLOCK` for
/// throttling.
///
/// # Errors
/// Returns [`ProposerError`] if the mempool-selected transactions fail
/// to encode or the block fails to build.
pub fn try_propose_block(
    chain: &PersistentChain,
    mempool: &Mempool,
    validator_kp: &Keypair,
    now_ms: i64,
    max_txs: usize,
) -> Result<Option<Block>, ProposerError> {
    let next_height = chain
        .height()
        .checked_add(1)
        .ok_or(ProposerError::HeightOverflow)?;

    // Leader check.
    if !is_leader_at(next_height, &validator_kp.public_key(), chain.validators()) {
        return Ok(None);
    }

    // Select transactions that would apply cleanly against current state.
    let selected = mempool.select_for_block(max_txs, chain.state());
    let mut tx_bytes: Vec<Vec<u8>> = Vec::with_capacity(selected.len());
    for stx in selected {
        tx_bytes.push(stx.to_bytes().map_err(ProposerError::Hash)?);
    }

    // Build the block on top of the tip. Timestamp must be strictly
    // greater than the tip's; if the caller's clock is behind, bump by 1.
    let prev_ts = chain.tip().block.header.timestamp_ms;
    let ts = if now_ms > prev_ts { now_ms } else { prev_ts + 1 };

    let block = Block::propose(
        &chain.tip().block,
        chain.chain_id(),
        ts,
        tx_bytes,
        validator_kp,
    )
    .map_err(|e| ProposerError::Block(Box::new(e)))?;

    Ok(Some(block))
}

// ═══════════════════════════════════════════════════════════════════
// VOTE
// ═══════════════════════════════════════════════════════════════════

/// Decide whether to vote on an incoming block proposal.
///
/// A validator votes iff:
/// 1. The block's proposer is the expected leader for its height.
/// 2. The block's height is exactly tip.height + 1.
/// 3. Structural validation passes.
/// 4. Linkage to previous passes.
/// 5. Speculative state apply succeeds (no invalid txs).
///
/// Returns `Ok(Some(vote))` if all checks pass, `Ok(None)` if we should
/// not vote (wrong height, wrong leader, etc.), or `Err` on a real error.
///
/// # Errors
/// Returns [`ProposerError`] if hashing fails.
pub fn consider_proposal(
    chain: &PersistentChain,
    proposal: &Block,
    validator_kp: &Keypair,
    now_ms: i64,
) -> Result<Option<Vote>, ProposerError> {
    // 1. Height check (must be exactly current_tip + 1).
    let expected_height = chain
        .height()
        .checked_add(1)
        .ok_or(ProposerError::HeightOverflow)?;
    if proposal.header.height != expected_height {
        return Ok(None);
    }

    // 2. Expected leader.
    let leader = leader_at(proposal.header.height, chain.validators());
    if proposal.header.proposer != leader {
        return Ok(None);
    }

    // 3. Structural validation.
    if proposal
        .validate_structure(chain.chain_id(), now_ms)
        .is_err()
    {
        return Ok(None);
    }

    // 4. Linkage to previous.
    if proposal
        .validate_against_previous(&chain.tip().block)
        .is_err()
    {
        return Ok(None);
    }

    // 5. Speculative state apply. If the block would fail, don't vote.
    let mut speculative: State = chain.state().clone();
    if speculative.apply_block(proposal).is_err() {
        return Ok(None);
    }

    // All checks pass — cast a vote.
    let block_hash = proposal.hash().map_err(|e| ProposerError::Block(Box::new(e)))?;
    Ok(Some(Vote::sign(
        proposal.header.height,
        block_hash,
        validator_kp,
    )))
}

// ═══════════════════════════════════════════════════════════════════
// COMMIT
// ═══════════════════════════════════════════════════════════════════

/// Record a vote with the consensus engine, then attempt to finalize.
///
/// Returns `Ok(Some(cb))` with the committed block if this vote just
/// completed a quorum. Returns `Ok(None)` otherwise (vote recorded but
/// quorum not yet reached, or vote was already on file).
///
/// The caller is responsible for:
/// - Looking up the corresponding Block (from a proposal-cache or from
///   a block-reserved-for-commit map) and passing it in.
///
/// # Errors
/// Returns [`ProposerError`] if the consensus engine rejects the vote
/// outright (unauthorized, stale, equivocation, etc.).
pub fn record_vote_and_maybe_commit(
    engine: &mut ConsensusEngine,
    vote: Vote,
    pending_block: &Block,
) -> Result<Option<CommittedBlock>, ProposerError> {
    let height = vote.height;
    let block_hash = vote.block_hash;

    engine.record_vote(vote).map_err(ProposerError::Consensus)?;

    match engine.try_form_quorum_certificate(height, block_hash) {
        Ok(qc) => {
            let cb = CommittedBlock::from_parts_unchecked(pending_block.clone(), qc);
            Ok(Some(cb))
        }
        Err(ConsensusError::InsufficientQuorum { .. }) => Ok(None),
        Err(e) => Err(ProposerError::Consensus(e)),
    }
}

// ═══════════════════════════════════════════════════════════════════
// CONVENIENCE: wrap outbound messages
// ═══════════════════════════════════════════════════════════════════

/// Wrap a block in a [`GossipMessage`] once its QC has been formed.
///
/// This is what a proposer broadcasts AFTER the quorum has signed the
/// block — the [`CommittedBlock`] variant carries block+QC together so
/// peers finalize in lockstep.
#[must_use]
pub const fn gossip_committed(cb: CommittedBlock) -> GossipMessage {
    GossipMessage::Committed(cb)
}

/// Wrap a QC over the tip to broadcast a committed form of an already-
/// known block. Returns a [`CommittedBlock`] for gossip.
#[must_use]
pub const fn make_committed(block: Block, qc: QuorumCertificate) -> CommittedBlock {
    CommittedBlock::from_parts_unchecked(block, qc)
}

// ═══════════════════════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════════════════════

/// Errors raised by proposer / voter / committer helpers.
#[derive(Debug, thiserror::Error)]
pub enum ProposerError {
    /// Height arithmetic would overflow u64 (astronomical).
    #[error("height overflow")]
    HeightOverflow,

    /// A block-layer error.
    #[error("block error: {0}")]
    Block(Box<crate::block::BlockError>),

    /// A consensus-layer error.
    #[error("consensus error: {0}")]
    Consensus(ConsensusError),

    /// A chain-layer error.
    #[error("chain error: {0}")]
    Chain(Box<ChainError>),

    /// A hashing / serialization error.
    #[error("hash error: {0}")]
    Hash(#[from] HashError),

    /// Dummy so the `Hash` variant isn't unused behind the From derive.
    #[allow(dead_code)]
    #[error("unreachable")]
    Unreachable,
}

// ═══════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{QuorumCertificate, Vote};
    use crate::crypto::address::Address;
    use crate::crypto::keypair::Keypair;
    use crate::genesis::build_genesis_block;
    use crate::tx::{InscribePayload, SignedTransaction, Transaction, TransferPayload, HYPHAE_PER_TFS};
    use tempfile::TempDir;

    const CHAIN_ID: &str = "tfs-test-1";

    fn kp() -> Keypair {
        Keypair::generate()
    }

    // ─── Leader selection ──────────────────────────────────────────

    #[test]
    fn leader_is_deterministic_and_rotates() {
        let kps: Vec<Keypair> = (0..3).map(|_| kp()).collect();
        let set = ValidatorSet::new(kps.iter().map(Keypair::public_key)).unwrap();
        let l0 = leader_at(0, &set);
        let l1 = leader_at(1, &set);
        let l2 = leader_at(2, &set);
        let l3 = leader_at(3, &set);
        // All four must be validators in the set.
        assert!(set.is_authorized(&l0));
        assert!(set.is_authorized(&l1));
        assert!(set.is_authorized(&l2));
        // Rotates back to the first after N.
        assert_eq!(l0, l3);
    }

    // Helper: bootstrap a PersistentChain at height 0 with president as
    // one of three validators.
    fn boot(dir: &TempDir) -> (PersistentChain, Keypair, Vec<Keypair>, ValidatorSet) {
        let president = kp();
        let v1 = kp();
        let v2 = kp();
        let set = ValidatorSet::new([
            president.public_key(),
            v1.public_key(),
            v2.public_key(),
        ])
        .unwrap();
        let block = build_genesis_block(CHAIN_ID, 1, &president).unwrap();
        let bh = block.hash().unwrap();
        let votes = vec![
            Vote::sign(0, bh, &president),
            Vote::sign(0, bh, &v1),
            Vote::sign(0, bh, &v2),
        ];
        let qc = QuorumCertificate::new(0, bh, votes, &set).unwrap();
        let chain =
            PersistentChain::create(dir.path(), CHAIN_ID, set.clone(), block, qc, 1).unwrap();
        (chain, president, vec![v1, v2], set)
    }

    // ─── Propose ────────────────────────────────────────────────────

    #[test]
    fn try_propose_returns_none_when_not_leader() {
        let dir = TempDir::new().unwrap();
        let (chain, _president, _vs, set) = boot(&dir);
        // Find a validator who is NOT the leader at height 1.
        let next_leader = leader_at(1, &set);
        // Pick one of the set's validators that is not the leader.
        let other = set.iter().find(|pk| **pk != next_leader).copied().unwrap();
        // We can't easily reconstruct the keypair from public key alone,
        // so generate a fresh keypair: this is NOT in the set, so still
        // "not the leader". The function checks via `is_leader_at` which
        // compares public keys, and a fresh keypair is never in the set.
        let _ = other;
        let outsider = kp();
        let result = try_propose_block(&chain, &Mempool::default(), &outsider, 2, 100).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn try_propose_returns_some_when_leader() {
        let dir = TempDir::new().unwrap();
        let (chain, president, vs, set) = boot(&dir);
        // Whoever is the leader at height 1, find which one in (president, v1, v2).
        let next_leader = leader_at(1, &set);
        // One of our three known keys must be the leader.
        let all_kps: Vec<&Keypair> = std::iter::once(&president).chain(vs.iter()).collect();
        let leader_kp = all_kps
            .iter()
            .find(|k| k.public_key() == next_leader)
            .copied()
            .expect("a known keypair is leader");
        let result = try_propose_block(&chain, &Mempool::default(), leader_kp, 2, 100).unwrap();
        let proposal = result.expect("should propose");
        assert_eq!(proposal.header.height, 1);
        assert_eq!(proposal.header.proposer, leader_kp.public_key());
    }

    // ─── Vote ───────────────────────────────────────────────────────

    #[test]
    fn consider_proposal_votes_on_valid_block() {
        let dir = TempDir::new().unwrap();
        let (chain, president, vs, set) = boot(&dir);
        // Build the "right" proposal: at height 1, by the leader.
        let next_leader = leader_at(1, &set);
        let all_kps: Vec<&Keypair> = std::iter::once(&president).chain(vs.iter()).collect();
        let leader_kp = all_kps
            .iter()
            .find(|k| k.public_key() == next_leader)
            .copied()
            .unwrap();
        let proposal = try_propose_block(&chain, &Mempool::default(), leader_kp, 2, 100)
            .unwrap()
            .unwrap();

        // Any validator now considers the proposal. Say v1.
        let voter = &vs[0];
        let vote = consider_proposal(&chain, &proposal, voter, 2)
            .unwrap()
            .expect("should vote");
        assert_eq!(vote.height, 1);
        assert_eq!(vote.validator, voter.public_key());
    }

    #[test]
    fn consider_proposal_declines_wrong_height() {
        let dir = TempDir::new().unwrap();
        let (chain, president, vs, set) = boot(&dir);
        let next_leader = leader_at(1, &set);
        let all_kps: Vec<&Keypair> = std::iter::once(&president).chain(vs.iter()).collect();
        let leader_kp = all_kps
            .iter()
            .find(|k| k.public_key() == next_leader)
            .copied()
            .unwrap();
        // Build a proposal for height 1, then ANOTHER at height 2 — and
        // submit the height-2 one without ever committing height 1.
        let b1 = try_propose_block(&chain, &Mempool::default(), leader_kp, 2, 100)
            .unwrap()
            .unwrap();
        let b2 = Block::propose(&b1, CHAIN_ID, 3, vec![], leader_kp).unwrap();
        let voter = &vs[0];
        let result = consider_proposal(&chain, &b2, voter, 3).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn consider_proposal_declines_wrong_leader() {
        let dir = TempDir::new().unwrap();
        let (chain, president, vs, _set) = boot(&dir);
        // Let's find the NON-leader at height 1.
        // next_leader is set; pick a keypair that isn't it.
        let all_kps: Vec<&Keypair> = std::iter::once(&president).chain(vs.iter()).collect();
        let non_leader = all_kps
            .iter()
            .find(|k| k.public_key() != leader_at(1, chain.validators()))
            .copied()
            .unwrap();
        // Build a proposal from the non-leader (structurally valid, but
        // proposer isn't the expected leader).
        let proposal =
            Block::propose(&chain.tip().block, CHAIN_ID, 2, vec![], non_leader).unwrap();
        let result = consider_proposal(&chain, &proposal, &vs[0], 2).unwrap();
        assert!(result.is_none());
    }

    // ─── Full proposer → voter → quorum flow ────────────────────────

    #[test]
    fn full_round_trip_from_propose_to_quorum() {
        let dir = TempDir::new().unwrap();
        let (mut chain, president, vs, set) = boot(&dir);
        let next_leader = leader_at(1, &set);
        let all_kps: Vec<&Keypair> = std::iter::once(&president).chain(vs.iter()).collect();
        let leader_kp = all_kps
            .iter()
            .find(|k| k.public_key() == next_leader)
            .copied()
            .unwrap();

        // Proposer builds a block (empty tx set).
        let proposal = try_propose_block(&chain, &Mempool::default(), leader_kp, 2, 100)
            .unwrap()
            .unwrap();
        let block_hash = proposal.hash().unwrap();

        // All three validators vote.
        let mut engine = ConsensusEngine::new(set.clone());
        for k in &all_kps {
            let v = consider_proposal(&chain, &proposal, k, 2).unwrap().unwrap();
            let _ = record_vote_and_maybe_commit(&mut engine, v, &proposal).unwrap();
        }

        // The QC should now exist.
        let qc = engine
            .try_form_quorum_certificate(1, block_hash)
            .expect("quorum");
        let committed = CommittedBlock::new(proposal, qc, &set).unwrap();

        // Append to chain succeeds.
        chain.append_committed_block(committed, 2).unwrap();
        assert_eq!(chain.height(), 1);
    }

    // ─── With transactions ──────────────────────────────────────────

    #[test]
    fn propose_includes_selected_mempool_txs() {
        let dir = TempDir::new().unwrap();
        let (chain, president, vs, set) = boot(&dir);
        // Put a transfer tx into the mempool.
        let alice = kp();
        let tx = SignedTransaction::sign_single(
            Transaction::Transfer(TransferPayload {
                from: Address::from_public_key(&president.public_key()),
                to: Address::from_public_key(&alice.public_key()),
                amount_hyphae: 100,
                nonce: 1,
                timestamp_ms: 2,
            }),
            &president,
        )
        .unwrap();
        let mut mempool = Mempool::default();
        mempool.insert(tx.clone(), chain.state()).unwrap();

        // Find the leader and propose.
        let next_leader = leader_at(1, &set);
        let all_kps: Vec<&Keypair> = std::iter::once(&president).chain(vs.iter()).collect();
        let leader_kp = all_kps
            .iter()
            .find(|k| k.public_key() == next_leader)
            .copied()
            .unwrap();
        let proposal = try_propose_block(&chain, &mempool, leader_kp, 2, 100)
            .unwrap()
            .unwrap();
        assert_eq!(proposal.transactions.len(), 1);
    }

    // Suppress the "unreachable" variant being unused.
    #[test]
    fn unreachable_variant_exists_for_completeness() {
        let _ = ProposerError::Unreachable;
        // Also silence unused-imports noise by making sure InscribePayload
        // is actually used for something in tests.
        let _ = InscribePayload::new(
            Address::from_public_key(&kp().public_key()),
            b"x".to_vec(),
            0,
            1,
        );
        assert_eq!(1_000 * HYPHAE_PER_TFS, 1_000_000_000_000);
    }
}
