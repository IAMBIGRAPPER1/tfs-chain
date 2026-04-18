// TFS_CHAIN · persistent_chain.rs · Layer 6
//
// THE DISK-BACKED CHAIN.
//
// [`PersistentChain`] = in-memory [`Chain`] + RocksDB-backed [`Storage`].
//
// Every append runs the full Layer 5 validation stack (block structural,
// linkage, proposer authorization, QC verification, state apply), and
// ONLY IF VALIDATION SUCCEEDS do we write to disk. The write is atomic —
// a single RocksDB WriteBatch with fsync.
//
// INVARIANT: the in-memory Chain's state at height H is byte-identical to
// what `Storage::load_state` would return from the same DB at height H.
// After every successful `append_committed_block`, this invariant holds.
//
// CRASH SEMANTICS:
//   - Crash BEFORE write_batch_sync: no disk change, restart replays from
//     last persisted height. Safe.
//   - Crash DURING write_batch_sync: RocksDB's WAL replays on reopen,
//     completing the partial write. Safe.
//   - Crash AFTER write_batch_sync but before returning: disk is advanced,
//     in-memory is behind. Restart reloads state from disk, matches. Safe.
//
// In ALL cases, the next boot reads disk-authoritative state. No manual
// reconciliation required.

//! Disk-backed chain wrapping [`Chain`] + [`Storage`].
//!
//! Gated behind the `storage` feature.

#![cfg(feature = "storage")]

use std::path::Path;

use crate::block::Block;
use crate::chain::{Chain, ChainError};
use crate::consensus::{CommittedBlock, QuorumCertificate, ValidatorSet};
use crate::crypto::hash::Hash;
use crate::state::State;
use crate::storage::{StateDiff, Storage, StorageError};

// ═══════════════════════════════════════════════════════════════════
// PERSISTENT CHAIN
// ═══════════════════════════════════════════════════════════════════

/// A chain that durably persists every committed block.
///
/// Construct fresh with [`PersistentChain::create`] and subsequently
/// reopen with [`PersistentChain::open`].
///
/// The two backing components:
/// - [`Chain`] — the pure in-memory validation and query engine
/// - [`Storage`] — the RocksDB persistence layer
///
/// are kept consistent on every append: validation runs first, then the
/// atomic disk commit, then the in-memory state advances. A failure in
/// validation is a clean rollback; a failure during the disk commit means
/// in-memory is ahead of disk momentarily — the next boot resyncs via
/// [`Storage::load_state`].
#[derive(Debug)]
pub struct PersistentChain {
    chain: Chain,
    storage: Storage,
}

impl PersistentChain {
    /// Create a fresh disk-backed chain at `path`, initialized with
    /// the given genesis block + QC and validator set.
    ///
    /// This is the one-time-only bootstrap. Subsequent starts use
    /// [`PersistentChain::open`].
    ///
    /// # Errors
    /// Returns [`PersistentChainError`] if:
    /// - `path` already holds a DB.
    /// - `genesis_block` fails Layer 5 validation.
    /// - The atomic disk commit fails.
    pub fn create<P: AsRef<Path>>(
        path: P,
        chain_id: &str,
        validators: ValidatorSet,
        genesis_block: Block,
        genesis_qc: QuorumCertificate,
        now_ms: i64,
    ) -> Result<Self, PersistentChainError> {
        // 1. Open storage (initializes meta with chain_id + validators).
        let storage = Storage::create(path, chain_id, &validators)?;

        // 2. Build the in-memory Chain (runs all Layer 5 validation).
        let chain = Chain::genesis(
            chain_id,
            validators,
            genesis_block,
            genesis_qc,
            now_ms,
        )?;

        // 3. Persist genesis. Diff is the full transition from empty state
        //    to the state after applying genesis.
        let before = State::new();
        let after = chain.state();
        let diff = StateDiff::between(&before, after);
        storage.commit_block(chain.tip(), &diff)?;

        Ok(Self { chain, storage })
    }

    /// Reopen an existing disk-backed chain.
    ///
    /// Rebuilds the in-memory Chain by loading state + last block from
    /// RocksDB. The reconstructed Chain holds ONLY the tip block in
    /// memory — historical blocks remain on disk and are fetched via
    /// [`PersistentChain::get_committed_block`] on demand.
    ///
    /// # Errors
    /// Returns [`PersistentChainError`] if:
    /// - `path` has no DB.
    /// - Schema version mismatch.
    /// - No genesis block has been committed yet (call [`Self::create`]).
    /// - Loaded state fails to round-trip.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, PersistentChainError> {
        let storage = Storage::open(path)?;

        let chain_id = storage.load_chain_id()?;
        let validators = storage.load_validators()?;

        // Verify we actually have a genesis.
        let tip_height = storage
            .load_height()?
            .ok_or(PersistentChainError::NoGenesisOnDisk)?;

        let tip = storage
            .get_committed_block(tip_height)?
            .ok_or(PersistentChainError::TipMissing(tip_height))?;
        let state = storage.load_state()?;

        // Reconstruct the in-memory Chain from disk-authoritative parts.
        let chain = Chain::restore_from_parts(chain_id, validators, tip, state);

        Ok(Self { chain, storage })
    }

    /// Append the next committed block to both memory and disk.
    ///
    /// Validation runs first. Only if the in-memory Chain accepts the
    /// block does the disk commit run. The disk commit is atomic (one
    /// RocksDB WriteBatch with `sync=true`).
    ///
    /// # Errors
    /// Returns [`PersistentChainError`] if either the Chain append or
    /// the disk commit fails. If the disk commit fails, the in-memory
    /// Chain is rolled back to its pre-append state so the
    /// `memory == disk` invariant holds.
    pub fn append_committed_block(
        &mut self,
        committed: CommittedBlock,
        now_ms: i64,
    ) -> Result<(), PersistentChainError> {
        let before_state = self.chain.state().clone();
        let before_tip = self.chain.tip().clone();

        // 1. Validate + apply in-memory.
        self.chain.append_committed_block(committed.clone(), now_ms)?;

        // 2. Persist. If this fails, roll back in-memory to keep the
        //    memory/disk invariant.
        let after_state = self.chain.state();
        let diff = StateDiff::between(&before_state, after_state);
        if let Err(e) = self.storage.commit_block(&committed, &diff) {
            // Roll back in-memory. Rebuilding the Chain from scratch here
            // would be expensive; instead we reconstruct from the snapshot
            // we took before calling Chain::append_committed_block.
            self.chain = Chain::restore_from_parts(
                self.chain.chain_id().to_string(),
                self.chain.validators().clone(),
                before_tip,
                before_state,
            );
            return Err(PersistentChainError::Storage(e));
        }

        Ok(())
    }

    // ───────────────────────────────────────────────────────────────
    // QUERIES — delegated to Chain (in-memory) or Storage (on-disk)
    // ───────────────────────────────────────────────────────────────

    /// Current chain height.
    #[must_use]
    pub fn height(&self) -> u64 {
        self.chain.height()
    }

    /// The chain's identifier.
    #[must_use]
    pub fn chain_id(&self) -> &str {
        self.chain.chain_id()
    }

    /// Authorized validator set.
    #[must_use]
    pub const fn validators(&self) -> &ValidatorSet {
        self.chain.validators()
    }

    /// Reference to the live in-memory state.
    #[must_use]
    pub const fn state(&self) -> &State {
        self.chain.state()
    }

    /// Most-recent committed block (tip). Cached in memory.
    #[must_use]
    pub fn tip(&self) -> &CommittedBlock {
        self.chain.tip()
    }

    /// Retrieve a committed block at the given height from disk.
    ///
    /// # Errors
    /// Returns [`PersistentChainError::Storage`] if the RocksDB read
    /// fails or the stored bytes fail to decode.
    pub fn get_committed_block(
        &self,
        height: u64,
    ) -> Result<Option<CommittedBlock>, PersistentChainError> {
        self.storage
            .get_committed_block(height)
            .map_err(PersistentChainError::Storage)
    }

    /// Retrieve a committed block by block hash (O(1) via secondary index).
    ///
    /// # Errors
    /// Returns [`PersistentChainError::Storage`] on read or decode failure.
    pub fn get_block_by_hash(
        &self,
        block_hash: &Hash,
    ) -> Result<Option<CommittedBlock>, PersistentChainError> {
        self.storage
            .get_block_by_hash(block_hash)
            .map_err(PersistentChainError::Storage)
    }

    /// Locate a transaction by its tx_id — returns the containing block's
    /// height and the tx's index within that block.
    ///
    /// # Errors
    /// Returns [`PersistentChainError::Storage`] on read or decode failure.
    pub fn get_tx_location(
        &self,
        tx_id: &Hash,
    ) -> Result<Option<crate::storage::TxLocation>, PersistentChainError> {
        self.storage
            .get_tx_location(tx_id)
            .map_err(PersistentChainError::Storage)
    }
}

// ═══════════════════════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════════════════════

/// Errors raised by [`PersistentChain`] operations.
#[derive(Debug, thiserror::Error)]
pub enum PersistentChainError {
    /// Chain-level (in-memory validation) error.
    #[error("chain error: {0}")]
    Chain(#[from] ChainError),

    /// Storage-level error.
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),

    /// Tried to open a DB that has no genesis committed. Call `create`.
    #[error("no genesis block on disk — use PersistentChain::create to initialize")]
    NoGenesisOnDisk,

    /// DB claims height=N but block at N is missing.
    #[error("tip block missing at height {0} — database corruption")]
    TipMissing(u64),
}

// ═══════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{CommittedBlock, Vote};
    use crate::crypto::address::Address;
    use crate::crypto::keypair::Keypair;
    use crate::genesis::build_genesis_block;
    use crate::tx::{HYPHAE_PER_TFS, InscribePayload, SignedTransaction, Transaction, TransferPayload};
    use tempfile::TempDir;

    const CHAIN_ID: &str = "tfs-test-1";

    fn kp() -> Keypair {
        Keypair::generate()
    }

    fn sign_qc(validators: &[&Keypair], height: u64, block_hash: Hash, set: &ValidatorSet) -> QuorumCertificate {
        let votes = validators
            .iter()
            .map(|k| Vote::sign(height, block_hash, k))
            .collect();
        QuorumCertificate::new(height, block_hash, votes, set).expect("qc")
    }

    fn bootstrap_chain(dir: &TempDir) -> (PersistentChain, Keypair, Vec<Keypair>, ValidatorSet) {
        let president = kp();
        let v1 = kp();
        let v2 = kp();
        let set = ValidatorSet::new([
            president.public_key(),
            v1.public_key(),
            v2.public_key(),
        ])
        .expect("set");
        let block = build_genesis_block(CHAIN_ID, 1, &president).expect("g");
        let bh = block.hash().expect("bh");
        let qc = sign_qc(&[&president, &v1, &v2], 0, bh, &set);
        let chain = PersistentChain::create(
            dir.path(),
            CHAIN_ID,
            set.clone(),
            block,
            qc,
            1,
        )
        .expect("create");
        (chain, president, vec![v1, v2], set)
    }

    // ─── Create / Open ──────────────────────────────────────────────

    #[test]
    fn create_produces_height_zero_with_genesis_mint() {
        let dir = TempDir::new().unwrap();
        let (chain, president, _vs, _set) = bootstrap_chain(&dir);
        assert_eq!(chain.height(), 0);
        let pres_addr = Address::from_public_key(&president.public_key());
        assert_eq!(chain.state().balance(&pres_addr), 1_000 * HYPHAE_PER_TFS);
    }

    #[test]
    fn open_after_create_restores_state() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_path_buf();
        let pres_addr = {
            let (chain, president, _vs, _set) = bootstrap_chain(&dir);
            let a = Address::from_public_key(&president.public_key());
            assert_eq!(chain.height(), 0);
            assert_eq!(chain.state().balance(&a), 1_000 * HYPHAE_PER_TFS);
            a
        }; // drop the chain — release DB lock

        let reopened = PersistentChain::open(&path).expect("reopen");
        assert_eq!(reopened.height(), 0);
        assert_eq!(reopened.state().balance(&pres_addr), 1_000 * HYPHAE_PER_TFS);
        assert_eq!(reopened.chain_id(), CHAIN_ID);
    }

    #[test]
    fn open_rejects_empty_dir() {
        let dir = TempDir::new().unwrap();
        let err = PersistentChain::open(dir.path()).expect_err("empty");
        assert!(matches!(err, PersistentChainError::Storage(StorageError::DatabaseNotFound(_))));
    }

    // ─── Append + reopen ────────────────────────────────────────────

    #[test]
    fn append_then_reopen_preserves_state() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_path_buf();
        let (pres_addr, alice_addr) = {
            let (mut chain, president, vs, set) = bootstrap_chain(&dir);
            let alice = kp();
            let pres_addr = Address::from_public_key(&president.public_key());
            let alice_addr = Address::from_public_key(&alice.public_key());

            let tx = SignedTransaction::sign_single(
                Transaction::Transfer(TransferPayload {
                    from: pres_addr,
                    to: alice_addr,
                    amount_hyphae: 500,
                    nonce: 1,
                    timestamp_ms: 2,
                }),
                &president,
            )
            .unwrap();
            let tx_bytes = tx.to_bytes().unwrap();

            let b1 = crate::block::Block::propose(
                &chain.tip().block,
                CHAIN_ID,
                2,
                vec![tx_bytes],
                &president,
            )
            .unwrap();
            let bh1 = b1.hash().unwrap();
            let refs: Vec<&Keypair> = std::iter::once(&president).chain(vs.iter()).collect();
            let qc1 = sign_qc(&refs, 1, bh1, &set);
            let cb1 = CommittedBlock::new(b1, qc1, &set).unwrap();
            chain.append_committed_block(cb1, 2).unwrap();

            assert_eq!(chain.height(), 1);
            assert_eq!(chain.state().balance(&alice_addr), 500);
            (pres_addr, alice_addr)
        };

        // Reopen.
        let reopened = PersistentChain::open(&path).expect("reopen");
        assert_eq!(reopened.height(), 1);
        assert_eq!(reopened.state().balance(&alice_addr), 500);
        // President's balance: 1000 TFS minus 500 hyphae.
        assert_eq!(
            reopened.state().balance(&pres_addr),
            1_000 * HYPHAE_PER_TFS - 500
        );
    }

    #[test]
    fn historical_block_retrievable_after_reopen() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_path_buf();
        let bh0 = {
            let (chain, _president, _vs, _set) = bootstrap_chain(&dir);
            chain.tip().block.hash().unwrap()
        };
        let reopened = PersistentChain::open(&path).expect("reopen");
        let b0 = reopened.get_committed_block(0).unwrap().unwrap();
        assert_eq!(b0.block.hash().unwrap(), bh0);
        let by_hash = reopened.get_block_by_hash(&bh0).unwrap().unwrap();
        assert_eq!(b0, by_hash);
    }

    // ─── Validation still works (can't append wrong block) ──────────

    #[test]
    fn append_rejects_block_with_bad_height() {
        let dir = TempDir::new().unwrap();
        let (mut chain, president, vs, set) = bootstrap_chain(&dir);
        // Build a block pretending to be height 5 (genesis is height 0, next should be 1).
        let g = chain.tip().block.clone();
        let b1 = crate::block::Block::propose(&g, CHAIN_ID, 2, vec![], &president).unwrap();
        let b_future = crate::block::Block::propose(&b1, CHAIN_ID, 3, vec![], &president).unwrap();
        let bh = b_future.hash().unwrap();
        let refs: Vec<&Keypair> = std::iter::once(&president).chain(vs.iter()).collect();
        let qc = sign_qc(&refs, 2, bh, &set);
        let cb = CommittedBlock::new(b_future, qc, &set).unwrap();
        let err = chain.append_committed_block(cb, 3).expect_err("gap");
        assert!(matches!(err, PersistentChainError::Chain(_)));
        // State is unchanged — rollback occurred.
        assert_eq!(chain.height(), 0);
    }

    // ─── Determinism ────────────────────────────────────────────────

    #[test]
    fn two_persistent_chains_with_same_inputs_match() {
        let dir1 = TempDir::new().unwrap();
        let dir2 = TempDir::new().unwrap();
        // Use the SAME president + validator keys in both DBs.
        let president = kp();
        let v1 = kp();
        let v2 = kp();
        let set = ValidatorSet::new([
            president.public_key(),
            v1.public_key(),
            v2.public_key(),
        ])
        .expect("set");
        let mk = || {
            let block = build_genesis_block(CHAIN_ID, 1, &president).unwrap();
            let bh = block.hash().unwrap();
            let qc = sign_qc(&[&president, &v1, &v2], 0, bh, &set);
            (block, qc)
        };
        let (b_a, qc_a) = mk();
        let (b_b, qc_b) = mk();
        let chain_a = PersistentChain::create(dir1.path(), CHAIN_ID, set.clone(), b_a, qc_a, 1).unwrap();
        let chain_b = PersistentChain::create(dir2.path(), CHAIN_ID, set, b_b, qc_b, 1).unwrap();
        // Same state content — though RocksDB files differ, the logical state must match.
        assert_eq!(chain_a.state(), chain_b.state());
    }

    // ─── Inscribe + verify flow end-to-end ──────────────────────────

    #[test]
    fn sigil_bind_then_reopen_preserves_binding_and_allowance() {
        use crate::tx::SigilBindPayload;

        let dir = TempDir::new().unwrap();
        let path = dir.path().to_path_buf();
        let (citizen_addr, citizen) = {
            let (mut chain, president, vs, set) = bootstrap_chain(&dir);
            let citizen = kp();
            let citizen_addr = Address::from_public_key(&citizen.public_key());

            let sigil_tx = SignedTransaction::sign_single(
                Transaction::SigilBind(SigilBindPayload::new(
                    "IAMBIGRAPPER1".to_string(),
                    citizen_addr,
                    0,
                    2,
                )),
                &citizen,
            )
            .unwrap();

            let b1 = crate::block::Block::propose(
                &chain.tip().block,
                CHAIN_ID,
                2,
                vec![sigil_tx.to_bytes().unwrap()],
                &president,
            )
            .unwrap();
            let bh1 = b1.hash().unwrap();
            let refs: Vec<&Keypair> = std::iter::once(&president).chain(vs.iter()).collect();
            let qc1 = sign_qc(&refs, 1, bh1, &set);
            let cb1 = CommittedBlock::new(b1, qc1, &set).unwrap();
            chain.append_committed_block(cb1, 2).unwrap();

            (citizen_addr, citizen)
        };
        let _ = citizen; // keep keypair alive until after block commit

        // Reopen.
        let reopened = PersistentChain::open(&path).expect("reopen");
        assert_eq!(
            reopened.state().address_of_sigil("IAMBIGRAPPER1"),
            Some(&citizen_addr)
        );
        assert_eq!(
            reopened.state().sigil_of(&citizen_addr),
            Some(&"IAMBIGRAPPER1".to_string())
        );
        // Onboarding allowance persisted.
        assert_eq!(
            reopened.state().balance(&citizen_addr),
            1_000 * HYPHAE_PER_TFS
        );
        // Sigil count persisted.
        assert_eq!(reopened.state().sigil_count(), 1);
    }

    #[test]
    fn inscribe_then_reopen_preserves_doctrine_and_reward() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_path_buf();
        let (pres_addr, doctrine_hash) = {
            let (mut chain, president, vs, set) = bootstrap_chain(&dir);
            let pres_addr = Address::from_public_key(&president.public_key());

            // Inscribe a second doctrine at height 1.
            let inscribe = SignedTransaction::sign_single(
                Transaction::Inscribe(InscribePayload::new(
                    pres_addr,
                    b"second scroll".to_vec(),
                    1,
                    2,
                )),
                &president,
            )
            .unwrap();
            let dh = if let Transaction::Inscribe(ref ip) = inscribe.tx {
                ip.doctrine_hash
            } else {
                panic!("not inscribe");
            };
            let b1 = crate::block::Block::propose(
                &chain.tip().block,
                CHAIN_ID,
                2,
                vec![inscribe.to_bytes().unwrap()],
                &president,
            )
            .unwrap();
            let bh1 = b1.hash().unwrap();
            let refs: Vec<&Keypair> = std::iter::once(&president).chain(vs.iter()).collect();
            let qc1 = sign_qc(&refs, 1, bh1, &set);
            let cb1 = CommittedBlock::new(b1, qc1, &set).unwrap();
            chain.append_committed_block(cb1, 2).unwrap();

            (pres_addr, dh)
        };

        let reopened = PersistentChain::open(&path).unwrap();
        // Two doctrines total (genesis + second).
        assert_eq!(reopened.state().doctrine_count, 2);
        // The second doctrine is in the inscribed set.
        assert!(reopened.state().inscribed_doctrines.contains(&doctrine_hash));
        // President has 2000 TFS (1000 from genesis + 1000 from second inscription).
        assert_eq!(
            reopened.state().balance(&pres_addr),
            2_000 * HYPHAE_PER_TFS
        );
    }
}
