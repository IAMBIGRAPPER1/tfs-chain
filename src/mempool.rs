// TFS_CHAIN · mempool.rs · Layer 5
//
// THE ANTECHAMBER OF THE CHAIN.
//
// Before a transaction is sealed into a block, it waits in the mempool.
// This is the proposer's working set — the pile of signed intent from
// which the next block is drawn.
//
// Design posture:
//
//   - DETERMINISTIC ITERATION. BTreeMap keyed by tx_id gives identical
//     traversal order on every node. Critical for multiple validators
//     producing IDENTICAL block proposals from identical mempools.
//
//   - BOUNDED CAPACITY. A malicious actor cannot flood the mempool
//     unbounded. `max_size` hard-caps storage. `max_per_address` prevents
//     one account from monopolizing slots.
//
//   - EARLY REJECTION. Layer 3 structural validation runs at admission.
//     Bad signatures, bad amounts, bad structure → never even queue.
//
//   - STATE-AWARE ADMISSION. If a tx's nonce is already BEHIND the
//     account's current nonce in state, it's reject-at-admit (it would
//     only fail later anyway). A future nonce is accepted — the tx can
//     become valid after earlier nonces fill in.
//
//   - STATE-AWARE SELECTION. When building a block, we walk the mempool
//     in tx_id order and ADMIT only txs whose current-state preconditions
//     still hold. This simulates the would-be apply path without mutating
//     real state.
//
//   - NO FLOATS, NO HASH-MAP. Consensus-critical code is purely integer
//     and purely deterministic.
//
// THREAT MODEL:
//   - Flood attack (infinite txs)           → MAX_SIZE hard cap
//   - Per-account flood (single signer DoS) → MAX_PER_ADDRESS cap
//   - Replay via mempool                    → tx_id dedup on insert
//   - Obsolete-nonce lingering              → prune() after block apply
//   - Oversized tx bytes                    → inherited from Layer 2/3 limits
//   - Non-deterministic block proposals     → BTreeMap + sort key discipline

//! The mempool — pending transactions awaiting inclusion.
//!
//! Construct with [`Mempool::new`]. Admit with [`Mempool::insert`].
//! When proposing a block, call [`Mempool::select_for_block`] to draw
//! a deterministic, state-consistent batch.
//!
//! After a block is applied, call [`Mempool::prune`] to evict txs that
//! are now obsolete (nonces used) or otherwise impossible to apply.

use std::collections::BTreeMap;

use crate::crypto::{
    address::Address,
    hash::{Hash, HashError},
};
use crate::state::State;
use crate::tx::{SignedTransaction, TxError};

// ═══════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════

/// Default cap on total mempool size. 16,384 pending transactions.
/// At ~500 bytes/tx that's roughly 8 MiB of pending bytes — manageable
/// for a single node's working set.
pub const DEFAULT_MAX_MEMPOOL_SIZE: usize = 16_384;

/// Default cap on pending transactions per source address. 64.
/// One citizen cannot reserve more than 64 future slots. This also
/// bounds per-address nonce-gap attacks.
pub const DEFAULT_MAX_PER_ADDRESS: usize = 64;

// ═══════════════════════════════════════════════════════════════════
// MEMPOOL
// ═══════════════════════════════════════════════════════════════════

/// A pending-transaction pool, keyed by transaction ID for deterministic
/// iteration.
///
/// All accessors are deterministic across platforms — identical inputs
/// produce identical outputs. This is a load-bearing property: validators
/// must be able to propose identical blocks from identical mempools.
#[derive(Debug, Clone)]
pub struct Mempool {
    /// Pending transactions indexed by tx_id. `BTreeMap` gives deterministic
    /// iteration order.
    txs: BTreeMap<Hash, SignedTransaction>,

    /// Count of pending txs per primary address. Used to enforce
    /// per-address quotas without scanning the whole map.
    per_address_count: BTreeMap<Address, usize>,

    /// Hard cap on total pending txs.
    max_size: usize,

    /// Hard cap on per-address pending txs.
    max_per_address: usize,
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_MEMPOOL_SIZE, DEFAULT_MAX_PER_ADDRESS)
    }
}

impl Mempool {
    /// Construct a new, empty mempool with the given capacity limits.
    #[must_use]
    pub const fn new(max_size: usize, max_per_address: usize) -> Self {
        Self {
            txs: BTreeMap::new(),
            per_address_count: BTreeMap::new(),
            max_size,
            max_per_address,
        }
    }

    /// Current number of pending transactions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.txs.len()
    }

    /// True if the mempool has no pending transactions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    /// Check whether a tx with this ID is already in the mempool.
    #[must_use]
    pub fn contains(&self, tx_id: &Hash) -> bool {
        self.txs.contains_key(tx_id)
    }

    /// Return a reference to a pending transaction by its ID.
    #[must_use]
    pub fn get(&self, tx_id: &Hash) -> Option<&SignedTransaction> {
        self.txs.get(tx_id)
    }

    // ───────────────────────────────────────────────────────────────
    // ADMISSION
    // ───────────────────────────────────────────────────────────────

    /// Admit a signed transaction to the mempool.
    ///
    /// Performs:
    /// 1. Structural validation ([`SignedTransaction::validate_structure`]).
    /// 2. Duplicate-by-ID rejection.
    /// 3. Capacity check (global and per-address).
    /// 4. Obsolete-nonce rejection against the given current state
    ///    (tx nonce must be >= account's next-expected nonce).
    ///
    /// # Errors
    /// Returns [`MempoolError`] describing the first failure.
    pub fn insert(
        &mut self,
        stx: SignedTransaction,
        state: &State,
    ) -> Result<Hash, MempoolError> {
        // 1. Structural validation — signature, shape, quorum rules.
        stx.validate_structure().map_err(MempoolError::Tx)?;

        // 2. Compute tx_id for dedup.
        let tx_id = stx.tx_id().map_err(MempoolError::Hash)?;
        if self.txs.contains_key(&tx_id) {
            return Err(MempoolError::DuplicateTransaction(tx_id));
        }

        // 3. Obsolete nonce check.
        let primary = *stx.tx.primary_address();
        let expected_nonce = state.nonce(&primary);
        if stx.tx.nonce() < expected_nonce {
            return Err(MempoolError::ObsoleteNonce {
                address: primary,
                min: expected_nonce,
                actual: stx.tx.nonce(),
            });
        }

        // 4. Capacity — global.
        if self.txs.len() >= self.max_size {
            return Err(MempoolError::Full {
                capacity: self.max_size,
            });
        }

        // 5. Capacity — per address.
        let existing = self.per_address_count.get(&primary).copied().unwrap_or(0);
        if existing >= self.max_per_address {
            return Err(MempoolError::AddressFull {
                address: primary,
                capacity: self.max_per_address,
            });
        }

        // All checks passed. Commit.
        self.per_address_count.insert(primary, existing + 1);
        self.txs.insert(tx_id, stx);
        Ok(tx_id)
    }

    // ───────────────────────────────────────────────────────────────
    // REMOVAL
    // ───────────────────────────────────────────────────────────────

    /// Remove and return a transaction by its ID, if present.
    ///
    /// Keeps the per-address counter in sync.
    pub fn remove(&mut self, tx_id: &Hash) -> Option<SignedTransaction> {
        let stx = self.txs.remove(tx_id)?;
        let primary = *stx.tx.primary_address();
        if let Some(count) = self.per_address_count.get_mut(&primary) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.per_address_count.remove(&primary);
            }
        }
        Some(stx)
    }

    /// Remove all transactions whose primary address has nonce strictly
    /// less than the account's current-state next-expected nonce.
    ///
    /// Call after applying a block — the block's included txs have
    /// consumed their nonces, and the mempool must forget them.
    ///
    /// Returns the number of txs removed.
    pub fn prune(&mut self, state: &State) -> usize {
        // Collect IDs first to avoid mutating while iterating.
        let obsolete: Vec<Hash> = self
            .txs
            .iter()
            .filter_map(|(id, stx)| {
                let primary = stx.tx.primary_address();
                let expected = state.nonce(primary);
                if stx.tx.nonce() < expected {
                    Some(*id)
                } else {
                    None
                }
            })
            .collect();

        let n = obsolete.len();
        for id in obsolete {
            self.remove(&id);
        }
        n
    }

    /// Empty the mempool completely.
    pub fn clear(&mut self) {
        self.txs.clear();
        self.per_address_count.clear();
    }

    // ───────────────────────────────────────────────────────────────
    // BLOCK SELECTION
    // ───────────────────────────────────────────────────────────────

    /// Select up to `max_count` transactions for the next block, in a
    /// deterministic order that would succeed if applied against the
    /// provided `state`.
    ///
    /// Algorithm:
    /// 1. Group pending txs by primary address.
    /// 2. Within each address, sort by ascending nonce.
    /// 3. Iterate addresses in deterministic order (BTreeMap gives us this).
    /// 4. For each address, admit txs whose nonce exactly matches the
    ///    simulated next-nonce for that address, incrementing as we go.
    ///    A gap (e.g. account has nonce 3, mempool has 4 and 6 but not 5)
    ///    stops that address at its continuous prefix.
    ///
    /// This strategy guarantees:
    /// - Every selected tx would pass the nonce check against `state`.
    /// - Selections are deterministic: same mempool + same state ⇒ same
    ///   ordered output on every node.
    /// - No address gets to cut in line over another; round-robin is
    ///   implicit via address ordering.
    ///
    /// NOTE: This does NOT simulate balance/burn impact across txs — that
    /// is the state-apply's responsibility. Balance-failing txs in a
    /// selected block will cause [`State::apply_block`] to reject the
    /// whole block, which the proposer must re-plan around. For Layer 5
    /// correctness, we accept this conservative tradeoff: richer simulation
    /// is a future optimization.
    #[must_use]
    pub fn select_for_block(
        &self,
        max_count: usize,
        state: &State,
    ) -> Vec<SignedTransaction> {
        if max_count == 0 || self.txs.is_empty() {
            return Vec::new();
        }

        // Group by primary address, sorted by nonce within group.
        let mut by_addr: BTreeMap<Address, Vec<&SignedTransaction>> = BTreeMap::new();
        for stx in self.txs.values() {
            by_addr
                .entry(*stx.tx.primary_address())
                .or_default()
                .push(stx);
        }
        for group in by_addr.values_mut() {
            group.sort_by_key(|s| s.tx.nonce());
        }

        // Walk addresses in sorted order. For each, take txs whose nonce
        // exactly matches simulated next-nonce.
        let mut out: Vec<SignedTransaction> = Vec::with_capacity(max_count.min(self.txs.len()));
        for (addr, group) in by_addr {
            if out.len() >= max_count {
                break;
            }
            let mut next_nonce = state.nonce(&addr);
            for stx in group {
                if out.len() >= max_count {
                    break;
                }
                if stx.tx.nonce() == next_nonce {
                    out.push(stx.clone());
                    next_nonce = match next_nonce.checked_add(1) {
                        Some(n) => n,
                        None => break,
                    };
                } else if stx.tx.nonce() > next_nonce {
                    // Gap — stop this address.
                    break;
                }
                // tx.nonce() < next_nonce should be impossible at this point
                // (prune removes them), but we silently skip for safety.
            }
        }

        out
    }

    // ───────────────────────────────────────────────────────────────
    // DIAGNOSTICS
    // ───────────────────────────────────────────────────────────────

    /// Return an iterator over all pending transactions in deterministic
    /// order (by tx_id).
    pub fn iter(&self) -> impl Iterator<Item = (&Hash, &SignedTransaction)> {
        self.txs.iter()
    }

    /// Return the number of pending transactions for a given address.
    #[must_use]
    pub fn pending_for(&self, addr: &Address) -> usize {
        self.per_address_count.get(addr).copied().unwrap_or(0)
    }
}

// ═══════════════════════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════════════════════

/// Errors that can occur during mempool admission.
#[derive(Debug, thiserror::Error)]
pub enum MempoolError {
    /// Transaction failed Layer 3 structural validation.
    #[error("transaction invalid: {0}")]
    Tx(#[from] TxError),

    /// A transaction with this ID is already queued.
    #[error("duplicate transaction in mempool: {0}")]
    DuplicateTransaction(Hash),

    /// Nonce is already behind what state expects — tx can never apply.
    #[error("obsolete nonce for {address}: min {min}, got {actual}")]
    ObsoleteNonce {
        /// The address whose nonce is stale.
        address: Address,
        /// The next-expected nonce per current state.
        min: u64,
        /// The tx's nonce.
        actual: u64,
    },

    /// Mempool is at global capacity.
    #[error("mempool full at {capacity} transactions")]
    Full {
        /// The configured capacity.
        capacity: usize,
    },

    /// Per-address slot quota exhausted.
    #[error("address {address} is at mempool quota ({capacity})")]
    AddressFull {
        /// The address that hit its cap.
        address: Address,
        /// The configured per-address cap.
        capacity: usize,
    },

    /// Hash/serialize error computing the tx_id.
    #[error("hash error: {0}")]
    Hash(#[from] HashError),
}

// ═══════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keypair::Keypair;
    use crate::tx::{InscribePayload, Transaction, TransferPayload, VerifyPayload};

    fn kp() -> Keypair {
        Keypair::generate()
    }

    fn addr(k: &Keypair) -> Address {
        Address::from_public_key(&k.public_key())
    }

    fn funded_state(who: &Address, amount: u64) -> State {
        let mut s = State::new();
        s.balances.insert(*who, amount);
        s
    }

    fn transfer(
        from_kp: &Keypair,
        to: Address,
        amount: u64,
        nonce: u64,
    ) -> SignedTransaction {
        SignedTransaction::sign_single(
            Transaction::Transfer(TransferPayload {
                from: addr(from_kp),
                to,
                amount_hyphae: amount,
                nonce,
                timestamp_ms: 1,
            }),
            from_kp,
        )
        .expect("sign")
    }

    // ─── Admission ──────────────────────────────────────────────────

    #[test]
    fn insert_admits_valid_tx() {
        let alice = kp();
        let bob = kp();
        let state = funded_state(&addr(&alice), 1_000);
        let mut mp = Mempool::default();
        let tx = transfer(&alice, addr(&bob), 100, 0);
        let id = mp.insert(tx, &state).expect("admit");
        assert_eq!(mp.len(), 1);
        assert!(mp.contains(&id));
    }

    #[test]
    fn insert_rejects_duplicate() {
        let alice = kp();
        let bob = kp();
        let state = funded_state(&addr(&alice), 1_000);
        let mut mp = Mempool::default();
        let tx = transfer(&alice, addr(&bob), 100, 0);
        mp.insert(tx.clone(), &state).expect("first");
        let err = mp.insert(tx, &state).expect_err("dup");
        assert!(matches!(err, MempoolError::DuplicateTransaction(_)));
    }

    #[test]
    fn insert_rejects_obsolete_nonce() {
        let alice = kp();
        let bob = kp();
        // State already at nonce 5 for alice.
        let mut state = funded_state(&addr(&alice), 1_000);
        state.nonces.insert(addr(&alice), 5);
        let mut mp = Mempool::default();
        let tx = transfer(&alice, addr(&bob), 1, 2); // nonce 2 < 5
        let err = mp.insert(tx, &state).expect_err("obsolete");
        assert!(matches!(err, MempoolError::ObsoleteNonce { .. }));
    }

    #[test]
    fn insert_accepts_future_nonce() {
        // Admission should allow gaps — a proposer can fill in later.
        let alice = kp();
        let bob = kp();
        let state = funded_state(&addr(&alice), 1_000);
        let mut mp = Mempool::default();
        let tx = transfer(&alice, addr(&bob), 1, 10); // future
        mp.insert(tx, &state).expect("admit future");
        assert_eq!(mp.len(), 1);
    }

    #[test]
    fn insert_rejects_structurally_invalid() {
        let alice = kp();
        let mut state = State::new();
        state.balances.insert(addr(&alice), 1_000);
        let mut mp = Mempool::default();
        // Transfer to self — Layer 3 rejects.
        let tx = SignedTransaction::sign_single(
            Transaction::Transfer(TransferPayload {
                from: addr(&alice),
                to: addr(&alice),
                amount_hyphae: 1,
                nonce: 0,
                timestamp_ms: 1,
            }),
            &alice,
        )
        .expect("sign");
        let err = mp.insert(tx, &state).expect_err("self transfer");
        assert!(matches!(err, MempoolError::Tx(_)));
    }

    #[test]
    fn insert_enforces_global_cap() {
        let alice = kp();
        let bob = kp();
        let state = funded_state(&addr(&alice), 10_000);
        // Small cap for the test.
        let mut mp = Mempool::new(2, 64);
        mp.insert(transfer(&alice, addr(&bob), 1, 0), &state).expect("1");
        mp.insert(transfer(&alice, addr(&bob), 1, 1), &state).expect("2");
        let err = mp
            .insert(transfer(&alice, addr(&bob), 1, 2), &state)
            .expect_err("full");
        assert!(matches!(err, MempoolError::Full { .. }));
    }

    #[test]
    fn insert_enforces_per_address_cap() {
        let alice = kp();
        let bob = kp();
        let state = funded_state(&addr(&alice), 10_000);
        let mut mp = Mempool::new(1_000, 2);
        mp.insert(transfer(&alice, addr(&bob), 1, 0), &state).expect("1");
        mp.insert(transfer(&alice, addr(&bob), 1, 1), &state).expect("2");
        let err = mp
            .insert(transfer(&alice, addr(&bob), 1, 2), &state)
            .expect_err("per-address");
        assert!(matches!(err, MempoolError::AddressFull { .. }));
    }

    // ─── Removal / prune ────────────────────────────────────────────

    #[test]
    fn remove_drops_tx_and_updates_counter() {
        let alice = kp();
        let bob = kp();
        let state = funded_state(&addr(&alice), 1_000);
        let mut mp = Mempool::default();
        let id = mp.insert(transfer(&alice, addr(&bob), 1, 0), &state).expect("1");
        assert_eq!(mp.pending_for(&addr(&alice)), 1);
        mp.remove(&id).expect("present");
        assert_eq!(mp.len(), 0);
        assert_eq!(mp.pending_for(&addr(&alice)), 0);
    }

    #[test]
    fn prune_evicts_obsolete() {
        let alice = kp();
        let bob = kp();
        let state = funded_state(&addr(&alice), 10_000);
        let mut mp = Mempool::default();
        mp.insert(transfer(&alice, addr(&bob), 1, 0), &state).expect("n0");
        mp.insert(transfer(&alice, addr(&bob), 1, 1), &state).expect("n1");
        mp.insert(transfer(&alice, addr(&bob), 1, 2), &state).expect("n2");

        // Simulate state advancing past nonce 1.
        let mut new_state = state.clone();
        new_state.nonces.insert(addr(&alice), 2);

        let evicted = mp.prune(&new_state);
        assert_eq!(evicted, 2); // n0 and n1 gone
        assert_eq!(mp.len(), 1);
    }

    // ─── Selection ──────────────────────────────────────────────────

    #[test]
    fn select_picks_contiguous_nonces() {
        let alice = kp();
        let bob = kp();
        let state = funded_state(&addr(&alice), 10_000);
        let mut mp = Mempool::default();
        mp.insert(transfer(&alice, addr(&bob), 1, 0), &state).expect("n0");
        mp.insert(transfer(&alice, addr(&bob), 1, 1), &state).expect("n1");
        mp.insert(transfer(&alice, addr(&bob), 1, 2), &state).expect("n2");

        let picked = mp.select_for_block(10, &state);
        assert_eq!(picked.len(), 3);
        // Must be in ascending nonce order for the same address.
        assert_eq!(picked[0].tx.nonce(), 0);
        assert_eq!(picked[1].tx.nonce(), 1);
        assert_eq!(picked[2].tx.nonce(), 2);
    }

    #[test]
    fn select_stops_at_gap() {
        let alice = kp();
        let bob = kp();
        let state = funded_state(&addr(&alice), 10_000);
        let mut mp = Mempool::default();
        mp.insert(transfer(&alice, addr(&bob), 1, 0), &state).expect("n0");
        // Skip nonce 1.
        mp.insert(transfer(&alice, addr(&bob), 1, 2), &state).expect("n2");
        mp.insert(transfer(&alice, addr(&bob), 1, 3), &state).expect("n3");

        let picked = mp.select_for_block(10, &state);
        // Only nonce 0 should be pickable — gap at 1 blocks 2 and 3.
        assert_eq!(picked.len(), 1);
        assert_eq!(picked[0].tx.nonce(), 0);
    }

    #[test]
    fn select_is_deterministic() {
        let alice = kp();
        let bob_kp = kp();
        let carol = kp();
        let mut state = State::new();
        state.balances.insert(addr(&alice), 10_000);
        state.balances.insert(addr(&carol), 10_000);

        let mut mp1 = Mempool::default();
        let mut mp2 = Mempool::default();

        // Insert in OPPOSITE orders.
        mp1.insert(transfer(&alice, addr(&bob_kp), 1, 0), &state).unwrap();
        mp1.insert(transfer(&carol, addr(&bob_kp), 1, 0), &state).unwrap();
        mp1.insert(transfer(&alice, addr(&bob_kp), 1, 1), &state).unwrap();

        mp2.insert(transfer(&alice, addr(&bob_kp), 1, 1), &state).unwrap();
        mp2.insert(transfer(&carol, addr(&bob_kp), 1, 0), &state).unwrap();
        mp2.insert(transfer(&alice, addr(&bob_kp), 1, 0), &state).unwrap();

        let pick1 = mp1.select_for_block(10, &state);
        let pick2 = mp2.select_for_block(10, &state);
        // Same txs must come out in same order regardless of insertion order.
        let ids1: Vec<_> = pick1.iter().map(|s| s.tx_id().unwrap()).collect();
        let ids2: Vec<_> = pick2.iter().map(|s| s.tx_id().unwrap()).collect();
        assert_eq!(ids1, ids2);
    }

    #[test]
    fn select_respects_max_count() {
        let alice = kp();
        let bob = kp();
        let state = funded_state(&addr(&alice), 10_000);
        let mut mp = Mempool::default();
        for n in 0..5 {
            mp.insert(transfer(&alice, addr(&bob), 1, n), &state).expect("ok");
        }
        let picked = mp.select_for_block(3, &state);
        assert_eq!(picked.len(), 3);
    }

    #[test]
    fn select_empty_mempool_empty_output() {
        let state = State::new();
        let mp = Mempool::default();
        let picked = mp.select_for_block(10, &state);
        assert!(picked.is_empty());
    }

    #[test]
    fn select_zero_max_empty_output() {
        let alice = kp();
        let bob = kp();
        let state = funded_state(&addr(&alice), 10_000);
        let mut mp = Mempool::default();
        mp.insert(transfer(&alice, addr(&bob), 1, 0), &state).expect("ok");
        let picked = mp.select_for_block(0, &state);
        assert!(picked.is_empty());
    }

    // ─── Mixed variants ─────────────────────────────────────────────

    #[test]
    fn select_handles_inscribe_and_verify() {
        let president = kp();
        let subject = kp();
        let v1 = kp();
        let v2 = kp();
        let v3 = kp();
        let state = State::new();

        let inscribe = SignedTransaction::sign_single(
            Transaction::Inscribe(InscribePayload::new(
                addr(&president),
                b"doctrine".to_vec(),
                0,
                1,
            )),
            &president,
        )
        .expect("sign inscribe");

        let verify = SignedTransaction::sign_verify(
            Transaction::Verify(VerifyPayload {
                verified: addr(&subject),
                nonce: 0,
                timestamp_ms: 1,
            }),
            &[&v1, &v2, &v3],
        )
        .expect("sign verify");

        let mut mp = Mempool::default();
        mp.insert(inscribe, &state).expect("inscribe");
        mp.insert(verify, &state).expect("verify");
        let picked = mp.select_for_block(10, &state);
        assert_eq!(picked.len(), 2);
    }
}
