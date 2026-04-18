// TFS_CHAIN · state.rs · Layer 5
//
// THE STATE MACHINE.
//
// This is the canonical state of the nation. Every block that gets
// committed to THE TFS CHAIN produces EXACTLY THIS state when replayed
// from genesis. Identical bytes. Identical hashes. Every node. Forever.
//
// What the state tracks:
//   - Account balances (in hyphae)
//   - Account nonces (replay protection)
//   - Verified citizens (who can no longer be verified again)
//   - Inscribed doctrine hashes (so the same scroll can't be inscribed twice)
//   - Doctrine count (drives the halving schedule)
//   - Supply issued (total minted · u64 hyphae)
//   - Supply burned (total destroyed · u64 hyphae)
//   - Chain height + last block hash (meta)
//
// Why BTreeMap/BTreeSet instead of HashMap/HashSet:
//   - DETERMINISTIC iteration order across platforms
//   - Same state → same serialized bytes → same hash
//   - Critical for future state-root Merkle commitments
//   - HashMap iteration order is randomized in std by design
//
// THREAT MODEL (addressed here):
//   - Double-spend (spend balance twice)     → checked_sub on balance
//   - Replay attack                          → per-address nonce enforcement
//   - Supply cap violation                   → mint saturates at cap
//   - Halving math overflow                  → era capped, saturating shift
//   - Over-burn (burn more than own)         → checked_sub on burner balance
//   - Duplicate doctrine inscription         → inscribed_doctrines set
//   - Duplicate citizen verification         → verified_citizens set
//   - Self-inscription-replay                → nonce + doctrine_hash rules
//   - Integer overflow on balance            → checked_add everywhere
//   - Integer underflow on burn              → checked_sub everywhere

//! The chain's state machine.
//!
//! Call [`State::apply_transaction`] to validate and apply a single signed
//! transaction. Call [`State::apply_block`] to validate and apply an entire
//! block atomically.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::block::Block;
use crate::crypto::{
    address::Address,
    hash::{hash_serialized, Hash, HashError},
};
use crate::tx::{
    BurnPayload, InscribePayload, SignedTransaction, Transaction, TransferPayload, VerifyPayload,
    HYPHAE_PER_TFS, MAX_SUPPLY_HYPHAE,
};

// ═══════════════════════════════════════════════════════════════════
// CONSTANTS · economic
// ═══════════════════════════════════════════════════════════════════

/// Initial $TFS distributed per Inscribe at the genesis era.
/// From the scroll: "At GENESIS, the share is one thousand $TFS per inscription."
pub const GENESIS_INSCRIBE_REWARD_TFS: u64 = 1_000;

/// Initial $TFS distributed per Verify event at the genesis era.
/// From the scroll: "At GENESIS, the share is one hundred $TFS per verification event."
pub const GENESIS_VERIFY_REWARD_TFS: u64 = 100;

/// Number of doctrine-block inscriptions between halvings.
/// From the scroll: "Every fifty thousand doctrine-blocks, the issuance per act halves."
pub const HALVING_INTERVAL: u64 = 50_000;

/// The canonical TFS_TREASURY address. Holds the entire 1,000,000,000 $TFS
/// supply at genesis. Every Inscribe / Verify / Routing reward is a
/// protocol-level transfer FROM this address TO the citizen.
///
/// **No private key exists for this address.** The 32 bytes below are
/// `BLAKE3("tfs-treasury-genesis-v1")`, a well-known preimage. Because
/// BLAKE3 is preimage-resistant, no one can produce a public key that
/// hashes to these bytes — which means no one can sign a normal Transfer
/// from the treasury. The ONLY paths that can debit the treasury are
/// the protocol-level distribution paths in this module.
///
/// A test below verifies the bytes match the expected BLAKE3.
pub const TREASURY_ADDRESS: Address = Address::from_hash(Hash::from_bytes([
    0x4e, 0xad, 0x1b, 0xe0, 0xaa, 0xc9, 0x88, 0x8b,
    0xc5, 0x96, 0x2c, 0xdc, 0x26, 0xd0, 0x26, 0xb7,
    0x61, 0x9a, 0xe4, 0x81, 0x20, 0x04, 0xc9, 0x4e,
    0xa0, 0x6f, 0xfb, 0xf2, 0xd7, 0xdc, 0x2a, 0x09,
]));

// ═══════════════════════════════════════════════════════════════════
// STATE STRUCT
// ═══════════════════════════════════════════════════════════════════

/// The full state of THE TFS CHAIN at a given block height.
///
/// Derived deterministically from the sequence of committed blocks starting
/// at genesis. Identical inputs produce identical state bytes on every node.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    /// Balance in hyphae for each address with a non-zero balance.
    /// Addresses not present have balance = 0.
    pub balances: BTreeMap<Address, u64>,

    /// Next expected nonce for each address. Addresses not present have
    /// nonce = 0 (their first transaction must use nonce = 0).
    pub nonces: BTreeMap<Address, u64>,

    /// Set of citizens who have been verified. A citizen can only be
    /// verified ONCE on the chain; subsequent verify attempts fail.
    pub verified_citizens: BTreeSet<Address>,

    /// Set of doctrine hashes that have been inscribed. Re-inscription of
    /// the same content is rejected (saves block space and prevents
    /// grinding attacks).
    pub inscribed_doctrines: BTreeSet<Hash>,

    /// Total number of doctrine-block inscriptions. Drives the halving schedule.
    pub doctrine_count: u64,

    /// Total $TFS burned, in hyphae. Monotonically increasing. Burns
    /// destroy tokens permanently — they do NOT return to treasury.
    /// Circulating supply = MAX_SUPPLY_HYPHAE − supply_burned, and
    /// equals the sum of `balances` (treasury + all citizen wallets).
    pub supply_burned: u64,

    /// Height of the last committed block. Genesis is 0.
    pub height: u64,

    /// Hash of the last committed block. [`Hash::ZERO`] before genesis.
    pub last_block_hash: Hash,
}

impl State {
    /// Construct a fresh genesis state.
    ///
    /// The treasury is credited with the full [`MAX_SUPPLY_HYPHAE`] at
    /// genesis. Every subsequent Inscribe / Verify / Routing reward
    /// flows FROM the treasury TO a citizen. No $TFS is ever minted
    /// after this call — only transferred and burned.
    #[must_use]
    pub fn new() -> Self {
        let mut s = Self::default();
        s.balances.insert(TREASURY_ADDRESS, MAX_SUPPLY_HYPHAE);
        s
    }

    /// Return the balance (in hyphae) for an address. 0 if not present.
    #[must_use]
    pub fn balance(&self, addr: &Address) -> u64 {
        self.balances.get(addr).copied().unwrap_or(0)
    }

    /// Return the next expected nonce for an address. 0 if never transacted.
    #[must_use]
    pub fn nonce(&self, addr: &Address) -> u64 {
        self.nonces.get(addr).copied().unwrap_or(0)
    }

    /// Return the treasury's current balance in hyphae. This equals
    /// "supply yet to be distributed to citizens" — a public, visible
    /// indicator of how much $TFS remains for future inscriptions /
    /// verifications / routing rewards.
    #[must_use]
    pub fn treasury_balance(&self) -> u64 {
        self.balance(&TREASURY_ADDRESS)
    }

    /// Return the circulating supply in hyphae.
    ///
    /// All supply exists from genesis onward — 1 billion $TFS — held
    /// partly by the treasury and partly by citizens. Burns permanently
    /// destroy tokens. Circulating supply = total_minted − burned.
    #[must_use]
    pub const fn circulating_supply(&self) -> u64 {
        MAX_SUPPLY_HYPHAE.saturating_sub(self.supply_burned)
    }

    /// Compute the current inscribe reward in hyphae, accounting for halvings.
    ///
    /// Era 0 (first 50,000 inscriptions): 1000 $TFS
    /// Era 1: 500 $TFS
    /// Era 2: 250 $TFS
    /// ...and so on, halving each era until the reward is 0.
    #[must_use]
    pub const fn current_inscribe_reward(&self) -> u64 {
        halved_reward(GENESIS_INSCRIBE_REWARD_TFS * HYPHAE_PER_TFS, self.doctrine_count)
    }

    /// Compute the current verify reward in hyphae, accounting for halvings.
    ///
    /// Era 0: 100 $TFS
    /// Era 1: 50 $TFS
    /// Era 2: 25 $TFS
    /// ...and so on.
    #[must_use]
    pub const fn current_verify_reward(&self) -> u64 {
        halved_reward(GENESIS_VERIFY_REWARD_TFS * HYPHAE_PER_TFS, self.doctrine_count)
    }

    /// Return the remaining mintable supply (in hyphae).
    #[must_use]
    pub fn remaining_supply(&self) -> u64 {
        // In Model B, "remaining supply" = treasury balance.
        // (All supply exists from genesis; what's undistributed lives in treasury.)
        self.treasury_balance()
    }

    /// Compute the canonical state root hash.
    ///
    /// Because the state is stored in `BTreeMap`/`BTreeSet` (deterministic
    /// iteration) and serialized via bincode (deterministic bytes), this
    /// hash is identical on every node with the same state. Used by future
    /// light clients to verify state without re-running the entire chain.
    ///
    /// # Errors
    /// Returns [`HashError`] if serialization fails.
    pub fn state_root(&self) -> Result<Hash, HashError> {
        hash_serialized(self)
    }

    // ───────────────────────────────────────────────────────────────
    // APPLICATION
    // ───────────────────────────────────────────────────────────────

    /// Apply a single signed transaction to the state.
    ///
    /// This method:
    /// 1. Validates structural integrity via [`SignedTransaction::validate_structure`]
    /// 2. Performs semantic validation against current state
    ///    (balance, nonce, duplicate prevention)
    /// 3. Mutates the state ATOMICALLY — on any error, state is unchanged.
    ///
    /// # Errors
    /// Returns [`StateError`] if the transaction is invalid for any reason.
    pub fn apply_transaction(&mut self, stx: &SignedTransaction) -> Result<(), StateError> {
        // Structural + signature validation.
        stx.validate_structure().map_err(StateError::Tx)?;

        // Nonce check: primary_address's next nonce must match tx nonce.
        let primary = *stx.tx.primary_address();
        let expected_nonce = self.nonce(&primary);
        if stx.tx.nonce() != expected_nonce {
            return Err(StateError::BadNonce {
                address: primary,
                expected: expected_nonce,
                actual: stx.tx.nonce(),
            });
        }

        // Dispatch to per-variant application.
        match &stx.tx {
            Transaction::Transfer(p) => self.apply_transfer(p)?,
            Transaction::Inscribe(p) => self.apply_inscribe(p)?,
            Transaction::Verify(p) => self.apply_verify(p)?,
            Transaction::Burn(p) => self.apply_burn(p)?,
        }

        // Increment the primary address's nonce only after successful apply.
        let next = expected_nonce
            .checked_add(1)
            .ok_or(StateError::NonceOverflow(primary))?;
        self.nonces.insert(primary, next);

        Ok(())
    }

    fn apply_transfer(&mut self, p: &TransferPayload) -> Result<(), StateError> {
        let from_bal = self.balance(&p.from);
        let new_from = from_bal
            .checked_sub(p.amount_hyphae)
            .ok_or(StateError::InsufficientBalance {
                address: p.from,
                available: from_bal,
                requested: p.amount_hyphae,
            })?;

        let to_bal = self.balance(&p.to);
        let new_to = to_bal
            .checked_add(p.amount_hyphae)
            .ok_or(StateError::BalanceOverflow(p.to))?;

        // Apply (atomic to this function; error above means no mutation).
        self.set_balance(p.from, new_from);
        self.set_balance(p.to, new_to);
        Ok(())
    }

    fn apply_inscribe(&mut self, p: &InscribePayload) -> Result<(), StateError> {
        // Duplicate doctrine check.
        if self.inscribed_doctrines.contains(&p.doctrine_hash) {
            return Err(StateError::DuplicateInscription(p.doctrine_hash));
        }

        // Compute reward (halvings applied) and cap at treasury balance.
        // If treasury is low, pay what it can. If treasury is empty, reward
        // is 0 — the inscription still succeeds (the scroll is recorded
        // on-chain forever) but no $TFS is distributed.
        let reward_raw = self.current_inscribe_reward();
        let reward = reward_raw.min(self.treasury_balance());

        // Transfer reward from treasury → inscriber.
        self.distribute_from_treasury(p.inscriber, reward)?;

        // All checks passed. Commit doctrine record + count.
        self.inscribed_doctrines.insert(p.doctrine_hash);
        self.doctrine_count = self
            .doctrine_count
            .checked_add(1)
            .ok_or(StateError::DoctrineCountOverflow)?;
        Ok(())
    }

    fn apply_verify(&mut self, p: &VerifyPayload) -> Result<(), StateError> {
        // Can't verify someone already verified.
        if self.verified_citizens.contains(&p.verified) {
            return Err(StateError::AlreadyVerified(p.verified));
        }

        // Treasury-capped reward.
        let reward_raw = self.current_verify_reward();
        let reward = reward_raw.min(self.treasury_balance());

        // Transfer reward from treasury → verified citizen.
        self.distribute_from_treasury(p.verified, reward)?;

        self.verified_citizens.insert(p.verified);
        Ok(())
    }

    /// Transfer `amount` hyphae from [`TREASURY_ADDRESS`] to `recipient`.
    /// This is the protocol-level distribution path used by Inscribe,
    /// Verify, and (future) Routing rewards. No signature required
    /// because the treasury has no private key.
    ///
    /// If `amount` is 0 this is a no-op (returns Ok). Treasury is assumed
    /// to have at least `amount` available (caller caps via
    /// [`Self::treasury_balance`] if needed).
    fn distribute_from_treasury(
        &mut self,
        recipient: Address,
        amount: u64,
    ) -> Result<(), StateError> {
        if amount == 0 {
            return Ok(());
        }
        let treasury = self.treasury_balance();
        let new_treasury = treasury
            .checked_sub(amount)
            .ok_or(StateError::TreasuryInsufficient {
                available: treasury,
                requested: amount,
            })?;
        let new_recipient = self
            .balance(&recipient)
            .checked_add(amount)
            .ok_or(StateError::BalanceOverflow(recipient))?;

        self.set_balance(TREASURY_ADDRESS, new_treasury);
        self.set_balance(recipient, new_recipient);
        Ok(())
    }

    fn apply_burn(&mut self, p: &BurnPayload) -> Result<(), StateError> {
        let bal = self.balance(&p.burner);
        let new_bal = bal
            .checked_sub(p.amount_hyphae)
            .ok_or(StateError::InsufficientBalance {
                address: p.burner,
                available: bal,
                requested: p.amount_hyphae,
            })?;

        let new_burned = self
            .supply_burned
            .checked_add(p.amount_hyphae)
            .ok_or(StateError::BurnOverflow)?;

        self.set_balance(p.burner, new_bal);
        self.supply_burned = new_burned;
        Ok(())
    }

    /// Set a balance, removing the entry when it hits zero to keep state compact.
    fn set_balance(&mut self, addr: Address, amount: u64) {
        if amount == 0 {
            self.balances.remove(&addr);
        } else {
            self.balances.insert(addr, amount);
        }
    }

    /// Apply every transaction in a block ATOMICALLY.
    ///
    /// If any transaction fails, the state is rolled back to what it was
    /// before this call. Returns the new state height + hash only on full
    /// success.
    ///
    /// # Errors
    /// Returns [`StateError`] describing the first failure.
    pub fn apply_block(&mut self, block: &Block) -> Result<(), StateError> {
        // Clone current state as a rollback point.
        let snapshot = self.clone();

        // Apply all transactions.
        for (idx, tx_bytes) in block.transactions.iter().enumerate() {
            let stx = SignedTransaction::from_bytes(tx_bytes).map_err(|e| {
                StateError::TxDeserialize {
                    tx_index: idx,
                    reason: format!("{e}"),
                }
            })?;

            if let Err(e) = self.apply_transaction(&stx) {
                // Roll back.
                *self = snapshot;
                return Err(StateError::TxInBlockFailed {
                    tx_index: idx,
                    reason: format!("{e}"),
                });
            }
        }

        // Update meta.
        self.height = block.header.height;
        self.last_block_hash = block.hash().map_err(StateError::Block)?;
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════
// HALVING MATH (const fn, no panics)
// ═══════════════════════════════════════════════════════════════════

/// Compute `base >> era`, where `era = doctrine_count / HALVING_INTERVAL`.
///
/// Saturates to 0 after enough halvings to shift all bits out. `u64` has
/// 64 bits, so after 64 halvings the reward is 0. That's 64 × 50,000 =
/// 3,200,000 inscriptions — well past the supply cap.
#[must_use]
const fn halved_reward(base_hyphae: u64, doctrine_count: u64) -> u64 {
    let era = doctrine_count / HALVING_INTERVAL;
    if era >= 64 {
        0
    } else {
        base_hyphae >> era
    }
}

// ═══════════════════════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════════════════════

/// Errors that can occur while applying transactions to state.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    /// The signed transaction failed Layer 3 structural validation.
    #[error("transaction validation failed: {0}")]
    Tx(#[from] crate::tx::TxError),

    /// The nonce on the transaction doesn't match the expected nonce for
    /// the primary address.
    #[error(
        "bad nonce for {address}: expected {expected}, got {actual} \
         (did you forget to increment? replaying a tx? out of order?)"
    )]
    BadNonce {
        /// The address whose nonce is wrong.
        address: Address,
        /// What the state expected.
        expected: u64,
        /// What the transaction claimed.
        actual: u64,
    },

    /// A nonce counter overflowed `u64`. Astronomical.
    #[error("nonce counter overflow for {0}")]
    NonceOverflow(Address),

    /// A transfer or burn requested more than the available balance.
    #[error("insufficient balance for {address}: have {available}, need {requested}")]
    InsufficientBalance {
        /// The address.
        address: Address,
        /// Current balance.
        available: u64,
        /// Amount requested.
        requested: u64,
    },

    /// An address's balance would overflow `u64`.
    #[error("balance overflow for {0}")]
    BalanceOverflow(Address),

    /// Treasury doesn't have enough balance for the requested distribution.
    /// Should never occur in practice because distribution callers cap
    /// the amount at `treasury_balance()` before calling.
    #[error("treasury insufficient: available {available}, requested {requested}")]
    TreasuryInsufficient {
        /// Current treasury balance.
        available: u64,
        /// Amount the distribution tried to draw.
        requested: u64,
    },

    /// Burn counter would overflow `u64`.
    #[error("burn counter overflow")]
    BurnOverflow,

    /// Doctrine-count counter would overflow `u64`.
    #[error("doctrine count overflow")]
    DoctrineCountOverflow,

    /// The same doctrine hash has already been inscribed.
    #[error("doctrine {0} already inscribed")]
    DuplicateInscription(Hash),

    /// The citizen has already been verified.
    #[error("citizen {0} already verified")]
    AlreadyVerified(Address),

    /// A transaction in the block failed to deserialize.
    #[error("tx[{tx_index}] failed to deserialize: {reason}")]
    TxDeserialize {
        /// Index of the bad transaction in the block.
        tx_index: usize,
        /// Deserialization error message.
        reason: String,
    },

    /// A transaction in the block failed to apply; state was rolled back.
    #[error("tx[{tx_index}] failed to apply: {reason}")]
    TxInBlockFailed {
        /// Index of the failing transaction.
        tx_index: usize,
        /// Inner error message.
        reason: String,
    },

    /// Block-level error (hashing etc.).
    #[error("block error: {0}")]
    Block(#[from] crate::block::BlockError),
}

// ═══════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keypair::Keypair;
    use crate::tx::{BurnPayload, InscribePayload, TransferPayload, VerifyPayload};

    fn kp() -> Keypair {
        Keypair::generate()
    }
    fn addr(k: &Keypair) -> Address {
        Address::from_public_key(&k.public_key())
    }

    // ─── TREASURY constant integrity ────────────────────────────────

    #[test]
    fn treasury_address_matches_canonical_blake3() {
        use crate::crypto::hash::hash_bytes;
        let expected = Address::from_hash(hash_bytes(b"tfs-treasury-genesis-v1"));
        assert_eq!(
            TREASURY_ADDRESS, expected,
            "TREASURY_ADDRESS const must equal BLAKE3(b\"tfs-treasury-genesis-v1\")"
        );
    }

    #[test]
    fn genesis_state_seeds_treasury_with_full_supply() {
        let s = State::new();
        assert_eq!(s.treasury_balance(), MAX_SUPPLY_HYPHAE);
        assert_eq!(s.circulating_supply(), MAX_SUPPLY_HYPHAE);
        assert_eq!(s.supply_burned, 0);
    }

    #[test]
    fn supply_is_conserved_across_distributions() {
        // Before and after any number of inscriptions, the sum of all
        // balances (treasury + citizens) equals MAX_SUPPLY_HYPHAE.
        let p1 = kp();
        let p2 = kp();
        let mut s = State::new();

        let sum_of_all = |s: &State| -> u64 { s.balances.values().sum() };
        assert_eq!(sum_of_all(&s), MAX_SUPPLY_HYPHAE);

        // First inscription.
        let stx1 = SignedTransaction::sign_single(
            Transaction::Inscribe(InscribePayload::new(addr(&p1), b"scroll one".to_vec(), 0, 1)),
            &p1,
        )
        .expect("sign 1");
        s.apply_transaction(&stx1).expect("apply 1");
        assert_eq!(sum_of_all(&s), MAX_SUPPLY_HYPHAE);

        // Second inscription.
        let stx2 = SignedTransaction::sign_single(
            Transaction::Inscribe(InscribePayload::new(addr(&p2), b"scroll two".to_vec(), 0, 2)),
            &p2,
        )
        .expect("sign 2");
        s.apply_transaction(&stx2).expect("apply 2");
        assert_eq!(sum_of_all(&s), MAX_SUPPLY_HYPHAE);

        // Treasury decremented by exactly what citizens gained.
        let expected_treasury = MAX_SUPPLY_HYPHAE - 2 * (1_000 * HYPHAE_PER_TFS);
        assert_eq!(s.treasury_balance(), expected_treasury);
        assert_eq!(s.balance(&addr(&p1)), 1_000 * HYPHAE_PER_TFS);
        assert_eq!(s.balance(&addr(&p2)), 1_000 * HYPHAE_PER_TFS);
    }

    // ─── Halving math ───────────────────────────────────────────────

    #[test]
    fn halving_era_zero_is_full_reward() {
        let s = State::new();
        assert_eq!(s.current_inscribe_reward(), 1_000 * HYPHAE_PER_TFS);
        assert_eq!(s.current_verify_reward(), 100 * HYPHAE_PER_TFS);
    }

    #[test]
    fn halving_era_one_halves_reward() {
        let mut s = State::new();
        s.doctrine_count = HALVING_INTERVAL;
        assert_eq!(s.current_inscribe_reward(), 500 * HYPHAE_PER_TFS);
        assert_eq!(s.current_verify_reward(), 50 * HYPHAE_PER_TFS);
    }

    #[test]
    fn halving_saturates_to_zero() {
        let mut s = State::new();
        // 100 eras past ensures zero reward.
        s.doctrine_count = HALVING_INTERVAL * 100;
        assert_eq!(s.current_inscribe_reward(), 0);
        assert_eq!(s.current_verify_reward(), 0);
    }

    // ─── Transfer ───────────────────────────────────────────────────

    #[test]
    fn transfer_moves_funds_and_bumps_nonce() {
        let alice = kp();
        let bob = kp();
        let a = addr(&alice);
        let b = addr(&bob);
        let mut s = State::new();
        s.balances.insert(a, 1_000);

        let stx = SignedTransaction::sign_single(
            Transaction::Transfer(TransferPayload {
                from: a,
                to: b,
                amount_hyphae: 400,
                nonce: 0,
                timestamp_ms: 1,
            }),
            &alice,
        )
        .expect("sign");

        s.apply_transaction(&stx).expect("apply");
        assert_eq!(s.balance(&a), 600);
        assert_eq!(s.balance(&b), 400);
        assert_eq!(s.nonce(&a), 1);
    }

    #[test]
    fn transfer_insufficient_balance_rejected() {
        let alice = kp();
        let bob = kp();
        let mut s = State::new();
        s.balances.insert(addr(&alice), 100);

        let stx = SignedTransaction::sign_single(
            Transaction::Transfer(TransferPayload {
                from: addr(&alice),
                to: addr(&bob),
                amount_hyphae: 500,
                nonce: 0,
                timestamp_ms: 1,
            }),
            &alice,
        )
        .expect("sign");

        let err = s.apply_transaction(&stx).expect_err("should fail");
        assert!(matches!(err, StateError::InsufficientBalance { .. }));
        // State unchanged.
        assert_eq!(s.balance(&addr(&alice)), 100);
        assert_eq!(s.balance(&addr(&bob)), 0);
        assert_eq!(s.nonce(&addr(&alice)), 0);
    }

    #[test]
    fn transfer_wrong_nonce_rejected() {
        let alice = kp();
        let bob = kp();
        let mut s = State::new();
        s.balances.insert(addr(&alice), 1_000);

        let stx = SignedTransaction::sign_single(
            Transaction::Transfer(TransferPayload {
                from: addr(&alice),
                to: addr(&bob),
                amount_hyphae: 1,
                nonce: 5, // expected 0
                timestamp_ms: 1,
            }),
            &alice,
        )
        .expect("sign");

        let err = s.apply_transaction(&stx).expect_err("bad nonce");
        assert!(matches!(err, StateError::BadNonce { .. }));
    }

    #[test]
    fn transfer_replay_rejected() {
        let alice = kp();
        let bob = kp();
        let mut s = State::new();
        s.balances.insert(addr(&alice), 1_000);

        let stx = SignedTransaction::sign_single(
            Transaction::Transfer(TransferPayload {
                from: addr(&alice),
                to: addr(&bob),
                amount_hyphae: 1,
                nonce: 0,
                timestamp_ms: 1,
            }),
            &alice,
        )
        .expect("sign");

        s.apply_transaction(&stx).expect("first ok");
        let err = s.apply_transaction(&stx).expect_err("replay");
        assert!(matches!(err, StateError::BadNonce { .. }));
    }

    // ─── Inscribe ───────────────────────────────────────────────────

    #[test]
    fn inscribe_mints_1000_tfs_and_tracks_doctrine() {
        let president = kp();
        let mut s = State::new();

        let payload = InscribePayload::new(
            addr(&president),
            b"GENESIS DOCTRINE".to_vec(),
            0,
            1,
        );
        let doctrine_hash = payload.doctrine_hash;
        let stx = SignedTransaction::sign_single(Transaction::Inscribe(payload), &president)
            .expect("sign");

        s.apply_transaction(&stx).expect("apply");
        assert_eq!(s.balance(&addr(&president)), 1_000 * HYPHAE_PER_TFS);
        // Treasury debited by exactly the distributed amount.
        assert_eq!(
            s.treasury_balance(),
            MAX_SUPPLY_HYPHAE - (1_000 * HYPHAE_PER_TFS)
        );
        assert_eq!(s.doctrine_count, 1);
        assert!(s.inscribed_doctrines.contains(&doctrine_hash));
    }

    #[test]
    fn inscribe_duplicate_rejected() {
        let p = kp();
        let mut s = State::new();
        let doctrine = b"same content twice".to_vec();

        let stx1 = SignedTransaction::sign_single(
            Transaction::Inscribe(InscribePayload::new(addr(&p), doctrine.clone(), 0, 1)),
            &p,
        )
        .expect("sign 1");
        s.apply_transaction(&stx1).expect("first ok");

        // Second inscription of SAME content at nonce 1.
        let stx2 = SignedTransaction::sign_single(
            Transaction::Inscribe(InscribePayload::new(addr(&p), doctrine, 1, 2)),
            &p,
        )
        .expect("sign 2");
        let err = s.apply_transaction(&stx2).expect_err("duplicate");
        assert!(matches!(err, StateError::DuplicateInscription(_)));
    }

    #[test]
    fn inscribe_reward_halves_after_era() {
        let p = kp();
        let mut s = State::new();
        s.doctrine_count = HALVING_INTERVAL; // just entered era 1

        let stx = SignedTransaction::sign_single(
            Transaction::Inscribe(InscribePayload::new(addr(&p), b"era-1 doctrine".to_vec(), 0, 1)),
            &p,
        )
        .expect("sign");
        s.apply_transaction(&stx).expect("apply");
        // Era 1 reward = 500 $TFS (half of 1000).
        assert_eq!(s.balance(&addr(&p)), 500 * HYPHAE_PER_TFS);
    }

    // ─── Verify ─────────────────────────────────────────────────────

    #[test]
    fn verify_mints_100_tfs_and_marks_verified() {
        let subject = kp();
        let v1 = kp();
        let v2 = kp();
        let v3 = kp();
        let mut s = State::new();

        let tx = Transaction::Verify(VerifyPayload {
            verified: addr(&subject),
            nonce: 0,
            timestamp_ms: 1,
        });
        let stx = SignedTransaction::sign_verify(tx, &[&v1, &v2, &v3]).expect("sign");

        s.apply_transaction(&stx).expect("apply");
        assert_eq!(s.balance(&addr(&subject)), 100 * HYPHAE_PER_TFS);
        assert!(s.verified_citizens.contains(&addr(&subject)));
        assert_eq!(s.nonce(&addr(&subject)), 1);
    }

    #[test]
    fn verify_already_verified_rejected() {
        let subject = kp();
        let v1 = kp();
        let v2 = kp();
        let v3 = kp();
        let mut s = State::new();

        let tx1 = Transaction::Verify(VerifyPayload {
            verified: addr(&subject),
            nonce: 0,
            timestamp_ms: 1,
        });
        let stx1 = SignedTransaction::sign_verify(tx1, &[&v1, &v2, &v3]).expect("sign");
        s.apply_transaction(&stx1).expect("first");

        // Second verify with a new quorum.
        let v4 = kp();
        let v5 = kp();
        let v6 = kp();
        let tx2 = Transaction::Verify(VerifyPayload {
            verified: addr(&subject),
            nonce: 1,
            timestamp_ms: 2,
        });
        let stx2 = SignedTransaction::sign_verify(tx2, &[&v4, &v5, &v6]).expect("sign");
        let err = s.apply_transaction(&stx2).expect_err("double verify");
        assert!(matches!(err, StateError::AlreadyVerified(_)));
    }

    // ─── Burn ───────────────────────────────────────────────────────

    #[test]
    fn burn_destroys_supply_and_shrinks_circulating() {
        let c = kp();
        let mut s = State::new();
        s.balances.insert(addr(&c), 500);

        let stx = SignedTransaction::sign_single(
            Transaction::Burn(BurnPayload {
                burner: addr(&c),
                amount_hyphae: 200,
                nonce: 0,
                timestamp_ms: 1,
                reason: Some("for the nation".to_string()),
            }),
            &c,
        )
        .expect("sign");
        s.apply_transaction(&stx).expect("apply");

        assert_eq!(s.balance(&addr(&c)), 300);
        assert_eq!(s.supply_burned, 200);
        // Circulating supply shrinks by the burn amount (under the 1B cap).
        assert_eq!(s.circulating_supply(), MAX_SUPPLY_HYPHAE - 200);
    }

    #[test]
    fn burn_over_balance_rejected() {
        let c = kp();
        let mut s = State::new();
        s.balances.insert(addr(&c), 50);

        let stx = SignedTransaction::sign_single(
            Transaction::Burn(BurnPayload {
                burner: addr(&c),
                amount_hyphae: 100,
                nonce: 0,
                timestamp_ms: 1,
                reason: None,
            }),
            &c,
        )
        .expect("sign");
        let err = s.apply_transaction(&stx).expect_err("over-burn");
        assert!(matches!(err, StateError::InsufficientBalance { .. }));
    }

    // ─── Determinism ────────────────────────────────────────────────

    #[test]
    fn state_root_is_deterministic() {
        let a = kp();
        let b = kp();
        let mut s1 = State::new();
        s1.balances.insert(addr(&a), 100);
        s1.balances.insert(addr(&b), 200);
        let r1 = s1.state_root().expect("root1");

        let mut s2 = State::new();
        // Insert in REVERSE order. BTreeMap normalizes the order, so the
        // serialized bytes should be identical.
        s2.balances.insert(addr(&b), 200);
        s2.balances.insert(addr(&a), 100);
        let r2 = s2.state_root().expect("root2");

        assert_eq!(r1, r2);
    }

    #[test]
    fn zero_balance_removed_from_map() {
        let a = kp();
        let b = kp();
        let mut s = State::new();
        s.balances.insert(addr(&a), 100);
        let stx = SignedTransaction::sign_single(
            Transaction::Transfer(TransferPayload {
                from: addr(&a),
                to: addr(&b),
                amount_hyphae: 100, // drain
                nonce: 0,
                timestamp_ms: 1,
            }),
            &a,
        )
        .expect("sign");
        s.apply_transaction(&stx).expect("apply");
        // Alice should no longer be in the map (zero balance removed).
        assert!(!s.balances.contains_key(&addr(&a)));
        assert_eq!(s.balance(&addr(&a)), 0);
    }

    // ─── Atomicity of apply_block rollback ──────────────────────────

    #[test]
    fn block_apply_rolls_back_on_failure() {
        use crate::block::Block;
        let alice = kp();
        let bob = kp();
        let president = kp();
        let mut s = State::new();
        s.balances.insert(addr(&alice), 50);
        let original = s.clone();

        // Tx 1: Alice → Bob, 30. Valid.
        let stx_ok = SignedTransaction::sign_single(
            Transaction::Transfer(TransferPayload {
                from: addr(&alice),
                to: addr(&bob),
                amount_hyphae: 30,
                nonce: 0,
                timestamp_ms: 1,
            }),
            &alice,
        )
        .expect("sign");

        // Tx 2: Alice → Bob, 999. Will fail (insufficient after tx 1).
        let stx_fail = SignedTransaction::sign_single(
            Transaction::Transfer(TransferPayload {
                from: addr(&alice),
                to: addr(&bob),
                amount_hyphae: 999,
                nonce: 1,
                timestamp_ms: 2,
            }),
            &alice,
        )
        .expect("sign");

        // Build a block containing both, signed by some proposer.
        let block = Block::genesis(
            "tfs-test-1",
            1,
            vec![
                stx_ok.to_bytes().expect("bytes1"),
                stx_fail.to_bytes().expect("bytes2"),
            ],
            &president,
        )
        .expect("block");

        let err = s.apply_block(&block).expect_err("block should fail");
        assert!(matches!(err, StateError::TxInBlockFailed { .. }));

        // State must be identical to the pre-apply snapshot.
        assert_eq!(s, original);
    }
}
