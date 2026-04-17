// TFS_CHAIN · storage/mod.rs · Layer 6
//
// THE MEMORY OF THE CHAIN.
//
// Layer 5 gave us the in-memory chain: state, mempool, consensus,
// append-only history. Layer 6 makes the chain SURVIVE. A node crashes,
// a node reboots, a node migrates to a new machine — the chain holds.
//
// ┌─ Storage ───────────────────────────────────────────┐
// │                                                      │
// │   RocksDB backing store, multi-CF:                   │
// │     - blocks           (height → block bytes)        │
// │     - block_hash_index (hash   → height)             │
// │     - tx_index         (tx_id  → (height, idx))      │
// │     - state_balances   (addr   → u64 balance)        │
// │     - state_nonces     (addr   → u64 nonce)          │
// │     - state_verified   (addr   → ∅)                  │
// │     - state_inscribed  (hash   → ∅)                  │
// │     - meta             (named scalars)               │
// │                                                      │
// │   Every block commit writes to ALL affected CFs in   │
// │   a single WriteBatch with fsync. Either the whole   │
// │   batch lands or none of it does.                    │
// │                                                      │
// └──────────────────────────────────────────────────────┘
//
// DOCTRINE:
//   - Big-endian u64 keys for lexicographic == numeric order
//   - Hash and Address keys are raw 32 bytes
//   - Block/validator serialization uses bincode (same codec as Layer 2–5
//     uses for hashing — guarantees no drift between on-wire and on-disk)
//   - WriteOptions set sync=true on all block commits — no silent loss
//     on kernel panic
//
// THREAT MODEL:
//   - Torn write (mid-commit crash)      → WriteBatch is atomic
//   - Byte-order drift across platforms  → big-endian u64 everywhere
//   - Schema drift (upgraded binary vs   → META_SCHEMA_VERSION check at
//     old DB)                                open-time, refuse mismatch
//   - CF name typo (silent data loss)    → CF list in schema.rs, open-time
//                                           verification
//   - Height gap from missed block       → append checks prev.height+1
//   - Double-init (open on existing DB   → create() refuses if data exists,
//     that already has genesis)             open() refuses if no meta

//! Persistent storage for THE TFS CHAIN, backed by RocksDB.
//!
//! Use [`Storage::create`] to initialize a fresh database with a genesis
//! block, or [`Storage::open`] to reopen an existing one. Operations on
//! a [`Storage`] are synchronous and thread-safe (RocksDB allows
//! concurrent reads; writes serialize through the DB).
//!
//! This module is gated behind the `storage` feature.

#![cfg(feature = "storage")]

pub mod keys;
pub mod schema;

use std::path::{Path, PathBuf};

use rocksdb::{
    ColumnFamilyDescriptor, IteratorMode, Options, WriteBatch, WriteOptions, DB,
};
use serde::{Deserialize, Serialize};

use crate::block::BlockError;
use crate::consensus::{CommittedBlock, ValidatorSet};
use crate::crypto::hash::{Hash, HashError};
use crate::state::State;

use self::keys::{
    address_from_key, address_key, hash_from_key, hash_key, u64_from_be, u64_to_be, KeyError,
};
use self::schema::{
    all_column_families, CF_BLOCKS, CF_BLOCK_HASH_INDEX, CF_META, CF_STATE_BALANCES,
    CF_STATE_INSCRIBED, CF_STATE_NONCES, CF_STATE_VERIFIED, CF_TX_INDEX, CURRENT_SCHEMA_VERSION,
    META_CHAIN_ID, META_DOCTRINE_COUNT, META_HEIGHT, META_LAST_BLOCK_HASH, META_SCHEMA_VERSION,
    META_SUPPLY_BURNED, META_SUPPLY_ISSUED, META_VALIDATORS,
};

// ═══════════════════════════════════════════════════════════════════
// TX LOCATION (value in CF_TX_INDEX)
// ═══════════════════════════════════════════════════════════════════

/// Where in the committed chain a transaction lives.
///
/// Stored in `CF_TX_INDEX` keyed by tx_id. Lets the node answer
/// "what block is this transaction in?" without scanning.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxLocation {
    /// Block height containing the transaction.
    pub height: u64,

    /// Zero-based index of the transaction within its block.
    pub tx_index: u32,
}

// ═══════════════════════════════════════════════════════════════════
// STATE DIFF (a WriteBatch's worth of state changes)
// ═══════════════════════════════════════════════════════════════════

/// The set of state mutations to commit for a single block.
///
/// Produced by diffing a "before" state against an "after" state, then
/// handed to [`Storage::commit_block`] which writes all mutations
/// atomically alongside the block itself.
#[derive(Debug, Default)]
pub struct StateDiff {
    /// Addresses whose balance changed. `None` means the balance became
    /// zero and the key should be DELETED to keep storage compact.
    pub balances: Vec<(crate::crypto::address::Address, Option<u64>)>,

    /// Addresses whose nonce advanced.
    pub nonces: Vec<(crate::crypto::address::Address, u64)>,

    /// Newly verified citizens.
    pub newly_verified: Vec<crate::crypto::address::Address>,

    /// Newly inscribed doctrine hashes.
    pub newly_inscribed: Vec<Hash>,

    /// Updated supply_issued value (if changed this block).
    pub supply_issued: Option<u64>,

    /// Updated supply_burned value (if changed this block).
    pub supply_burned: Option<u64>,

    /// Updated doctrine_count value (if changed this block).
    pub doctrine_count: Option<u64>,
}

impl StateDiff {
    /// Compute the diff between a `before` and `after` state snapshot.
    ///
    /// Any balance present in `before` but absent (or 0) in `after` is
    /// emitted as `None` so the key is removed on commit.
    #[must_use]
    pub fn between(before: &State, after: &State) -> Self {
        use crate::crypto::address::Address;
        use std::collections::BTreeSet;

        let mut out = Self::default();

        // BALANCES: union of keys, check each for change.
        let all_balance_addrs: BTreeSet<Address> = before
            .balances
            .keys()
            .chain(after.balances.keys())
            .copied()
            .collect();
        for addr in all_balance_addrs {
            let b = before.balances.get(&addr).copied().unwrap_or(0);
            let a = after.balances.get(&addr).copied().unwrap_or(0);
            if b != a {
                out.balances.push((addr, if a == 0 { None } else { Some(a) }));
            }
        }

        // NONCES: union; emit new value on change.
        let all_nonce_addrs: BTreeSet<Address> = before
            .nonces
            .keys()
            .chain(after.nonces.keys())
            .copied()
            .collect();
        for addr in all_nonce_addrs {
            let b = before.nonces.get(&addr).copied().unwrap_or(0);
            let a = after.nonces.get(&addr).copied().unwrap_or(0);
            if b != a {
                out.nonces.push((addr, a));
            }
        }

        // VERIFIED: only additions (set is monotone within a block).
        for addr in after.verified_citizens.difference(&before.verified_citizens) {
            out.newly_verified.push(*addr);
        }

        // INSCRIBED: only additions.
        for h in after.inscribed_doctrines.difference(&before.inscribed_doctrines) {
            out.newly_inscribed.push(*h);
        }

        if before.supply_issued != after.supply_issued {
            out.supply_issued = Some(after.supply_issued);
        }
        if before.supply_burned != after.supply_burned {
            out.supply_burned = Some(after.supply_burned);
        }
        if before.doctrine_count != after.doctrine_count {
            out.doctrine_count = Some(after.doctrine_count);
        }

        out
    }
}

// ═══════════════════════════════════════════════════════════════════
// STORAGE
// ═══════════════════════════════════════════════════════════════════

/// A persistent, RocksDB-backed store for a TFS_CHAIN node.
///
/// Opened with [`Storage::open`] or created with [`Storage::create`].
/// Commit a block to disk with [`Storage::commit_block`]. Restore the
/// in-memory state and chain metadata at boot with [`Storage::load_state`]
/// and [`Storage::load_validators`].
///
/// The struct owns its underlying `DB` handle. Dropping the `Storage`
/// flushes and closes the database.
pub struct Storage {
    db: DB,
    path: PathBuf,
}

impl std::fmt::Debug for Storage {
    // `rocksdb::DB` doesn't implement Debug, so we only show the path.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Storage").field("path", &self.path).finish()
    }
}

impl Storage {
    /// Create a new, empty database at `path`.
    ///
    /// Writes the schema version, chain ID, and validator set into meta.
    /// This is the first step in starting a fresh chain — before genesis
    /// is applied. Call [`Storage::commit_block`] next with the genesis
    /// block.
    ///
    /// # Errors
    /// Returns [`StorageError`] if:
    /// - `path` already contains a non-empty DB (use [`Storage::open`]).
    /// - RocksDB fails to create the DB.
    /// - Bincode fails to serialize the validator set (should never).
    pub fn create<P: AsRef<Path>>(
        path: P,
        chain_id: &str,
        validators: &ValidatorSet,
    ) -> Result<Self, StorageError> {
        let db_path = path.as_ref().to_path_buf();

        // Refuse if the directory already holds a DB (CURRENT file is the
        // RocksDB marker).
        if db_path.join("CURRENT").exists() {
            return Err(StorageError::DatabaseAlreadyExists(db_path));
        }

        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
        // Use 4 background jobs for compaction — modest default, tunable later.
        db_opts.increase_parallelism(4);

        let cf_descriptors: Vec<ColumnFamilyDescriptor> = all_column_families()
            .iter()
            .map(|name| ColumnFamilyDescriptor::new(*name, Options::default()))
            .collect();

        let db = DB::open_cf_descriptors(&db_opts, &db_path, cf_descriptors)
            .map_err(|e| StorageError::RocksDb(e.to_string()))?;

        let storage = Self { db, path: db_path };

        // Initialize meta.
        let validators_bytes =
            bincode::serialize(validators).map_err(|e| StorageError::Encode(e.to_string()))?;

        let mut batch = WriteBatch::default();
        storage.batch_put_meta(
            &mut batch,
            META_SCHEMA_VERSION,
            &u32_to_be(CURRENT_SCHEMA_VERSION),
        )?;
        storage.batch_put_meta(&mut batch, META_CHAIN_ID, chain_id.as_bytes())?;
        storage.batch_put_meta(&mut batch, META_VALIDATORS, &validators_bytes)?;
        storage.batch_put_meta(&mut batch, META_SUPPLY_ISSUED, &u64_to_be(0))?;
        storage.batch_put_meta(&mut batch, META_SUPPLY_BURNED, &u64_to_be(0))?;
        storage.batch_put_meta(&mut batch, META_DOCTRINE_COUNT, &u64_to_be(0))?;
        // Height and last_block_hash left unset until genesis lands.
        storage.write_batch_sync(batch)?;

        Ok(storage)
    }

    /// Open an existing database at `path`.
    ///
    /// # Errors
    /// Returns [`StorageError`] if:
    /// - `path` doesn't contain a DB (use [`Storage::create`] first).
    /// - The on-disk schema version doesn't match
    ///   [`schema::CURRENT_SCHEMA_VERSION`].
    /// - RocksDB fails to open.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, StorageError> {
        let db_path = path.as_ref().to_path_buf();

        if !db_path.join("CURRENT").exists() {
            return Err(StorageError::DatabaseNotFound(db_path));
        }

        let mut db_opts = Options::default();
        db_opts.create_if_missing(false);
        db_opts.increase_parallelism(4);

        let cf_descriptors: Vec<ColumnFamilyDescriptor> = all_column_families()
            .iter()
            .map(|name| ColumnFamilyDescriptor::new(*name, Options::default()))
            .collect();

        let db = DB::open_cf_descriptors(&db_opts, &db_path, cf_descriptors)
            .map_err(|e| StorageError::RocksDb(e.to_string()))?;

        let storage = Self { db, path: db_path };

        // Verify schema version.
        let stored_version_bytes = storage
            .get_meta(META_SCHEMA_VERSION)?
            .ok_or(StorageError::MissingMeta("schema_version"))?;
        let stored_version = u32_from_be(&stored_version_bytes)?;
        if stored_version != CURRENT_SCHEMA_VERSION {
            return Err(StorageError::SchemaVersionMismatch {
                on_disk: stored_version,
                binary: CURRENT_SCHEMA_VERSION,
            });
        }

        Ok(storage)
    }

    /// Path to the underlying DB directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    // ───────────────────────────────────────────────────────────────
    // META
    // ───────────────────────────────────────────────────────────────

    /// Load the chain's stored chain_id string.
    ///
    /// # Errors
    /// Returns [`StorageError`] if the key is missing or not valid UTF-8.
    pub fn load_chain_id(&self) -> Result<String, StorageError> {
        let bytes = self
            .get_meta(META_CHAIN_ID)?
            .ok_or(StorageError::MissingMeta("chain_id"))?;
        String::from_utf8(bytes).map_err(|_| StorageError::Corrupt("chain_id is not UTF-8"))
    }

    /// Load the authorized validator set.
    ///
    /// # Errors
    /// Returns [`StorageError`] if the key is missing or decoding fails.
    pub fn load_validators(&self) -> Result<ValidatorSet, StorageError> {
        let bytes = self
            .get_meta(META_VALIDATORS)?
            .ok_or(StorageError::MissingMeta("validators"))?;
        bincode::deserialize(&bytes).map_err(|e| StorageError::Decode(e.to_string()))
    }

    /// Return the height of the most-recently-committed block, or `None`
    /// if no blocks have been committed yet.
    ///
    /// # Errors
    /// Returns [`StorageError`] if the stored value is malformed.
    pub fn load_height(&self) -> Result<Option<u64>, StorageError> {
        match self.get_meta(META_HEIGHT)? {
            Some(bytes) => Ok(Some(u64_from_be(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Return the hash of the most-recently-committed block, or `None`
    /// if no blocks have been committed yet.
    ///
    /// # Errors
    /// Returns [`StorageError`] if the stored value is malformed.
    pub fn load_last_block_hash(&self) -> Result<Option<Hash>, StorageError> {
        match self.get_meta(META_LAST_BLOCK_HASH)? {
            Some(bytes) => Ok(Some(hash_from_key(&bytes)?)),
            None => Ok(None),
        }
    }

    // ───────────────────────────────────────────────────────────────
    // BLOCK READ PATH
    // ───────────────────────────────────────────────────────────────

    /// Retrieve a committed block by its height.
    ///
    /// # Errors
    /// Returns [`StorageError`] if RocksDB fails or the stored bytes fail
    /// to decode.
    pub fn get_committed_block(
        &self,
        height: u64,
    ) -> Result<Option<CommittedBlock>, StorageError> {
        let cf = self
            .db
            .cf_handle(CF_BLOCKS)
            .ok_or(StorageError::MissingColumnFamily(CF_BLOCKS))?;
        let key = u64_to_be(height);
        match self
            .db
            .get_cf(&cf, key)
            .map_err(|e| StorageError::RocksDb(e.to_string()))?
        {
            Some(bytes) => {
                let cb: CommittedBlock = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Decode(e.to_string()))?;
                Ok(Some(cb))
            }
            None => Ok(None),
        }
    }

    /// Retrieve a committed block by its block hash.
    ///
    /// Goes via the `block_hash_index` CF for O(1) height lookup, then
    /// fetches from `blocks`.
    ///
    /// # Errors
    /// Returns [`StorageError`] if RocksDB fails or decoding fails.
    pub fn get_block_by_hash(
        &self,
        block_hash: &Hash,
    ) -> Result<Option<CommittedBlock>, StorageError> {
        let idx_cf = self
            .db
            .cf_handle(CF_BLOCK_HASH_INDEX)
            .ok_or(StorageError::MissingColumnFamily(CF_BLOCK_HASH_INDEX))?;
        let height_bytes = self
            .db
            .get_cf(&idx_cf, hash_key(block_hash))
            .map_err(|e| StorageError::RocksDb(e.to_string()))?;
        match height_bytes {
            Some(bytes) => {
                let height = u64_from_be(&bytes)?;
                self.get_committed_block(height)
            }
            None => Ok(None),
        }
    }

    /// Look up where a transaction lives in the committed chain.
    ///
    /// # Errors
    /// Returns [`StorageError`] on RocksDB or decode failure.
    pub fn get_tx_location(&self, tx_id: &Hash) -> Result<Option<TxLocation>, StorageError> {
        let cf = self
            .db
            .cf_handle(CF_TX_INDEX)
            .ok_or(StorageError::MissingColumnFamily(CF_TX_INDEX))?;
        match self
            .db
            .get_cf(&cf, hash_key(tx_id))
            .map_err(|e| StorageError::RocksDb(e.to_string()))?
        {
            Some(bytes) => {
                let loc: TxLocation = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Decode(e.to_string()))?;
                Ok(Some(loc))
            }
            None => Ok(None),
        }
    }

    // ───────────────────────────────────────────────────────────────
    // STATE RECONSTRUCTION
    // ───────────────────────────────────────────────────────────────

    /// Reconstruct the in-memory [`State`] from the persistent CFs.
    ///
    /// Called at boot. Reads every row in balances, nonces, verified,
    /// inscribed, plus the scalar meta keys. Deterministic: calling this
    /// twice on the same DB produces byte-identical state.
    ///
    /// # Errors
    /// Returns [`StorageError`] if any CF read or decode fails.
    pub fn load_state(&self) -> Result<State, StorageError> {
        let mut state = State::new();

        // BALANCES
        {
            let cf = self
                .db
                .cf_handle(CF_STATE_BALANCES)
                .ok_or(StorageError::MissingColumnFamily(CF_STATE_BALANCES))?;
            for entry in self.db.iterator_cf(&cf, IteratorMode::Start) {
                let (k, v) = entry.map_err(|e| StorageError::RocksDb(e.to_string()))?;
                let addr = address_from_key(&k)?;
                let bal = u64_from_be(&v)?;
                state.balances.insert(addr, bal);
            }
        }

        // NONCES
        {
            let cf = self
                .db
                .cf_handle(CF_STATE_NONCES)
                .ok_or(StorageError::MissingColumnFamily(CF_STATE_NONCES))?;
            for entry in self.db.iterator_cf(&cf, IteratorMode::Start) {
                let (k, v) = entry.map_err(|e| StorageError::RocksDb(e.to_string()))?;
                let addr = address_from_key(&k)?;
                let n = u64_from_be(&v)?;
                state.nonces.insert(addr, n);
            }
        }

        // VERIFIED
        {
            let cf = self
                .db
                .cf_handle(CF_STATE_VERIFIED)
                .ok_or(StorageError::MissingColumnFamily(CF_STATE_VERIFIED))?;
            for entry in self.db.iterator_cf(&cf, IteratorMode::Start) {
                let (k, _) = entry.map_err(|e| StorageError::RocksDb(e.to_string()))?;
                let addr = address_from_key(&k)?;
                state.verified_citizens.insert(addr);
            }
        }

        // INSCRIBED
        {
            let cf = self
                .db
                .cf_handle(CF_STATE_INSCRIBED)
                .ok_or(StorageError::MissingColumnFamily(CF_STATE_INSCRIBED))?;
            for entry in self.db.iterator_cf(&cf, IteratorMode::Start) {
                let (k, _) = entry.map_err(|e| StorageError::RocksDb(e.to_string()))?;
                let h = hash_from_key(&k)?;
                state.inscribed_doctrines.insert(h);
            }
        }

        // SCALARS
        if let Some(b) = self.get_meta(META_SUPPLY_ISSUED)? {
            state.supply_issued = u64_from_be(&b)?;
        }
        if let Some(b) = self.get_meta(META_SUPPLY_BURNED)? {
            state.supply_burned = u64_from_be(&b)?;
        }
        if let Some(b) = self.get_meta(META_DOCTRINE_COUNT)? {
            state.doctrine_count = u64_from_be(&b)?;
        }
        if let Some(b) = self.get_meta(META_HEIGHT)? {
            state.height = u64_from_be(&b)?;
        }
        if let Some(b) = self.get_meta(META_LAST_BLOCK_HASH)? {
            state.last_block_hash = hash_from_key(&b)?;
        }

        Ok(state)
    }

    // ───────────────────────────────────────────────────────────────
    // BLOCK COMMIT (the atomic write path)
    // ───────────────────────────────────────────────────────────────

    /// Commit a block to disk atomically, together with its state diff.
    ///
    /// Writes (all in one [`WriteBatch`]):
    /// - `CF_BLOCKS[height] = bincode(block)`
    /// - `CF_BLOCK_HASH_INDEX[block_hash] = height`
    /// - `CF_TX_INDEX[tx_id] = TxLocation` for each tx in the block
    /// - every balance / nonce / verified / inscribed change in `diff`
    /// - meta: height, last_block_hash, supply_issued, supply_burned,
    ///   doctrine_count
    ///
    /// The batch is flushed with `sync = true` so a power loss after this
    /// call cannot leave the chain in a torn state.
    ///
    /// # Errors
    /// Returns [`StorageError`] on any RocksDB, encoding, or hash failure.
    pub fn commit_block(
        &self,
        committed: &CommittedBlock,
        diff: &StateDiff,
    ) -> Result<(), StorageError> {
        let mut batch = WriteBatch::default();

        // Blocks CF.
        let block_bytes = bincode::serialize(committed)
            .map_err(|e| StorageError::Encode(e.to_string()))?;
        let height = committed.block.header.height;
        let block_hash = committed
            .block
            .hash()
            .map_err(StorageError::Block)?;

        self.batch_put(&mut batch, CF_BLOCKS, &u64_to_be(height), &block_bytes)?;
        self.batch_put(
            &mut batch,
            CF_BLOCK_HASH_INDEX,
            &hash_key(&block_hash),
            &u64_to_be(height),
        )?;

        // Tx index: for each tx, tx_id → TxLocation.
        for (idx, tx_bytes) in committed.block.transactions.iter().enumerate() {
            let stx: crate::tx::SignedTransaction = bincode::deserialize(tx_bytes)
                .map_err(|e| StorageError::Decode(e.to_string()))?;
            let tx_id = stx.tx_id().map_err(StorageError::Hash)?;
            let loc = TxLocation {
                height,
                tx_index: u32::try_from(idx).map_err(|_| {
                    StorageError::Corrupt("tx index exceeds u32 (block has too many txs)")
                })?,
            };
            let loc_bytes = bincode::serialize(&loc)
                .map_err(|e| StorageError::Encode(e.to_string()))?;
            self.batch_put(&mut batch, CF_TX_INDEX, &hash_key(&tx_id), &loc_bytes)?;
        }

        // State diff: balances.
        for (addr, value) in &diff.balances {
            let key = address_key(addr);
            match value {
                Some(v) => {
                    self.batch_put(&mut batch, CF_STATE_BALANCES, &key, &u64_to_be(*v))?;
                }
                None => {
                    self.batch_delete(&mut batch, CF_STATE_BALANCES, &key)?;
                }
            }
        }

        // Nonces.
        for (addr, nonce) in &diff.nonces {
            self.batch_put(
                &mut batch,
                CF_STATE_NONCES,
                &address_key(addr),
                &u64_to_be(*nonce),
            )?;
        }

        // Verified (additions only).
        for addr in &diff.newly_verified {
            self.batch_put(&mut batch, CF_STATE_VERIFIED, &address_key(addr), &[])?;
        }

        // Inscribed (additions only).
        for h in &diff.newly_inscribed {
            self.batch_put(&mut batch, CF_STATE_INSCRIBED, &hash_key(h), &[])?;
        }

        // Scalar meta updates.
        if let Some(v) = diff.supply_issued {
            self.batch_put_meta(&mut batch, META_SUPPLY_ISSUED, &u64_to_be(v))?;
        }
        if let Some(v) = diff.supply_burned {
            self.batch_put_meta(&mut batch, META_SUPPLY_BURNED, &u64_to_be(v))?;
        }
        if let Some(v) = diff.doctrine_count {
            self.batch_put_meta(&mut batch, META_DOCTRINE_COUNT, &u64_to_be(v))?;
        }
        self.batch_put_meta(&mut batch, META_HEIGHT, &u64_to_be(height))?;
        self.batch_put_meta(&mut batch, META_LAST_BLOCK_HASH, &hash_key(&block_hash))?;

        self.write_batch_sync(batch)
    }

    // ───────────────────────────────────────────────────────────────
    // INTERNAL HELPERS
    // ───────────────────────────────────────────────────────────────

    fn get_meta(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let cf = self
            .db
            .cf_handle(CF_META)
            .ok_or(StorageError::MissingColumnFamily(CF_META))?;
        self.db
            .get_cf(&cf, key)
            .map_err(|e| StorageError::RocksDb(e.to_string()))
    }

    fn batch_put(
        &self,
        batch: &mut WriteBatch,
        cf_name: &'static str,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), StorageError> {
        let cf = self
            .db
            .cf_handle(cf_name)
            .ok_or(StorageError::MissingColumnFamily(cf_name))?;
        batch.put_cf(&cf, key, value);
        Ok(())
    }

    fn batch_delete(
        &self,
        batch: &mut WriteBatch,
        cf_name: &'static str,
        key: &[u8],
    ) -> Result<(), StorageError> {
        let cf = self
            .db
            .cf_handle(cf_name)
            .ok_or(StorageError::MissingColumnFamily(cf_name))?;
        batch.delete_cf(&cf, key);
        Ok(())
    }

    fn batch_put_meta(
        &self,
        batch: &mut WriteBatch,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), StorageError> {
        self.batch_put(batch, CF_META, key, value)
    }

    fn write_batch_sync(&self, batch: WriteBatch) -> Result<(), StorageError> {
        let mut opts = WriteOptions::default();
        opts.set_sync(true);
        self.db
            .write_opt(batch, &opts)
            .map_err(|e| StorageError::RocksDb(e.to_string()))
    }
}

// ═══════════════════════════════════════════════════════════════════
// u32 HELPERS (schema version)
// ═══════════════════════════════════════════════════════════════════

#[must_use]
const fn u32_to_be(n: u32) -> [u8; 4] {
    n.to_be_bytes()
}

fn u32_from_be(bytes: &[u8]) -> Result<u32, StorageError> {
    let arr: [u8; 4] = bytes
        .try_into()
        .map_err(|_| StorageError::Corrupt("u32 meta value is not 4 bytes"))?;
    Ok(u32::from_be_bytes(arr))
}

// ═══════════════════════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════════════════════

/// Errors raised by the storage layer.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// Tried to create a DB at a path that already contains one.
    #[error("database already exists at {0:?}")]
    DatabaseAlreadyExists(PathBuf),

    /// Tried to open a DB at a path that contains no DB.
    #[error("no database at {0:?}")]
    DatabaseNotFound(PathBuf),

    /// A column family that should exist wasn't reachable.
    #[error("missing column family: {0}")]
    MissingColumnFamily(&'static str),

    /// A required meta key is missing from disk.
    #[error("missing meta key: {0}")]
    MissingMeta(&'static str),

    /// On-disk schema version doesn't match what the running binary expects.
    #[error(
        "schema version mismatch: on-disk {on_disk}, binary {binary} \
         (refusing to touch DB to prevent silent corruption)"
    )]
    SchemaVersionMismatch {
        /// Version found in the DB's meta.
        on_disk: u32,
        /// Version this binary was built against.
        binary: u32,
    },

    /// RocksDB returned an error.
    #[error("rocksdb error: {0}")]
    RocksDb(String),

    /// bincode encode failed.
    #[error("encode error: {0}")]
    Encode(String),

    /// bincode decode failed.
    #[error("decode error: {0}")]
    Decode(String),

    /// On-disk bytes failed key decoding.
    #[error("key decode error: {0}")]
    Key(#[from] KeyError),

    /// Hash computation error.
    #[error("hash error: {0}")]
    Hash(#[from] HashError),

    /// Block-layer error.
    #[error("block error: {0}")]
    Block(#[from] BlockError),

    /// On-disk data has an impossible value (e.g., wrong length).
    #[error("corrupt on-disk data: {0}")]
    Corrupt(&'static str),
}

// ═══════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::Chain;
    use crate::consensus::{QuorumCertificate, Vote};
    use crate::crypto::keypair::Keypair;
    use crate::genesis::build_genesis_block;
    use crate::tx::{InscribePayload, SignedTransaction, Transaction, TransferPayload, HYPHAE_PER_TFS};
    use tempfile::TempDir;

    const CHAIN_ID: &str = "tfs-test-1";

    fn kp() -> Keypair {
        Keypair::generate()
    }

    fn make_validator_set(n: usize) -> (Vec<Keypair>, ValidatorSet) {
        let kps: Vec<Keypair> = (0..n).map(|_| kp()).collect();
        let set = ValidatorSet::new(kps.iter().map(Keypair::public_key)).expect("set");
        (kps, set)
    }

    fn sign_qc(validators: &[&Keypair], height: u64, block_hash: Hash, set: &ValidatorSet) -> QuorumCertificate {
        let votes = validators
            .iter()
            .map(|k| Vote::sign(height, block_hash, k))
            .collect();
        QuorumCertificate::new(height, block_hash, votes, set).expect("qc")
    }

    // ─── Create / open ──────────────────────────────────────────────

    #[test]
    fn create_initializes_empty_db() {
        let dir = TempDir::new().unwrap();
        let (_kps, set) = make_validator_set(3);
        let storage = Storage::create(dir.path(), CHAIN_ID, &set).expect("create");
        assert_eq!(storage.load_chain_id().unwrap(), CHAIN_ID);
        assert_eq!(storage.load_validators().unwrap(), set);
        assert_eq!(storage.load_height().unwrap(), None);
        assert_eq!(storage.load_last_block_hash().unwrap(), None);
    }

    #[test]
    fn create_rejects_if_db_exists() {
        let dir = TempDir::new().unwrap();
        let (_kps, set) = make_validator_set(3);
        let _s1 = Storage::create(dir.path(), CHAIN_ID, &set).expect("first");
        drop(_s1);
        let err = Storage::create(dir.path(), CHAIN_ID, &set).expect_err("second");
        assert!(matches!(err, StorageError::DatabaseAlreadyExists(_)));
    }

    #[test]
    fn open_rejects_empty_directory() {
        let dir = TempDir::new().unwrap();
        let err = Storage::open(dir.path()).expect_err("no db");
        assert!(matches!(err, StorageError::DatabaseNotFound(_)));
    }

    #[test]
    fn open_reads_what_create_wrote() {
        let dir = TempDir::new().unwrap();
        let (_kps, set) = make_validator_set(3);
        {
            let _s = Storage::create(dir.path(), CHAIN_ID, &set).expect("create");
        } // drop to release the DB lock
        let s = Storage::open(dir.path()).expect("reopen");
        assert_eq!(s.load_chain_id().unwrap(), CHAIN_ID);
        assert_eq!(s.load_validators().unwrap(), set);
    }

    // ─── Genesis commit roundtrip ───────────────────────────────────

    fn genesis_setup() -> (TempDir, Keypair, Vec<Keypair>, ValidatorSet, CommittedBlock) {
        let dir = TempDir::new().unwrap();
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
        let committed = CommittedBlock::new(block, qc, &set).expect("cb");
        (dir, president, vec![v1, v2], set, committed)
    }

    #[test]
    fn commit_block_stores_genesis_and_state_diff() {
        let (dir, president, _vs, set, committed) = genesis_setup();
        let storage = Storage::create(dir.path(), CHAIN_ID, &set).expect("create");

        // Compute the expected state diff from applying genesis to empty state.
        let before = State::new();
        let mut after = before.clone();
        after.apply_block(&committed.block).expect("apply");
        let diff = StateDiff::between(&before, &after);

        storage.commit_block(&committed, &diff).expect("commit");

        // Height and hash now persisted.
        let h = storage.load_height().unwrap().expect("has height");
        assert_eq!(h, 0);
        let bh = committed.block.hash().unwrap();
        assert_eq!(storage.load_last_block_hash().unwrap().unwrap(), bh);

        // Block retrievable by height AND by hash.
        let by_height = storage.get_committed_block(0).unwrap().expect("by height");
        let by_hash = storage.get_block_by_hash(&bh).unwrap().expect("by hash");
        assert_eq!(by_height, by_hash);

        // State reconstructed from disk.
        let restored = storage.load_state().unwrap();
        assert_eq!(restored, after);

        // President has 1000 $TFS.
        let pres_addr = crate::crypto::address::Address::from_public_key(&president.public_key());
        assert_eq!(restored.balance(&pres_addr), 1_000 * HYPHAE_PER_TFS);
    }

    #[test]
    fn reopen_restores_full_state_and_height() {
        let (dir, _president, _vs, set, committed) = genesis_setup();
        let path = dir.path().to_path_buf();
        let expected_state = {
            let storage = Storage::create(&path, CHAIN_ID, &set).expect("create");
            let before = State::new();
            let mut after = before.clone();
            after.apply_block(&committed.block).expect("apply");
            let diff = StateDiff::between(&before, &after);
            storage.commit_block(&committed, &diff).expect("commit");
            after
        };
        // storage dropped — reopen.
        let storage = Storage::open(&path).expect("reopen");
        let restored = storage.load_state().unwrap();
        assert_eq!(restored, expected_state);
        assert_eq!(storage.load_height().unwrap(), Some(0));
    }

    // ─── Multi-block commits ────────────────────────────────────────

    #[test]
    fn two_block_commit_is_atomic_and_chained() {
        let (dir, president, vs, set, g_committed) = genesis_setup();
        let storage = Storage::create(dir.path(), CHAIN_ID, &set).expect("create");

        // Genesis.
        let before = State::new();
        let mut s = before.clone();
        s.apply_block(&g_committed.block).expect("apply g");
        let g_diff = StateDiff::between(&before, &s);
        storage.commit_block(&g_committed, &g_diff).expect("commit g");

        // Build block 1: president transfers 500 to a new citizen.
        let alice = kp();
        let pres_addr = crate::crypto::address::Address::from_public_key(&president.public_key());
        let alice_addr = crate::crypto::address::Address::from_public_key(&alice.public_key());

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
        .expect("sign");
        let tx_bytes = tx.to_bytes().expect("bytes");

        let b1 = crate::block::Block::propose(
            &g_committed.block,
            CHAIN_ID,
            2,
            vec![tx_bytes],
            &president,
        )
        .expect("b1");
        let bh1 = b1.hash().expect("bh1");
        let refs: Vec<&Keypair> = std::iter::once(&president).chain(vs.iter()).collect();
        let qc1 = sign_qc(&refs, 1, bh1, &set);
        let b1_committed = CommittedBlock::new(b1, qc1, &set).expect("cb1");

        let before_b1 = s.clone();
        s.apply_block(&b1_committed.block).expect("apply b1");
        let b1_diff = StateDiff::between(&before_b1, &s);
        storage.commit_block(&b1_committed, &b1_diff).expect("commit b1");

        // Verify: height 1, alice has 500, president nonce advanced.
        let restored = storage.load_state().unwrap();
        assert_eq!(restored.height, 1);
        assert_eq!(restored.balance(&alice_addr), 500);
        assert_eq!(restored.nonce(&pres_addr), 2);

        // Tx index: find the transfer.
        let tx_id = tx.tx_id().unwrap();
        let loc = storage.get_tx_location(&tx_id).unwrap().expect("indexed");
        assert_eq!(loc.height, 1);
        assert_eq!(loc.tx_index, 0);
    }

    // ─── State diff correctness ─────────────────────────────────────

    #[test]
    fn diff_captures_balance_removal() {
        use crate::crypto::address::Address;
        let a = Address::from_public_key(&kp().public_key());
        let mut before = State::new();
        before.balances.insert(a, 100);
        let after = State::new();
        let diff = StateDiff::between(&before, &after);
        // Balance went to 0 → emit None to signal delete.
        assert_eq!(diff.balances.len(), 1);
        assert!(diff.balances[0].1.is_none());
    }

    #[test]
    fn diff_captures_new_verified_and_inscribed() {
        use crate::crypto::address::Address;
        let a = Address::from_public_key(&kp().public_key());
        let h = Hash::from_bytes([7u8; 32]);
        let before = State::new();
        let mut after = before.clone();
        after.verified_citizens.insert(a);
        after.inscribed_doctrines.insert(h);
        let diff = StateDiff::between(&before, &after);
        assert_eq!(diff.newly_verified, vec![a]);
        assert_eq!(diff.newly_inscribed, vec![h]);
    }

    // ─── Chain integration smoke test ───────────────────────────────

    #[test]
    fn in_memory_chain_matches_disk_after_commits() {
        let (dir, president, vs, set, g_committed) = genesis_setup();
        let storage = Storage::create(dir.path(), CHAIN_ID, &set).expect("create");

        // In-memory Chain starts from genesis.
        let mut chain = Chain::genesis(CHAIN_ID, set.clone(), g_committed.block.clone(), g_committed.qc.clone(), 1)
            .expect("chain");

        // Commit genesis to disk.
        let before = State::new();
        let mut s = before.clone();
        s.apply_block(&g_committed.block).expect("apply g");
        storage
            .commit_block(&g_committed, &StateDiff::between(&before, &s))
            .expect("commit g");

        // Inscribe a second doctrine at height 1.
        let pres_addr = crate::crypto::address::Address::from_public_key(&president.public_key());
        let inscribe = SignedTransaction::sign_single(
            Transaction::Inscribe(InscribePayload::new(
                pres_addr,
                b"second doctrine".to_vec(),
                1,
                2,
            )),
            &president,
        )
        .expect("sign");
        let b1 = crate::block::Block::propose(
            &g_committed.block,
            CHAIN_ID,
            2,
            vec![inscribe.to_bytes().unwrap()],
            &president,
        )
        .expect("b1");
        let bh1 = b1.hash().unwrap();
        let refs: Vec<&Keypair> = std::iter::once(&president).chain(vs.iter()).collect();
        let qc1 = sign_qc(&refs, 1, bh1, &set);
        let cb1 = CommittedBlock::new(b1, qc1, &set).expect("cb1");

        let before_b1 = s.clone();
        s.apply_block(&cb1.block).expect("apply b1");
        let diff = StateDiff::between(&before_b1, &s);

        chain.append_committed_block(cb1.clone(), 2).expect("append");
        storage.commit_block(&cb1, &diff).expect("commit b1");

        // On-disk state equals in-memory state.
        let disk_state = storage.load_state().unwrap();
        assert_eq!(&disk_state, chain.state());
    }
}
