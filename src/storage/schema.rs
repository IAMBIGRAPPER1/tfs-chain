// TFS_CHAIN · storage/schema.rs · Layer 6
//
// THE ON-DISK SHAPE OF THE CHAIN.
//
// Every byte written to RocksDB lives in one of the column families
// defined here. Separating data by kind (blocks vs. state vs. indices)
// gives us:
//   - independent compaction per family
//   - per-family read caches
//   - atomic cross-family writes via WriteBatch
//   - simple range scans (by big-endian key order)
//
// CHANGING A COLUMN FAMILY NAME IS A HARD FORK.
// Adding a NEW column family is safe (existing data unaffected).
// Removing one is a hard fork.
//
// KEY ENCODING DOCTRINE:
//   - u64 keys are stored BIG-ENDIAN so byte-lex order == numeric order
//   - 32-byte keys (Address, Hash) are stored as-is
//   - Strings are stored as UTF-8 bytes
//   - No separators, no varint, no self-describing format — the CF is
//     the schema

//! On-disk schema for THE TFS CHAIN.
//!
//! Defines column family names and metadata keys. All on-disk layout
//! constants live here so changes are auditable in one place.

// ═══════════════════════════════════════════════════════════════════
// COLUMN FAMILIES
// ═══════════════════════════════════════════════════════════════════

/// CF · committed blocks indexed by height.
///
/// - Key: `u64` big-endian (height)
/// - Value: `bincode(CommittedBlock)`
pub const CF_BLOCKS: &str = "blocks";

/// CF · block height lookup by block hash.
///
/// - Key: 32-byte block hash
/// - Value: `u64` big-endian (height)
pub const CF_BLOCK_HASH_INDEX: &str = "block_hash_index";

/// CF · transaction location lookup by tx_id.
///
/// - Key: 32-byte tx_id
/// - Value: `bincode(TxLocation)` where `TxLocation` carries
///   `(height, tx_index_in_block)`.
pub const CF_TX_INDEX: &str = "tx_index";

/// CF · citizen balances in hyphae.
///
/// - Key: 32-byte address
/// - Value: `u64` big-endian (balance in hyphae)
/// - Absence of a key means balance = 0.
pub const CF_STATE_BALANCES: &str = "state_balances";

/// CF · per-account nonce counters.
///
/// - Key: 32-byte address
/// - Value: `u64` big-endian (next-expected nonce)
/// - Absence of a key means nonce = 0.
pub const CF_STATE_NONCES: &str = "state_nonces";

/// CF · verified citizens.
///
/// - Key: 32-byte address
/// - Value: empty — existence is the signal
pub const CF_STATE_VERIFIED: &str = "state_verified";

/// CF · inscribed doctrines.
///
/// - Key: 32-byte doctrine hash
/// - Value: empty — existence is the signal
pub const CF_STATE_INSCRIBED: &str = "state_inscribed";

/// CF · scalar state and chain metadata.
///
/// - Key: one of the `META_*` constants below
/// - Value: bytes encoded per the constant's contract
pub const CF_META: &str = "meta";

/// Return the list of all column families that TFS_CHAIN uses.
/// Must include every `CF_*` constant in this file.
#[must_use]
pub fn all_column_families() -> Vec<&'static str> {
    vec![
        CF_BLOCKS,
        CF_BLOCK_HASH_INDEX,
        CF_TX_INDEX,
        CF_STATE_BALANCES,
        CF_STATE_NONCES,
        CF_STATE_VERIFIED,
        CF_STATE_INSCRIBED,
        CF_META,
    ]
}

// ═══════════════════════════════════════════════════════════════════
// META KEYS (inside CF_META)
// ═══════════════════════════════════════════════════════════════════

/// Version of the on-disk schema. If this value ever changes between
/// a running binary and an existing data dir, the binary must refuse to
/// open the DB. Bumped manually when the schema changes incompatibly.
pub const META_SCHEMA_VERSION: &[u8] = b"schema_version";

/// The chain's string identifier (e.g. `"tfs-mainnet-1"`).
/// Stored as UTF-8 bytes.
pub const META_CHAIN_ID: &[u8] = b"chain_id";

/// The authorized validator set, serialized with bincode.
pub const META_VALIDATORS: &[u8] = b"validators";

/// Total $TFS issued to date, in hyphae. u64 big-endian.
pub const META_SUPPLY_ISSUED: &[u8] = b"supply_issued";

/// Total $TFS burned to date, in hyphae. u64 big-endian.
pub const META_SUPPLY_BURNED: &[u8] = b"supply_burned";

/// Total doctrine-blocks inscribed to date. u64 big-endian.
/// Drives the halving schedule.
pub const META_DOCTRINE_COUNT: &[u8] = b"doctrine_count";

/// Height of the most recently committed block. u64 big-endian.
pub const META_HEIGHT: &[u8] = b"height";

/// Hash of the most recently committed block. 32 bytes.
pub const META_LAST_BLOCK_HASH: &[u8] = b"last_block_hash";

// ═══════════════════════════════════════════════════════════════════
// SCHEMA VERSION
// ═══════════════════════════════════════════════════════════════════

/// Current on-disk schema version. Bump on any breaking change.
///
/// A mismatched version is a hard error at `Storage::open` — the binary
/// refuses to touch a DB with a different version. This prevents
/// silent corruption when schema changes.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;
