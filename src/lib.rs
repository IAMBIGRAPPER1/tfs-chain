// TFS_CHAIN · MINES. VENTURE, LLC · IAMBIGRAPPER1 · ALL RIGHTS MINES.
//
// THE SOVEREIGN MYCELIAL CRYPTO LEDGER
//
// This is the crate root. Every module of THE TFS CHAIN is exported here.
// Each layer is a sealed module. Adding a new module is a constitutional act.
//
// Architecture (seven layers, each a Dragon Run unit):
//
//   Layer 1 · crypto           ed25519 signing · BLAKE3 hashing · bech32 addresses
//   Layer 2 · block            the atom of the chain
//   Layer 3 · tx               transactions: transfer, inscribe, verify, burn
//   Layer 4 · mines_script     the doctrine-block format (HOA-tone DSL)
//   Layer 5 · chain            append-only validation · mempool · BFT consensus
//   Layer 6 · storage          RocksDB persistence
//   Layer 7 · node             HTTP API + libp2p networking
//
// Immutability doctrine:
//   The chain remembers.
//   The chain forgives.
//   The chain does not forget.
//
// PRESIDENT MINES. INSCRIBES.
// IAMBIGRAPPER1 SEALS.
// THE CHAIN HOLDS.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]

//! # TFS_CHAIN
//!
//! The sovereign mycelial crypto ledger of THE FINAL SERVER.
//!
//! ## Design principles
//!
//! - **Sovereign by posture.** Validators are authorized, not anonymous.
//!   Citizens scale infinitely; validators scale by invitation.
//! - **Immutable by design.** Sealed blocks cannot be rewritten. Even by
//!   PRESIDENT MINES. Doctrine evolves through new blocks, never through edits.
//! - **Deterministic by default.** No floating point. No non-canonical
//!   serialization. Identical inputs produce identical hashes on every
//!   machine, forever.
//! - **Memory-safe by compiler proof.** No `unsafe` Rust anywhere in this crate.
//! - **Zeroized on drop.** Private keys are wiped from memory when dropped.
//!
//! ## Layer 1 — Cryptographic Foundation (sealed)
//!
//! See [`crypto`] for hashing, keypair, and address primitives.
//!
//! ## Layer 2+ — Pending
//!
//! Under construction. The chain is being built in order.

// Layer 1 · Cryptographic Foundation
pub mod crypto;

// Layer 2 · The Block
pub mod block;

// Layers 3–7 · pending Dragon Runs before they land
// pub mod tx;
// pub mod mines_script;
// pub mod chain;
// pub mod consensus;
// pub mod storage;
// pub mod node;

/// The protocol version. Incremented only by constitutional act of PRESIDENT MINES.
pub const PROTOCOL_VERSION: u32 = 1;

/// The canonical chain identifier. Inscribed in the genesis block.
/// Forks must use a different chain ID.
pub const CHAIN_ID: &str = "tfs-mainnet-1";

/// The human-readable address prefix (bech32 HRP).
/// Every address on the chain starts with `tfs1...`.
pub const ADDRESS_HRP: &str = "tfs";
