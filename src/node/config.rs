// TFS_CHAIN · node/config.rs · Layer 7
//
// NODE CONFIGURATION.
//
// Everything a node needs to know at boot, in one struct:
//   - data directory (where RocksDB lives)
//   - chain id (must match on-disk if the DB exists)
//   - HTTP listen address
//   - libp2p listen address
//   - bootstrap peers (optional multiaddrs to dial at startup)
//   - validator role (None if a read-only full node; Some(keypair) if a
//     validator that signs blocks and votes)
//   - optional network identity key (separate from validator key; random
//     if unset)
//
// Everything else is derived at runtime from the Layer 6 storage.

//! Node configuration for Layer 7.

#![cfg(feature = "node")]

use std::net::SocketAddr;
use std::path::PathBuf;

use crate::crypto::keypair::Keypair;

// ═══════════════════════════════════════════════════════════════════
// CONFIG
// ═══════════════════════════════════════════════════════════════════

/// Configuration for a running [`crate::node::Node`] instance.
///
/// Build with [`NodeConfig::new`] and the `with_*` builder methods.
pub struct NodeConfig {
    /// Directory where the RocksDB lives. Created on first boot.
    pub data_dir: PathBuf,

    /// Chain identifier. Must match the on-disk chain id if the DB
    /// already exists. For mainnet: `"tfs-mainnet-1"`.
    pub chain_id: String,

    /// Address the HTTP API listens on.
    pub http_listen: SocketAddr,

    /// libp2p multiaddr the node listens on.
    /// Example: `/ip4/0.0.0.0/tcp/9090`.
    pub p2p_listen: String,

    /// Peers to dial at startup (multiaddr form).
    /// Empty = isolated / first node.
    pub bootstrap_peers: Vec<String>,

    /// If this node is a validator, its signing keypair (signs blocks
    /// and votes). If `None`, this node runs as a read-only full node
    /// that gossips, indexes, and serves queries but never proposes or
    /// votes.
    pub validator_key: Option<Keypair>,

    /// Optional override for the libp2p network identity keypair. If
    /// `None`, a random one is generated at boot (the node gets a new
    /// peer id each run). Set this to a persistent secret for a stable
    /// peer id across reboots.
    pub network_key_seed: Option<[u8; 32]>,
}

impl NodeConfig {
    /// Construct a minimum-viable config.
    ///
    /// Defaults:
    /// - HTTP on `127.0.0.1:8080` (loopback — override for public exposure)
    /// - P2P on `/ip4/0.0.0.0/tcp/9090`
    /// - No bootstrap peers
    /// - Not a validator (read-only full node)
    #[must_use]
    pub fn new(data_dir: impl Into<PathBuf>, chain_id: impl Into<String>) -> Self {
        Self {
            data_dir: data_dir.into(),
            chain_id: chain_id.into(),
            http_listen: "127.0.0.1:8080"
                .parse()
                .expect("hardcoded loopback is always parseable"),
            p2p_listen: "/ip4/0.0.0.0/tcp/9090".to_string(),
            bootstrap_peers: Vec::new(),
            validator_key: None,
            network_key_seed: None,
        }
    }

    /// Set the HTTP listen address.
    #[must_use]
    pub fn with_http_listen(mut self, addr: SocketAddr) -> Self {
        self.http_listen = addr;
        self
    }

    /// Set the libp2p listen multiaddr (e.g. `/ip4/0.0.0.0/tcp/9090`).
    #[must_use]
    pub fn with_p2p_listen(mut self, addr: impl Into<String>) -> Self {
        self.p2p_listen = addr.into();
        self
    }

    /// Add a bootstrap peer multiaddr.
    #[must_use]
    pub fn with_bootstrap_peer(mut self, addr: impl Into<String>) -> Self {
        self.bootstrap_peers.push(addr.into());
        self
    }

    /// Promote this node to a validator with the given signing keypair.
    #[must_use]
    pub fn with_validator_key(mut self, kp: Keypair) -> Self {
        self.validator_key = Some(kp);
        self
    }

    /// Set a persistent libp2p network identity seed.
    #[must_use]
    pub const fn with_network_key_seed(mut self, seed: [u8; 32]) -> Self {
        self.network_key_seed = Some(seed);
        self
    }

    /// True if this node has a validator signing key and should sign
    /// blocks/votes.
    #[must_use]
    pub const fn is_validator(&self) -> bool {
        self.validator_key.is_some()
    }
}

// ═══════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_produces_sensible_defaults() {
        let c = NodeConfig::new("/tmp/tfs", "tfs-test-1");
        assert_eq!(c.chain_id, "tfs-test-1");
        assert_eq!(c.http_listen.to_string(), "127.0.0.1:8080");
        assert_eq!(c.p2p_listen, "/ip4/0.0.0.0/tcp/9090");
        assert!(c.bootstrap_peers.is_empty());
        assert!(!c.is_validator());
    }

    #[test]
    fn with_validator_key_toggles_role() {
        let kp = Keypair::generate();
        let c = NodeConfig::new("/tmp/tfs", "tfs-test-1").with_validator_key(kp);
        assert!(c.is_validator());
    }

    #[test]
    fn with_bootstrap_peer_accumulates() {
        let c = NodeConfig::new("/tmp/tfs", "tfs-test-1")
            .with_bootstrap_peer("/ip4/1.2.3.4/tcp/9090")
            .with_bootstrap_peer("/ip4/5.6.7.8/tcp/9090");
        assert_eq!(c.bootstrap_peers.len(), 2);
    }
}
