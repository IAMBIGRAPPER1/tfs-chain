// TFS_CHAIN · node/messages.rs · Layer 7
//
// P2P WIRE MESSAGES.
//
// Every byte that crosses the libp2p gossipsub network is one of these
// three messages, serialized with bincode and prefixed with a single
// VERSION BYTE so that old nodes can reject future-version messages
// cleanly instead of accepting garbage.
//
//   [version:u8][bincode(GossipMessage)]
//
// Messages are size-bounded by Layer 2/3 limits (a tx ≤ 1 MiB, a block
// ≤ 4 MiB). A malformed or oversized frame is dropped at decode time —
// libp2p's own gossipsub message size limit enforces the upper bound.

//! Wire-format messages for the peer-to-peer network.
//!
//! The three topics map one-to-one with the enum variants:
//! - `tfs-tx-v1`    → [`GossipMessage::Transaction`]
//! - `tfs-block-v1` → [`GossipMessage::Block`]
//! - `tfs-vote-v1`  → [`GossipMessage::Vote`]

#![cfg(feature = "node")]

use serde::{Deserialize, Serialize};

use crate::block::Block;
use crate::consensus::{CommittedBlock, Vote};
use crate::tx::SignedTransaction;

// ═══════════════════════════════════════════════════════════════════
// TOPICS
// ═══════════════════════════════════════════════════════════════════

/// Gossipsub topic for transaction broadcast.
pub const TOPIC_TX: &str = "tfs-tx-v1";

/// Gossipsub topic for un-finalized block proposals.
/// Leader broadcasts a [`GossipMessage::Proposal`] here; validators
/// vote on it via [`TOPIC_VOTE`].
pub const TOPIC_PROPOSAL: &str = "tfs-proposal-v1";

/// Gossipsub topic for finalized / committed blocks.
/// Anyone who locally forms a quorum broadcasts the resulting
/// [`GossipMessage::Committed`] here so peers converge in lockstep.
pub const TOPIC_COMMITTED: &str = "tfs-committed-v1";

/// Gossipsub topic for consensus-vote broadcast.
pub const TOPIC_VOTE: &str = "tfs-vote-v1";

// ═══════════════════════════════════════════════════════════════════
// WIRE FRAME
// ═══════════════════════════════════════════════════════════════════

/// Current wire format version.
///
/// Incremented on any breaking change to how messages are serialized or
/// what fields a message carries. An old node receiving a new version
/// drops the frame rather than mis-decoding it.
pub const WIRE_VERSION: u8 = 1;

/// Maximum size of a single gossip message in bytes.
///
/// 5 MiB — safely larger than `MAX_BLOCK_SIZE_BYTES` (4 MiB from Layer 2)
/// plus framing overhead, smaller than a libp2p default of 10 MiB.
pub const MAX_MESSAGE_BYTES: usize = 5 * 1024 * 1024;

/// A peer-to-peer gossip message.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GossipMessage {
    /// A signed transaction offered to peers.
    Transaction(SignedTransaction),

    /// An un-finalized block proposal. The leader broadcasts this;
    /// validators then vote via [`GossipMessage::Vote`].
    Proposal(Block),

    /// A validator's vote on a proposed block.
    Vote(Vote),

    /// A finalized block with its quorum certificate. Broadcast by any
    /// node that locally forms a QC so peers can converge without
    /// waiting to see every vote individually.
    Committed(CommittedBlock),
}

impl GossipMessage {
    /// Serialize this message into a versioned wire frame.
    ///
    /// Format: `[WIRE_VERSION as u8][bincode(self)]`.
    ///
    /// # Errors
    /// Returns [`WireError`] if bincode serialization fails (should be
    /// impossible for the types involved) or if the encoded size would
    /// exceed [`MAX_MESSAGE_BYTES`].
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let body = bincode::serialize(self).map_err(|e| WireError::Encode(e.to_string()))?;
        if body.len() + 1 > MAX_MESSAGE_BYTES {
            return Err(WireError::TooLarge {
                actual: body.len() + 1,
                max: MAX_MESSAGE_BYTES,
            });
        }
        let mut out = Vec::with_capacity(body.len() + 1);
        out.push(WIRE_VERSION);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Parse a wire frame back into a [`GossipMessage`].
    ///
    /// # Errors
    /// Returns [`WireError`] if:
    /// - The frame is empty.
    /// - The version byte doesn't match [`WIRE_VERSION`].
    /// - The body fails to decode via bincode.
    /// - The frame is larger than [`MAX_MESSAGE_BYTES`].
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(WireError::TooLarge {
                actual: bytes.len(),
                max: MAX_MESSAGE_BYTES,
            });
        }
        let Some((&ver, body)) = bytes.split_first() else {
            return Err(WireError::EmptyFrame);
        };
        if ver != WIRE_VERSION {
            return Err(WireError::UnsupportedVersion {
                got: ver,
                expected: WIRE_VERSION,
            });
        }
        bincode::deserialize(body).map_err(|e| WireError::Decode(e.to_string()))
    }
}

// ═══════════════════════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════════════════════

/// Errors that can occur encoding or decoding a gossip frame.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    /// Received an empty frame.
    #[error("empty gossip frame")]
    EmptyFrame,

    /// Version byte didn't match the binary's expected version.
    #[error("unsupported wire version: got {got}, expected {expected}")]
    UnsupportedVersion {
        /// The version byte in the frame.
        got: u8,
        /// The version this binary speaks.
        expected: u8,
    },

    /// Frame exceeds the protocol size limit.
    #[error("gossip frame too large: {actual} bytes, max {max}")]
    TooLarge {
        /// Actual frame size.
        actual: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Encoding failed.
    #[error("wire encode error: {0}")]
    Encode(String),

    /// Decoding failed.
    #[error("wire decode error: {0}")]
    Decode(String),
}

// ═══════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash::Hash;
    use crate::crypto::keypair::Keypair;
    use crate::tx::{SignedTransaction, Transaction, TransferPayload};

    fn kp() -> Keypair {
        Keypair::generate()
    }

    #[test]
    fn tx_roundtrip() {
        let alice = kp();
        let bob = kp();
        let tx = Transaction::Transfer(TransferPayload {
            from: crate::crypto::address::Address::from_public_key(&alice.public_key()),
            to: crate::crypto::address::Address::from_public_key(&bob.public_key()),
            amount_hyphae: 42,
            nonce: 0,
            timestamp_ms: 1,
        });
        let stx = SignedTransaction::sign_single(tx, &alice).expect("sign");
        let msg = GossipMessage::Transaction(stx.clone());
        let bytes = msg.encode().expect("encode");
        match GossipMessage::decode(&bytes).expect("decode") {
            GossipMessage::Transaction(got) => assert_eq!(got, stx),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn vote_roundtrip() {
        let v = kp();
        let bh = Hash::from_bytes([7u8; 32]);
        let vote = Vote::sign(42, bh, &v);
        let msg = GossipMessage::Vote(vote.clone());
        let bytes = msg.encode().expect("encode");
        match GossipMessage::decode(&bytes).expect("decode") {
            GossipMessage::Vote(got) => assert_eq!(got, vote),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn decode_rejects_empty() {
        let err = GossipMessage::decode(&[]).expect_err("empty");
        assert!(matches!(err, WireError::EmptyFrame));
    }

    #[test]
    fn decode_rejects_wrong_version() {
        // Fake frame with version 99.
        let bytes = vec![99u8, 0, 0];
        let err = GossipMessage::decode(&bytes).expect_err("bad version");
        assert!(matches!(err, WireError::UnsupportedVersion { got: 99, .. }));
    }

    #[test]
    fn decode_rejects_oversized() {
        let big = vec![0u8; MAX_MESSAGE_BYTES + 1];
        let err = GossipMessage::decode(&big).expect_err("too big");
        assert!(matches!(err, WireError::TooLarge { .. }));
    }

    #[test]
    fn decode_rejects_garbage_body() {
        let mut bytes = vec![WIRE_VERSION];
        bytes.extend_from_slice(&[0xFF; 100]);
        let err = GossipMessage::decode(&bytes).expect_err("garbage");
        assert!(matches!(err, WireError::Decode(_)));
    }

    #[test]
    fn encode_prepends_version_byte() {
        let v = kp();
        let msg = GossipMessage::Vote(Vote::sign(1, Hash::from_bytes([0u8; 32]), &v));
        let bytes = msg.encode().unwrap();
        assert_eq!(bytes[0], WIRE_VERSION);
    }

    #[test]
    fn topics_are_distinct() {
        let topics = [TOPIC_TX, TOPIC_PROPOSAL, TOPIC_VOTE, TOPIC_COMMITTED];
        for i in 0..topics.len() {
            for j in (i + 1)..topics.len() {
                assert_ne!(topics[i], topics[j], "topics must be distinct");
            }
        }
    }
}
