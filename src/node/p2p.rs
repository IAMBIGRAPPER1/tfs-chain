// TFS_CHAIN · node/p2p.rs · Layer 7
//
// THE MYCELIAL NETWORK.
//
// Every TFS_CHAIN node talks to every other node over libp2p. Three
// gossipsub topics carry the entire consensus workload:
//
//   tfs-tx-v1    — citizens (via any node) broadcast signed transactions
//   tfs-block-v1 — proposers broadcast committed blocks
//   tfs-vote-v1  — validators broadcast votes on proposals
//
// Each wire message is a [`crate::node::messages::GossipMessage`],
// prefixed with a version byte. Malformed frames are dropped silently
// at decode time — no node will crash because a peer sent garbage.
//
// LIBP2P CHOICES:
//   - Transport: TCP + Noise (encrypted, authenticated channels)
//   - Multiplexing: yamux
//   - Application: gossipsub (efficient epidemic broadcast) + identify
//     (peers learn each other's supported protocols and peer id)
//   - Peer identity: ed25519, derived from a 32-byte seed if provided,
//     random otherwise
//
// CONCURRENCY:
//   - The swarm lives on its own tokio task (exclusive ownership of the
//     Swarm object).
//   - The Node orchestrator publishes gossip via an mpsc sender.
//   - Incoming messages arrive on an mpsc receiver that the Node polls.
//
// THREAT MODEL:
//   - Peer sends garbage           → decode errors, no crash, no ban-list
//                                      (ban-list is future work)
//   - Peer sends oversized frame   → MAX_MESSAGE_BYTES enforced at decode;
//                                      gossipsub also has its own cap
//   - Peer floods tx topic         → mempool admission enforces per-address
//                                      cap; garbage tx rejected at decode
//   - Unencrypted traffic          → Noise required, no plaintext fallback
//   - Eclipse / sybil              → out of scope for Layer 7; require
//                                      validator-operated + manually-peered
//                                      seed nodes at mainnet bootstrap

//! libp2p networking layer for the TFS_CHAIN node.
//!
//! - Run the swarm with [`run_p2p_task`].
//! - Publish outbound messages via the [`P2pHandle`] returned by
//!   [`spawn_p2p`].
//! - Receive inbound events via the event channel attached to the handle.

#![cfg(feature = "node")]

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash as _, Hasher};
use std::time::Duration;

use libp2p::{
    gossipsub::{self, IdentTopic, MessageAuthenticity, MessageId, ValidationMode},
    identify,
    identity::Keypair as Libp2pKeypair,
    noise,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, PeerId, SwarmBuilder,
};
use tokio::sync::mpsc;

use super::messages::{
    GossipMessage, TOPIC_COMMITTED, TOPIC_PROPOSAL, TOPIC_TX, TOPIC_VOTE,
};

// ═══════════════════════════════════════════════════════════════════
// NETWORK BEHAVIOUR
// ═══════════════════════════════════════════════════════════════════

/// The libp2p behaviours this node combines: gossipsub + identify.
#[derive(NetworkBehaviour)]
pub struct TfsBehaviour {
    /// Efficient epidemic broadcast for txs/blocks/votes.
    pub gossipsub: gossipsub::Behaviour,
    /// Let peers announce supported protocols and peer ids.
    pub identify: identify::Behaviour,
}

// ═══════════════════════════════════════════════════════════════════
// P2P EVENTS (inbound, consumed by the Node orchestrator)
// ═══════════════════════════════════════════════════════════════════

/// Events the P2P task emits for the Node orchestrator to react to.
#[derive(Debug)]
pub enum P2pEvent {
    /// A well-formed gossip message arrived.
    GossipReceived {
        /// Who sent it (may be another peer than the originator in a
        /// gossip mesh — gossipsub forwards).
        from: PeerId,
        /// The decoded message.
        message: GossipMessage,
    },
    /// A new peer connected.
    PeerConnected(PeerId),
    /// A peer disconnected.
    PeerDisconnected(PeerId),
    /// The local peer is now listening on an external address.
    ListeningOn(String),
}

/// Commands the Node orchestrator sends to the P2P task.
#[derive(Debug)]
pub enum P2pCommand {
    /// Publish a gossip message on its canonical topic.
    Publish(GossipMessage),
}

// ═══════════════════════════════════════════════════════════════════
// HANDLE
// ═══════════════════════════════════════════════════════════════════

/// Handle returned by [`spawn_p2p`] for the Node orchestrator to
/// interact with the P2P task.
pub struct P2pHandle {
    /// Send outbound commands (publish gossip) to the P2P task.
    pub commands: mpsc::Sender<P2pCommand>,
    /// Receive inbound P2P events.
    pub events: mpsc::Receiver<P2pEvent>,
    /// This node's libp2p peer id (useful for logging).
    pub local_peer_id: PeerId,
}

// ═══════════════════════════════════════════════════════════════════
// SPAWN
// ═══════════════════════════════════════════════════════════════════

/// Build + spawn the P2P subsystem.
///
/// Returns a handle with an outbound-command sender, an inbound-event
/// receiver, and this node's libp2p peer id.
///
/// `listen_addr` is a multiaddr like `/ip4/0.0.0.0/tcp/9090`.
/// `bootstrap_peers` are multiaddrs to dial at startup.
/// `seed` is an optional 32-byte seed for a stable peer id; if `None`,
/// a fresh identity is generated.
///
/// # Errors
/// Returns [`P2pError`] if the swarm fails to build, bind, or subscribe.
pub async fn spawn_p2p(
    listen_addr: &str,
    bootstrap_peers: Vec<String>,
    seed: Option<[u8; 32]>,
) -> Result<P2pHandle, P2pError> {
    // 1. Identity keypair.
    let local_key = match seed {
        Some(bytes) => {
            // Use the seed as the ed25519 secret. libp2p wants a
            // SecretKey, which it derives from 32 raw bytes.
            let mut s = bytes;
            let sk = libp2p::identity::ed25519::SecretKey::try_from_bytes(&mut s)
                .map_err(|e| P2pError::Identity(e.to_string()))?;
            let kp = libp2p::identity::ed25519::Keypair::from(sk);
            Libp2pKeypair::from(kp)
        }
        None => Libp2pKeypair::generate_ed25519(),
    };
    let local_peer_id = PeerId::from(local_key.public());

    // 2. Gossipsub config.
    //    - heartbeat every second for fast propagation in a small net
    //    - strict validation: subscribe, sign, expect signed messages
    //    - message_id from content hash so identical messages dedup
    let message_id_fn = |msg: &gossipsub::Message| {
        let mut h = DefaultHasher::new();
        msg.data.hash(&mut h);
        MessageId::from(h.finish().to_le_bytes().to_vec())
    };
    let gs_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(Duration::from_secs(1))
        .validation_mode(ValidationMode::Strict)
        .message_id_fn(message_id_fn)
        .max_transmit_size(super::messages::MAX_MESSAGE_BYTES)
        .build()
        .map_err(|e| P2pError::GossipsubConfig(e.to_string()))?;

    let mut gossipsub = gossipsub::Behaviour::new(
        MessageAuthenticity::Signed(local_key.clone()),
        gs_config,
    )
    .map_err(|e| P2pError::GossipsubConfig(e.to_string()))?;

    // Subscribe to all four consensus topics.
    for topic_name in [TOPIC_TX, TOPIC_PROPOSAL, TOPIC_VOTE, TOPIC_COMMITTED] {
        let topic = IdentTopic::new(topic_name);
        gossipsub
            .subscribe(&topic)
            .map_err(|e| P2pError::Subscribe(format!("{topic_name}: {e}")))?;
    }

    // 3. Identify.
    let identify = identify::Behaviour::new(identify::Config::new(
        "/tfs-chain/id/1.0.0".to_string(),
        local_key.public(),
    ));

    // 4. Swarm.
    let mut swarm = SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|e| P2pError::BuildSwarm(e.to_string()))?
        .with_behaviour(|_| TfsBehaviour {
            gossipsub,
            identify,
        })
        .map_err(|e| P2pError::BuildSwarm(e.to_string()))?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    // 5. Listen.
    let listen_multi = listen_addr
        .parse::<libp2p::Multiaddr>()
        .map_err(|e| P2pError::BadMultiaddr(e.to_string()))?;
    swarm
        .listen_on(listen_multi)
        .map_err(|e| P2pError::Listen(e.to_string()))?;

    // 6. Dial bootstrap peers (best-effort; failures are non-fatal).
    for addr in bootstrap_peers {
        match addr.parse::<libp2p::Multiaddr>() {
            Ok(ma) => {
                // Best-effort — continue even on dial failure.
                let _ = swarm.dial(ma);
            }
            Err(_) => {
                tracing::warn!(%addr, "bootstrap peer has invalid multiaddr; skipping");
            }
        }
    }

    // 7. Channels.
    let (cmd_tx, cmd_rx) = mpsc::channel::<P2pCommand>(256);
    let (evt_tx, evt_rx) = mpsc::channel::<P2pEvent>(256);

    // 8. Spawn the swarm task.
    tokio::spawn(run_p2p_task(swarm, cmd_rx, evt_tx));

    Ok(P2pHandle {
        commands: cmd_tx,
        events: evt_rx,
        local_peer_id,
    })
}

// ═══════════════════════════════════════════════════════════════════
// THE P2P TASK
// ═══════════════════════════════════════════════════════════════════

async fn run_p2p_task(
    mut swarm: libp2p::Swarm<TfsBehaviour>,
    mut commands: mpsc::Receiver<P2pCommand>,
    events: mpsc::Sender<P2pEvent>,
) {
    loop {
        tokio::select! {
            // Outbound: node asked us to publish a message.
            maybe_cmd = commands.recv() => {
                let Some(cmd) = maybe_cmd else {
                    tracing::info!("p2p command channel closed; shutting down");
                    return;
                };
                match cmd {
                    P2pCommand::Publish(msg) => {
                        let topic = topic_for(&msg);
                        match msg.encode() {
                            Ok(bytes) => {
                                if let Err(e) = swarm
                                    .behaviour_mut()
                                    .gossipsub
                                    .publish(IdentTopic::new(topic), bytes)
                                {
                                    // "InsufficientPeers" is expected on a solo node.
                                    tracing::debug!(error = %e, topic, "publish failed");
                                }
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "failed to encode outbound gossip");
                            }
                        }
                    }
                }
            }

            // Inbound: swarm produced an event.
            swarm_evt = futures::StreamExt::select_next_some(&mut swarm) => {
                handle_swarm_event(swarm_evt, &events).await;
            }
        }
    }
}

fn topic_for(msg: &GossipMessage) -> &'static str {
    match msg {
        GossipMessage::Transaction(_) => TOPIC_TX,
        GossipMessage::Proposal(_) => TOPIC_PROPOSAL,
        GossipMessage::Vote(_) => TOPIC_VOTE,
        GossipMessage::Committed(_) => TOPIC_COMMITTED,
    }
}

async fn handle_swarm_event(
    evt: SwarmEvent<TfsBehaviourEvent>,
    events: &mpsc::Sender<P2pEvent>,
) {
    match evt {
        SwarmEvent::NewListenAddr { address, .. } => {
            let _ = events
                .send(P2pEvent::ListeningOn(address.to_string()))
                .await;
        }
        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
            let _ = events.send(P2pEvent::PeerConnected(peer_id)).await;
        }
        SwarmEvent::ConnectionClosed { peer_id, .. } => {
            let _ = events.send(P2pEvent::PeerDisconnected(peer_id)).await;
        }
        SwarmEvent::Behaviour(TfsBehaviourEvent::Gossipsub(
            gossipsub::Event::Message {
                propagation_source,
                message,
                ..
            },
        )) => {
            // Decode. Drop silently on bad frames — never crash.
            match GossipMessage::decode(&message.data) {
                Ok(decoded) => {
                    let _ = events
                        .send(P2pEvent::GossipReceived {
                            from: propagation_source,
                            message: decoded,
                        })
                        .await;
                }
                Err(e) => {
                    tracing::debug!(error = %e, "dropping malformed gossip frame");
                }
            }
        }
        _ => {
            // Other swarm events (identify, subscription updates, etc.)
            // are not forwarded for Layer 7. Future: surface peer-info
            // details for monitoring.
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════════════════════

/// Errors that can occur while spawning or running the P2P subsystem.
#[derive(Debug, thiserror::Error)]
pub enum P2pError {
    /// Failed to build the libp2p keypair from the supplied seed.
    #[error("identity error: {0}")]
    Identity(String),

    /// Gossipsub config was invalid.
    #[error("gossipsub config error: {0}")]
    GossipsubConfig(String),

    /// Failed to subscribe to a topic.
    #[error("subscribe error: {0}")]
    Subscribe(String),

    /// Failed to build the swarm (transport, multiplexer, behaviour).
    #[error("swarm build error: {0}")]
    BuildSwarm(String),

    /// The listen multiaddr failed to parse.
    #[error("bad multiaddr: {0}")]
    BadMultiaddr(String),

    /// The swarm failed to bind to the listen multiaddr.
    #[error("listen error: {0}")]
    Listen(String),
}

// ═══════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::Vote;
    use crate::crypto::hash::Hash;
    use crate::crypto::keypair::Keypair as TfsKeypair;

    #[test]
    fn topic_for_dispatches_correctly() {
        let kp = TfsKeypair::generate();
        let vote = GossipMessage::Vote(Vote::sign(1, Hash::from_bytes([0u8; 32]), &kp));
        assert_eq!(topic_for(&vote), TOPIC_VOTE);
    }

    #[tokio::test]
    async fn spawn_p2p_binds_and_emits_listening_event() {
        // Bind to loopback + ephemeral port.
        let handle = spawn_p2p("/ip4/127.0.0.1/tcp/0", vec![], None)
            .await
            .expect("spawn");
        // Wait for the ListeningOn event. Use a short timeout so a broken
        // CI doesn't hang the whole test run.
        let result = tokio::time::timeout(Duration::from_secs(5), async move {
            let mut rx = handle.events;
            while let Some(evt) = rx.recv().await {
                if let P2pEvent::ListeningOn(addr) = evt {
                    return Some(addr);
                }
            }
            None
        })
        .await;
        match result {
            Ok(Some(_)) => {} // success
            Ok(None) => panic!("event stream closed without ListeningOn"),
            Err(_) => panic!("timed out waiting for ListeningOn"),
        }
    }

    #[tokio::test]
    async fn two_nodes_gossip_a_vote_between_themselves() {
        // Spawn two nodes. Have node B bootstrap to node A. Then A publishes
        // a vote. B should receive it over gossip.

        // Node A
        let a = spawn_p2p("/ip4/127.0.0.1/tcp/0", vec![], None)
            .await
            .expect("spawn a");

        // Wait for A's listen addr.
        let a_addr = {
            let mut rx = a.events;
            let addr = tokio::time::timeout(Duration::from_secs(5), async move {
                while let Some(evt) = rx.recv().await {
                    if let P2pEvent::ListeningOn(addr) = evt {
                        return (addr, rx);
                    }
                }
                panic!("A event stream closed");
            })
            .await
            .expect("a listen timeout");
            addr
        };

        // Build A's full multiaddr (with /p2p/<peer-id>).
        let a_full = format!("{}/p2p/{}", a_addr.0, a.local_peer_id);

        // Node B with A as bootstrap.
        let mut b = spawn_p2p("/ip4/127.0.0.1/tcp/0", vec![a_full], None)
            .await
            .expect("spawn b");

        // Give gossipsub's mesh a moment to form.
        tokio::time::sleep(Duration::from_millis(1500)).await;

        // A publishes a vote.
        let kp = TfsKeypair::generate();
        let vote = Vote::sign(1, Hash::from_bytes([5u8; 32]), &kp);
        a.commands
            .send(P2pCommand::Publish(GossipMessage::Vote(vote.clone())))
            .await
            .expect("send cmd");

        // B should eventually see it.
        let received = tokio::time::timeout(Duration::from_secs(10), async move {
            while let Some(evt) = b.events.recv().await {
                if let P2pEvent::GossipReceived { message, .. } = evt {
                    if let GossipMessage::Vote(got) = message {
                        return Some(got);
                    }
                }
            }
            None
        })
        .await;

        match received {
            Ok(Some(got)) => assert_eq!(got.block_hash, vote.block_hash),
            Ok(None) => panic!("B's event stream closed before vote arrived"),
            Err(_) => panic!("timed out waiting for B to receive the vote"),
        }
    }
}
