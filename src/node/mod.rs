// TFS_CHAIN · node/mod.rs · Layer 7
//
// THE NODE.
//
// This ties the six prior layers into a runnable sovereign daemon:
//
//   ┌───────────────────────────────────────────────────────────────┐
//   │                          NODE                                  │
//   │                                                                │
//   │  ┌───────────────┐   ┌──────────────┐   ┌──────────────────┐   │
//   │  │ HTTP (axum)   │   │ P2P (libp2p) │   │ PROPOSE / VOTE   │   │
//   │  │ /status, /tx, │   │ gossipsub    │   │ round-robin      │   │
//   │  │ /block, /addr │   │ tx/prop/vote │   │ leader → block   │   │
//   │  └─────┬─────────┘   └──────┬───────┘   └──────────┬───────┘   │
//   │        │                    │                      │           │
//   │        │    shared state    │    shared state      │           │
//   │        └────────────┬───────┴──────────┬───────────┘           │
//   │                     ▼                  ▼                       │
//   │              ┌──────────────────────────────┐                  │
//   │              │ Arc<RwLock<NodeState>>       │                  │
//   │              │  · PersistentChain (L5 + L6) │                  │
//   │              │  · Mempool                   │                  │
//   │              │  · ConsensusEngine           │                  │
//   │              │  · proposal cache            │                  │
//   │              └──────────────────────────────┘                  │
//   └───────────────────────────────────────────────────────────────┘
//
// RUN LOOP:
//   tokio::select! on:
//     - P2P events (tx / proposal / vote / committed arriving)
//     - Propose timer (if we're a validator and leader, build + gossip)
//     - Shutdown signal
//
// DETERMINISM:
//   Every node running from the same genesis + same gossip history
//   converges to the same state. Non-determinism is confined to:
//     - Timer firing order (not safety-critical; worst case we skip a
//       round)
//     - P2P delivery order (gossipsub is eventually consistent;
//       consensus tolerates out-of-order votes)

//! The TFS_CHAIN sovereign node daemon.
//!
//! Build with [`Node::spawn`], then drive with [`NodeHandle::run_until_shutdown`].

#![cfg(feature = "node")]

pub mod config;
pub mod http;
pub mod messages;
pub mod p2p;
pub mod proposer;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot, RwLock};

use crate::block::Block;
use crate::consensus::{CommittedBlock, ConsensusEngine, Vote};
use crate::crypto::hash::Hash;
use crate::crypto::keypair::Keypair;
use crate::genesis::build_genesis_block;
use crate::mempool::Mempool;
use crate::persistent_chain::PersistentChain;

use self::config::NodeConfig;
use self::messages::GossipMessage;
use self::p2p::{P2pCommand, P2pEvent, P2pHandle};
use self::proposer::{
    consider_proposal, gossip_committed, record_vote_and_maybe_commit, try_propose_block,
};

// ═══════════════════════════════════════════════════════════════════
// NODE STATE
// ═══════════════════════════════════════════════════════════════════

/// The full mutable state of a running node.
///
/// Wrapped in `Arc<RwLock<...>>` so the HTTP handlers (readers) and the
/// orchestrator (writer) can share it safely. Write lock is only held
/// during admission (mempool insert), proposal construction, vote
/// recording, and block commit — all short-duration operations.
pub struct NodeState {
    /// Disk-backed chain.
    pub chain: PersistentChain,

    /// Pending transaction pool.
    pub mempool: Mempool,

    /// BFT vote aggregator.
    pub consensus: ConsensusEngine,

    /// Block proposals we've seen, keyed by `(height, block_hash)`.
    /// Needed so that when a QC forms from incoming votes, we can pair
    /// it with its block.
    pub pending_proposals: BTreeMap<(u64, Hash), Block>,
}

/// Convenience alias for the full node state shared across HTTP, P2P,
/// and the proposer loop.
pub type SharedNodeState = Arc<RwLock<NodeState>>;

// ═══════════════════════════════════════════════════════════════════
// NODE HANDLE
// ═══════════════════════════════════════════════════════════════════

/// Handle returned by [`Node::spawn`]. Call [`Self::run_until_shutdown`]
/// to drive the run loop; call [`Self::shutdown`] to request termination.
pub struct NodeHandle {
    /// Shared mutable state.
    pub state: Arc<RwLock<NodeState>>,
    /// Sender to request a graceful shutdown.
    pub shutdown_tx: oneshot::Sender<()>,
    /// Receiver for the run loop to consume.
    shutdown_rx: Option<oneshot::Receiver<()>>,
    /// P2P subsystem handle.
    p2p: P2pHandle,
    /// If this node is a validator, its signing keypair.
    validator_key: Option<Keypair>,
    /// Our local libp2p peer id (for logging).
    pub local_peer_id: libp2p::PeerId,
    /// HTTP listen address actually bound.
    pub http_addr: std::net::SocketAddr,
}

impl NodeHandle {
    /// Consume this handle and run the main event loop until shutdown.
    ///
    /// Shutdown is requested by dropping `self.shutdown_tx` or sending
    /// `()` through it.
    pub async fn run_until_shutdown(mut self) {
        tracing::info!(
            peer_id = %self.local_peer_id,
            http = %self.http_addr,
            "tfs-node running"
        );

        // Take the shutdown receiver out of the handle.
        let shutdown_rx = self
            .shutdown_rx
            .take()
            .expect("shutdown rx present at start");

        // Proposer tick interval: 2 seconds. Lightweight; we only
        // actually propose when we're the leader.
        let mut propose_ticker = tokio::time::interval(Duration::from_secs(2));
        propose_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        tokio::pin!(shutdown_rx);

        loop {
            tokio::select! {
                // 1. Shutdown.
                _ = &mut shutdown_rx => {
                    tracing::info!("shutdown received; exiting run loop");
                    return;
                }

                // 2. Proposer tick.
                _ = propose_ticker.tick() => {
                    if let Err(e) = self.proposer_tick().await {
                        tracing::warn!(error = %e, "proposer tick errored");
                    }
                }

                // 3. P2P event.
                Some(evt) = self.p2p.events.recv() => {
                    self.handle_p2p_event(evt).await;
                }
            }
        }
    }

    /// Called on each proposer tick. If we're the leader for the next
    /// height, build a proposal and broadcast it.
    async fn proposer_tick(&mut self) -> Result<(), NodeError> {
        let Some(kp) = &self.validator_key else {
            return Ok(());
        };
        let now_ms = now_ms();

        let maybe_proposal = {
            let guard = self.state.read().await;
            try_propose_block(
                &guard.chain,
                &guard.mempool,
                kp,
                now_ms,
                crate::block::MAX_TXS_PER_BLOCK,
            )
            .map_err(NodeError::Proposer)?
        };

        if let Some(block) = maybe_proposal {
            // Cache the proposal so we can pair it with votes later.
            let block_hash = block.hash().map_err(|e| NodeError::Block(Box::new(e)))?;
            {
                let mut guard = self.state.write().await;
                guard
                    .pending_proposals
                    .insert((block.header.height, block_hash), block.clone());
            }
            // Broadcast proposal.
            self.publish(GossipMessage::Proposal(block.clone())).await;

            // We also vote on our own proposal (pretend we just received it).
            self.vote_on_proposal(block, now_ms).await;
        }

        Ok(())
    }

    /// Route an incoming P2P event by variant.
    async fn handle_p2p_event(&mut self, evt: P2pEvent) {
        match evt {
            P2pEvent::GossipReceived { message, .. } => self.handle_gossip(message).await,
            P2pEvent::PeerConnected(pid) => tracing::info!(peer = %pid, "peer connected"),
            P2pEvent::PeerDisconnected(pid) => tracing::info!(peer = %pid, "peer disconnected"),
            P2pEvent::ListeningOn(addr) => tracing::info!(addr, "p2p listening"),
        }
    }

    async fn handle_gossip(&mut self, message: GossipMessage) {
        match message {
            GossipMessage::Transaction(stx) => {
                let mut guard = self.state.write().await;
                let state_snapshot = guard.chain.state().clone();
                match guard.mempool.insert(stx, &state_snapshot) {
                    Ok(_id) => {
                        // Accepted — don't re-broadcast; gossipsub already
                        // forwards in the mesh.
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "mempool admission rejected tx");
                    }
                }
            }

            GossipMessage::Proposal(block) => {
                let now_ms = now_ms();
                // Cache the proposal ONLY if it's for the immediate-next height.
                // Rejecting far-future heights here prevents an unbounded-memory
                // DoS where a malicious peer gossips proposals at arbitrarily
                // large heights and we'd cache them all waiting to commit.
                //
                // Cross-layer defense (Final Dragon Run advisory).
                let block_hash = match block.hash() {
                    Ok(h) => h,
                    Err(e) => {
                        tracing::warn!(error = %e, "dropping proposal with bad hash");
                        return;
                    }
                };
                {
                    let guard = self.state.read().await;
                    let expected = guard.chain.height().saturating_add(1);
                    if block.header.height != expected {
                        tracing::debug!(
                            got = block.header.height,
                            expected,
                            "dropping proposal for non-next height"
                        );
                        return;
                    }
                }
                {
                    let mut guard = self.state.write().await;
                    guard
                        .pending_proposals
                        .insert((block.header.height, block_hash), block.clone());
                }
                self.vote_on_proposal(block, now_ms).await;
            }

            GossipMessage::Vote(vote) => {
                let height = vote.height;
                let block_hash = vote.block_hash;

                // Record the vote; if a QC would form, commit + re-broadcast.
                let committed_opt = {
                    let mut guard = self.state.write().await;
                    // Need the Block paired with this vote. Look it up
                    // in the proposal cache.
                    let Some(block) = guard.pending_proposals.get(&(height, block_hash)).cloned()
                    else {
                        // We haven't seen the proposal yet — just record
                        // the vote in the engine without committing.
                        if let Err(e) = guard.consensus.record_vote(vote) {
                            tracing::debug!(error = %e, "vote rejected");
                        }
                        return;
                    };

                    match record_vote_and_maybe_commit(&mut guard.consensus, vote, &block) {
                        Ok(Some(cb)) => Some(cb),
                        Ok(None) => None,
                        Err(e) => {
                            tracing::debug!(error = %e, "record_vote_and_maybe_commit errored");
                            None
                        }
                    }
                };

                if let Some(cb) = committed_opt {
                    self.try_commit_and_broadcast(cb).await;
                }
            }

            GossipMessage::Committed(cb) => {
                self.try_commit(cb, /* broadcast_if_new = */ false).await;
            }
        }
    }

    async fn vote_on_proposal(&mut self, block: Block, now_ms: i64) {
        let Some(kp) = &self.validator_key else {
            return; // Not a validator — don't vote.
        };
        let vote = {
            let guard = self.state.read().await;
            match consider_proposal(&guard.chain, &block, kp, now_ms) {
                Ok(Some(v)) => v,
                Ok(None) => return,
                Err(e) => {
                    tracing::debug!(error = %e, "consider_proposal errored");
                    return;
                }
            }
        };
        // Record our own vote.
        {
            let mut guard = self.state.write().await;
            if let Err(e) = guard.consensus.record_vote(vote.clone()) {
                tracing::debug!(error = %e, "self-vote rejected by engine");
            }
        }
        // Check if our own vote formed a quorum (small N: quite likely).
        let maybe_committed = {
            let mut guard = self.state.write().await;
            if let Some(blk) = guard
                .pending_proposals
                .get(&(vote.height, vote.block_hash))
                .cloned()
            {
                match guard
                    .consensus
                    .try_form_quorum_certificate(vote.height, vote.block_hash)
                {
                    Ok(qc) => Some(CommittedBlock::from_parts_unchecked(blk, qc)),
                    Err(_) => None,
                }
            } else {
                None
            }
        };

        // Broadcast the vote regardless.
        self.publish(GossipMessage::Vote(vote)).await;

        if let Some(cb) = maybe_committed {
            self.try_commit_and_broadcast(cb).await;
        }
    }

    async fn try_commit_and_broadcast(&mut self, cb: CommittedBlock) {
        let gossip = gossip_committed(cb.clone());
        if self.try_commit(cb, /* broadcast_if_new = */ true).await {
            self.publish(gossip).await;
        }
    }

    /// Attempt to append a CommittedBlock to the chain.
    ///
    /// Returns `true` if the append succeeded (and broadcast is warranted).
    /// Returns `false` on any failure (already-at-height, bad block, etc.).
    async fn try_commit(&mut self, cb: CommittedBlock, _broadcast_if_new: bool) -> bool {
        let now_ms = now_ms();
        let mut guard = self.state.write().await;

        // Don't try to re-append a block we're already past.
        let cb_height = cb.block.header.height;
        if cb_height <= guard.chain.height() {
            return false;
        }

        match guard.chain.append_committed_block(cb.clone(), now_ms) {
            Ok(()) => {
                // Tell the consensus engine we've finalized this height.
                guard.consensus.on_finalized(cb_height);
                // Prune the mempool of now-stale txs.
                let state_snapshot = guard.chain.state().clone();
                let _ = guard.mempool.prune(&state_snapshot);
                // Remove the pending-proposal cache entry.
                guard
                    .pending_proposals
                    .retain(|&(h, _), _| h > cb_height);
                tracing::info!(height = cb_height, "committed block");
                true
            }
            Err(e) => {
                tracing::warn!(error = %e, height = cb_height, "append rejected");
                false
            }
        }
    }

    async fn publish(&self, msg: GossipMessage) {
        if let Err(e) = self.p2p.commands.send(P2pCommand::Publish(msg)).await {
            tracing::warn!(error = %e, "p2p command channel closed");
        }
    }

    /// Request a graceful shutdown.
    pub fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
    }
}

// ═══════════════════════════════════════════════════════════════════
// NODE (spawn entry point)
// ═══════════════════════════════════════════════════════════════════

/// Builder / entry point for starting a node.
pub struct Node;

impl Node {
    /// Open (or create with genesis) a node and spawn its HTTP and P2P
    /// subsystems. Returns a [`NodeHandle`] that the caller drives with
    /// [`NodeHandle::run_until_shutdown`].
    ///
    /// If `genesis` is `Some`, this creates a fresh chain at
    /// `config.data_dir` with the provided genesis inscriber. If `None`,
    /// we open an existing chain (failing if the data dir has no DB).
    ///
    /// # Errors
    /// Returns [`NodeError`] if the chain fails to open, HTTP fails to
    /// bind, or P2P fails to start.
    pub async fn spawn(
        config: NodeConfig,
        genesis: Option<GenesisBootstrap>,
    ) -> Result<NodeHandle, NodeError> {
        // 1. Open or create the persistent chain.
        let chain = match genesis {
            Some(g) => {
                let block = build_genesis_block(&config.chain_id, now_ms(), &g.inscriber)
                    .map_err(NodeError::Genesis)?;
                let bh = block.hash().map_err(|e| NodeError::Block(Box::new(e)))?;
                let votes: Vec<Vote> = g
                    .initial_validator_keys
                    .iter()
                    .map(|k| Vote::sign(0, bh, k))
                    .collect();
                let set = g.validator_set.clone();
                let qc = crate::consensus::QuorumCertificate::new(0, bh, votes, &set)
                    .map_err(|e| NodeError::Consensus(Box::new(e)))?;
                PersistentChain::create(
                    &config.data_dir,
                    &config.chain_id,
                    set,
                    block,
                    qc,
                    now_ms(),
                )
                .map_err(NodeError::Persistent)?
            }
            None => PersistentChain::open(&config.data_dir).map_err(NodeError::Persistent)?,
        };

        // 2. Mempool + consensus engine.
        let mempool = Mempool::default();
        let consensus = ConsensusEngine::new(chain.validators().clone());

        let state = Arc::new(RwLock::new(NodeState {
            chain,
            mempool,
            consensus,
            pending_proposals: BTreeMap::new(),
        }));

        // 3. Spawn P2P.
        let p2p = p2p::spawn_p2p(
            &config.p2p_listen,
            config.bootstrap_peers.clone(),
            config.network_key_seed,
        )
        .await
        .map_err(NodeError::P2p)?;

        // 4. Spawn HTTP — handlers share the SAME node state as the
        //    orchestrator. Read handlers take the read lock; POST /tx
        //    takes the write lock briefly for mempool admission.
        let router = http::build_router(Arc::clone(&state));
        let listener = tokio::net::TcpListener::bind(config.http_listen)
            .await
            .map_err(NodeError::HttpBind)?;
        let http_addr = listener.local_addr().map_err(NodeError::HttpBind)?;
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, router.into_make_service()).await {
                tracing::error!(error = %e, "http server exited");
            }
        });

        // 5. Shutdown channel.
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let local_peer_id = p2p.local_peer_id;

        Ok(NodeHandle {
            state,
            shutdown_tx,
            shutdown_rx: Some(shutdown_rx),
            p2p,
            validator_key: config.validator_key,
            local_peer_id,
            http_addr,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════
// GENESIS BOOTSTRAP
// ═══════════════════════════════════════════════════════════════════

/// Bootstrap parameters for creating a fresh chain via [`Node::spawn`].
pub struct GenesisBootstrap {
    /// The validator set that will be authorized from block 0.
    pub validator_set: crate::consensus::ValidatorSet,

    /// Keypairs for ENOUGH validators to form a quorum on the genesis
    /// QC. Must be a super-majority of `validator_set`.
    pub initial_validator_keys: Vec<Keypair>,

    /// The inscriber keypair. Receives the 1000 $TFS inscription reward.
    /// Must be a validator so that they can sign the genesis block.
    pub inscriber: Keypair,
}

// ═══════════════════════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════════════════════

/// Top-level node error.
#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    /// Persistent-chain error (open/create/append).
    #[error("persistent chain error: {0}")]
    Persistent(#[from] crate::persistent_chain::PersistentChainError),

    /// P2P error (spawn/listen).
    #[error("p2p error: {0}")]
    P2p(#[from] p2p::P2pError),

    /// HTTP listener failed to bind.
    #[error("http bind error: {0}")]
    HttpBind(std::io::Error),

    /// Genesis-block construction failed.
    #[error("genesis error: {0}")]
    Genesis(#[from] crate::genesis::GenesisError),

    /// Block-layer error.
    #[error("block error: {0}")]
    Block(Box<crate::block::BlockError>),

    /// Consensus-layer error.
    #[error("consensus error: {0}")]
    Consensus(Box<crate::consensus::ConsensusError>),

    /// Proposer helper error.
    #[error("proposer error: {0}")]
    Proposer(proposer::ProposerError),
}

// ═══════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════

#[must_use]
fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(i64::MAX)
}

// ═══════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::ValidatorSet;
    use crate::crypto::keypair::Keypair;
    use tempfile::TempDir;

    fn kp() -> Keypair {
        Keypair::generate()
    }

    fn free_loopback() -> std::net::SocketAddr {
        // Bind to :0 to ask the OS for a free port, then capture it.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        addr
    }

    #[tokio::test]
    async fn spawn_node_as_validator_with_fresh_genesis() {
        let dir = TempDir::new().unwrap();
        let president = kp();
        let v1 = kp();
        let v2 = kp();
        let set = ValidatorSet::new([
            president.public_key(),
            v1.public_key(),
            v2.public_key(),
        ])
        .unwrap();

        // Keypair doesn't impl Clone; rebuild by secret-seed round-trip.
        let president_seed = president.secret_bytes();
        let config = NodeConfig::new(dir.path(), "tfs-test-1")
            .with_http_listen(free_loopback())
            .with_p2p_listen("/ip4/127.0.0.1/tcp/0")
            .with_validator_key(Keypair::from_secret_bytes(&president_seed));

        let bootstrap = GenesisBootstrap {
            validator_set: set,
            initial_validator_keys: vec![
                Keypair::from_secret_bytes(&president_seed),
                v1,
                v2,
            ],
            inscriber: Keypair::from_secret_bytes(&president_seed),
        };

        let handle = Node::spawn(config, Some(bootstrap)).await.unwrap();
        assert_eq!(handle.state.read().await.chain.height(), 0);

        // Request shutdown + run loop should exit quickly.
        let state_arc = Arc::clone(&handle.state);
        let jh = tokio::spawn(handle.run_until_shutdown());
        // Let it breathe for a moment so the proposer tick has a chance.
        tokio::time::sleep(Duration::from_millis(200)).await;
        // Verify state is still accessible concurrently.
        assert_eq!(state_arc.read().await.chain.height(), 0);
        jh.abort();
    }
}
