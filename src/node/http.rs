// TFS_CHAIN · node/http.rs · Layer 7
//
// THE CITIZEN HTTP GATE.
//
// Citizens, wallets, block explorers, and ops tools talk to a node
// over HTTP/JSON. This file defines the read-only query surface plus
// the single write endpoint:
//
//   GET  /status              node + chain overview
//   GET  /validators          authorized validator public keys (hex)
//   GET  /block/{height}      committed block at height
//   GET  /block/hash/{hex}    committed block by 32-byte hex hash
//   GET  /tx/{hex}            where a tx lives in the committed chain
//   GET  /address/{bech32}    balance, nonce, verified-status for an address
//   GET  /state/root          the state root hash (for light-client proofs)
//   GET  /mempool/size        pending tx count in this node's mempool
//   POST /tx                  submit a signed transaction as bincode bytes
//
// SECURITY POSTURE:
//   - No TLS. Deploy behind a reverse proxy that terminates TLS.
//   - No authentication. All endpoints are public — the chain is public.
//     There is nothing here a peer couldn't learn from the p2p gossip.
//   - POST /tx body size capped at MAX_TX_SIZE_BYTES (1 MiB from Layer 3).
//     axum's default request limit also caps this.
//   - All handlers hold the state lock for as short as possible.
//
// THREAT MODEL:
//   - Malformed JSON / binary input    → decode errors → 400 Bad Request
//   - DoS via huge request bodies      → axum body limit + tx size cap
//   - Concurrent writes corrupting     → a single axum write path goes
//     state                              through Mempool::insert under
//                                        write lock; readers only take
//                                        the read lock
//   - Privilege escalation             → no write endpoint mutates chain;
//                                        only mempool accepts input, and
//                                        only Layer 3-valid signed txs
//                                        via validate_structure

//! HTTP / JSON API for a TFS_CHAIN node.
//!
//! Build a router with [`build_router`] and hand the returned value to
//! `axum::serve`. The router uses the [`ApiState`] type to share node
//! state across handlers.

#![cfg(feature = "node")]

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tower_http::cors::{Any, CorsLayer};

use crate::crypto::address::Address;
use crate::crypto::hash::Hash;
use crate::tx::SignedTransaction;

use super::SharedNodeState;

// ═══════════════════════════════════════════════════════════════════
// RESPONSE SHAPES
// ═══════════════════════════════════════════════════════════════════

/// `GET /status` response body.
#[derive(Serialize, Deserialize)]
pub struct StatusResponse {
    /// Chain identifier (e.g. `"tfs-mainnet-1"`).
    pub chain_id: String,
    /// Current chain height (genesis is 0).
    pub height: u64,
    /// Hex-encoded hash of the most recent block.
    pub last_block_hash: String,
    /// Total $TFS issued in hyphae (10⁻⁹ $TFS).
    pub supply_issued_hyphae: u64,
    /// Total $TFS burned in hyphae.
    pub supply_burned_hyphae: u64,
    /// Circulating supply = issued − burned, in hyphae.
    pub circulating_supply_hyphae: u64,
    /// Number of inscribed doctrines.
    pub doctrine_count: u64,
    /// Number of verified citizens.
    pub verified_citizen_count: u64,
    /// Number of pending txs in this node's mempool.
    pub mempool_size: u64,
    /// Protocol version this binary speaks.
    pub protocol_version: u32,
}

/// `GET /validators` response body.
#[derive(Serialize, Deserialize)]
pub struct ValidatorsResponse {
    /// Quorum threshold = `(2N/3) + 1`.
    pub quorum_threshold: u64,
    /// Total number of authorized validators.
    pub total: u64,
    /// Hex-encoded 32-byte public keys of the authorized validators.
    pub public_keys_hex: Vec<String>,
}

/// `GET /tx/{hex}` response body.
#[derive(Serialize, Deserialize)]
pub struct TxLocationResponse {
    /// Height of the block containing the transaction.
    pub height: u64,
    /// Zero-based index of the tx within the block.
    pub tx_index: u32,
}

/// `GET /block/{height}/summary` response body — JSON-friendly subset
/// of a committed block for UI display.
#[derive(Serialize, Deserialize)]
pub struct BlockSummaryResponse {
    /// Block height.
    pub height: u64,
    /// Hex-encoded block hash.
    pub block_hash: String,
    /// Hex-encoded previous-block hash.
    pub previous_hash: String,
    /// Unix ms timestamp of the block.
    pub timestamp_ms: i64,
    /// Hex-encoded proposer public key.
    pub proposer_hex: String,
    /// Hex-encoded tx Merkle root.
    pub tx_merkle_root: String,
    /// Number of transactions in the block.
    pub tx_count: u64,
    /// Number of vote signatures in the QC.
    pub qc_vote_count: u64,
}

/// `GET /address/{bech32}` response body.
#[derive(Serialize, Deserialize)]
pub struct AccountResponse {
    /// Canonical bech32 encoding of the address.
    pub address: String,
    /// Balance in hyphae.
    pub balance_hyphae: u64,
    /// Next-expected nonce.
    pub nonce: u64,
    /// True if the citizen has been verified on-chain.
    pub verified: bool,
}

/// `POST /tx` response body.
#[derive(Serialize, Deserialize)]
pub struct TxSubmitResponse {
    /// Hex-encoded 32-byte tx_id assigned on admission.
    pub tx_id_hex: String,
    /// Whether the transaction was admitted to the mempool.
    pub admitted: bool,
}

/// `GET /mempool/size` response body.
#[derive(Serialize, Deserialize)]
pub struct MempoolSizeResponse {
    /// Pending transaction count.
    pub pending: u64,
}

/// `GET /state/root` response body.
#[derive(Serialize, Deserialize)]
pub struct StateRootResponse {
    /// Hex-encoded 32-byte state root hash.
    pub state_root_hex: String,
    /// Height at which this root was produced.
    pub height: u64,
}

/// Simple error envelope for all 4xx / 5xx responses.
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorBody {
    /// Short machine-friendly error code.
    pub code: &'static str,
    /// Human-readable message.
    pub message: String,
}

// ═══════════════════════════════════════════════════════════════════
// ROUTER
// ═══════════════════════════════════════════════════════════════════

/// Build the HTTP router.
///
/// CORS is permissive (Any origin, Any method, Any header) because the
/// chain is public-by-design: every read is something a peer could
/// learn via gossipsub, and POST /tx is just admitting a signed
/// transaction (which a peer could also do directly over p2p). This
/// lets browser-based wallets and block explorers on any origin talk
/// to the node's HTTP endpoint.
///
/// Deploy behind a TLS-terminating reverse proxy for production.
#[must_use]
pub fn build_router(state: SharedNodeState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/status", get(get_status))
        .route("/validators", get(get_validators))
        .route("/block/:height", get(get_block_by_height))
        .route("/block/:height/summary", get(get_block_summary_by_height))
        .route("/block/hash/:hex", get(get_block_by_hash))
        .route("/block/hash/:hex/summary", get(get_block_summary_by_hash))
        .route("/tx/:hex", get(get_tx_location))
        .route("/address/:bech32", get(get_address))
        .route("/state/root", get(get_state_root))
        .route("/mempool/size", get(get_mempool_size))
        .route("/tx", post(post_tx))
        .layer(cors)
        .with_state(state)
}

// ═══════════════════════════════════════════════════════════════════
// HANDLERS
// ═══════════════════════════════════════════════════════════════════

async fn get_status(State(st): State<SharedNodeState>) -> Result<Json<StatusResponse>, ApiError> {
    let guard = st.read().await;
    let chain = &guard.chain;
    let state = chain.state();
    let last_hash = chain
        .tip()
        .block
        .hash()
        .map_err(|e| ApiError::internal("block hash", e.to_string()))?;
    Ok(Json(StatusResponse {
        chain_id: chain.chain_id().to_string(),
        height: chain.height(),
        last_block_hash: last_hash.to_hex(),
        supply_issued_hyphae: state.supply_issued,
        supply_burned_hyphae: state.supply_burned,
        circulating_supply_hyphae: state.circulating_supply(),
        doctrine_count: state.doctrine_count,
        verified_citizen_count: u64::try_from(state.verified_citizens.len()).unwrap_or(u64::MAX),
        mempool_size: u64::try_from(guard.mempool.len()).unwrap_or(u64::MAX),
        protocol_version: crate::PROTOCOL_VERSION,
    }))
}

async fn get_validators(
    State(st): State<SharedNodeState>,
) -> Result<Json<ValidatorsResponse>, ApiError> {
    let guard = st.read().await;
    let set = guard.chain.validators();
    let keys: Vec<String> = set.iter().map(|pk| hex::encode(pk.to_bytes())).collect();
    Ok(Json(ValidatorsResponse {
        quorum_threshold: u64::try_from(set.quorum_threshold()).unwrap_or(u64::MAX),
        total: u64::try_from(set.len()).unwrap_or(u64::MAX),
        public_keys_hex: keys,
    }))
}

async fn get_block_by_height(
    State(st): State<SharedNodeState>,
    Path(height): Path<u64>,
) -> Result<Vec<u8>, ApiError> {
    let guard = st.read().await;
    let cb = guard
        .chain
        .get_committed_block(height)
        .map_err(|e| ApiError::internal("storage", e.to_string()))?
        .ok_or_else(|| ApiError::not_found(format!("no block at height {height}")))?;
    bincode::serialize(&cb).map_err(|e| ApiError::internal("encode", e.to_string()))
}

async fn get_block_by_hash(
    State(st): State<SharedNodeState>,
    Path(hex_str): Path<String>,
) -> Result<Vec<u8>, ApiError> {
    let hash = Hash::from_hex(&hex_str)
        .map_err(|_| ApiError::bad_request("hash", "hash must be 64 hex chars"))?;
    let guard = st.read().await;
    let cb = guard
        .chain
        .get_block_by_hash(&hash)
        .map_err(|e| ApiError::internal("storage", e.to_string()))?
        .ok_or_else(|| ApiError::not_found(format!("no block with hash {hex_str}")))?;
    bincode::serialize(&cb).map_err(|e| ApiError::internal("encode", e.to_string()))
}

fn summarize_block(
    cb: &crate::consensus::CommittedBlock,
) -> Result<BlockSummaryResponse, ApiError> {
    let block_hash = cb
        .block
        .hash()
        .map_err(|e| ApiError::internal("hash", e.to_string()))?;
    Ok(BlockSummaryResponse {
        height: cb.block.header.height,
        block_hash: block_hash.to_hex(),
        previous_hash: cb.block.header.previous_hash.to_hex(),
        timestamp_ms: cb.block.header.timestamp_ms,
        proposer_hex: hex::encode(cb.block.header.proposer.to_bytes()),
        tx_merkle_root: cb.block.header.tx_merkle_root.to_hex(),
        tx_count: u64::try_from(cb.block.transactions.len()).unwrap_or(u64::MAX),
        qc_vote_count: u64::try_from(cb.qc.votes.len()).unwrap_or(u64::MAX),
    })
}

async fn get_block_summary_by_height(
    State(st): State<SharedNodeState>,
    Path(height): Path<u64>,
) -> Result<Json<BlockSummaryResponse>, ApiError> {
    let guard = st.read().await;
    let cb = guard
        .chain
        .get_committed_block(height)
        .map_err(|e| ApiError::internal("storage", e.to_string()))?
        .ok_or_else(|| ApiError::not_found(format!("no block at height {height}")))?;
    Ok(Json(summarize_block(&cb)?))
}

async fn get_block_summary_by_hash(
    State(st): State<SharedNodeState>,
    Path(hex_str): Path<String>,
) -> Result<Json<BlockSummaryResponse>, ApiError> {
    let hash = Hash::from_hex(&hex_str)
        .map_err(|_| ApiError::bad_request("hash", "hash must be 64 hex chars"))?;
    let guard = st.read().await;
    let cb = guard
        .chain
        .get_block_by_hash(&hash)
        .map_err(|e| ApiError::internal("storage", e.to_string()))?
        .ok_or_else(|| ApiError::not_found(format!("no block with hash {hex_str}")))?;
    Ok(Json(summarize_block(&cb)?))
}

async fn get_tx_location(
    State(st): State<SharedNodeState>,
    Path(hex_str): Path<String>,
) -> Result<Json<TxLocationResponse>, ApiError> {
    let tx_id = Hash::from_hex(&hex_str)
        .map_err(|_| ApiError::bad_request("tx_id", "tx_id must be 64 hex chars"))?;
    let guard = st.read().await;
    let loc = guard
        .chain
        .get_tx_location(&tx_id)
        .map_err(|e| ApiError::internal("storage", e.to_string()))?
        .ok_or_else(|| ApiError::not_found(format!("tx {hex_str} not found")))?;
    Ok(Json(TxLocationResponse {
        height: loc.height,
        tx_index: loc.tx_index,
    }))
}

async fn get_address(
    State(st): State<SharedNodeState>,
    Path(bech32): Path<String>,
) -> Result<Json<AccountResponse>, ApiError> {
    let addr = Address::parse(&bech32)
        .map_err(|e| ApiError::bad_request("address", e.to_string()))?;
    let guard = st.read().await;
    let s = guard.chain.state();
    Ok(Json(AccountResponse {
        address: addr.to_bech32(),
        balance_hyphae: s.balance(&addr),
        nonce: s.nonce(&addr),
        verified: s.verified_citizens.contains(&addr),
    }))
}

async fn get_state_root(
    State(st): State<SharedNodeState>,
) -> Result<Json<StateRootResponse>, ApiError> {
    let guard = st.read().await;
    let root = guard
        .chain
        .state()
        .state_root()
        .map_err(|e| ApiError::internal("hash", e.to_string()))?;
    Ok(Json(StateRootResponse {
        state_root_hex: root.to_hex(),
        height: guard.chain.height(),
    }))
}

async fn get_mempool_size(
    State(st): State<SharedNodeState>,
) -> Result<Json<MempoolSizeResponse>, ApiError> {
    let guard = st.read().await;
    Ok(Json(MempoolSizeResponse {
        pending: u64::try_from(guard.mempool.len()).unwrap_or(u64::MAX),
    }))
}

/// Submit a signed transaction. Body must be the bincode-serialized
/// [`SignedTransaction`] bytes (same format used on disk and over gossip).
async fn post_tx(
    State(st): State<SharedNodeState>,
    body: Bytes,
) -> Result<Json<TxSubmitResponse>, ApiError> {
    if body.len() > crate::block::MAX_TX_SIZE_BYTES {
        return Err(ApiError::bad_request(
            "tx",
            format!("tx exceeds MAX_TX_SIZE_BYTES ({})", crate::block::MAX_TX_SIZE_BYTES),
        ));
    }
    let stx = SignedTransaction::from_bytes(&body)
        .map_err(|e| ApiError::bad_request("tx", e.to_string()))?;
    // Short write-lock window: admit to mempool.
    let mut guard = st.write().await;
    let state_snapshot = guard.chain.state().clone();
    match guard.mempool.insert(stx, &state_snapshot) {
        Ok(tx_id) => Ok(Json(TxSubmitResponse {
            tx_id_hex: tx_id.to_hex(),
            admitted: true,
        })),
        Err(e) => Err(ApiError::bad_request("mempool", e.to_string())),
    }
}

// ═══════════════════════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════════════════════

/// Structured error type that converts into an HTTP response.
#[derive(Debug)]
pub struct ApiError {
    /// HTTP status code to return.
    pub status: StatusCode,
    /// JSON body.
    pub body: ErrorBody,
}

impl ApiError {
    /// Build a 400 Bad Request.
    #[must_use]
    pub fn bad_request(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            body: ErrorBody {
                code,
                message: message.into(),
            },
        }
    }

    /// Build a 404 Not Found.
    #[must_use]
    pub fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            body: ErrorBody {
                code: "not_found",
                message: message.into(),
            },
        }
    }

    /// Build a 500 Internal Server Error.
    #[must_use]
    pub fn internal(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            body: ErrorBody {
                code,
                message: message.into(),
            },
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(self.body)).into_response()
    }
}

// ═══════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{CommittedBlock, ConsensusEngine, QuorumCertificate, ValidatorSet, Vote};
    use crate::crypto::keypair::Keypair;
    use crate::genesis::build_genesis_block;
    use crate::mempool::Mempool;
    use crate::node::NodeState;
    use crate::persistent_chain::PersistentChain;
    use crate::tx::{Transaction, TransferPayload, HYPHAE_PER_TFS};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::collections::BTreeMap;
    use tempfile::TempDir;
    use tokio::sync::RwLock;
    use tower::ServiceExt;

    const CHAIN_ID: &str = "tfs-test-1";

    fn kp() -> Keypair {
        Keypair::generate()
    }

    fn bootstrap_state() -> (SharedNodeState, Keypair, TempDir) {
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
        let block = build_genesis_block(CHAIN_ID, 1, &president).unwrap();
        let bh = block.hash().unwrap();
        let votes = vec![
            Vote::sign(0, bh, &president),
            Vote::sign(0, bh, &v1),
            Vote::sign(0, bh, &v2),
        ];
        let qc = QuorumCertificate::new(0, bh, votes, &set).unwrap();
        let chain =
            PersistentChain::create(dir.path(), CHAIN_ID, set.clone(), block, qc, 1).unwrap();
        let consensus = ConsensusEngine::new(set);
        let node_state = Arc::new(RwLock::new(NodeState {
            chain,
            mempool: Mempool::default(),
            consensus,
            pending_proposals: BTreeMap::new(),
            our_votes: BTreeMap::new(),
        }));
        (node_state, president, dir)
    }

    #[tokio::test]
    async fn status_endpoint_reports_genesis_info() {
        let (state, _president, _dir) = bootstrap_state();
        let router = build_router(state);
        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: StatusResponse = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body.chain_id, CHAIN_ID);
        assert_eq!(body.height, 0);
        assert_eq!(body.doctrine_count, 1);
        assert_eq!(body.supply_issued_hyphae, 1_000 * HYPHAE_PER_TFS);
    }

    #[tokio::test]
    async fn address_endpoint_returns_presidents_balance() {
        let (state, president, _dir) = bootstrap_state();
        let pres_addr = Address::from_public_key(&president.public_key());
        let router = build_router(state);
        let resp = router
            .oneshot(
                Request::builder()
                    .uri(format!("/address/{}", pres_addr.to_bech32()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: AccountResponse = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body.balance_hyphae, 1_000 * HYPHAE_PER_TFS);
        assert_eq!(body.nonce, 1); // one inscription done
    }

    #[tokio::test]
    async fn address_endpoint_rejects_malformed() {
        let (state, _p, _dir) = bootstrap_state();
        let router = build_router(state);
        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/address/not-a-bech32")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn block_by_height_returns_bincode() {
        let (state, _p, _dir) = bootstrap_state();
        let router = build_router(state);
        let resp = router
            .oneshot(Request::builder().uri("/block/0").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let cb: CommittedBlock = bincode::deserialize(&body_bytes).unwrap();
        assert_eq!(cb.block.header.height, 0);
    }

    #[tokio::test]
    async fn block_by_height_404_out_of_range() {
        let (state, _p, _dir) = bootstrap_state();
        let router = build_router(state);
        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/block/99999")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn validators_endpoint_lists_three() {
        let (state, _p, _dir) = bootstrap_state();
        let router = build_router(state);
        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/validators")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: ValidatorsResponse = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body.total, 3);
        assert_eq!(body.quorum_threshold, 3);
        assert_eq!(body.public_keys_hex.len(), 3);
    }

    #[tokio::test]
    async fn post_tx_admits_valid_and_reports_tx_id() {
        let (state, president, _dir) = bootstrap_state();
        let alice = kp();
        let tx = SignedTransaction::sign_single(
            Transaction::Transfer(TransferPayload {
                from: Address::from_public_key(&president.public_key()),
                to: Address::from_public_key(&alice.public_key()),
                amount_hyphae: 100,
                nonce: 1, // president already has nonce 1 after genesis
                timestamp_ms: 2,
            }),
            &president,
        )
        .unwrap();
        let bytes = tx.to_bytes().unwrap();

        let router = build_router(state.clone());
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/tx")
                    .body(Body::from(bytes))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // mempool size should now be 1.
        let router2 = build_router(state);
        let resp2 = router2
            .oneshot(
                Request::builder()
                    .uri("/mempool/size")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body_bytes = axum::body::to_bytes(resp2.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: MempoolSizeResponse = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body.pending, 1);
    }

    #[tokio::test]
    async fn post_tx_rejects_malformed_bytes() {
        let (state, _p, _dir) = bootstrap_state();
        let router = build_router(state);
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/tx")
                    .body(Body::from(vec![0xFFu8; 100]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
