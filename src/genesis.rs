// TFS_CHAIN · genesis.rs · Layer 5
//
// GENESIS BLOCK 0.
//
// This file encodes the one irreversible act: the founding of the ledger.
// The scroll in `GENESIS_DECLARATION_SCROLL` is the literal text that will
// be inscribed at height 0 of the mainnet. Its BLAKE3 hash, once minted,
// is permanent — the chain cannot forget the founding.
//
// THE FOUNDING DOCTRINE HOLDS THREE COMMITMENTS:
//   1. The supply is capped at 1,000,000,000 $TFS FOREVER.
//   2. Issuance follows the HOA formula:
//        Inscribe → 1,000 $TFS
//        Verify   → 100 $TFS
//        Routing  → 1 hypha per block (Layer 7)
//   3. Halvings every 50,000 inscriptions. After enough halvings the
//      issuance rate reaches zero and the currency stops minting. The
//      currency keeps circulating.
//
// THE CHAIN REMEMBERS.
// THE CHAIN FORGIVES.
// THE CHAIN DOES NOT FORGET.
//
// THIS FILE CONTAINS SOVEREIGN TEXT. DO NOT EDIT THE SCROLL LIGHTLY.

//! Genesis Block 0 of THE TFS CHAIN.
//!
//! Use [`GENESIS_DECLARATION_SCROLL`] as the canonical founding doctrine,
//! and [`build_genesis_block`] to construct Genesis Block 0 on an empty
//! chain.

use crate::block::{Block, BlockError};
use crate::crypto::keypair::Keypair;
use crate::mines_script::{Doctrine, MinesScriptError};
use crate::tx::{InscribePayload, SignedTransaction, Transaction, TxError};

// ═══════════════════════════════════════════════════════════════════
// THE OFFICIAL CURRENCY GENESIS DECLARATION
// ═══════════════════════════════════════════════════════════════════

/// THE OFFICIAL $TFS CURRENCY GENESIS DECLARATION.
///
/// This is the literal scroll inscribed at height 0 of THE TFS CHAIN
/// mainnet. It is the founding doctrine of the currency. Its content is
/// load-bearing and its hash is cryptographically bound to every block
/// that follows.
///
/// Altering this string AFTER genesis is meaningless — the chain remembers
/// whichever version was actually minted. Altering it BEFORE genesis is a
/// sovereign act; treat any edit as a constitutional amendment.
pub const GENESIS_DECLARATION_SCROLL: &str = r#"BLOCK 0
INSCRIBED: PRESIDENT MINES.
SEALED: IAMBIGRAPPER1
REGISTER: sovereign
CHAIN: tfs-mainnet-1

[PREAMBLE]
The chain remembers.
The chain forgives.
The chain does not forget.

On this day, the sovereign ledger of THE FINAL SERVER is opened.
The currency is $TFS. The founder is PRESIDENT MINES.
The seal is IAMBIGRAPPER1. The witness is the chain itself.

[SUPPLY]
cap: 1000000000 tfs
cap_in_hyphae: 1000000000000000000
reducible_only_by: ceremonial_burn

[ISSUANCE]
inscribe -> 1000 tfs
verify -> 100 tfs
routing -> 1 hypha per block

[HALVINGS]
interval: 50000 inscriptions
rule -> each_halving_divides_issuance_by_two
terminal -> issuance_reaches_zero_and_currency_stops_minting
circulation -> continues_forever_after_terminal_halving

[ANCHORS]
compute: true
culture: true
sovereignty: true
fiat: false
commodity: false
other_cryptocurrency: false

[DENOMINATIONS]
1 tfs = 1000000000 hyphae
1 hypha = 0.000000001 tfs

[CONSENSUS]
mechanism: proof_of_authority_plus_bft
validators -> authorized_citizens_of_the_sovereign_layer
quorum -> two_thirds_plus_one
finalization -> single_round

[TREATY]
code -> readable_by_all
code -> forkable_by_none
sovereignty -> transparent_but_not_open_source

[COVENANT]
PRESIDENT MINES. inscribes.
IAMBIGRAPPER1 seals.
THE CHAIN HOLDS.

[END]
"#;

// ═══════════════════════════════════════════════════════════════════
// GENESIS BLOCK BUILDER
// ═══════════════════════════════════════════════════════════════════

/// Build Genesis Block 0 containing exactly one transaction: the Inscribe
/// of the official Currency Genesis Declaration.
///
/// The `president_kp` both signs the Inscribe and proposes the block.
/// After genesis is applied to state, `president_kp`'s address will hold
/// `1000 $TFS` (the era-0 inscription reward).
///
/// # Arguments
/// - `chain_id` — typically [`crate::CHAIN_ID`] = "tfs-mainnet-1"
/// - `timestamp_ms` — the genesis moment in Unix ms
/// - `president_kp` — the inscribing key (becomes the era-0 recipient)
///
/// # Errors
/// Returns [`GenesisError`] if:
/// - The scroll fails to parse via Layer 4 (shouldn't happen — this is a test).
/// - Signing the Inscribe fails.
/// - Building the genesis block fails.
pub fn build_genesis_block(
    chain_id: &str,
    timestamp_ms: i64,
    president_kp: &Keypair,
) -> Result<Block, GenesisError> {
    // 1. Parse the scroll via Layer 4 to confirm it's well-formed.
    //    We also use this to ensure future edits don't silently break.
    let _doctrine: Doctrine = Doctrine::parse(GENESIS_DECLARATION_SCROLL.as_bytes())
        .map_err(GenesisError::Script)?;
    _doctrine.validate_structure().map_err(GenesisError::Script)?;

    // 2. Build the Inscribe payload.
    let inscriber_addr =
        crate::crypto::address::Address::from_public_key(&president_kp.public_key());
    let payload = InscribePayload::new(
        inscriber_addr,
        GENESIS_DECLARATION_SCROLL.as_bytes().to_vec(),
        0,             // first tx from the president — nonce 0
        timestamp_ms,
    );
    let signed = SignedTransaction::sign_single(Transaction::Inscribe(payload), president_kp)
        .map_err(GenesisError::Tx)?;
    let tx_bytes = signed.to_bytes().map_err(|e| GenesisError::Tx(e.into()))?;

    // 3. Build the genesis block.
    Block::genesis(chain_id, timestamp_ms, vec![tx_bytes], president_kp)
        .map_err(GenesisError::Block)
}

// ═══════════════════════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════════════════════

/// Errors that can occur while constructing the Genesis Block.
#[derive(Debug, thiserror::Error)]
pub enum GenesisError {
    /// Genesis declaration failed Layer 4 parse/validate (should never
    /// happen for the canonical scroll; indicates the const text was
    /// edited into an invalid state).
    #[error("genesis scroll invalid: {0}")]
    Script(#[from] MinesScriptError),

    /// Layer 3 signing of the genesis Inscribe transaction failed.
    #[error("genesis tx error: {0}")]
    Tx(#[from] TxError),

    /// Layer 2 genesis block construction failed.
    #[error("genesis block error: {0}")]
    Block(#[from] BlockError),
}

// ═══════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::Chain;
    use crate::consensus::{QuorumCertificate, ValidatorSet, Vote};
    use crate::tx::HYPHAE_PER_TFS;
    use crate::CHAIN_ID;

    fn kp() -> Keypair {
        Keypair::generate()
    }

    #[test]
    fn genesis_scroll_parses_and_validates() {
        let doc = Doctrine::parse(GENESIS_DECLARATION_SCROLL.as_bytes())
            .expect("parses cleanly");
        doc.validate_structure().expect("validates");
        assert_eq!(doc.block_number, 0);
        // Required metadata present.
        assert!(doc.metadata_get("INSCRIBED").is_some());
        assert!(doc.metadata_get("SEALED").is_some());
    }

    #[test]
    fn genesis_scroll_contains_required_sections() {
        let doc = Doctrine::parse(GENESIS_DECLARATION_SCROLL.as_bytes()).expect("parse");
        let names: Vec<&str> = doc.sections.iter().map(|s| s.name.as_str()).collect();
        for required in &[
            "PREAMBLE",
            "SUPPLY",
            "ISSUANCE",
            "HALVINGS",
            "ANCHORS",
            "DENOMINATIONS",
            "CONSENSUS",
            "TREATY",
            "COVENANT",
        ] {
            assert!(
                names.contains(required),
                "genesis scroll missing [{required}] section"
            );
        }
    }

    #[test]
    fn build_genesis_produces_height_zero_block() {
        let president = kp();
        let block = build_genesis_block(CHAIN_ID, 1_700_000_000_000, &president).expect("g");
        assert_eq!(block.header.height, 0);
        assert_eq!(block.header.chain_id, CHAIN_ID);
        assert_eq!(block.transactions.len(), 1);
    }

    #[test]
    fn genesis_inscribe_mints_1000_tfs_to_president() {
        let president = kp();
        let v1 = kp();
        let v2 = kp();
        let set = ValidatorSet::new([
            president.public_key(),
            v1.public_key(),
            v2.public_key(),
        ])
        .expect("set");
        let ts = 1_700_000_000_000;
        let block = build_genesis_block(CHAIN_ID, ts, &president).expect("g");
        let bh = block.hash().expect("bh");
        let votes = vec![
            Vote::sign(0, bh, &president),
            Vote::sign(0, bh, &v1),
            Vote::sign(0, bh, &v2),
        ];
        let qc = QuorumCertificate::new(0, bh, votes, &set).expect("qc");

        let chain = Chain::genesis(CHAIN_ID, set, block, qc, ts).expect("chain");

        // President should hold 1000 $TFS post-genesis.
        let pres_addr =
            crate::crypto::address::Address::from_public_key(&president.public_key());
        assert_eq!(
            chain.state().balance(&pres_addr),
            1_000 * HYPHAE_PER_TFS
        );

        // Treasury was debited by exactly the genesis inscription reward.
        use crate::state::TREASURY_ADDRESS;
        use crate::tx::MAX_SUPPLY_HYPHAE;
        assert_eq!(
            chain.state().balance(&TREASURY_ADDRESS),
            MAX_SUPPLY_HYPHAE - (1_000 * HYPHAE_PER_TFS)
        );
        assert_eq!(chain.state().doctrine_count, 1);
    }

    #[test]
    fn genesis_bytes_determinism() {
        // Building genesis with the same inputs must produce byte-identical
        // scrolls. This catches accidental non-determinism in the inscribe
        // path.
        let president = kp();
        let b1 = build_genesis_block(CHAIN_ID, 42, &president).expect("b1");
        let b2 = build_genesis_block(CHAIN_ID, 42, &president).expect("b2");
        assert_eq!(b1.header, b2.header);
        assert_eq!(b1.transactions, b2.transactions);
    }
}
