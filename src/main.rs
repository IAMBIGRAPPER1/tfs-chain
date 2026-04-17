// TFS_CHAIN · main.rs · node binary entry point
// MINES. VENTURE, LLC · IAMBIGRAPPER1 · ALL RIGHTS MINES.
//
// This is the tfs-node binary. Layer 1 is the only layer sealed so far,
// so this binary just announces itself and exits. Real node logic arrives
// with Layer 7.

fn main() -> anyhow::Result<()> {
    println!("◈ TFS_CHAIN · THE SOVEREIGN MYCELIAL CRYPTO LEDGER");
    println!("  protocol version: {}", tfs_chain::PROTOCOL_VERSION);
    println!("  chain id:         {}", tfs_chain::CHAIN_ID);
    println!("  address prefix:   {}1...", tfs_chain::ADDRESS_HRP);
    println!();
    println!("  Layer 1 sealed. Layers 2-7 pending.");
    println!("  ALL RIGHTS MINES.");
    Ok(())
}
