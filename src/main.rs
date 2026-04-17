// TFS_CHAIN · main.rs · the tfs-node binary
// MINES. VENTURE, LLC · IAMBIGRAPPER1 · ALL RIGHTS MINES.
//
// Sovereign node daemon. Subcommands:
//
//   tfs-node keygen
//     Print a new ed25519 secret seed (64 hex chars) to stdout.
//     Address + public key printed to stderr for info.
//
//   tfs-node init --data-dir <dir> --validator-key <hex>
//                 --peer <hex>... --peer-secret <hex>... [--chain-id <id>]
//     Initialize a fresh chain. Mints genesis with THIS node as
//     inscriber, signed by a quorum of the supplied peer-secrets + self.
//
//   tfs-node run --data-dir <dir> [--validator-key <hex>]
//                [--http <host:port>] [--p2p <multiaddr>] [--bootstrap <multiaddr>...]
//     Run an existing chain. --validator-key makes this node a validator.

#[cfg(not(feature = "node"))]
fn main() {
    println!("tfs-node requires the `node` feature. Rebuild with:");
    println!("  cargo build --release --features node");
}

#[cfg(feature = "node")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    cli::run().await
}

#[cfg(feature = "node")]
mod cli {
    use std::env;

    use anyhow::{anyhow, Context, Result};
    use tfs_chain::consensus::ValidatorSet;
    use tfs_chain::crypto::keypair::{
        Keypair, PublicKey, PUBLIC_KEY_LEN, SECRET_KEY_LEN,
    };
    use tfs_chain::node::{config::NodeConfig, GenesisBootstrap, Node};

    pub async fn run() -> Result<()> {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "tfs_chain=info,tfs_node=info".into()),
            )
            .init();

        let args: Vec<String> = env::args().collect();
        let sub = args.get(1).map(String::as_str).unwrap_or("help");

        match sub {
            "keygen" => cmd_keygen(),
            "init" => cmd_init(&args[2..]).await,
            "run" => cmd_run(&args[2..]).await,
            "help" | "--help" | "-h" => {
                print_banner();
                print_help();
                Ok(())
            }
            _ => {
                print_banner();
                print_help();
                Err(anyhow!("unknown subcommand: {sub}"))
            }
        }
    }

    fn print_banner() {
        println!("◈ TFS_CHAIN · THE SOVEREIGN MYCELIAL CRYPTO LEDGER");
        println!("  protocol version: {}", tfs_chain::PROTOCOL_VERSION);
        println!("  chain id:         {}", tfs_chain::CHAIN_ID);
        println!("  address prefix:   {}1...", tfs_chain::ADDRESS_HRP);
        println!();
    }

    fn print_help() {
        println!("usage:");
        println!("  tfs-node keygen");
        println!("  tfs-node init --data-dir <dir> --validator-key <hex>");
        println!("                --peer <hex> --peer-secret <hex>");
        println!("                [--peer <hex> --peer-secret <hex>]...");
        println!("                [--chain-id <id>]");
        println!("  tfs-node run  --data-dir <dir> [--validator-key <hex>]");
        println!("                [--http <host:port>] [--p2p <multiaddr>]");
        println!("                [--bootstrap <multiaddr>]...");
        println!();
        println!("ALL RIGHTS MINES.");
    }

    fn cmd_keygen() -> Result<()> {
        let kp = Keypair::generate();
        let secret_hex = hex::encode(kp.secret_bytes());
        let public_hex = hex::encode(kp.public_key().to_bytes());
        let address = tfs_chain::crypto::address::Address::from_public_key(&kp.public_key());
        eprintln!("# TFS_CHAIN validator keypair");
        eprintln!("# address:    {}", address.to_bech32());
        eprintln!("# public_key: {public_hex}");
        eprintln!("# secret_key: (printed to stdout — KEEP SECRET)");
        println!("{secret_hex}");
        Ok(())
    }

    async fn cmd_init(args: &[String]) -> Result<()> {
        let data_dir = flag(args, "--data-dir").context("missing --data-dir")?;
        let validator_hex = flag(args, "--validator-key").context("missing --validator-key")?;
        let chain_id =
            flag(args, "--chain-id").unwrap_or_else(|| tfs_chain::CHAIN_ID.to_string());

        let my_kp = parse_keypair_hex(&validator_hex)?;
        let peer_hexes: Vec<String> = flags(args, "--peer");
        let peer_secret_hexes: Vec<String> = flags(args, "--peer-secret");

        if peer_hexes.len() < 2 {
            return Err(anyhow!(
                "genesis requires at least 2 --peer public keys (minimum quorum = 3)"
            ));
        }

        let mut public_keys: Vec<PublicKey> = vec![my_kp.public_key()];
        for hex_str in &peer_hexes {
            public_keys.push(parse_public_key_hex(hex_str)?);
        }

        let set = ValidatorSet::new(public_keys.iter().copied())
            .map_err(|e| anyhow!("validator set: {e}"))?;

        let q = quorum_size(public_keys.len());
        if peer_secret_hexes.len() + 1 < q {
            return Err(anyhow!(
                "genesis needs {q} signing keys. Provide own + --peer-secret <hex> \
                 for at least {} peers. Got {} peer secrets.",
                q - 1,
                peer_secret_hexes.len()
            ));
        }

        let mut all_kps = vec![Keypair::from_secret_bytes(&my_kp.secret_bytes())];
        for hex_str in &peer_secret_hexes {
            all_kps.push(parse_keypair_hex(hex_str)?);
        }

        let bootstrap = GenesisBootstrap {
            validator_set: set,
            initial_validator_keys: all_kps,
            inscriber: Keypair::from_secret_bytes(&my_kp.secret_bytes()),
        };

        let config = NodeConfig::new(&data_dir, &chain_id).with_validator_key(my_kp);
        let handle = Node::spawn(config, Some(bootstrap)).await?;
        println!();
        println!("✅ Genesis minted at height 0.");
        println!("   data dir: {}", data_dir);
        println!("   chain id: {}", chain_id);
        println!("   HTTP:     http://{}", handle.http_addr);
        println!("   peer id:  {}", handle.local_peer_id);
        println!();
        println!("   Inscriber now holds 1000 $TFS.");
        println!("   To continue running, use `tfs-node run ...`.");
        handle.shutdown();
        Ok(())
    }

    async fn cmd_run(args: &[String]) -> Result<()> {
        let data_dir = flag(args, "--data-dir").context("missing --data-dir")?;
        let mut config = NodeConfig::new(&data_dir, tfs_chain::CHAIN_ID);

        if let Some(http) = flag(args, "--http") {
            config = config.with_http_listen(http.parse().context("bad --http")?);
        }
        if let Some(p2p) = flag(args, "--p2p") {
            config = config.with_p2p_listen(p2p);
        }
        for peer in flags(args, "--bootstrap") {
            config = config.with_bootstrap_peer(peer);
        }
        if let Some(vhex) = flag(args, "--validator-key") {
            let kp = parse_keypair_hex(&vhex)?;
            config = config.with_validator_key(kp);
        }

        let handle = Node::spawn(config, None).await?;
        println!("◈ tfs-node running");
        println!("   HTTP:    http://{}", handle.http_addr);
        println!("   peer id: {}", handle.local_peer_id);
        handle.run_until_shutdown().await;
        Ok(())
    }

    // ─── helpers ─────────────────────────────────────────────────────

    fn quorum_size(n: usize) -> usize {
        (2 * n) / 3 + 1
    }

    fn flag(args: &[String], name: &str) -> Option<String> {
        let mut iter = args.iter();
        while let Some(a) = iter.next() {
            if a == name {
                return iter.next().cloned();
            }
        }
        None
    }

    fn flags(args: &[String], name: &str) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let mut iter = args.iter();
        while let Some(a) = iter.next() {
            if a == name {
                if let Some(v) = iter.next() {
                    out.push(v.clone());
                }
            }
        }
        out
    }

    fn parse_keypair_hex(s: &str) -> Result<Keypair> {
        let bytes = hex::decode(s).context("secret hex invalid")?;
        if bytes.len() != SECRET_KEY_LEN {
            return Err(anyhow!(
                "secret key must be {SECRET_KEY_LEN} bytes ({}), got {}",
                SECRET_KEY_LEN * 2,
                bytes.len()
            ));
        }
        let mut arr = [0u8; SECRET_KEY_LEN];
        arr.copy_from_slice(&bytes);
        Ok(Keypair::from_secret_bytes(&arr))
    }

    fn parse_public_key_hex(s: &str) -> Result<PublicKey> {
        let bytes = hex::decode(s).context("public-key hex invalid")?;
        if bytes.len() != PUBLIC_KEY_LEN {
            return Err(anyhow!(
                "public key must be {PUBLIC_KEY_LEN} bytes ({}), got {}",
                PUBLIC_KEY_LEN * 2,
                bytes.len()
            ));
        }
        let mut arr = [0u8; PUBLIC_KEY_LEN];
        arr.copy_from_slice(&bytes);
        PublicKey::from_bytes(&arr).map_err(|e| anyhow!("invalid public key: {e}"))
    }
}
