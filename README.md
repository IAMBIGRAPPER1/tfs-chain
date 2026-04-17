# TFS_CHAIN

### THE SOVEREIGN MYCELIAL CRYPTO LEDGER

> *The chain remembers. The chain forgives. The chain does not forget.*

**TFS_CHAIN** is the sovereign blockchain of **THE FINAL SERVER** — the sovereign digital nation state operated by **MINES. VENTURE, LLC**, presided over by **PRESIDENT MINES.** (IAMBIGRAPPER1).

This repository contains the Rust reference implementation of the chain.

---

## ARCHITECTURE

Seven layers. Each a sovereign seal. Each passes a Dragon Run before the next begins.

| Layer | Module | Status |
|------:|---|---|
| 1 | **Cryptographic Foundation** — ed25519 + BLAKE3 + bech32m | 🐉 SEALED |
| 2 | **The Block** — header · Merkle tree · validation | 🐉 SEALED |
| 3 | **Transactions** — transfer · inscribe · verify · burn | 🐉 SEALED |
| 4 | **MINES.script** — the doctrine-block DSL | 🐉 SEALED |
| 5 | **Chain Logic** — append-only validation · mempool · BFT consensus | 🐉 SEALED |
| 6 | **Persistent Storage** — RocksDB | 🐉 SEALED |
| 7 | **The Node** — HTTP API + libp2p networking | pending |

---

## THE CURRENCY · $TFS

**Supply cap:** 1,000,000,000 $TFS (hard, encoded at Genesis Block 0, can only be lowered through ceremonial burns).

**Issuance — $TFS is minted by act, not by fiat:**

- **Inscription:** 1,000 $TFS per doctrine-block inscribed on the chain.
- **Verification:** 100 $TFS per citizen verified by a 3-peer quorum.
- **Routing:** 1 hypha (10⁻⁹ $TFS) per block of traffic routed through a node.

**Halvings:** every 50,000 doctrine-blocks, the issuance per act halves. After the last halving (at 1 billion $TFS issued), the currency stops minting. The currency keeps circulating.

**Anchoring:** $TFS is anchored to three substrates — **Compute**, **Culture**, and **Sovereignty** itself. Not to fiat. Not to commodity. Not to another cryptocurrency.

---

## CONSENSUS · SOVEREIGN BFT

TFS_CHAIN uses **Proof-of-Authority + Byzantine Fault Tolerance** (Tendermint-style). Validators are authorized citizens of the sovereign layer. Blocks finalize in a single round when ⅔ of validators sign. The chain tolerates up to ⅓ of validators being compromised.

Citizens scale infinitely. Validators scale by invitation.

---

## CRYPTOGRAPHIC POSTURE

- **Signing:** ed25519 via `ed25519-dalek` (strict verification, zeroize-on-drop).
- **Hashing:** BLAKE3 (deterministic, 256-bit).
- **Addresses:** bech32m with `tfs1...` prefix (checksum detects up to 6 typos per 90 chars).
- **Weak keys rejected at construction** — stronger posture than default ed25519-dalek.
- **No `unsafe` code** — forbidden at the crate level.
- **No floating-point** — forbidden in consensus-critical code.
- **Deterministic serialization** — bincode everywhere. Identical inputs produce identical hashes on every platform, forever.

---

## BUILDING

```bash
cargo check --lib     # type-check
cargo test --lib      # run unit tests
cargo build --release # produce the node binary (after Layer 7)
```

Requires stable Rust ≥ 1.75.

---

## THE DRAGON RUN DOCTRINE

Between each layer, the entire written codebase is rescanned for vulnerabilities. Each Dragon Run enumerates attack vectors and verifies defenses. A layer is not sealed until its Dragon Run passes with zero critical findings. A final comprehensive Dragon Run — **rendered by Claude Mythos** — seals the chain before Genesis Block 0 mints.

The chain deploys with **zero vulnerabilities**.

---

## LICENSE

**All Rights MINES.** See [LICENSE](./LICENSE).

The code is public. The code may be read, studied, audited. The code may **not** be forked, redeployed, or used to build competing chains without explicit written permission from MINES. VENTURE, LLC.

Transparent sovereignty. Not open-source-forkable. Two different things.

---

## RENDERED BY

- **Claude Opus 4.7** — Layers 1–7 and Dragon Runs 1–7 (the build phase).
- **Claude Mythos** — Final Dragon Run and Genesis Mint (the sealing phase).

Inscribed by **PRESIDENT MINES.**
Sealed by **IAMBIGRAPPER1** · MINES. VENTURE, LLC.

---

```
MINES. VENTURE, LLC
TFS_THOTH · SOVEREIGN INTELLIGENCE
ALL RIGHTS MINES.
```

🐉
