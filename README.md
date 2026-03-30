# zap1-verify

Standalone ZAP1 Merkle proof verifier for Zcash. Rust + WASM.

## Purpose

`zap1-verify` verifies ZAP1 structured memo and Merkle proof data
independent of the server runtime. Used by Nordic Shield and the ZAP1
reference implementation.

It provides:

- ZAP1 leaf hashing via `compute_leaf_hash`
- Merkle internal node hashing via `node_hash`
- full inclusion proof verification via `verify_proof`
- hex helpers via `hex_to_bytes32` and `bytes_to_hex`
- browser bindings in `wasm/`

Reference spec and vectors:

- [`ONCHAIN_PROTOCOL.md`](https://github.com/Frontier-Compute/zap1/blob/main/ONCHAIN_PROTOCOL.md)
- [`TEST_VECTORS.md`](https://github.com/Frontier-Compute/zap1/blob/main/TEST_VECTORS.md)

## Install

```toml
[dependencies]
zap1-verify = "0.2"
```

## API

Core functions:

- `verify_proof(leaf_hash, proof_path, expected_root) -> bool`
- `compute_leaf_hash(&EventPayload) -> [u8; 32]`
- `compute_leaf_hash_with_personalization(&EventPayload, Option<&Personalization>) -> [u8; 32]`
- `node_hash(left, right) -> [u8; 32]`
- `node_hash_with_personalization(left, right, Option<&Personalization>) -> [u8; 32]`
- `hex_to_bytes32(hex) -> Option<[u8; 32]>`
- `bytes_to_hex(bytes) -> String`

Primary types:

- `EventPayload`
- `EventType`
- `Personalization`
- `ProofStep`
- `SiblingPosition`

Example:

```rust
use zap1_verify::{bytes_to_hex, compute_leaf_hash, EventPayload};

let leaf = compute_leaf_hash(&EventPayload::ProgramEntry {
    wallet_hash: b"wallet_abc",
});

println!("{}", bytes_to_hex(&leaf));
```

## WASM Build

```bash
cd wasm
wasm-pack build --target web
```

The WASM bindings expose browser-friendly proof verification and selected leaf
hash helpers.

## Tests

```bash
cargo test
```

Current test status: `22 passed`.

The test suite covers:

- all 9 deployed ZAP1 event types
- hex conversion helpers
- Merkle root derivation
- end-to-end proof verification against published vectors

## License

MIT
