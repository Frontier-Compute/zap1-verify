//! zap1-verify-wasm - WASM bindings for in-browser ZAP1 Merkle proof verification.

use zap1_verify::{
    self, bytes_to_hex, compute_leaf_hash, hex_to_bytes32, node_hash, verify_proof,
    EventPayload, ProofStep, SiblingPosition,
};
use serde::Deserialize;
use wasm_bindgen::prelude::*;

// JS-facing types

#[derive(Deserialize)]
struct JsProofStep {
    hash: String,
    position: String,
}

#[derive(Deserialize)]
struct JsProofBundle {
    leaf_hash: String,
    proof: Vec<JsProofStep>,
    root: String,
}

// Exported functions

/// Verify a Merkle proof from JS.
///
/// Accepts a proof bundle as a JS object:
/// ```js
/// { leaf_hash: "abcd...", proof: [{hash: "...", position: "left|right"}, ...], root: "ef01..." }
/// ```
#[wasm_bindgen(js_name = "verifyProof")]
pub fn js_verify_proof(bundle: JsValue) -> Result<bool, JsError> {
    let b: JsProofBundle =
        serde_wasm_bindgen::from_value(bundle).map_err(|e| JsError::new(&e.to_string()))?;

    let leaf = hex_to_bytes32(&b.leaf_hash)
        .ok_or_else(|| JsError::new("invalid leaf_hash hex (need 64 chars)"))?;
    let root = hex_to_bytes32(&b.root)
        .ok_or_else(|| JsError::new("invalid root hex (need 64 chars)"))?;

    let mut path = Vec::with_capacity(b.proof.len());
    for (i, step) in b.proof.iter().enumerate() {
        let hash = hex_to_bytes32(&step.hash)
            .ok_or_else(|| JsError::new(&format!("invalid hex in proof step {}", i)))?;
        let position = match step.position.as_str() {
            "left" => SiblingPosition::Left,
            "right" => SiblingPosition::Right,
            other => {
                return Err(JsError::new(&format!(
                    "step {}: position must be 'left' or 'right', got '{}'",
                    i, other
                )))
            }
        };
        path.push(ProofStep { hash, position });
    }

    Ok(verify_proof(&leaf, &path, &root))
}

/// Compute the leaf hash for a PROGRAM_ENTRY event.
#[wasm_bindgen(js_name = "computeProgramEntry")]
pub fn js_compute_program_entry(wallet_hash: &str) -> String {
    let h = compute_leaf_hash(&EventPayload::ProgramEntry {
        wallet_hash: wallet_hash.as_bytes(),
    });
    bytes_to_hex(&h)
}

/// Compute the leaf hash for an OWNERSHIP_ATTEST event.
#[wasm_bindgen(js_name = "computeOwnershipAttest")]
pub fn js_compute_ownership_attest(wallet_hash: &str, serial_number: &str) -> String {
    let h = compute_leaf_hash(&EventPayload::OwnershipAttest {
        wallet_hash: wallet_hash.as_bytes(),
        serial_number: serial_number.as_bytes(),
    });
    bytes_to_hex(&h)
}

/// Compute a Merkle node hash: BLAKE2b-256("NordicShield_MRK", left || right).
#[wasm_bindgen(js_name = "nodeHash")]
pub fn js_node_hash(left_hex: &str, right_hex: &str) -> Result<String, JsError> {
    let left =
        hex_to_bytes32(left_hex).ok_or_else(|| JsError::new("invalid left hex (need 64 chars)"))?;
    let right = hex_to_bytes32(right_hex)
        .ok_or_else(|| JsError::new("invalid right hex (need 64 chars)"))?;
    Ok(bytes_to_hex(&node_hash(&left, &right)))
}
