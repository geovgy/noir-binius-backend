#![no_main]

use noir_binius_verifier::{ProofBundle, VerificationKey, field_to_be_bytes};
use sha2::{Digest, Sha256};

sp1_zkvm::entrypoint!(main);

/// Verifies a complete noir-binius proof, including delegated recursive calls, and commits the
/// exact verification key and ordered Noir public inputs as the SP1 public values.
pub fn main() {
    let verification_key_bytes = sp1_zkvm::io::read::<Vec<u8>>();
    let proof_bytes = sp1_zkvm::io::read::<Vec<u8>>();

    let verification_key = VerificationKey::decode(&verification_key_bytes)
        .expect("invalid noir-binius verification key");
    let proof = ProofBundle::decode(&proof_bytes).expect("invalid noir-binius proof bundle");
    verification_key
        .verify_bundle(&proof)
        .expect("noir-binius proof verification failed");

    let noir_public_inputs = verification_key
        .noir_public_values(&proof)
        .expect("invalid Noir public inputs");
    let mut encoded_public_inputs = Vec::with_capacity(noir_public_inputs.len() * 32);
    for value in noir_public_inputs {
        encoded_public_inputs.extend_from_slice(&field_to_be_bytes(value));
    }

    sp1_zkvm::io::commit_slice(&Sha256::digest(&verification_key_bytes));
    sp1_zkvm::io::commit_slice(&Sha256::digest(&encoded_public_inputs));
}
