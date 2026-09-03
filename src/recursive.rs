use acir::{AcirField, FieldElement};
use anyhow::{Result, ensure};
use serde::Serialize;

use crate::proof::ProofBundle;

pub use noir_binius_verifier::{
    BINIUS_ZK_PROOF_TYPE, FieldRef, RecursiveCallSpec, RecursiveMetadata, VerificationKey,
};
use noir_binius_verifier::{FieldValue, pack_bytes, recursive_verification_key_hash};

/// Copy-pasteable values for Noir's `verify_proof_with_type` API.
#[derive(Clone, Debug, Serialize)]
pub struct RecursiveInputs {
    pub verification_key: Vec<String>,
    pub proof: Vec<String>,
    pub public_inputs: Vec<String>,
    pub key_hash: String,
    pub proof_type: u32,
}

impl RecursiveInputs {
    /// Renders these fields as a Nargo `Prover.toml` file.
    pub fn to_toml(&self) -> String {
        fn array(out: &mut String, name: &str, values: &[String]) {
            out.push_str(name);
            out.push_str(" = [\n");
            for value in values {
                out.push_str("    \"");
                out.push_str(value);
                out.push_str("\",\n");
            }
            out.push_str("]\n\n");
        }

        let mut out = String::new();
        array(&mut out, "verification_key", &self.verification_key);
        array(&mut out, "proof", &self.proof);
        array(&mut out, "public_inputs", &self.public_inputs);
        out.push_str("key_hash = \"");
        out.push_str(&self.key_hash);
        out.push_str("\"\n");
        out
    }
}

pub(crate) fn recursive_inputs(
    key: &VerificationKey,
    proof: &ProofBundle,
) -> Result<RecursiveInputs> {
    let key_bytes = key.encode()?;
    let proof_bytes = proof.encode()?;
    let public_inputs = key.noir_public_values(proof)?;
    Ok(RecursiveInputs {
        verification_key: fields_to_strings(&pack_bytes(&key_bytes))?,
        proof: fields_to_strings(&pack_bytes(&proof_bytes))?,
        public_inputs: fields_to_strings(&public_inputs)?,
        key_hash: field_to_noir(recursive_verification_key_hash(&key_bytes))?.to_short_hex(),
        proof_type: BINIUS_ZK_PROOF_TYPE,
    })
}

fn fields_to_strings(fields: &[FieldValue]) -> Result<Vec<String>> {
    fields
        .iter()
        .copied()
        .map(field_to_noir)
        .map(|field| field.map(|value| value.to_short_hex()))
        .collect()
}

fn field_to_noir(limbs: FieldValue) -> Result<FieldElement> {
    let bytes: Vec<_> = limbs.into_iter().flat_map(u64::to_le_bytes).collect();
    let value = FieldElement::from_le_bytes_reduce(&bytes);
    let mut canonical = value.to_le_bytes();
    canonical.resize(32, 0);
    let actual: FieldValue = std::array::from_fn(|index| {
        u64::from_le_bytes(canonical[index * 8..(index + 1) * 8].try_into().unwrap())
    });
    ensure!(actual == limbs, "non-canonical BN254 field value");
    Ok(value)
}
