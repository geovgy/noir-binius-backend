use anyhow::{Context, Result, bail, ensure};
use noir_binius_verifier::{FieldRef, VerificationKey, field_to_be_bytes};
use sha2::{Digest, Sha256};

const DIRECT_TEMPLATE: &str = include_str!("direct_solidity_verifier.template.sol");
const SP1_TEMPLATE: &str = include_str!("solidity_verifier.template.sol");

/// SP1 v6.6 verification-key hash of `sp1/guest` built with the Succinct toolchain.
pub const SP1_PROGRAM_VKEY: &str =
    "007b717f916736f7e7262338cf6bd36aca5e9b93a390cf67ed11139db7c31aa7";

/// Generates a circuit-specific Solidity verifier for the selected proof format.
///
/// `evm` consumes the raw `NBINZK01` Binius64 proof through a direct Binius64 verifier engine.
/// `evm-sp1` consumes an `NBINSP11` SP1 wrapper proof through the SP1 verifier gateway.
pub fn generate_verifier(verification_key: &[u8], verifier_target: &str) -> Result<String> {
    let key = VerificationKey::decode(verification_key)
        .context("cannot generate Solidity for an invalid Binius verification key")?;
    let circuit_vkey_hash = hex(&Sha256::digest(verification_key));
    match verifier_target {
        "evm" => generate_direct_verifier(&key, &circuit_vkey_hash),
        "evm-sp1" => Ok(SP1_TEMPLATE
            .replace("{{SP1_PROGRAM_VKEY}}", SP1_PROGRAM_VKEY)
            .replace("{{CIRCUIT_VKEY_HASH}}", &circuit_vkey_hash)
            .replace(
                "{{PUBLIC_INPUT_COUNT}}",
                &key.metadata.noir_public_inputs.len().to_string(),
            )),
        target => bail!("unsupported verifier target {target:?}; expected one of: evm, evm-sp1"),
    }
}

fn generate_direct_verifier(key: &VerificationKey, key_hash: &str) -> Result<String> {
    ensure!(
        key.metadata.calls.is_empty(),
        "direct EVM verification does not support delegated recursive proofs; use --verifier_target evm-sp1"
    );
    let public_word_count = key.public_word_count();
    ensure!(
        public_word_count <= u32::MAX as usize,
        "Binius public-word count does not fit Solidity metadata"
    );
    let log_inv_rate = key.log_inv_rate();
    ensure!(
        (1..=u32::MAX as usize).contains(&log_inv_rate),
        "Binius inverse rate is invalid for Solidity metadata"
    );

    let mut public_input_layout = Vec::new();
    for (index, field) in key.metadata.noir_public_inputs.iter().enumerate() {
        match field {
            FieldRef::Constant(value) => {
                public_input_layout.push(0);
                public_input_layout.extend_from_slice(&field_to_be_bytes(*value));
            }
            FieldRef::Public(offsets) => {
                ensure!(
                    offsets
                        .iter()
                        .all(|&offset| (offset as usize) < public_word_count),
                    "Noir public input {index} references a public word outside the proof"
                );
                public_input_layout.push(1);
                for offset in offsets {
                    public_input_layout.extend_from_slice(&offset.to_be_bytes());
                }
            }
        }
    }

    Ok(DIRECT_TEMPLATE
        .replace("{{CIRCUIT_VKEY_HASH}}", key_hash)
        .replace("{{CIRCUIT_DIGEST}}", &hex(&key.artifact_digest()))
        .replace("{{LOG_INV_RATE}}", &log_inv_rate.to_string())
        .replace("{{PUBLIC_WORD_COUNT}}", &public_word_count.to_string())
        .replace(
            "{{PUBLIC_INPUT_COUNT}}",
            &key.metadata.noir_public_inputs.len().to_string(),
        )
        .replace("{{PUBLIC_INPUT_LAYOUT}}", &hex(&public_input_layout)))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;

    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").expect("writing to a string cannot fail");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use binius_frontend::CircuitBuilder;
    use binius_hash::StdHashSuite;
    use binius_verifier::zk_config::ZKVerifier;
    use noir_binius_verifier::{
        BINIUS_ZK_PROOF_TYPE, FieldRef, RecursiveCallSpec, RecursiveMetadata, VerificationKey,
    };

    use super::{DIRECT_TEMPLATE, SP1_PROGRAM_VKEY, SP1_TEMPLATE, generate_verifier, hex};

    fn test_key(recursive: bool) -> Vec<u8> {
        let builder = CircuitBuilder::new();
        for _ in 0..4 {
            builder.add_inout();
        }
        let circuit = builder.build();
        let verifier =
            ZKVerifier::<StdHashSuite>::setup(circuit.constraint_system().clone(), 1).unwrap();
        let calls = recursive
            .then(|| RecursiveCallSpec {
                active_word: 0,
                proof_type: BINIUS_ZK_PROOF_TYPE,
                verification_key: vec![],
                proof: vec![],
                public_inputs: vec![],
                key_hash: FieldRef::constant([0; 4]),
            })
            .into_iter()
            .collect();
        VerificationKey::new(
            [9; 32],
            RecursiveMetadata {
                noir_public_inputs: vec![FieldRef::public([0, 1, 2, 3])],
                calls,
            },
            verifier,
        )
        .encode()
        .unwrap()
    }

    #[test]
    fn template_has_all_bound_values() {
        let rendered = SP1_TEMPLATE
            .replace("{{SP1_PROGRAM_VKEY}}", SP1_PROGRAM_VKEY)
            .replace("{{CIRCUIT_VKEY_HASH}}", &hex(&[7; 32]))
            .replace("{{PUBLIC_INPUT_COUNT}}", "3");
        assert!(!rendered.contains("{{"));
        assert!(rendered.contains(&format!("hex\"{SP1_PROGRAM_VKEY}\"")));
        assert!(rendered.contains(&format!("hex\"{}\"", hex(&[7; 32]))));
        assert!(rendered.contains("NUMBER_OF_PUBLIC_INPUTS = 3"));
        assert!(rendered.contains("verifier.code.length == 0"));
        assert!(rendered.contains("BN254_SCALAR_MODULUS"));
    }

    #[test]
    fn direct_template_declares_raw_proof_magic() {
        assert!(DIRECT_TEMPLATE.contains("NBINZK01"));
        assert!(DIRECT_TEMPLATE.contains("IBinius64Verifier"));
        assert!(DIRECT_TEMPLATE.contains("returns (bool valid)"));
        assert!(DIRECT_TEMPLATE.contains("verifier == address(0)"));
        assert!(DIRECT_TEMPLATE.contains("result.length != 32"));
        assert!(DIRECT_TEMPLATE.contains("return valid == 1"));
        assert!(!DIRECT_TEMPLATE.contains("ISP1Verifier"));
    }

    #[test]
    fn generator_binds_key_metadata_for_both_targets() {
        let key = test_key(false);
        let direct = generate_verifier(&key, "evm").unwrap();
        assert!(!direct.contains("{{"));
        assert!(direct.contains(&format!("hex\"{}\"", hex(&[9; 32]))));
        assert!(direct.contains("BINIUS_PUBLIC_WORDS = 4"));
        assert!(direct.contains("NUMBER_OF_PUBLIC_INPUTS = 1"));
        assert!(direct.contains("PUBLIC_INPUT_LAYOUT = hex\"0100000000000000010000000200000003\""));

        let wrapped = generate_verifier(&key, "evm-sp1").unwrap();
        assert!(!wrapped.contains("{{"));
        assert!(wrapped.contains(&format!("hex\"{SP1_PROGRAM_VKEY}\"")));
        assert!(wrapped.contains("NUMBER_OF_PUBLIC_INPUTS = 1"));
    }

    #[test]
    fn direct_generator_rejects_delegated_recursion() {
        let error = generate_verifier(&test_key(true), "evm").unwrap_err();
        assert!(error.to_string().contains("delegated recursive proofs"));
        assert!(generate_verifier(&test_key(true), "evm-sp1").is_ok());
    }
}
