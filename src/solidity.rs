use anyhow::{Context, Result, bail, ensure};
use noir_binius_verifier::{FieldRef, VerificationKey, field_to_be_bytes};
use sha2::{Digest, Sha256};

mod codec;
mod program;

const DIRECT_TEMPLATE: &str = include_str!("direct_solidity_verifier.template.sol");
const SP1_TEMPLATE: &str = include_str!("solidity_verifier.template.sol");
const RUNTIME: &str = include_str!("solidity/runtime.sol");
const FRI_RUNTIME: &str = include_str!("solidity/fri.sol");
const CODEC_RUNTIME: &str = include_str!("solidity/codec.sol");

/// SP1 v6.6 verification-key hash of `sp1/guest` built with the Succinct toolchain.
pub const SP1_PROGRAM_VKEY: &str =
    "007b717f916736f7e7262338cf6bd36aca5e9b93a390cf67ed11139db7c31aa7";

/// Generates a circuit-specific Solidity verifier for the selected proof format.
///
/// `evm` verifies the raw `NBINZK01` Binius64 proof entirely in the generated contract.
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

    let program = program::compile(key.binius_verifier())?;
    let (compressed, encoded_length) = codec::pack(&program.bytes);
    // The compressed literal alone is a lower bound on creation bytecode.
    // Do not emit a purported single-deployment verifier when even its data
    // already exceeds the EVM initcode limit. Solc must check the final size.
    ensure!(
        compressed.len() < 49_152,
        "direct verifier circuit data compresses to {} bytes, exceeding the 49152-byte EVM initcode limit before executable code; this circuit cannot currently be generated for a single deployment",
        compressed.len()
    );
    let mut runtime = RUNTIME.to_owned();
    let mut codec = CODEC_RUNTIME.to_owned();
    for opcode in 0..32 {
        if program.used_opcodes & (1u32 << opcode) == 0 {
            runtime = runtime.replace(&format!("opcode == {opcode})"), "false)");
            let switch = codec.find("switch op\n").expect("operand codec switch");
            let start = switch
                + codec[switch..]
                    .find(&format!("case {opcode} {{"))
                    .expect("operand codec case");
            let brace = start + codec[start..].find('{').unwrap();
            let mut depth = 0;
            let mut end = brace;
            for (i, b) in codec.bytes().enumerate().skip(brace) {
                if b == b'{' {
                    depth += 1;
                }
                if b == b'}' {
                    depth -= 1;
                }
                if depth == 0 {
                    end = i + 1;
                    break;
                }
            }
            codec.replace_range(start..end, "");
        }
    }
    Ok(DIRECT_TEMPLATE
        .replace("{{RUNTIME}}", &[&runtime, FRI_RUNTIME, &codec].concat())
        .replace("{{COMPRESSED_PROGRAM}}", &hex(&compressed))
        .replace("{{ENCODED_PROGRAM_LENGTH}}", &encoded_length.to_string())
        .replace("{{PROGRAM_LENGTH}}", &program.bytes.len().to_string())
        .replace("{{PROOF_LENGTH}}", &program.proof_len.to_string())
        .replace("{{REGISTER_COUNT}}", &program.registers.to_string())
        .replace("{{CIRCUIT_VKEY_HASH}}", key_hash)
        .replace("{{CIRCUIT_DIGEST}}", &hex(&key.artifact_digest()))
        .replace("{{LOG_INV_RATE}}", &log_inv_rate.to_string())
        .replace("{{PUBLIC_WORD_COUNT}}", &public_word_count.to_string())
        .replace(
            "{{PUBLIC_INPUT_COUNT}}",
            &key.metadata.noir_public_inputs.len().to_string(),
        )
        .replace("{{PUBLIC_INPUT_LAYOUT}}", &hex(&public_input_layout))
        .replace(
            "{{NOIR_INPUT_CHECKS}}",
            &noir_input_checks(&key.metadata.noir_public_inputs),
        ))
}

fn noir_input_checks(inputs: &[FieldRef]) -> String {
    use std::fmt::Write;

    // For small interfaces, specialize the key's input layout too. Larger
    // interfaces retain the table interpreter to avoid linear code growth.
    if inputs.len() > 4 {
        return "return _validateNoirInputsGeneric(proof, publicInputs);".into();
    }
    let mut code = String::new();
    for (i, field) in inputs.iter().enumerate() {
        match field {
            FieldRef::Constant(value) => {
                writeln!(
                    code,
                    "if (publicInputs[{i}] != hex\"{}\") return false;",
                    hex(&field_to_be_bytes(*value))
                )
                .unwrap();
            }
            FieldRef::Public(offsets) => {
                let expression = if offsets
                    .windows(2)
                    .all(|p| u64::from(p[0]) + 1 == u64::from(p[1]))
                {
                    let start = 48 + 8 * u64::from(offsets[0]);
                    format!("_reverse(uint256(bytes32(proof[{start}:{}])))", start + 32)
                } else {
                    offsets
                        .iter()
                        .enumerate()
                        .map(|(limb, offset)| {
                            format!("(_publicWord(proof, {offset}) << {})", 64 * limb)
                        })
                        .collect::<Vec<_>>()
                        .join(" | ")
                };
                writeln!(code, "uint256 input{i} = {expression};\nif (input{i} >= BN254_SCALAR_MODULUS || uint256(publicInputs[{i}]) != input{i}) return false;").unwrap();
            }
        }
    }
    code.push_str("return true;");
    code
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
    fn direct_template_has_no_delegated_verification() {
        assert!(DIRECT_TEMPLATE.contains("NBINZK01"));
        assert!(DIRECT_TEMPLATE.contains("contract BiniusVerifier is IVerifier"));
        assert!(DIRECT_TEMPLATE.contains("external view override returns (bool)"));
        assert!(!DIRECT_TEMPLATE.contains("staticcall"));
        assert!(!DIRECT_TEMPLATE.contains("delegatecall"));
        assert!(DIRECT_TEMPLATE.contains("constructor()"));
        assert!(!DIRECT_TEMPLATE.contains("constructor(address"));
        assert!(!DIRECT_TEMPLATE.contains("loadVerificationProgramChunk"));
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
