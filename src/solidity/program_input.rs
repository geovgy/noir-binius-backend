//! Optional public circuit data in calldata. Its constructor-bound digest is
//! checked before the unchanged verification program is decoded or executed.
use super::{deployment::decode_hex, hex, program::ConstructedProgram};
use anyhow::{Context, Result, ensure};
use digest::Digest;
use serde::Serialize;
use serde_json::Value;

const MAGIC: &[u8; 8] = b"NBINK001";
const KIND: &str = "keccak-calldata-v1";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgramInputInfo {
    pub kind: &'static str,
    pub magic: String,
    pub program_length: usize,
    pub program_keccak256: String,
}

fn stored(plan: &ConstructedProgram) -> &[u8] {
    plan.storage.as_ref().map_or(&plan.bytes, |s| &s.bytes)
}

fn hash(bytes: &[u8]) -> String {
    format!("0x{}", hex(&sha3::Keccak256::digest(bytes)))
}

pub(super) fn metadata(plan: &ConstructedProgram) -> Option<ProgramInputInfo> {
    plan.authenticated_program.then(|| ProgramInputInfo {
        kind: KIND,
        magic: format!("0x{}", hex(MAGIC)),
        program_length: stored(plan).len(),
        program_keccak256: hash(stored(plan)),
    })
}

// The typed option survives both constructor renderings during compilation.
// Slot zero holds the digest; data still starts at keccak256(abi.encode(0)).
// No Solidity dynamic-bytes access remains in this version of the contract.
pub(super) fn constructor(mut source: String, plan: &ConstructedProgram) -> String {
    let marker = "sstore(verificationProgram.slot, add(mul(length, 2), 1))";
    assert_eq!(source.matches(marker).count(), 1);
    // The existing constructor checks already bind data to the key's fixed
    // logical/stored digest. Recompute that same digest for slot zero to avoid
    // another literal in the size-constrained creation code.
    let _ = plan;
    source = source.replace(
        marker,
        "sstore(verificationProgram.slot, keccak256(add(data, 32), length))",
    );
    source.replace("verificationProgram.slot", "verificationProgramHash.slot")
}

pub(super) fn runtime(mut source: String, plan: &ConstructedProgram) -> Result<String> {
    let length = stored(plan).len();
    let prefix = length
        .checked_add(MAGIC.len())
        .context("program input size overflow")?;
    let declaration = "    bytes private verificationProgram;";
    ensure!(
        source.matches(declaration).count() == 1,
        "missing program storage declaration"
    );
    source = source.replace(declaration, concat!(
        "    // Slot zero binds optional calldata; circuit data begins at keccak256(slot zero).\n",
        "    bytes32 private verificationProgramHash;"
    ));
    let marker = "        // NBINH001 adds only digest hints.";
    ensure!(
        source.matches(marker).count() == 1,
        "missing native/hinted proof dispatcher"
    );
    let frame = format!(
        r#"        // Optional public circuit data. Authenticate it before decoding or execution.
        uint256 suppliedProgram;
        assembly ("memory-safe") {{
            if eq(shr(192, calldataload(proof.offset)), 0x4e42494e4b303031) {{
                if lt(proof.length, {prefix}) {{ mstore(0, 0) return(0, 32) }}
                suppliedProgram := add(proof.offset, 8)
                proof.offset := add(proof.offset, {prefix})
                proof.length := sub(proof.length, {prefix})
            }}
        }}
"#
    );
    source = source.replace(marker, &(frame + marker));
    let old = r#"            mstore(0, verificationProgram.slot)
            let slot := keccak256(0, 32)
            for { let p := start } lt(p, end) { p := add(p, 32) } {
                mstore(p, sload(slot))
                slot := add(slot, 1)
            }"#;
    ensure!(
        source.matches(old).count() == 1,
        "missing immutable program loader"
    );
    let copy = old.replace("verificationProgram.slot", "verificationProgramHash.slot");
    let new = format!(
        r#"            switch suppliedProgram
            case 0 {{
{copy}
            }}
            default {{
                calldatacopy(start, suppliedProgram, {length})
                if iszero(eq(keccak256(start, {length}), sload(verificationProgramHash.slot))) {{
                    mstore(0, 0)
                    return(0, 32)
                }}
            }}"#
    );
    source = source.replace(old, &new);
    source = source.replace(
        "// The constructor is the only writer. Its exact length is fixed by\n        // generation, so copy the immutable data directly from its own slots.",
        "// Generation fixes the length. Load the constructor's data, or authenticate\n        // identical caller-supplied bytes against its constructor-bound digest.",
    );
    ensure!(
        !source.contains("verificationProgram.slot"),
        "unexpected dynamic program storage access"
    );
    Ok(source)
}

/// Add optional public circuit data to the proof argument of IVerifier.verify.
/// This only frames the input: it does not verify the proof. The contract checks
/// the data digest and executes the same native ZK verifier. Raw proofs remain
/// accepted. Only deployments explicitly advertising this format support it.
pub fn with_verifier_program(deployment: &Value, proof: &[u8]) -> Result<Vec<u8>> {
    let construction = &deployment["construction"];
    let info = &construction["programInput"];
    ensure!(
        info["kind"] == KIND && info["magic"] == format!("0x{}", hex(MAGIC)),
        "deployment does not support authenticated program input"
    );
    let data = if construction["storageCompression"].is_object() {
        &construction["storageCompression"]["storedProgram"]
    } else {
        &construction["verificationProgram"]
    };
    let bytes = decode_hex(data.as_str().context("missing deployment program")?)?;
    ensure!(
        !bytes.is_empty()
            && info["programLength"].as_u64() == Some(bytes.len() as u64)
            && info["programKeccak256"] == hash(&bytes),
        "inconsistent authenticated program metadata"
    );
    ensure!(
        proof.starts_with(b"NBINZK01") || proof.starts_with(b"NBINH001NBINZK01"),
        "expected native NBINZK01 proof or NBINH001 hash hints"
    );
    let mut output = Vec::with_capacity(MAGIC.len() + bytes.len() + proof.len());
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&bytes);
    output.extend_from_slice(proof);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn framing_binds_the_selected_stored_representation() {
        for compressed in [false, true] {
            let bytes = if compressed {
                vec![1, 2, 3]
            } else {
                vec![4, 5]
            };
            let mut artifact = json!({"construction": {
                "verificationProgram": "0x0405",
                "programInput": {"kind": KIND, "magic": format!("0x{}", hex(MAGIC)),
                    "programLength": bytes.len(), "programKeccak256": hash(&bytes)}
            }});
            if compressed {
                artifact["construction"]["storageCompression"] =
                    json!({"storedProgram": "0x010203"});
            }
            for proof in [&b"NBINZK01example"[..], &b"NBINH001NBINZK01example"[..]] {
                let framed = with_verifier_program(&artifact, proof).unwrap();
                assert_eq!(framed, [MAGIC.as_slice(), &bytes, proof].concat());
                assert!(with_verifier_program(&artifact, &framed).is_err());
            }
            assert!(with_verifier_program(&artifact, b"NBINSP11example").is_err());
            artifact["construction"]["programInput"]["programKeccak256"] = json!(hash(&[0]));
            assert!(with_verifier_program(&artifact, b"NBINZK01example").is_err());
            artifact["construction"]["programInput"] = Value::Null;
            assert!(with_verifier_program(&artifact, b"NBINZK01example").is_err());
        }
    }
}
