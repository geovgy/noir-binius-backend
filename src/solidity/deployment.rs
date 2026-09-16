//! Constructor compression of the compiler's own complete verification code.
//! No runtime address, verifier service, or installation transaction is used.
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    io::Read,
    path::Path,
    process::{Command, Stdio},
};

const SETTINGS: &str =
    "solc 0.8.35, optimizer 200 runs, viaIR, evmVersion osaka, metadata.bytecodeHash none";

pub(super) fn decode_hex(value: &str) -> Result<Vec<u8>> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    ensure!(
        value.len() % 2 == 0,
        "compiler returned an odd bytecode length"
    );
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digits = std::str::from_utf8(pair)?;
            u8::from_str_radix(digits, 16).context("compiler returned non-hexadecimal bytecode")
        })
        .collect()
}

fn compile(source: &str, compiler: &Path) -> Result<(Vec<u8>, Vec<u8>)> {
    let input = json!({
        "language": "Solidity",
        "sources": {"BiniusVerifier.sol": {"content": source}},
        "settings": {
            "optimizer": {"enabled": true, "runs": 200}, "viaIR": true,
            "evmVersion": "osaka", "metadata": {"bytecodeHash": "none"},
            "outputSelection": {"*": {"BiniusVerifier": ["evm.bytecode.object", "evm.deployedBytecode.object"]}}
        }
    });
    let result = standard_json(&input, compiler)?;
    let evm = &result["contracts"]["BiniusVerifier.sol"]["BiniusVerifier"]["evm"];
    let creation = decode_hex(
        evm["bytecode"]["object"]
            .as_str()
            .context("missing constructor bytecode")?,
    )?;
    let runtime = decode_hex(
        evm["deployedBytecode"]["object"]
            .as_str()
            .context("missing verifier runtime")?,
    )?;
    ensure!(
        !creation.is_empty() && !runtime.is_empty(),
        "compiler returned empty verifier code"
    );
    Ok((creation, runtime))
}

pub(super) fn standard_json(input: &Value, compiler: &Path) -> Result<Value> {
    let mut child = Command::new(compiler)
        .arg("--standard-json")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to run Solidity compiler {}", compiler.display()))?;
    // The compiler must receive EOF before compilation. Its standard-json
    // response is collected concurrently by wait_with_output after closing stdin.
    let mut input_pipe = child.stdin.take().context("missing compiler stdin")?;
    let written = serde_json::to_writer(&mut input_pipe, input);
    drop(input_pipe);
    if let Err(error) = written {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error).context("failed to write Solidity compiler input");
    }
    let output = child
        .wait_with_output()
        .context("failed to read Solidity compiler output")?;
    ensure!(
        output.status.success(),
        "Solidity compiler failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result = parse_output(&output.stdout).context("invalid solc standard-json output")?;
    if let Some(errors) = result["errors"].as_array() {
        let failures: Vec<_> = errors
            .iter()
            .filter(|e| e["severity"] == "error")
            .map(|e| {
                e["formattedMessage"]
                    .as_str()
                    .unwrap_or("unknown solc error")
            })
            .collect();
        ensure!(
            failures.is_empty(),
            "Solidity compilation failed:\n{}",
            failures.join("\n")
        );
    }
    Ok(result)
}

fn parse_output(bytes: &[u8]) -> Result<Value> {
    // Optimized Yul ASTs can exceed serde_json's default depth of 128. Bound
    // their nesting explicitly before parsing instead of accepting arbitrary
    // recursion. Ignore braces inside the compiler's escaped source strings.
    let (mut depth, mut quoted, mut escaped) = (0usize, false, false);
    for &byte in bytes {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
        } else {
            match byte {
                b'"' => quoted = true,
                b'{' | b'[' => {
                    depth += 1;
                    ensure!(depth <= 256, "compiler JSON exceeds 256 nested containers");
                }
                b'}' | b']' => depth = depth.checked_sub(1).context("unbalanced compiler JSON")?,
                _ => {}
            }
        }
    }
    ensure!(depth == 0 && !quoted, "unterminated compiler JSON");
    let mut parser = serde_json::Deserializer::from_slice(bytes);
    parser.disable_recursion_limit();
    let result = Value::deserialize(&mut parser)?;
    parser.end()?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiler_ast_depth_is_explicitly_bounded() {
        let nested = |depth: usize| format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
        assert!(parse_output(nested(180).as_bytes()).is_ok());
        assert!(parse_output(nested(257).as_bytes()).is_err());
        let string = json!({"source": "[".repeat(300) + "\\\"" + &"]".repeat(300)});
        assert_eq!(parse_output(string.to_string().as_bytes()).unwrap(), string);
        for invalid in ["[}", "{", "\"unterminated", "0 0", "}"] {
            assert!(parse_output(invalid.as_bytes()).is_err(), "{invalid}");
        }
    }
}

fn constant(source: &str, name: &str) -> Result<usize> {
    let marker = format!("uint256 private constant {name} = ");
    let value = source
        .split_once(&marker)
        .with_context(|| format!("missing {name}"))?
        .1;
    value
        .split_once(';')
        .context("unterminated verifier constant")?
        .0
        .parse()
        .context("invalid verifier constant")
}

pub(super) fn constructor_range(source: &str) -> Result<std::ops::Range<usize>> {
    let start = source
        .find("    constructor() {")
        .context("missing verifier constructor")?;
    let brace = start + source[start..].find('{').unwrap();
    let mut depth = 0;
    for (position, byte) in source.bytes().enumerate().skip(brace) {
        if byte == b'{' {
            depth += 1;
        }
        if byte == b'}' {
            depth -= 1;
        }
        if depth == 0 {
            return Ok(start..position + 1);
        }
    }
    anyhow::bail!("unterminated verifier constructor")
}

pub(super) struct CompressedDeployment {
    pub source: String,
    pub runtime: Vec<u8>,
    pub compressed_bytes: usize,
    pub creation_bytes: usize,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub(super) struct SizeLimit {
    kind: &'static str,
    actual: usize,
    limit: usize,
}
impl std::fmt::Display for SizeLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "compressed direct verifier {} is {} bytes, exceeding the {}-byte EVM limit",
            self.kind, self.actual, self.limit
        )
    }
}
impl std::error::Error for SizeLimit {}

impl SizeLimit {
    pub(super) fn is_initcode(&self) -> bool {
        matches!(self.kind, "initcode" | "Yul initcode")
    }
}

pub(super) fn check_size(kind: &'static str, actual: usize, limit: usize) -> Result<()> {
    if actual > limit {
        return Err(SizeLimit {
            kind,
            actual,
            limit,
        }
        .into());
    }
    Ok(())
}

pub(super) fn compress_runtime_info(source: &str, compiler: &Path) -> Result<CompressedDeployment> {
    let compiled = prepare_runtime(source, compiler)?;
    check_size("initcode", compiled.creation_bytes, 49_152)?;
    Ok(compiled)
}

// This intermediate Solidity constructor may be oversized. Only the explicit
// Yul deployment path can consume it, and must check its final creation code.
pub(super) fn prepare_runtime(source: &str, compiler: &Path) -> Result<CompressedDeployment> {
    prepare_runtime_with_construction(source, compiler, None)
}

pub(super) fn prepare_runtime_with_construction(
    source: &str,
    compiler: &Path,
    construction: Option<&super::program::ConstructedProgram>,
) -> Result<CompressedDeployment> {
    prepare_runtime_with_compressor(source, compiler, construction, super::codec::compress)
}

pub(super) fn prepare_runtime_with_compressor(
    source: &str,
    compiler: &Path,
    construction: Option<&super::program::ConstructedProgram>,
    compress: fn(&[u8]) -> Vec<u8>,
) -> Result<CompressedDeployment> {
    let version = Command::new(compiler)
        .arg("--version")
        .output()
        .with_context(|| format!("failed to run Solidity compiler {}", compiler.display()))?;
    ensure!(
        version.status.success()
            && String::from_utf8_lossy(&version.stdout)
                .lines()
                .any(|line| line.starts_with("Version: 0.8.35+")),
        "compressed deployment requires solc 0.8.35 with the documented settings"
    );
    let range = constructor_range(source)?;
    let encoded_len = constant(source, "ENCODED_PROGRAM_LENGTH")?;
    let program_len = constant(source, "VERIFICATION_PROGRAM_LENGTH")?;
    let width = constant(source, "PROGRAM_WORD_BYTES")?;
    let literal = source[range.clone()]
        .split_once("_unlzma(hex\"")
        .context("missing compressed program")?
        .1
        .split_once('"')
        .context("unterminated compressed program")?
        .0;
    let packed = decode_hex(literal)?;
    let headers = construction
        .and_then(|plan| plan.storage.as_ref())
        .map_or(&[][..], |storage| storage.headers.as_slice());
    let prefix_length = encoded_len
        .checked_add(headers.len())
        .context("constructor payload size overflow")?;
    let mut reader = lzma_rust2::LzmaReader::new_with_props(
        packed.as_slice(),
        prefix_length as u64,
        1,
        1 << 20,
        None,
    )?;
    let mut encoded = Vec::new();
    reader.read_to_end(&mut encoded)?;
    ensure!(
        encoded.len() == prefix_length,
        "compressed program length mismatch"
    );
    ensure!(
        &encoded[encoded_len..] == headers,
        "constructor packing headers differ from typed plan"
    );
    encoded.truncate(encoded_len);
    let decoded = super::codec::operands(&encoded, false, width);
    if let Some(plan) = construction {
        ensure!(
            width == plan.precursor.word_bytes
                && decoded == plan.precursor.bytes
                && program_len == plan.bytes.len(),
            "constructor precursor differs from its typed construction plan"
        );
    } else {
        ensure!(
            decoded.len() == program_len,
            "compressed program length mismatch"
        );
    }
    let (_, runtime) = compile(source, compiler)?;
    if runtime.len() > 24_576 {
        return Err(SizeLimit {
            kind: "runtime",
            actual: runtime.len(),
            limit: 24_576,
        }
        .into());
    }
    let mut joint = encoded;
    joint.extend_from_slice(headers);
    joint.extend_from_slice(&runtime);
    let compressed = compress(&joint);
    let constructor = if let Some(plan) = construction {
        super::construction::constructor(plan, &compressed, joint.len(), Some(runtime.len()))
    } else {
        format!(
            r#"    constructor() {{
        // Exact compiler-produced runtime plus the complete fixed circuit data.
        // Keep the allocation above the executable suffix while expanding data.
        bytes memory joint = _unlzma(hex"{}", {});
        uint256 executable;
        assembly ("memory-safe") {{
            executable := add(add(joint, 32), ENCODED_PROGRAM_LENGTH)
            mstore(joint, ENCODED_PROGRAM_LENGTH)
        }}
        bytes memory data = _expandProgram(joint, VERIFICATION_PROGRAM_LENGTH);
        assembly ("memory-safe") {{
            let length := mload(data)
            sstore(verificationProgram.slot, add(mul(length, 2), 1))
            mstore(0, verificationProgram.slot)
            let slot := keccak256(0, 32)
            for {{ let i := 0 }} lt(i, length) {{ i := add(i, 32) }} {{
                sstore(add(slot, shr(5, i)), mload(add(add(data, 32), i)))
            }}
            return(executable, {})
        }}
    }}"#,
            super::hex(&compressed),
            joint.len(),
            runtime.len()
        )
    };
    let mut emitted = source.to_owned();
    emitted.replace_range(range, &constructor);
    let pragma = "pragma solidity ^0.8.35;";
    emitted = emitted.replacen(pragma, &format!("pragma solidity 0.8.35;\n\n// Required compiler settings: {SETTINGS}.\n// The constructor returns the runtime compiled from this complete implementation."), 1);
    let (creation, actual) = compile(&emitted, compiler)?;
    // Removing content-hash metadata permits a stable runtime despite the
    // constructor literal. Reject any mismatch; never emit a guessed runtime.
    ensure!(
        actual == runtime,
        "compressed constructor runtime differs from its Solidity implementation"
    );
    Ok(CompressedDeployment {
        source: emitted,
        runtime,
        compressed_bytes: compressed.len(),
        creation_bytes: creation.len(),
        payload: compressed,
    })
}
