//! Compact creation code for the complete Solidity verifier.
//!
//! Solidity emits a long bytes literal as individual MSTORE instructions.
//! Replace only those checked stores with a Yul data section and DATACOPY.
//! The installed program and compiler-produced verification runtime are unchanged.

use super::deployment::{check_size, decode_hex, standard_json};
use anyhow::{Context, Result, ensure};
use num_bigint::BigUint;
use serde::Serialize;
use serde_json::{Value, json};
use std::{ops::Range, path::Path};

/// A single-deployment verifier, generated from a verification key alone.
/// Deploy `bytecode` with `abi` and no constructor arguments. The Solidity
/// source binds the runtime; its ordinary creation code can exceed EVM limits.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifierDeployment {
    pub contract_name: &'static str,
    pub abi: Value,
    pub bytecode: String,
    pub deployed_bytecode: String,
    pub solidity_source: String,
    pub yul_source: String,
    pub compiler_settings: Value,
    pub initcode_bytes: usize,
    pub runtime_bytes: usize,
    pub solidity_initcode_bytes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub construction: Option<super::construction::ConstructionInfo>,
}

pub(super) struct Compiled {
    pub artifact: VerifierDeployment,
    pub runtime: Vec<u8>,
    pub compressed_bytes: usize,
}

pub(super) fn compile(source: &str, compiler: &Path) -> Result<Compiled> {
    compile_with_construction(source, compiler, None)
}

pub(super) fn compile_with_construction(
    source: &str,
    compiler: &Path,
    construction: Option<&super::program::ConstructedProgram>,
) -> Result<Compiled> {
    compile_with_compressor(source, compiler, construction, super::codec::compress)
}

pub(super) fn compile_with_compressor(
    source: &str,
    compiler: &Path,
    construction: Option<&super::program::ConstructedProgram>,
    compress: fn(&[u8]) -> Vec<u8>,
) -> Result<Compiled> {
    let prepared = super::deployment::prepare_runtime_with_compressor(
        source,
        compiler,
        construction,
        compress,
    )?;
    let settings = json!({
        "optimizer": {"enabled": true, "runs": 200}, "viaIR": true,
        "evmVersion": "osaka", "metadata": {"bytecodeHash": "none"}
    });
    let mut requested = settings.clone();
    requested["outputSelection"] = json!({"*": {"BiniusVerifier": [
        "abi", "irOptimized", "evm.bytecode.object",
        "evm.deployedBytecode.object", "evm.deployedBytecode.sourceMap"
    ]}});
    let result = standard_json(
        &json!({
            "language": "Solidity", "sources": {"BiniusVerifier.sol": {"content": prepared.source}},
            "settings": requested
        }),
        compiler,
    )?;
    let contract = &result["contracts"]["BiniusVerifier.sol"]["BiniusVerifier"];
    let runtime = decode_hex(
        contract["evm"]["deployedBytecode"]["object"]
            .as_str()
            .context("missing runtime")?,
    )?;
    ensure!(
        runtime == prepared.runtime,
        "IR compilation changed the verifier runtime"
    );
    check_runtime(
        &runtime,
        &contract["evm"]["deployedBytecode"]["sourceMap"],
        &contract["abi"],
    )?;
    let ir = contract["irOptimized"]
        .as_str()
        .context("missing optimized constructor IR")?;
    // Exporting the AST requires solc's experimental switch, which also changes
    // runtime CBOR metadata. Use that compilation only for the constructor AST.
    // Its entire printed constructor must match the ordinary IR byte for byte;
    // its runtime and creation bytecode are never used in the artifact.
    let mut ast_settings = settings.clone();
    ast_settings["experimental"] = json!(true);
    ast_settings["outputSelection"] =
        json!({"*": {"BiniusVerifier": ["irOptimized", "irOptimizedAst"]}});
    let ast_result = standard_json(
        &json!({"language": "Solidity", "sources": {"BiniusVerifier.sol": {"content": prepared.source}},
            "settings": ast_settings}),
        compiler,
    )?;
    let ast_contract = &ast_result["contracts"]["BiniusVerifier.sol"]["BiniusVerifier"];
    let ast = checked_constructor_ast(ir, ast_contract)?;
    let yul = relocate_literal(ir, ast, &prepared.payload)?;
    let result = standard_json(
        &json!({
            "language": "Yul", "sources": {"BiniusVerifier.yul": {"content": yul}},
            "settings": {"optimizer": {"enabled": true, "runs": 200}, "evmVersion": "osaka",
                "outputSelection": {"*": {"*": ["evm.bytecode.object"]}}}
        }),
        compiler,
    )?;
    let contracts = result["contracts"]["BiniusVerifier.yul"]
        .as_object()
        .context("missing compiled Yul object")?;
    ensure!(
        contracts.len() == 1,
        "expected exactly one Yul creation object"
    );
    let creation = decode_hex(
        contracts.values().next().unwrap()["evm"]["bytecode"]["object"]
            .as_str()
            .context("missing Yul creation code")?,
    )?;
    ensure!(!creation.is_empty(), "empty Yul creation code");
    check_size("Yul initcode", creation.len(), 49_152)?;
    let artifact = VerifierDeployment {
        contract_name: "BiniusVerifier",
        abi: contract["abi"].clone(),
        bytecode: format!("0x{}", super::hex(&creation)),
        deployed_bytecode: format!("0x{}", super::hex(&runtime)),
        solidity_source: prepared.source,
        yul_source: yul,
        compiler_settings: json!({"version": "0.8.35", "solidity": settings,
            "yul": {"optimizer": {"enabled": true, "runs": 200}, "evmVersion": "osaka"}}),
        initcode_bytes: creation.len(),
        runtime_bytes: runtime.len(),
        solidity_initcode_bytes: prepared.creation_bytes,
        construction: construction.map(super::construction::metadata),
    };
    Ok(Compiled {
        artifact,
        runtime,
        compressed_bytes: prepared.compressed_bytes,
    })
}

fn check_runtime(code: &[u8], source_map: &Value, abi: &Value) -> Result<()> {
    let abi = abi.as_array().context("missing Solidity ABI")?;
    let constructors: Vec<_> = abi.iter().filter(|x| x["type"] == "constructor").collect();
    ensure!(
        constructors.len() == 1 && constructors[0]["inputs"] == json!([]),
        "constructor requires arguments"
    );
    let functions: Vec<_> = abi.iter().filter(|x| x["type"] == "function").collect();
    ensure!(
        functions.len() == 1,
        "verifier must expose exactly one function"
    );
    let verify = functions[0];
    ensure!(
        verify["name"] == "verify" && verify["stateMutability"] == "view",
        "expected IVerifier.verify view"
    );
    let inputs = verify["inputs"]
        .as_array()
        .context("missing verify inputs")?;
    let outputs = verify["outputs"]
        .as_array()
        .context("missing verify output")?;
    ensure!(
        inputs.len() == 2
            && inputs[0]["type"] == "bytes"
            && inputs[1]["type"] == "bytes32[]"
            && outputs.len() == 1
            && outputs[0]["type"] == "bool",
        "unexpected IVerifier signature"
    );
    check_size("runtime", code.len(), 24_576)?;
    ensure!(code.len() >= 2, "empty verifier runtime");
    let suffix = usize::from(u16::from_be_bytes(
        code[code.len() - 2..].try_into().unwrap(),
    )) + 2;
    let metadata = code
        .len()
        .checked_sub(suffix)
        .context("invalid runtime metadata size")?;
    let source_map = source_map
        .as_str()
        .filter(|s| !s.is_empty())
        .context("missing executable source map")?;
    let mut offset = 0;
    for _ in source_map.split(';') {
        ensure!(
            offset < metadata,
            "runtime source map exceeds executable code"
        );
        let op = code[offset];
        ensure!(
            !matches!(
                op,
                0x55 | 0x5d | 0xf0 | 0xf1 | 0xf2 | 0xf4 | 0xf5 | 0xfa | 0xff
            ),
            "verifier runtime has a call, creation, or state-writing opcode at {offset}"
        );
        offset += 1 + if (0x60..=0x7f).contains(&op) {
            usize::from(op - 0x5f)
        } else {
            0
        };
    }
    ensure!(offset <= metadata, "instruction overlaps runtime metadata");
    if offset < metadata {
        ensure!(
            code[offset] == 0xfe && !code[offset..metadata].contains(&0x5b),
            "unmapped runtime data can be entered as code"
        );
    }
    Ok(())
}

fn call<'a>(node: &'a Value, name: &str, arity: usize) -> Option<&'a [Value]> {
    if node["nodeType"] != "YulFunctionCall" || node["functionName"]["name"] != name {
        return None;
    }
    node["arguments"]
        .as_array()
        .filter(|a| a.len() == arity)
        .map(Vec::as_slice)
}

// Evaluate only pure, bounded integer expressions that solc uses to encode
// PUSH constants. Every result is subsequently compared with the exact literal.
fn constant(node: &Value, depth: usize) -> Option<BigUint> {
    if depth > 16 {
        return None;
    }
    let modulus = BigUint::from(1u8) << 256usize;
    let mask = &modulus - 1u8;
    if node["nodeType"] == "YulLiteral" && node["kind"] == "string" {
        // Solc may print a short, printable payload tail as a Yul string.
        // Its bytes occupy the high end of the word, padded with zeros. Use
        // the AST's exact bytes, never JSON/Unicode string escape semantics.
        let encoded = node["hexValue"].as_str()?;
        if encoded.len() > 64
            || encoded.len() % 2 != 0
            || !encoded.as_bytes().iter().all(u8::is_ascii_hexdigit)
        {
            return None;
        }
        let mut bytes = decode_hex(encoded).ok()?;
        bytes.resize(32, 0);
        return Some(BigUint::from_bytes_be(&bytes));
    }
    if node["nodeType"] == "YulLiteral" && node["kind"] == "number" {
        let text = node["value"].as_str()?;
        let (digits, radix) = text.strip_prefix("0x").map_or((text, 10), |s| (s, 16));
        let value = BigUint::parse_bytes(digits.as_bytes(), radix)?;
        return (value.bits() <= 256).then_some(value);
    }
    if let Some(args) = call(node, "not", 1) {
        return Some(mask ^ constant(&args[0], depth + 1)?);
    }
    let name = node["functionName"]["name"].as_str()?;
    let args = call(node, name, 2)?;
    let a = constant(&args[0], depth + 1)?;
    let b = constant(&args[1], depth + 1)?;
    Some(match name {
        "and" => a & b,
        "or" => a | b,
        "xor" => a ^ b,
        "add" => (a + b) & mask,
        "sub" => (a + modulus - b) & mask,
        "mul" => (a * b) & mask,
        "shl" | "shr" => {
            if a >= BigUint::from(256u32) {
                BigUint::from(0u8)
            } else {
                let shift = usize::try_from(a).ok()?;
                if name == "shl" {
                    (b << shift) & mask
                } else {
                    b >> shift
                }
            }
        }
        _ => return None,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Address {
    base: Option<String>,
    offset: usize,
}

fn address(node: &Value, alias: Option<(&str, &Value)>) -> Option<Address> {
    if node["nodeType"] == "YulIdentifier" {
        let name = node["name"].as_str()?;
        if let Some((alias_name, expression)) = alias.filter(|(a, _)| *a == name) {
            // The declaration immediately before the first store is the only
            // alias allowed; no assignment can intervene in the store sequence.
            if expression["name"].as_str() == Some(alias_name) {
                return None;
            }
            return address(expression, None);
        }
        return Some(Address {
            base: Some(name.into()),
            offset: 0,
        });
    }
    if let Some(value) = constant(node, 0) {
        return Some(Address {
            base: None,
            offset: usize::try_from(value).ok()?,
        });
    }
    let args = call(node, "add", 2)?;
    for (base, offset) in [(&args[0], &args[1]), (&args[1], &args[0])] {
        if let Some(offset) = constant(offset, 0).and_then(|n| usize::try_from(n).ok())
            && let Some(mut base) = address(base, alias)
        {
            base.offset = base.offset.checked_add(offset)?;
            return Some(base);
        }
    }
    None
}

fn native_range(node: &Value, ir: &str) -> Result<Range<usize>> {
    let parts: Vec<_> = node["nativeSrc"]
        .as_str()
        .context("missing native Yul source span")?
        .split(':')
        .collect();
    ensure!(
        parts.len() == 3 && parts[2] == "0",
        "unexpected Yul source file"
    );
    let start: usize = parts[0].parse().context("invalid Yul source start")?;
    let length: usize = parts[1].parse().context("invalid Yul source length")?;
    let end = start
        .checked_add(length)
        .context("Yul source span overflow")?;
    ensure!(
        ir.get(start..end).is_some(),
        "Yul AST and printed IR disagree on source bounds"
    );
    Ok(start..end)
}

fn checked_constructor_ast<'a>(ir: &str, exported: &'a Value) -> Result<&'a Value> {
    let printed = exported["irOptimized"]
        .as_str()
        .context("missing AST's printed IR")?;
    let ast = &exported["irOptimizedAst"];
    let range = native_range(&ast["code"]["block"], printed)?;
    ensure!(
        ir.get(..range.end) == printed.get(..range.end),
        "experimental AST constructor differs from ordinary compiler IR"
    );
    Ok(ast)
}

fn store(statement: &Value) -> Option<&[Value]> {
    if statement["nodeType"] != "YulExpressionStatement" {
        return None;
    }
    call(&statement["expression"], "mstore", 2)
}

struct Replacement {
    range: Range<usize>,
    pointer: String,
}

fn find_stores(
    node: &Value,
    ir: &str,
    padded: &[u8],
    found: &mut Vec<Replacement>,
    depth: usize,
) -> Result<()> {
    ensure!(depth <= 256, "Yul constructor AST is too deeply nested");
    if node["nodeType"] == "YulBlock" {
        let statements = node["statements"]
            .as_array()
            .context("missing Yul statements")?;
        let count = padded.len() / 32;
        for start in 0..statements.len() {
            let Some(first) = store(&statements[start]) else {
                continue;
            };
            let alias = start.checked_sub(1).and_then(|i| {
                let previous = &statements[i];
                if previous["nodeType"] != "YulVariableDeclaration" {
                    return None;
                }
                let variables = previous["variables"].as_array()?;
                if variables.len() != 1 {
                    return None;
                }
                Some((variables[0]["name"].as_str()?, &previous["value"]))
            });
            let Some(first_address) = address(&first[0], alias) else {
                continue;
            };
            let Some(sequence) = statements.get(start..start + count) else {
                continue;
            };
            let equal = sequence
                .iter()
                .zip(padded.chunks_exact(32))
                .enumerate()
                .all(|(i, (statement, word))| {
                    let Some(args) = store(statement) else {
                        return false;
                    };
                    let Some(actual) = address(&args[0], alias) else {
                        return false;
                    };
                    actual.base == first_address.base
                        && first_address.offset.checked_add(32 * i) == Some(actual.offset)
                        && constant(&args[1], 0) == Some(BigUint::from_bytes_be(word))
                });
            if !equal {
                continue;
            }
            let first_range = native_range(&sequence[0], ir)?;
            let last_range = native_range(sequence.last().unwrap(), ir)?;
            // These are contiguous AST statements; text spans include only
            // those statements and compiler comments, never an intervening call.
            ensure!(
                first_range.start <= last_range.start,
                "reversed Yul source spans"
            );
            let pointer = ir[native_range(&first[0], ir)?].to_owned();
            found.push(Replacement {
                range: first_range.start..last_range.end,
                pointer,
            });
        }
    }
    match node {
        Value::Object(map) => {
            for value in map.values() {
                if value.is_object() || value.is_array() {
                    find_stores(value, ir, padded, found, depth + 1)?;
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                if value.is_object() || value.is_array() {
                    find_stores(value, ir, padded, found, depth + 1)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn relocate_literal(ir: &str, ast: &Value, payload: &[u8]) -> Result<String> {
    ensure!(
        !payload.is_empty() && payload.len() <= 49_152,
        "invalid constructor payload length"
    );
    ensure!(ast["nodeType"] == "YulObject", "missing Yul object AST");
    let mut padded = payload.to_vec();
    padded.resize(payload.len().div_ceil(32) * 32, 0);
    let mut matches = vec![];
    // Search only creation code, never any nested executable/runtime object.
    find_stores(&ast["code"]["block"], ir, &padded, &mut matches, 0)?;
    ensure!(
        matches.len() == 1,
        "expected one exact constructor literal store sequence, found {}",
        matches.len()
    );
    let replacement = matches.pop().unwrap();
    let name = "binius_constructor_payload";
    ensure!(
        !ir.contains(name),
        "Yul constructor data name is already used"
    );
    let closing = ir.trim_end().len().checked_sub(1).context("empty Yul IR")?;
    ensure!(
        ir.as_bytes()[closing] == b'}' && replacement.range.end < closing,
        "missing Yul object terminator"
    );
    let mut yul = ir.to_owned();
    yul.insert_str(
        closing,
        &format!("    data \"{name}\" hex\"{}\"\n", super::hex(&padded)),
    );
    yul.replace_range(
        replacement.range,
        &format!(
            "datacopy({}, dataoffset(\"{name}\"), datasize(\"{name}\"))",
            replacement.pointer
        ),
    );
    Ok(yul)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn number(value: &str) -> Value {
        json!({"nodeType":"YulLiteral","kind":"number","value":value})
    }
    fn expression(name: &str, arguments: Vec<Value>) -> Value {
        json!({"nodeType":"YulFunctionCall","functionName":{"name":name},"arguments":arguments})
    }
    #[test]
    fn constant_evaluation_preserves_evm_wrap_and_shift_boundaries() {
        let zero = BigUint::from(0u8);
        let mask = (BigUint::from(1u8) << 256usize) - 1u8;
        let all = expression("not", vec![number("0")]);
        assert_eq!(constant(&all, 0), Some(mask.clone()));
        assert_eq!(
            constant(&expression("add", vec![all.clone(), number("1")]), 0),
            Some(zero.clone())
        );
        assert_eq!(
            constant(&expression("sub", vec![number("0"), number("1")]), 0),
            Some(mask.clone())
        );
        assert_eq!(
            constant(&expression("mul", vec![all.clone(), number("5")]), 0),
            Some(mask - 4u8)
        );
        for shift in [0usize, 127, 255, 256, 257] {
            let actual = constant(
                &expression("shl", vec![number(&shift.to_string()), number("1")]),
                0,
            );
            assert_eq!(
                actual,
                Some(if shift >= 256 {
                    zero.clone()
                } else {
                    BigUint::from(1u8) << shift
                })
            );
        }
        assert!(constant(&expression("mload", vec![number("0")]), 0).is_none());
        assert!(constant(&number(&format!("0x1{}", "00".repeat(32))), 0).is_none());
    }

    #[test]
    fn string_constants_preserve_bytes_and_word_alignment() {
        let string =
            |value: &str| json!({"nodeType":"YulLiteral","kind":"string","hexValue":value});
        for bytes in [
            vec![],
            vec![0x4f],
            vec![0, 0xff, 0x22, 0x5c],
            vec![0xff; 32],
        ] {
            let mut word = bytes.clone();
            word.resize(32, 0);
            assert_eq!(
                constant(&string(&super::super::hex(&bytes)), 0),
                Some(BigUint::from_bytes_be(&word))
            );
        }
        for invalid in ["f", "gg", "0x4f", &"ab".repeat(33)] {
            assert!(constant(&string(invalid), 0).is_none());
        }
        assert!(
            constant(
                &json!({"nodeType":"YulLiteral","kind":"string","value":"O"}),
                0
            )
            .is_none()
        );
    }

    #[test]
    #[ignore = "requires solc 0.8.35; run with BINIUS_SOLC set to its path"]
    fn relocates_actual_compiler_literal_ast_and_rejects_changed_bytes() {
        let compiler = std::env::var_os("BINIUS_SOLC").expect("set BINIUS_SOLC");
        let compiler = Path::new(&compiler);
        // Include dense words, leading zeros and a partial padded tail. The
        // constructor returns this payload, so the stores cannot be optimized out.
        let payload: Vec<_> = (0..1053).map(|i| (i * 149 + i / 7) as u8).collect();
        check_literal_relocation(compiler, payload);
        // A printable one-byte tail is emitted as mstore(..., "O"). It must
        // pass the same address, exact-word, padding and AST/IR checks.
        let mut printable: Vec<_> = (0..1024).map(|i| (i * 149 + i / 7) as u8).collect();
        printable.push(b'O');
        check_literal_relocation(compiler, printable);
    }

    fn check_literal_relocation(compiler: &Path, payload: Vec<u8>) {
        let source = format!(
            "pragma solidity ^0.8.35; contract C {{ constructor() {{ bytes memory b=hex\"{}\"; assembly(\"memory-safe\") {{ return(add(b,32),mload(b)) }} }} }}",
            super::super::hex(&payload)
        );
        let result=standard_json(&json!({"language":"Solidity","sources":{"C.sol":{"content":source}},
            "settings":{"experimental":true,"optimizer":{"enabled":true,"runs":200},"viaIR":true,"evmVersion":"osaka",
                "outputSelection":{"*":{"C":["irOptimized","irOptimizedAst"]}}}}),compiler).unwrap();
        let contract = &result["contracts"]["C.sol"]["C"];
        let ordinary = standard_json(
            &json!({"language":"Solidity","sources":{"C.sol":{"content":source}},
            "settings":{"optimizer":{"enabled":true,"runs":200},"viaIR":true,"evmVersion":"osaka",
                "outputSelection":{"*":{"C":["irOptimized"]}}}}),
            compiler,
        )
        .unwrap();
        let ir = ordinary["contracts"]["C.sol"]["C"]["irOptimized"]
            .as_str()
            .unwrap();
        let ast = checked_constructor_ast(ir, contract).unwrap();
        assert!(checked_constructor_ast(&ir.replacen("mstore(", "mstore8(", 1), contract).is_err());
        let yul = relocate_literal(ir, ast, &payload).unwrap();
        assert!(yul.contains("datacopy("));
        let result = standard_json(
            &json!({"language":"Yul","sources":{"C.yul":{"content":yul}},
            "settings":{"optimizer":{"enabled":true,"runs":200},"evmVersion":"osaka",
                "outputSelection":{"*":{"*":["evm.bytecode.object"]}}}}),
            compiler,
        )
        .unwrap();
        assert!(
            result["contracts"]["C.yul"]
                .as_object()
                .is_some_and(|c| c.len() == 1)
        );
        let mut wrong = payload;
        wrong[32] ^= 1;
        assert!(relocate_literal(ir, ast, &wrong).is_err());
        wrong[32] ^= 1;
        *wrong.last_mut().unwrap() ^= 1;
        assert!(relocate_literal(ir, ast, &wrong).is_err());
    }
}
