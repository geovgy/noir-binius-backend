//! Explicit stack scheduling of the existing seven-lane SHA-256 operations.
//!
//! This optional final stage recognizes an exact optimized Yul equation span.
//! It changes evaluation order/stack placement and shares the packed core
//! with scalar calls. Scalar ingress has canonical 32-bit words; feed-forward
//! preserves canonical lanes, and scalar digest extraction uses only lane 0.
//! The hash, its 64 rounds, proof format, field equations, and security
//! parameters remain unchanged. See scripts/sha_stack_check.py.

use super::{construction, deployment, program::ConstructedProgram, yul_deployment};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{io::Read, ops::Range, path::Path};

const REFERENCE: &str = include_str!("sha_stack/rounds.yul");
const BLOCK_HEX: &str = include_str!("sha_stack/round-block.hex");
const BLOCK_HASH: &str = "25aaa3f04cee1446d5901296eecd247b0dbd9d6d2fca036533802f7485d09fbd";
const PLACEMENT_HEX: &str = include_str!("sha_stack/round-placement-block.hex");
const PLACEMENT_HASH: &str = "fcb13ca730f9b4f8a65662a14d75ee0731a31d7251addfe3931873f2c67e3717";
const CURSOR_HEX: &str = include_str!("sha_stack/round-cursor-block.hex");
const CURSOR_HASH: &str = "b95b04dd62c7769294246ea85f6ae6e5fce78e954ec8e0c0b87b7b88d1bde25f";
const FOUR_HEX: &str = include_str!("sha_stack/round-four-block.hex");
const FOUR_HASH: &str = "89d86e1aa7d12b47bc53ddd4391018dc61f0b5560e6a5e10aa4ebdc2869f846a";
const GROUP_HEX: &str = include_str!("sha_stack/round-group-block.hex");
const GROUP_HASH: &str = "c6b97f9bf6025e0ed5cdb7ecbf46f5b2099dba4f09d28c601edcef6a5d38e741";
const SIGMA_HEX: &str = include_str!("sha_stack/round-sigma-block.hex");
const SIGMA_HASH: &str = "8747454f3932cbbc93ac3ddaa05fc4d4ffcb30142ef0f88b8d51c1e4bf1ac55b";
const RETAINED_HEX: &str = include_str!("sha_stack/round-retained-block.hex");
const RETAINED_HASH: &str = "c42783843e8233d2402c8f174feea2ffd8ae2ade1f503a60aa888ee2bc67c4ad";
const RETAINED_MASKS: &str = include_str!("sha_stack/round-retained-masks.json");
const SCALAR_REFERENCE: &str = include_str!("sha_stack/scalar-rounds.yul");
const SCALAR_PACKED: &str = include_str!("sha_stack/scalar-packed.yul");
const PACKED_REFERENCE: &str = include_str!("sha_stack/packed-rounds.yul");
const WORD_REFERENCE: &str = include_str!("sha_stack/words.yul");
const WORD_BLOCK_HEX: &str = include_str!("sha_stack/word-block.hex");
const WORD_BLOCK_HASH: &str = "4c6cc06c6965224f123533b5ad7b855828b107042ebde9993c31516bd1e11bda";
const WORD_ORDER_HEX: &str = include_str!("sha_stack/word-order-block.hex");
const WORD_ORDER_HASH: &str = "4e56b829a8c054a5388a18673f804cfc74f71ce617feb5b788fcb78747b02776";
const WORD_LOOP_REFERENCE: &str = include_str!("sha_stack/word-loop.yul");
const WORD_LOOP_HEX: &str = include_str!("sha_stack/word-loop-block.hex");
const WORD_LOOP_HASH: &str = "6234a2eab2cd341248e9c642e3d588a1f1cfcbfefe8b4af95802a28c0db80a30";
const WORD_DOUBLE_HEX: &str = include_str!("sha_stack/word-double-block.hex");
const WORD_DOUBLE_HASH: &str = "4dd2efd40dc163b484fc7b6526cdba1f1d82bece8845961aa0067939bf0930e9";
const WORD_GROUP_HEX: &str = include_str!("sha_stack/word-group-block.hex");
const WORD_GROUP_HASH: &str = "12fbd5916a21d830f2707a3ab5a7849c4d1f90f1c1b3e417cf7c06dcd05cbb52";
const WORD_GROUP_MASKS: &str = include_str!("sha_stack/word-group-masks.json");

const WORD_PAIR_HEX: &str = include_str!("sha_stack/word-pair-block.hex");
const WORD_PAIR_HASH: &str = "997d259dd8aece2235a17177f6422949b27ec974286b968ba83aa0a25ea96071";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Variant {
    Rounds,
    Words,
    Placement,
    Cursor,
    WordOrder,
    Four,
    GroupCursor,
    WordLoop,
    DoubleWords,
    GroupWords,
    PairWords,
}

impl Variant {
    fn round_hex(self) -> &'static str {
        match self {
            Self::PairWords => RETAINED_HEX,
            Self::DoubleWords | Self::GroupWords => SIGMA_HEX,
            Self::GroupCursor | Self::WordLoop => GROUP_HEX,
            Self::Four => FOUR_HEX,
            Self::Cursor | Self::WordOrder => CURSOR_HEX,
            Self::Placement => PLACEMENT_HEX,
            Self::Rounds | Self::Words => BLOCK_HEX,
        }
    }

    fn round_hash(self) -> &'static str {
        match self {
            Self::PairWords => RETAINED_HASH,
            Self::DoubleWords | Self::GroupWords => SIGMA_HASH,
            Self::GroupCursor | Self::WordLoop => GROUP_HASH,
            Self::Four => FOUR_HASH,
            Self::Cursor | Self::WordOrder => CURSOR_HASH,
            Self::Placement => PLACEMENT_HASH,
            Self::Rounds | Self::Words => BLOCK_HASH,
        }
    }

    fn with_words(self) -> bool {
        self != Self::Rounds
    }

    fn shared_scalar(self) -> bool {
        matches!(
            self,
            Self::Four
                | Self::GroupCursor
                | Self::WordLoop
                | Self::DoubleWords
                | Self::GroupWords
                | Self::PairWords
        )
    }

    fn word_hex(self) -> &'static str {
        if self == Self::PairWords {
            WORD_PAIR_HEX
        } else if self == Self::GroupWords {
            WORD_GROUP_HEX
        } else if self == Self::DoubleWords {
            WORD_DOUBLE_HEX
        } else if self == Self::WordLoop {
            WORD_LOOP_HEX
        } else if matches!(self, Self::WordOrder | Self::Four | Self::GroupCursor) {
            WORD_ORDER_HEX
        } else {
            WORD_BLOCK_HEX
        }
    }

    fn word_hash(self) -> &'static str {
        if self == Self::PairWords {
            WORD_PAIR_HASH
        } else if self == Self::GroupWords {
            WORD_GROUP_HASH
        } else if self == Self::DoubleWords {
            WORD_DOUBLE_HASH
        } else if self == Self::WordLoop {
            WORD_LOOP_HASH
        } else if matches!(self, Self::WordOrder | Self::Four | Self::GroupCursor) {
            WORD_ORDER_HASH
        } else {
            WORD_BLOCK_HASH
        }
    }

    fn kind(self) -> &'static str {
        match self {
            Self::Rounds => "yul-sha-rounds-v1",
            Self::Words => "yul-sha-rounds-v2",
            Self::Placement => "yul-sha-rounds-v3",
            Self::Cursor => "yul-sha-rounds-v4",
            Self::WordOrder => "yul-sha-rounds-v5",
            Self::Four => "yul-sha-rounds-v6",
            Self::GroupCursor => "yul-sha-rounds-v7",
            Self::WordLoop => "yul-sha-rounds-v8",
            Self::DoubleWords => "yul-sha-rounds-v9",
            Self::GroupWords => "yul-sha-rounds-v10",
            Self::PairWords => "yul-sha-rounds-v11",
        }
    }
}

/// Explicit provenance for artifacts whose emitted Yul compiles both creation
/// and runtime. The complete Solidity body remains the semantic reference.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeCompilation {
    pub kind: &'static str,
    pub runtime_source: &'static str,
    pub solidity_reference_runtime_sha256: String,
    pub round_block_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub word_block_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scalar_core: Option<&'static str>,
}

pub(super) fn finish(
    plan: &ConstructedProgram,
    baseline: yul_deployment::VerifierDeployment,
    compiler: &Path,
) -> Result<yul_deployment::VerifierDeployment> {
    // Retain each earlier complete variant if the preferred exact source shape
    // or its complete deployment cannot satisfy the ordinary size limits.
    for variant in [
        Variant::PairWords,
        Variant::GroupWords,
        Variant::DoubleWords,
        Variant::WordLoop,
        Variant::GroupCursor,
        Variant::Four,
        Variant::WordOrder,
        Variant::Cursor,
        Variant::Placement,
        Variant::Words,
        Variant::Rounds,
    ] {
        let Some(yul) = replace_kernels(&baseline.yul_source, variant)? else {
            continue;
        };
        match compile(plan, &baseline, &yul, compiler, variant) {
            Ok(Some(candidate)) => return Ok(candidate),
            Ok(None) => {}
            Err(error) if error.downcast_ref::<deployment::SizeLimit>().is_some() => {}
            Err(error) => return Err(error),
        }
    }
    Ok(baseline)
}

fn compile(
    plan: &ConstructedProgram,
    baseline: &yul_deployment::VerifierDeployment,
    yul: &str,
    compiler: &Path,
    variant: Variant,
) -> Result<Option<yul_deployment::VerifierDeployment>> {
    ensure!(
        baseline.runtime_compilation.is_none(),
        "SHA stack stage already applied"
    );
    let block = deployment::decode_hex(variant.round_hex().trim())?;
    let word_block = variant
        .with_words()
        .then(|| deployment::decode_hex(variant.word_hex().trim()))
        .transpose()?;
    let compiled = yul_deployment::compile_yul(yul, compiler)?;
    let runtime = runtime_bytes(&compiled)?;
    yul_deployment::check_runtime_with_blocks(
        &runtime,
        &compiled["deployedBytecode"]["sourceMap"],
        &baseline.abi,
        Some(&block),
        word_block.as_deref(),
    )?;
    if !construction::fixed_sha_entry_fits(&runtime) {
        return Ok(None);
    }
    let reference = deployment::decode_hex(&baseline.deployed_bytecode)?;
    let mut joint = checked_prefix(plan, &baseline.solidity_source, &reference)?;
    joint.extend_from_slice(&runtime);
    let build = |compress: fn(&[u8]) -> Vec<u8>| {
        let payload = compress(&joint);
        let mut source = baseline.solidity_source.clone();
        source.replace_range(
            deployment::constructor_range(&source)?,
            &construction::constructor(plan, &payload, joint.len(), Some(runtime.len())),
        );
        source = source.replace(
            "// The constructor returns the runtime compiled from this complete implementation.",
            "// The constructor returns the runtime compiled from the companion BiniusVerifier.yul.\n\
             // The complete Solidity body is its semantic reference; see runtimeCompilation in the artifact.",
        );
        // Generate every constructor bound from the typed plan and new payload.
        // Do not replace numeric literals in already-optimized constructor IR.
        let lowered = yul_deployment::lower_solidity_creation(&source, &payload, compiler)?;
        let actual_reference = deployment::decode_hex(
            lowered.contract["evm"]["deployedBytecode"]["object"]
                .as_str()
                .context("missing reference runtime")?,
        )?;
        ensure!(
            actual_reference == reference,
            "SHA stack constructor changed the Solidity reference runtime"
        );
        ensure!(
            lowered.contract["abi"] == baseline.abi,
            "SHA stack stage changed the ABI"
        );
        let yul = replace_kernels(&lowered.yul, variant)?
            .context("new constructor changed the eligible SHA equations")?;
        let compiled = yul_deployment::compile_yul(&yul, compiler)?;
        ensure!(
            runtime_bytes(&compiled)? == runtime,
            "SHA stack constructor changed the Yul runtime"
        );
        yul_deployment::check_runtime_with_blocks(
            &runtime,
            &compiled["deployedBytecode"]["sourceMap"],
            &baseline.abi,
            Some(&block),
            word_block.as_deref(),
        )?;
        let creation = deployment::decode_hex(
            compiled["bytecode"]["object"]
                .as_str()
                .context("missing creation code")?,
        )?;
        ensure!(!creation.is_empty(), "empty Yul creation code");
        deployment::check_size("Yul initcode", creation.len(), 49_152)?;
        let ordinary_creation = deployment::decode_hex(
            lowered.contract["evm"]["bytecode"]["object"]
                .as_str()
                .context("missing ordinary Solidity creation code")?,
        )?;
        Ok(yul_deployment::VerifierDeployment {
            contract_name: "BiniusVerifier",
            abi: baseline.abi.clone(),
            bytecode: format!("0x{}", super::hex(&creation)),
            deployed_bytecode: format!("0x{}", super::hex(&runtime)),
            solidity_source: source,
            yul_source: yul,
            compiler_settings: baseline.compiler_settings.clone(),
            initcode_bytes: creation.len(),
            runtime_bytes: runtime.len(),
            solidity_initcode_bytes: ordinary_creation.len(),
            runtime_compilation: Some(RuntimeCompilation {
                kind: variant.kind(),
                runtime_source: "BiniusVerifier.yul",
                solidity_reference_runtime_sha256: format!(
                    "0x{}",
                    super::hex(&Sha256::digest(&reference))
                ),
                round_block_sha256: format!("0x{}", variant.round_hash()),
                word_block_sha256: variant
                    .with_words()
                    .then(|| format!("0x{}", variant.word_hash())),
                scalar_core: variant.shared_scalar().then_some("packed"),
            }),
            construction: Some(construction::metadata(plan)),
        })
    };
    let candidate: Result<_> = build(super::codec::compress);
    match candidate {
        Err(error)
            if error
                .downcast_ref::<deployment::SizeLimit>()
                .is_some_and(deployment::SizeLimit::is_initcode) =>
        {
            build(super::codec::compress_size_retry).map(Some)
        }
        other => other.map(Some),
    }
}

fn runtime_bytes(compiled: &Value) -> Result<Vec<u8>> {
    deployment::decode_hex(
        compiled["deployedBytecode"]["object"]
            .as_str()
            .context("missing Yul runtime")?,
    )
}

/// Reconstruct the prefix independently from the typed circuit plan, then bind
/// it and the preceding runtime to every decompressed byte of the old payload.
fn checked_prefix(plan: &ConstructedProgram, source: &str, runtime: &[u8]) -> Result<Vec<u8>> {
    let mut prefix = super::codec::operands(&plan.precursor.bytes, true, plan.precursor.word_bytes);
    if let Some(storage) = &plan.storage {
        prefix.extend_from_slice(&storage.headers);
    }
    let constructor = &source[deployment::constructor_range(source)?];
    ensure!(
        constructor.matches("_unlzma(hex\"").count() == 1,
        "expected one constructor payload"
    );
    let (literal, tail) = constructor
        .split_once("_unlzma(hex\"")
        .unwrap()
        .1
        .split_once('\"')
        .context("unterminated constructor payload")?;
    let length: usize = tail
        .strip_prefix(", ")
        .context("missing constructor payload length")?
        .split_once(')')
        .context("unterminated constructor payload call")?
        .0
        .parse()?;
    ensure!(
        length == prefix.len() + runtime.len(),
        "constructor payload length differs from typed plan"
    );
    let packed = deployment::decode_hex(literal)?;
    let mut reader =
        lzma_rust2::LzmaReader::new_with_props(packed.as_slice(), length as u64, 1, 1 << 20, None)?;
    let mut joint = Vec::new();
    reader.read_to_end(&mut joint)?;
    ensure!(
        joint.len() == length
            && joint[..prefix.len()] == prefix
            && joint[prefix.len()..] == *runtime,
        "constructor payload differs from typed prefix or preceding runtime"
    );
    Ok(prefix)
}

struct Token<'a> {
    text: &'a str,
    range: Range<usize>,
}

/// A small lexer, not a text/whitespace substitution: never match identifiers
/// inside strings or comments, nor join tokens across a comment boundary.
fn tokens(source: &str) -> Result<Vec<Token<'_>>> {
    let s = source.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() {
        if s[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if s[i..].starts_with(b"//") {
            i += s[i..]
                .iter()
                .position(|b| *b == b'\n')
                .unwrap_or(s.len() - i);
            continue;
        }
        if s[i..].starts_with(b"/*") {
            i += 2;
            i += s[i..]
                .windows(2)
                .position(|w| w == b"*/")
                .context("unterminated Yul comment")?
                + 2;
            continue;
        }
        let start = i;
        if s[i] == b'"' {
            i += 1;
            while i < s.len() && s[i] != b'"' {
                if s[i] == b'\\' {
                    i += 1;
                }
                i += 1;
            }
            ensure!(i < s.len(), "unterminated Yul string");
            i += 1;
        } else if s[i].is_ascii_alphanumeric() || matches!(s[i], b'_' | b'$') {
            i += 1;
            while i < s.len()
                && (s[i].is_ascii_alphanumeric() || matches!(s[i], b'_' | b'$' | b'.'))
            {
                i += 1;
            }
        } else {
            ensure!(s[i].is_ascii(), "unexpected non-ASCII Yul token");
            i += if s[i..].starts_with(b":=") || s[i..].starts_with(b"->") {
                2
            } else {
                1
            };
        }
        out.push(Token {
            text: &source[start..i],
            range: start..i,
        });
    }
    Ok(out)
}

#[cfg(test)]
fn replace_rounds(source: &str) -> Result<Option<String>> {
    replace_rounds_with_block(source, BLOCK_HEX)
}

fn replace_rounds_with_block(source: &str, block_hex: &str) -> Result<Option<String>> {
    let input = tokens(source)?;
    ensure!(
        !input.iter().any(|t| t.text.starts_with("verbatim_")),
        "unexpected existing verbatim code"
    );
    let block = deployment::decode_hex(block_hex.trim())?;
    validate_block(&block)?;
    replace_span(
        source,
        REFERENCE,
        &format!("verbatim_0i_0o(hex\"{}\")", block_hex.trim()),
    )
}

fn replace_kernels(source: &str, variant: Variant) -> Result<Option<String>> {
    let unified;
    let source = if variant.shared_scalar() {
        let Some(source) = unify_scalar(source)? else {
            return Ok(None);
        };
        unified = source;
        unified.as_str()
    } else {
        source
    };
    let Some(rounds) = replace_rounds_with_block(source, variant.round_hex())? else {
        return Ok(None);
    };
    if !variant.with_words() {
        return Ok(Some(rounds));
    }
    let word_hex = variant.word_hex().trim();
    validate_word_block(&deployment::decode_hex(word_hex)?)?;
    if matches!(
        variant,
        Variant::WordLoop | Variant::DoubleWords | Variant::GroupWords | Variant::PairWords
    ) {
        // unify_scalar has already bound the complete packed callee, including
        // the Boolean cached flag and the surrounding copy/cache/feed-forward.
        return replace_span(
            &rounds,
            WORD_LOOP_REFERENCE,
            &format!("verbatim_1i_0o(hex\"{word_hex}\", usr$cached)"),
        );
    }
    replace_span(
        &rounds,
        WORD_REFERENCE,
        &format!("verbatim_1i_0o(hex\"{word_hex}\", usr$p)"),
    )
}

/// Bind the scalar rewrite to both complete equations and the actual packed
/// callee. Solc's specialization names swap between circuit shapes. A name by
/// itself is never evidence that this is the packed implementation.
fn unify_scalar(source: &str) -> Result<Option<String>> {
    for (scalar, packed) in [
        ("fun_shaRounds", "fun__shaRounds"),
        ("fun__shaRounds", "fun_shaRounds"),
    ] {
        // Pin the entire packed callee, including schedule caching, state
        // copying and feed-forward. Matching only its round loop would not
        // establish the scalar continuation invariant.
        let packed_reference = PACKED_REFERENCE.replacen("fun__shaRounds", packed, 1);
        if replace_span(source, &packed_reference, &packed_reference)?.is_none() {
            continue;
        }
        let reference = SCALAR_REFERENCE.replacen("fun_shaRounds", scalar, 1);
        let replacement = if scalar == "fun_shaRounds" {
            SCALAR_PACKED.trim().to_owned()
        } else {
            format!("function {scalar}(var_m_mpos) {{ mstore(0x2420, 0) {packed}(var_m_mpos) }}")
        };
        if let Some(result) = replace_span(source, &reference, &replacement)? {
            return Ok(Some(result));
        }
    }
    Ok(None)
}

fn replace_span(source: &str, reference: &str, replacement: &str) -> Result<Option<String>> {
    let input = tokens(source)?;
    let reference = tokens(reference)?;
    let objects: Vec<_> = input
        .windows(3)
        .enumerate()
        .filter_map(|(i, w)| {
            (w[0].text == "object" && w[1].text.ends_with("_deployed\"") && w[2].text == "{")
                .then_some(i + 2)
        })
        .collect();
    if objects.len() != 1 {
        return Ok(None);
    }
    let start = objects[0];
    let mut depth = 0usize;
    let mut end = None;
    for (i, token) in input.iter().enumerate().skip(start) {
        if token.text == "{" {
            depth += 1;
        }
        if token.text == "}" {
            depth = depth
                .checked_sub(1)
                .context("unbalanced Yul runtime object")?;
            if depth == 0 {
                end = Some(i);
                break;
            }
        }
    }
    let end = end.context("unterminated Yul runtime object")?;
    let matches: Vec<_> = input[start..end]
        .windows(reference.len())
        .filter(|w| w.iter().zip(&reference).all(|(a, b)| a.text == b.text))
        .map(|w| w[0].range.start..w.last().unwrap().range.end)
        .collect();
    ensure!(matches.len() <= 1, "ambiguous packed SHA equations");
    let Some(range) = matches.into_iter().next() else {
        return Ok(None);
    };
    let mut output = source.to_owned();
    output.replace_range(range, replacement);
    Ok(Some(output))
}

/// Evaluate the constant-only prefix with exact uint256 semantics. No memory,
/// control flow or caller stack is available while deriving the retained masks.
fn validate_mask_prefix(prefix: &[u8], expected: &str) -> Result<()> {
    use num_bigint::BigUint;
    let expected: [String; 6] = serde_json::from_str(expected)?;
    let expected = expected
        .iter()
        .map(|value| {
            BigUint::parse_bytes(value.trim_start_matches("0x").as_bytes(), 16)
                .context("invalid retained SHA mask")
        })
        .collect::<Result<Vec<_>>>()?;
    let mask = (BigUint::from(1u8) << 256usize) - 1u8;
    let mut stack: Vec<BigUint> = Vec::new();
    let mut pc = 0;
    while pc < prefix.len() {
        let op = prefix[pc];
        pc += 1;
        match op {
            0x60..=0x7f => {
                let n = usize::from(op - 0x5f);
                ensure!(pc + n <= prefix.len(), "truncated SHA mask literal");
                stack.push(BigUint::from_bytes_be(&prefix[pc..pc + n]));
                pc += n;
            }
            0x80..=0x8f => {
                let n = usize::from(op - 0x7f);
                ensure!(stack.len() >= n, "SHA mask DUP reads caller stack");
                stack.push(stack[stack.len() - n].clone());
            }
            0x16 | 0x17 | 0x1b | 0x1c => {
                let a = stack.pop().context("SHA mask stack underflow")?;
                let b = stack.pop().context("SHA mask stack underflow")?;
                let value = match op {
                    0x16 => a & b,
                    0x17 => a | b,
                    _ => {
                        let shift = a.to_u32_digits();
                        ensure!(shift.len() <= 1, "invalid SHA mask shift");
                        let shift = shift.first().copied().unwrap_or(0);
                        ensure!(shift < 256, "invalid SHA mask shift");
                        if op == 0x1b {
                            (b << shift as usize) & &mask
                        } else {
                            b >> shift as usize
                        }
                    }
                };
                stack.push(value);
            }
            _ => anyhow::bail!("unexpected SHA mask opcode {op:02x}"),
        }
        ensure!(stack.len() <= 8, "excess SHA mask stack usage");
    }
    ensure!(
        stack == expected,
        "derived SHA masks differ from expected values"
    );
    Ok(())
}

/// Entry consumes the original Boolean cache flag. On a miss, initialize
/// [masks, p, W15, W14]. Every word preserves p and changes [previous, old] to
/// [new, previous], while also storing new at p+offset. The independent symbolic
/// checker proves this recurrence and the complete original word expressions.
fn validate_word_pair(block: &[u8]) -> Result<()> {
    ensure!(
        block[0] == 0x61 && block[3..6] == [0x58, 0x01, 0x57],
        "invalid pair cache branch"
    );
    validate_mask_prefix(&block[6..92], WORD_GROUP_MASKS)?;
    ensure!(
        block[92..104]
            == [
                0x61, 0x1c, 0, 0x61, 0x1b, 0xe0, 0x51, 0x61, 0x1b, 0xc0, 0x51, 0x5b
            ],
        "invalid SHA predecessor initialization"
    );
    for (start, end) in [
        (104, 198),
        (198, 295),
        (295, 392),
        (392, 489),
        (489, 586),
        (586, 683),
        (683, 780),
        (780, 874),
    ] {
        let body = &block[start..end];
        let (mut pc, mut depth, mut high, mut loads, mut stores) = (0, 9usize, 9, 0, 0);
        while pc < body.len() {
            let op = body[pc];
            pc += 1;
            match op {
                0x01 | 0x03 | 0x16 | 0x18 | 0x1b | 0x1c => {
                    ensure!(depth >= 10, "SHA pair consumes retained frame");
                    depth -= 1;
                }
                0x51 => {
                    ensure!(depth > 9 && stores == 0, "invalid SHA pair load");
                    loads += 1;
                }
                0x52 => {
                    ensure!(depth >= 11, "invalid SHA pair store");
                    stores += 1;
                    depth -= 2;
                }
                0x60..=0x7f => {
                    pc += usize::from(op - 0x5f);
                    depth += 1;
                }
                0x80..=0x8f => {
                    ensure!(
                        depth >= usize::from(op - 0x7f),
                        "SHA pair DUP reads caller stack"
                    );
                    depth += 1;
                }
                0x90..=0x9f => {
                    ensure!(
                        depth > 6 + usize::from(op - 0x8f),
                        "SHA pair SWAP changes masks"
                    );
                }
                _ => anyhow::bail!("unexpected SHA pair opcode {op:02x}"),
            }
            ensure!(
                pc <= body.len() && depth >= 9,
                "invalid SHA pair instruction or stack"
            );
            high = high.max(depth);
        }
        ensure!(
            depth == 9 && high == 14 && loads == 3 && stores == 1,
            "invalid SHA pair stack/memory effects"
        );
    }
    // Six groups advance p by256 below the predecessor pair, then discard all
    // nine owned values. The hit jumps to the same empty-stack final boundary.
    ensure!(
        block[874..888]
            == [
                0x91, 0x61, 1, 0, 0x01, 0x91, 0x82, 0x61, 0x22, 0, 0x11, 0x61, 3, 0x11
            ]
            && block[888..]
                == [
                    0x58, 0x03, 0x57, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x5b
                ],
        "invalid SHA pair cursor, branch or cleanup"
    );
    let forward = 3 + usize::from(u16::from_be_bytes([block[1], block[2]]));
    let backward = 888usize.checked_sub(usize::from(u16::from_be_bytes([block[886], block[887]])));
    ensure!(
        forward == 900 && backward == Some(103),
        "SHA pair branch leaves block"
    );
    Ok(())
}

/// The complete group loop consumes the original Boolean cache flag. Its
/// six masks and one base cursor remain below each of four word bodies.
/// Independent symbolic checks prove the actual value/address expressions.
fn validate_word_group(block: &[u8]) -> Result<()> {
    ensure!(
        block[0] == 0x61 && block[3..6] == [0x58, 0x01, 0x57],
        "invalid grouped SHA cache branch"
    );
    let masks: [String; 6] = serde_json::from_str(WORD_GROUP_MASKS)?;
    let masks = masks
        .iter()
        .map(|m| deployment::decode_hex(m.trim_start_matches("0x")))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        masks[0].len() == 32 && masks[1].len() == 32,
        "invalid grouped SHA mask width"
    );
    // AND of bits 13..31 and its two-bit left shift is exactly bits 15..31.
    // Evaluate that identity on the actual 256-bit constants, including the
    // truncated high bits; no big-integer or field assumption is needed.
    for i in 0..32 {
        let shifted = (masks[0][i] << 2) | masks[0].get(i + 1).copied().unwrap_or(0) >> 6;
        ensure!(
            masks[1][i] == masks[0][i] & shifted,
            "invalid derived SHA mask"
        );
    }
    let push = |out: &mut Vec<u8>, value: &[u8]| -> Result<()> {
        ensure!(
            !value.is_empty() && value.len() <= 32,
            "invalid SHA mask literal"
        );
        out.push(0x5f + value.len() as u8);
        out.extend_from_slice(value);
        Ok(())
    };
    let mut prefix = Vec::new();
    push(&mut prefix, &masks[0])?;
    prefix.extend([0x80, 0x80, 0x60, 0x02, 0x1b, 0x16]);
    for mask in &masks[2..] {
        push(&mut prefix, mask)?;
    }
    prefix.extend([0x61, 0x1c, 0x00]);
    ensure!(
        prefix.len() == 173 && block[6..179] == prefix,
        "invalid SHA word mask/cursor prefix"
    );
    ensure!(block[179] == 0x5b, "invalid grouped SHA loop entry");
    for (start, end) in [(180, 277), (277, 377), (377, 474), (474, 574)] {
        let body = &block[start..end];
        let (mut pc, mut depth, mut high, mut loads, mut stores) = (0, 7usize, 7, 0, 0);
        while pc < body.len() {
            let op = body[pc];
            pc += 1;
            match op {
                0x01 | 0x03 | 0x16 | 0x18 | 0x1b | 0x1c => {
                    ensure!(depth >= 9, "SHA group consumes retained stack");
                    depth -= 1;
                }
                0x51 => {
                    ensure!(depth > 7 && stores == 0, "invalid grouped SHA load");
                    loads += 1;
                }
                0x52 => {
                    ensure!(depth >= 9, "invalid grouped SHA store");
                    stores += 1;
                    depth -= 2;
                }
                0x60..=0x7f => {
                    pc += usize::from(op - 0x5f);
                    depth += 1;
                }
                0x80..=0x8f => {
                    ensure!(
                        depth >= usize::from(op - 0x7f),
                        "SHA group DUP accesses underlying stack"
                    );
                    depth += 1;
                }
                0x90..=0x9f => {
                    ensure!(
                        depth > 6 + usize::from(op - 0x8f),
                        "SHA group SWAP changes retained masks"
                    );
                }
                _ => anyhow::bail!("unexpected grouped SHA word opcode {op:02x}"),
            }
            ensure!(
                pc <= body.len() && depth >= 7,
                "invalid grouped SHA word decoding"
            );
            high = high.max(depth);
        }
        ensure!(
            depth == 7 && high == 13 && loads == 4 && stores == 1,
            "invalid SHA word group stack/memory effects"
        );
    }
    // Twelve groups: p starts at 0x1c00, advances by 128, and stops at 0x2200. Four
    // rebased stores per group cover W16..W63 once, in the original order.
    ensure!(
        block[574..585]
            == [
                0x60, 0x80, 0x01, 0x80, 0x61, 0x22, 0x00, 0x11, 0x61, 0x01, 0x96
            ]
            && block[585..]
                == [
                    0x58, 0x03, 0x57, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x5b
                ],
        "invalid grouped SHA cursor, branch or stack cleanup"
    );
    let forward = 3 + usize::from(u16::from_be_bytes([block[1], block[2]]));
    let backward = 585usize.checked_sub(usize::from(u16::from_be_bytes([block[583], block[584]])));
    ensure!(
        forward == 595 && backward == Some(179),
        "grouped SHA branch leaves block"
    );
    Ok(())
}

/// One cursor input, no output: four earlier schedule reads and one word
/// store. The maintained checker independently proves the actual address and
/// value expressions; the fixed hash binds this structural decoder to it.
pub(super) fn validate_word_block(block: &[u8]) -> Result<()> {
    let hash = super::hex(&Sha256::digest(block));
    if block.len() == 901 && hash == WORD_PAIR_HASH {
        return validate_word_pair(block);
    }
    if block.len() == 596 && hash == WORD_GROUP_HASH {
        return validate_word_group(block);
    }
    if (block.len() == 315 && hash == WORD_LOOP_HASH)
        || (block.len() == 607 && hash == WORD_DOUBLE_HASH)
    {
        let double = hash == WORD_DOUBLE_HASH;
        // Entry consumes the Boolean cache flag. Its forward branch arrives
        // at the final JUMPDEST with zero owned words; a miss starts p=0x1c00.
        ensure!(
            block[0] == 0x61 && block[3..11] == [0x58, 0x01, 0x57, 0x61, 0x1c, 0x00, 0x5b, 0x80],
            "invalid SHA word cache branch or loop entry"
        );
        // DUP1 retains the cursor below the existing one-input, zero-output
        // word body. Its seven-word maximum therefore becomes eight.
        validate_word_block(&block[11..299])?;
        let suffix = if double {
            // The first word is already stored before evaluating the next
            // word at p+32. The retained loop cursor itself remains p.
            ensure!(
                block[299..303] == [0x80, 0x60, 0x20, 0x01],
                "invalid second SHA word input"
            );
            validate_word_block(&block[303..591])?;
            591
        } else {
            299
        };
        ensure!(
            block[suffix..suffix + 9]
                == [
                    0x60,
                    if double { 64 } else { 32 },
                    0x01,
                    0x80,
                    0x61,
                    0x22,
                    0x00,
                    0x11,
                    0x61
                ]
                && block[suffix + 11..] == [0x58, 0x03, 0x57, 0x50, 0x5b],
            "invalid SHA word loop bound, branch or exit"
        );
        // Increment32 for48 iterations, or increment64 for24 pairs. Both
        // write W16..W63 in order and stop at0x2200 without wrapping. The
        // back-edge owns one word; POP gives zero at the forward hit target.
        let forward = 3 + usize::from(u16::from_be_bytes([block[1], block[2]]));
        let backward = (suffix + 11).checked_sub(usize::from(u16::from_be_bytes([
            block[suffix + 9],
            block[suffix + 10],
        ])));
        ensure!(
            forward == block.len() - 1 && backward == Some(9),
            "SHA word branch leaves block"
        );
        return Ok(());
    }
    ensure!(
        (block.len() == 292 && hash == WORD_BLOCK_HASH)
            || (block.len() == 288 && hash == WORD_ORDER_HASH),
        "unrecognized SHA word stack block"
    );
    let (mut pc, mut depth, mut high, mut loads, mut stores) = (0, 1usize, 1, 0, 0);
    while pc < block.len() {
        let op = block[pc];
        pc += 1;
        let (take, give) = match op {
            0x01 | 0x03 | 0x16 | 0x18 | 0x1b | 0x1c => (2, 1),
            0x51 => {
                ensure!(stores == 0, "SHA word read after write");
                loads += 1;
                (1, 1)
            }
            0x52 => {
                stores += 1;
                (2, 0)
            }
            0x5f => (0, 1),
            0x60..=0x7f => {
                pc += usize::from(op - 0x5f);
                (0, 1)
            }
            0x80..=0x8f => {
                ensure!(
                    depth >= usize::from(op - 0x7f),
                    "SHA word DUP accesses underlying stack"
                );
                (0, 1)
            }
            0x90..=0x9f => {
                ensure!(
                    depth > usize::from(op - 0x8f),
                    "SHA word SWAP accesses underlying stack"
                );
                (0, 0)
            }
            _ => anyhow::bail!("unexpected SHA word opcode {op:02x}"),
        };
        ensure!(
            pc <= block.len() && depth >= take,
            "invalid SHA word instruction or stack underflow"
        );
        depth = depth - take + give;
        high = high.max(depth);
    }
    ensure!(
        depth == 0 && high == 7 && loads == 4 && stores == 1,
        "invalid SHA word block stack or memory operations"
    );
    Ok(())
}

/// The exact block is bound to the symbolic proof. Decode all of its opcodes
/// again here; check zero net stack use, no underlying-stack access, and the
/// sole PC-relative branch back to the block's own round-loop entry.
pub(super) fn validate_block(block: &[u8]) -> Result<()> {
    let hash = super::hex(&Sha256::digest(block));
    ensure!(
        (block.len() == 488 && hash == BLOCK_HASH)
            || (block.len() == 487 && hash == PLACEMENT_HASH)
            || (block.len() == 485 && hash == CURSOR_HASH)
            || (block.len() == 1290 && hash == FOUR_HASH)
            || (block.len() == 1261 && hash == GROUP_HASH)
            || (block.len() == 1018 && hash == SIGMA_HASH)
            || (block.len() == 705 && hash == RETAINED_HASH),
        "unrecognized SHA stack block"
    );
    if hash == RETAINED_HASH {
        validate_mask_prefix(&block[..136], RETAINED_MASKS)?;
    }
    let (mut pc, mut depth, mut high, mut stores) = (0usize, 0usize, 0usize, 0usize);
    let (mut entry, mut branch) = (None, None);
    while pc < block.len() {
        let at = pc;
        let op = block[pc];
        pc += 1;
        let (take, give) = match op {
            0x01 | 0x03 | 0x11 | 0x16..=0x18 | 0x1b | 0x1c => (2, 1),
            0x50 => (1, 0),
            0x51 => (1, 1),
            0x52 => {
                stores += 1;
                (2, 0)
            }
            0x57 => {
                ensure!(
                    branch.is_none()
                        && at >= 5
                        && block[at - 5] == 0x61
                        && block[at - 2..at] == [0x58, 0x03],
                    "invalid SHA loop branch"
                );
                let distance = usize::from(u16::from_be_bytes([block[at - 4], block[at - 3]]));
                branch = Some((
                    (at - 2)
                        .checked_sub(distance)
                        .context("SHA branch leaves block")?,
                    depth.checked_sub(2).context("SHA stack underflow")?,
                ));
                (2, 0)
            }
            0x58 | 0x5f => (0, 1),
            0x5b => {
                ensure!(entry.is_none(), "extra SHA jump destination");
                entry = Some((at, depth));
                (0, 0)
            }
            0x60..=0x7f => {
                pc += usize::from(op - 0x5f);
                (0, 1)
            }
            0x80..=0x8f => {
                ensure!(
                    depth >= usize::from(op - 0x7f),
                    "SHA DUP accesses underlying stack"
                );
                (0, 1)
            }
            0x90..=0x9f => {
                ensure!(
                    depth > usize::from(op - 0x8f),
                    "SHA SWAP accesses underlying stack"
                );
                (0, 0)
            }
            _ => anyhow::bail!("unexpected SHA opcode {op:02x}"),
        };
        ensure!(
            pc <= block.len() && depth >= take,
            "invalid SHA instruction or stack underflow"
        );
        depth = depth - take + give;
        high = high.max(depth);
    }
    ensure!(
        depth == 0
            && high
                == if hash == RETAINED_HASH {
                    20
                } else if hash == SIGMA_HASH {
                    17
                } else if hash == FOUR_HASH || hash == GROUP_HASH {
                    16
                } else {
                    13
                }
            && stores == 8
            && entry.is_some()
            && entry == branch,
        "invalid SHA block stack, stores, or loop"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn object(body: &str) -> String {
        format!(
            "object \"C\" {{ code {{ }} object \"C_deployed\" {{ code {{ function sha() {{ {body} }} }} }} }}"
        )
    }

    #[test]
    fn equation_match_is_token_exact_unique_and_inside_runtime() {
        let source = object(REFERENCE);
        let replaced = replace_rounds(&source).unwrap().unwrap();
        assert_eq!(replaced.matches("verbatim_0i_0o").count(), 1);
        assert!(replace_rounds(&replaced).is_err());
        let commented = object(&REFERENCE.replace("mload(", "mload /* @src \"} ignored\" */ ("));
        assert!(replace_rounds(&commented).unwrap().is_some());
        for (before, after) in [
            ("shr(6,", "shr(5,"),
            ("2048", "2016"),
            ("0x1000", "0x1001"),
            ("8992", "8993"),
            ("usr$h)", "usr$g)"),
        ] {
            assert!(
                replace_rounds(&object(&REFERENCE.replace(before, after)))
                    .unwrap()
                    .is_none(),
                "{before}"
            );
        }
        assert!(replace_rounds(&object(&format!("{REFERENCE}\n{REFERENCE}"))).is_err());
        let constructor_only = format!(
            "object \"C\" {{ code {{ {REFERENCE} }} object \"C_deployed\" {{ code {{ }} }} }}"
        );
        assert!(replace_rounds(&constructor_only).unwrap().is_none());
        assert!(
            replace_rounds(&object(&format!("/* {REFERENCE} */")))
                .unwrap()
                .is_none()
        );
        assert!(tokens("/* unterminated").is_err());
        assert!(tokens("\"unterminated\\").is_err());
        assert_eq!(tokens("usr/*split*/$a").unwrap().len(), 2);
    }

    #[test]
    fn block_is_bound_to_the_checked_stack_and_loop() {
        for hex in [
            BLOCK_HEX,
            PLACEMENT_HEX,
            CURSOR_HEX,
            FOUR_HEX,
            GROUP_HEX,
            SIGMA_HEX,
            RETAINED_HEX,
        ] {
            let block = deployment::decode_hex(hex.trim()).unwrap();
            validate_block(&block).unwrap();
            for at in 0..block.len() {
                let mut bad = block.clone();
                bad[at] ^= 1;
                assert!(validate_block(&bad).is_err(), "byte {at}");
            }
            assert!(validate_block(&block[..block.len() - 1]).is_err());
        }
        assert!(validate_block(&[]).is_err());
    }

    #[test]
    fn placement_variant_changes_only_the_proved_round_block_and_metadata() {
        let original = object(&format!("{WORD_REFERENCE}\n{REFERENCE}"));
        let legacy = replace_kernels(&original, Variant::Words).unwrap().unwrap();
        let placed = replace_kernels(&original, Variant::Placement)
            .unwrap()
            .unwrap();
        assert_eq!(legacy.matches(BLOCK_HEX.trim()).count(), 1);
        assert_eq!(placed.matches(PLACEMENT_HEX.trim()).count(), 1);
        assert_eq!(
            legacy.replace(BLOCK_HEX.trim(), PLACEMENT_HEX.trim()),
            placed
        );
        assert!(replace_kernels(&placed, Variant::Placement).is_err());
        assert!(
            replace_kernels(&object(REFERENCE), Variant::Placement)
                .unwrap()
                .is_none()
        );
        for variant in [
            Variant::Rounds,
            Variant::Words,
            Variant::Placement,
            Variant::Cursor,
            Variant::WordOrder,
            Variant::Four,
            Variant::GroupCursor,
            Variant::WordLoop,
            Variant::DoubleWords,
            Variant::GroupWords,
            Variant::PairWords,
        ] {
            let block = deployment::decode_hex(variant.round_hex().trim()).unwrap();
            assert_eq!(
                super::super::hex(&Sha256::digest(block)),
                variant.round_hash()
            );
            assert_eq!(variant.with_words(), variant != Variant::Rounds);
            let word = deployment::decode_hex(variant.word_hex().trim()).unwrap();
            assert_eq!(
                super::super::hex(&Sha256::digest(word)),
                variant.word_hash()
            );
        }
        assert_eq!(Variant::Placement.kind(), "yul-sha-rounds-v3");
    }

    #[test]
    fn cursor_variant_retains_word_block_and_the_original_reference_span() {
        let original = object(&format!("{WORD_REFERENCE}\n{REFERENCE}"));
        let placed = replace_kernels(&original, Variant::Placement)
            .unwrap()
            .unwrap();
        let cursor = replace_kernels(&original, Variant::Cursor)
            .unwrap()
            .unwrap();
        assert_eq!(
            placed.replace(PLACEMENT_HEX.trim(), CURSOR_HEX.trim()),
            cursor
        );
        assert_eq!(cursor.matches(WORD_BLOCK_HEX.trim()).count(), 1);
        assert!(replace_kernels(&cursor, Variant::Cursor).is_err());
        assert!(
            replace_kernels(&object(REFERENCE), Variant::Cursor)
                .unwrap()
                .is_none()
        );
        for (before, after) in [("2048", "2016"), ("0x1000", "0x1001")] {
            assert!(
                replace_kernels(&original.replace(before, after), Variant::Cursor)
                    .unwrap()
                    .is_none()
            );
        }
        assert_eq!(Variant::Cursor.kind(), "yul-sha-rounds-v4");
    }

    #[test]
    fn word_operand_order_retains_rounds_and_exact_source_guards() {
        let original = object(&format!("{WORD_REFERENCE}\n{REFERENCE}"));
        let cursor = replace_kernels(&original, Variant::Cursor)
            .unwrap()
            .unwrap();
        let ordered = replace_kernels(&original, Variant::WordOrder)
            .unwrap()
            .unwrap();
        assert_eq!(
            cursor.replace(WORD_BLOCK_HEX.trim(), WORD_ORDER_HEX.trim()),
            ordered
        );
        assert_eq!(ordered.matches(CURSOR_HEX.trim()).count(), 1);
        assert!(replace_kernels(&ordered, Variant::WordOrder).is_err());
        assert!(
            replace_kernels(&object(REFERENCE), Variant::WordOrder)
                .unwrap()
                .is_none()
        );
        for (before, after) in [("not(479)", "not(478)"), ("shr(7,", "shr(6,")] {
            assert!(
                replace_kernels(&original.replace(before, after), Variant::WordOrder)
                    .unwrap()
                    .is_none()
            );
        }
        assert_eq!(Variant::WordOrder.kind(), "yul-sha-rounds-v5");
    }

    #[test]
    fn shared_scalar_core_binds_both_complete_functions_in_either_name_order() {
        for variant in [Variant::Four, Variant::GroupCursor] {
            for (scalar, packed) in [
                ("fun_shaRounds", "fun__shaRounds"),
                ("fun__shaRounds", "fun_shaRounds"),
            ] {
                let scalar_reference = SCALAR_REFERENCE.replacen("fun_shaRounds", scalar, 1);
                let packed_reference = PACKED_REFERENCE.replacen("fun__shaRounds", packed, 1);
                let original = object(&format!("{scalar_reference}\n{packed_reference}"));
                let four = replace_kernels(&original, variant).unwrap().unwrap();
                let wrapper = format!(
                    "function {scalar}(var_m_mpos) {{ mstore(0x2420, 0) {packed}(var_m_mpos) }}"
                );
                assert!(four.contains(&wrapper));
                assert_eq!(four.matches(variant.round_hex().trim()).count(), 1);
                assert_eq!(four.matches(WORD_ORDER_HEX.trim()).count(), 1);
                let unified = unify_scalar(&original).unwrap().unwrap();
                let ordered = replace_kernels(&unified, Variant::WordOrder)
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    ordered.replace(CURSOR_HEX.trim(), variant.round_hex().trim()),
                    four
                );
                assert!(
                    replace_kernels(&object(&scalar_reference), variant)
                        .unwrap()
                        .is_none()
                );
                assert!(
                    replace_kernels(&object(&packed_reference), variant)
                        .unwrap()
                        .is_none()
                );
                // Neither body may be matched in the constructor, in a comment,
                // under a different name, or with different feed-forward equations.
                for bad in [
                    original.replace(&packed_reference, &format!("/* {packed_reference} */")),
                    original.replace(&scalar_reference, &scalar_reference.replace("_6)", "_1)")),
                    original.replace(
                        &packed_reference,
                        &packed_reference.replace("and(add", "xor(add"),
                    ),
                    original.replace(&format!("function {packed}"), "function unknown"),
                    format!(
                        "object \"C\" {{ code {{ {packed_reference} }} object \"C_deployed\" {{ code {{ {scalar_reference} }} }} }}"
                    ),
                    format!(
                        "object \"C\" {{ code {{ {scalar_reference} }} object \"C_deployed\" {{ code {{ {packed_reference} }} }} }}"
                    ),
                ] {
                    assert_ne!(bad, original);
                    assert!(replace_kernels(&bad, variant).unwrap().is_none());
                }
                assert!(
                    unify_scalar(&object(&format!(
                        "{scalar_reference}\n{packed_reference}\n{packed_reference}"
                    )))
                    .is_err()
                );
            }
        }
        assert_eq!(Variant::GroupCursor.kind(), "yul-sha-rounds-v7");
        assert_eq!(Variant::Four.kind(), "yul-sha-rounds-v6");
    }

    #[test]
    fn group_cursor_changes_only_the_bound_round_block() {
        let original = object(&format!("{SCALAR_REFERENCE}\n{PACKED_REFERENCE}"));
        let four = replace_kernels(&original, Variant::Four).unwrap().unwrap();
        let group = replace_kernels(&original, Variant::GroupCursor)
            .unwrap()
            .unwrap();
        assert_eq!(four.replace(FOUR_HEX.trim(), GROUP_HEX.trim()), group);
        assert!(Variant::Four.shared_scalar() && Variant::GroupCursor.shared_scalar());
        assert!(!Variant::WordOrder.shared_scalar());
        for (before, after) in [("2048", "2016"), ("8992", "8993"), ("usr$h)", "usr$g)")] {
            let changed = original.replace(before, after);
            assert_ne!(changed, original);
            assert!(
                replace_kernels(&changed, Variant::GroupCursor)
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn word_loop_binds_the_complete_cache_and_scalar_callee_in_both_name_orders() {
        for (scalar, packed) in [
            ("fun_shaRounds", "fun__shaRounds"),
            ("fun__shaRounds", "fun_shaRounds"),
        ] {
            let original = object(&format!(
                "{}\n{}",
                SCALAR_REFERENCE.replacen("fun_shaRounds", scalar, 1),
                PACKED_REFERENCE.replacen("fun__shaRounds", packed, 1)
            ));
            let previous = replace_kernels(&original, Variant::GroupCursor)
                .unwrap()
                .unwrap();
            let candidate = replace_kernels(&original, Variant::WordLoop)
                .unwrap()
                .unwrap();
            let loop_span = format!(
                "let usr$p := add(mul(usr$cached, 1536), 7168) \
                for {{}} lt(usr$p, 0x2200) {{usr$p := add(usr$p, 32)}} \
                {{verbatim_1i_0o(hex\"{}\", usr$p)}}",
                WORD_ORDER_HEX.trim()
            );
            let call = format!(
                "verbatim_1i_0o(hex\"{}\", usr$cached)",
                WORD_LOOP_HEX.trim()
            );
            assert_eq!(
                replace_span(&previous, &loop_span, &call).unwrap().unwrap(),
                candidate
            );
            assert_eq!(candidate.matches(GROUP_HEX.trim()).count(), 1);
            assert_eq!(candidate.matches(WORD_LOOP_HEX.trim()).count(), 1);
            for (before, after) in [
                ("mul(usr$cached, 1536)", "mul(usr$cached, 1504)"),
                (
                    "and(usr$requested, eq(usr$paddingKey, mload(0x2440)))",
                    "usr$paddingKey",
                ),
                ("mcopy(0x1c00, 0x2460, 1536)", "mcopy(0x1c00, 0x2460, 1504)"),
                ("and(add(mload(_3), _2), _1)", "xor(add(mload(_3), _2), _1)"),
            ] {
                let changed = original.replace(before, after);
                assert_ne!(changed, original);
                assert!(
                    replace_kernels(&changed, Variant::WordLoop)
                        .unwrap()
                        .is_none()
                );
            }
        }
        assert_eq!(Variant::WordLoop.kind(), "yul-sha-rounds-v8");
    }

    #[test]
    fn word_equations_are_exact_and_optional() {
        let original = object(&format!("{WORD_REFERENCE}\n{REFERENCE}"));
        let replaced = replace_kernels(&original, Variant::Words).unwrap().unwrap();
        assert_eq!(replaced.matches("verbatim_0i_0o").count(), 1);
        assert_eq!(replaced.matches("verbatim_1i_0o").count(), 1);
        assert!(
            replace_kernels(&object(REFERENCE), Variant::Words)
                .unwrap()
                .is_none()
        );
        assert!(
            replace_kernels(&object(REFERENCE), Variant::Rounds)
                .unwrap()
                .is_some()
        );
        assert!(replace_kernels(&replaced, Variant::Words).is_err());
        for (before, after) in [
            ("not(479)", "not(478)"),
            ("shr(7,", "shr(6,"),
            ("mstore(usr$p", "mstore(usr$x"),
            ("0x3fffffffc1", "0x3fffffffc0"),
        ] {
            let changed = object(&format!(
                "{}\n{REFERENCE}",
                WORD_REFERENCE.replace(before, after)
            ));
            assert!(
                replace_kernels(&changed, Variant::Words).unwrap().is_none(),
                "{before}"
            );
            assert!(
                replace_kernels(&changed, Variant::Rounds)
                    .unwrap()
                    .is_some()
            );
        }
        assert!(
            replace_kernels(
                &object(&format!("{WORD_REFERENCE}\n{WORD_REFERENCE}\n{REFERENCE}")),
                Variant::Words
            )
            .is_err()
        );
        let constructor_only = format!(
            "object \"C\" {{ code {{ {WORD_REFERENCE} }} object \"C_deployed\" {{ code {{ {REFERENCE} }} }} }}"
        );
        assert!(
            replace_kernels(&constructor_only, Variant::Words)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn double_words_change_only_the_two_checked_blocks_in_either_name_order() {
        for (scalar, packed) in [
            ("fun_shaRounds", "fun__shaRounds"),
            ("fun__shaRounds", "fun_shaRounds"),
        ] {
            let original = object(&format!(
                "{}\n{}",
                SCALAR_REFERENCE.replacen("fun_shaRounds", scalar, 1),
                PACKED_REFERENCE.replacen("fun__shaRounds", packed, 1)
            ));
            let previous = replace_kernels(&original, Variant::WordLoop)
                .unwrap()
                .unwrap();
            let double = replace_kernels(&original, Variant::DoubleWords)
                .unwrap()
                .unwrap();
            assert_eq!(
                previous
                    .replace(GROUP_HEX.trim(), SIGMA_HEX.trim())
                    .replace(WORD_LOOP_HEX.trim(), WORD_DOUBLE_HEX.trim()),
                double
            );
            for (before, after) in [
                ("shr(13, usr$a)", "shr(12, usr$a)"),
                ("mul(usr$cached, 1536)", "mul(usr$cached, 1504)"),
                (
                    "and(usr$requested, eq(usr$paddingKey, mload(0x2440)))",
                    "usr$paddingKey",
                ),
                ("and(add(mload(_3), _2), _1)", "xor(add(mload(_3), _2), _1)"),
            ] {
                let changed = original.replace(before, after);
                assert_ne!(changed, original);
                assert!(
                    replace_kernels(&changed, Variant::DoubleWords)
                        .unwrap()
                        .is_none()
                );
            }
        }
        assert_eq!(Variant::DoubleWords.kind(), "yul-sha-rounds-v9");
    }

    #[test]
    fn word_groups_change_only_the_bound_word_loop_in_both_name_orders() {
        for (scalar, packed) in [
            ("fun_shaRounds", "fun__shaRounds"),
            ("fun__shaRounds", "fun_shaRounds"),
        ] {
            let original = object(&format!(
                "{}\n{}",
                SCALAR_REFERENCE.replacen("fun_shaRounds", scalar, 1),
                PACKED_REFERENCE.replacen("fun__shaRounds", packed, 1)
            ));
            let previous = replace_kernels(&original, Variant::DoubleWords)
                .unwrap()
                .unwrap();
            let grouped = replace_kernels(&original, Variant::GroupWords)
                .unwrap()
                .unwrap();
            assert_eq!(
                previous.replace(WORD_DOUBLE_HEX.trim(), WORD_GROUP_HEX.trim()),
                grouped
            );
            for (before, after) in [
                ("not(479)", "not(478)"),
                ("mul(usr$cached, 1536)", "mul(usr$cached, 1504)"),
                (
                    "and(usr$requested, eq(usr$paddingKey, mload(0x2440)))",
                    "usr$paddingKey",
                ),
                ("and(add(mload(_3), _2), _1)", "xor(add(mload(_3), _2), _1)"),
            ] {
                let changed = original.replace(before, after);
                assert_ne!(changed, original);
                assert!(
                    replace_kernels(&changed, Variant::GroupWords)
                        .unwrap()
                        .is_none()
                );
            }
        }
        assert_eq!(Variant::GroupWords.kind(), "yul-sha-rounds-v10");
    }

    #[test]
    fn predecessor_pair_changes_only_bound_kernels_in_both_name_orders() {
        for (scalar, packed) in [
            ("fun_shaRounds", "fun__shaRounds"),
            ("fun__shaRounds", "fun_shaRounds"),
        ] {
            let original = object(&format!(
                "{}\n{}",
                SCALAR_REFERENCE.replacen("fun_shaRounds", scalar, 1),
                PACKED_REFERENCE.replacen("fun__shaRounds", packed, 1)
            ));
            let previous = replace_kernels(&original, Variant::GroupWords)
                .unwrap()
                .unwrap();
            let grouped = replace_kernels(&original, Variant::PairWords)
                .unwrap()
                .unwrap();
            assert_eq!(
                previous
                    .replace(SIGMA_HEX.trim(), RETAINED_HEX.trim())
                    .replace(WORD_GROUP_HEX.trim(), WORD_PAIR_HEX.trim()),
                grouped
            );
            for (before, after) in [
                ("not(479)", "not(478)"),
                ("mul(usr$cached, 1536)", "mul(usr$cached, 1504)"),
                (
                    "and(usr$requested, eq(usr$paddingKey, mload(0x2440)))",
                    "usr$paddingKey",
                ),
                ("and(add(mload(_3), _2), _1)", "xor(add(mload(_3), _2), _1)"),
            ] {
                let changed = original.replace(before, after);
                assert_ne!(changed, original);
                assert!(
                    replace_kernels(&changed, Variant::PairWords)
                        .unwrap()
                        .is_none()
                );
            }
        }
        let pair = deployment::decode_hex(WORD_PAIR_HEX.trim()).unwrap();
        assert!(validate_mask_prefix(&pair[6..92], RETAINED_MASKS).is_err());
        let mut invalid = pair[6..92].to_vec();
        invalid[0] = 0x51;
        assert!(validate_mask_prefix(&invalid, WORD_GROUP_MASKS).is_err());
        assert_eq!(Variant::PairWords.kind(), "yul-sha-rounds-v11");
    }

    #[test]
    fn word_block_reads_four_values_and_preserves_underlying_stack() {
        for hex in [
            WORD_BLOCK_HEX,
            WORD_ORDER_HEX,
            WORD_LOOP_HEX,
            WORD_DOUBLE_HEX,
            WORD_GROUP_HEX,
            WORD_PAIR_HEX,
        ] {
            let block = deployment::decode_hex(hex.trim()).unwrap();
            validate_word_block(&block).unwrap();
            for at in 0..block.len() {
                let mut bad = block.clone();
                bad[at] ^= 1;
                assert!(validate_word_block(&bad).is_err(), "byte {at}");
            }
            assert!(validate_word_block(&block[..block.len() - 1]).is_err());
        }
        assert!(validate_word_block(&[]).is_err());
    }

    #[test]
    fn runtime_audit_consumes_one_map_entry_without_skipping_tail_checks() {
        let block = deployment::decode_hex(BLOCK_HEX.trim()).unwrap();
        let abi = json!([
            {"type":"constructor","inputs":[]},
            {"type":"function","name":"verify","stateMutability":"view",
                "inputs":[{"type":"bytes"},{"type":"bytes32[]"}],"outputs":[{"type":"bool"}]}
        ]);
        let mut code = vec![0x5f, 0x50];
        code.extend(&block);
        code.extend([0x5f, 0x50, 0x00, 0xfe, 0xa0, 0x00, 0x01]);
        let map = json!("0;0;0;0;0;0");
        let check = |code: &[u8], map: &Value| {
            yul_deployment::check_runtime_with_block(code, map, &abi, Some(&block))
        };
        check(&code, &map).unwrap();
        assert!(yul_deployment::check_runtime(&code, &map, &abi).is_err());
        for op in [0x55, 0x5d, 0xf0, 0xf1, 0xf2, 0xf4, 0xf5, 0xfa, 0xff] {
            let mut bad = code.clone();
            bad[block.len() + 4] = op;
            assert!(check(&bad, &map).is_err());
        }
        let mut bad = code.clone();
        bad[block.len() + 5] = 0x5b; // unaccounted executable tail
        assert!(check(&bad, &map).is_err());
        let mut bad = code.clone();
        bad.splice(2..2, block.iter().copied());
        assert!(check(&bad, &map).is_err());
        assert!(check(&code, &json!("0;0;0")).is_err());
        assert!(check(&code, &json!("0;0;0;0;0;0;0;0")).is_err());
        let mut bad = code;
        bad[5] ^= 1;
        assert!(check(&bad, &map).is_err());

        // Both opaque blocks still count as one source-map entry each. Their
        // interiors are decoded separately; no executable tail can be skipped.
        let word = deployment::decode_hex(WORD_BLOCK_HEX.trim()).unwrap();
        let mut two = block.clone();
        two.extend(&word);
        two.extend([0x00, 0xfe, 0xa0, 0x00, 0x01]);
        let map = json!("0;0;0");
        let check_two = |code: &[u8], map: &Value| {
            yul_deployment::check_runtime_with_blocks(code, map, &abi, Some(&block), Some(&word))
        };
        check_two(&two, &map).unwrap();
        assert!(yul_deployment::check_runtime_with_block(&two, &map, &abi, Some(&block)).is_err());
        assert!(
            yul_deployment::check_runtime_with_blocks(&two, &map, &abi, None, Some(&word)).is_err()
        );
        assert!(check_two(&two, &json!("0;0")).is_err());
        assert!(check_two(&two, &json!("0;0;0;0;0;0")).is_err());
        for op in [0x55, 0x5d, 0xf0, 0xf1, 0xf2, 0xf4, 0xf5, 0xfa, 0xff] {
            let mut bad = two.clone();
            bad[block.len() + word.len()] = op;
            assert!(check_two(&bad, &map).is_err());
        }
        let mut bad = two.clone();
        bad.splice(block.len()..block.len(), word.iter().copied());
        assert!(check_two(&bad, &map).is_err());
        let mut bad = two;
        bad[block.len() + word.len() + 1] = 0x5b;
        assert!(check_two(&bad, &map).is_err());
    }

    #[test]
    #[ignore = "requires solc and a saved full deployment; set BINIUS_SHA_STACK_BASELINE, BINIUS_VK, BINIUS_SHA_STACK_OUTPUT, BINIUS_SOLC"]
    fn integrates_saved_deployment_with_independently_reconstructed_plan() {
        // Skip slow earlier compiler stages only in this integration harness.
        // Reconstruct all circuit transformations and check every metadata byte
        // before invoking the production final stage. Public key-only generation
        // is validated separately; this is not reported as that public API test.
        let file = |name| std::env::var_os(name).expect(name);
        let old: Value =
            serde_json::from_slice(&std::fs::read(file("BINIUS_SHA_STACK_BASELINE")).unwrap())
                .unwrap();
        let key = noir_binius_verifier::VerificationKey::decode(
            &std::fs::read(file("BINIUS_VK")).unwrap(),
        )
        .unwrap();
        let p = super::super::program::compile_with_factored_wiring(key.binius_verifier(), true)
            .unwrap();
        let p = super::super::program::with_constructed_matrix(&p).unwrap();
        let p = super::super::program::with_constructed_public(&p).unwrap();
        let p = super::super::program::with_grouped_private(&p).unwrap();
        let p = super::super::program::with_grouped_precommit(&p).unwrap();
        let p = super::super::program::with_product_terminals(&p).unwrap();
        let mut p = super::super::program::with_factored_precommit(&p).unwrap();
        p.authenticated_program = true;
        p.storage = super::super::storage::construct(
            &p.bytes,
            old["construction"]["storageCompression"]["minimumMatch"]
                .as_u64()
                .unwrap() as usize,
        );
        let info = construction::metadata(&p);
        assert_eq!(serde_json::to_value(&info).unwrap(), old["construction"]);
        let baseline = yul_deployment::VerifierDeployment {
            contract_name: "BiniusVerifier",
            abi: old["abi"].clone(),
            bytecode: old["bytecode"].as_str().unwrap().into(),
            deployed_bytecode: old["deployedBytecode"].as_str().unwrap().into(),
            solidity_source: old["soliditySource"].as_str().unwrap().into(),
            yul_source: old["yulSource"].as_str().unwrap().into(),
            compiler_settings: old["compilerSettings"].clone(),
            initcode_bytes: old["initcodeBytes"].as_u64().unwrap() as usize,
            runtime_bytes: old["runtimeBytes"].as_u64().unwrap() as usize,
            solidity_initcode_bytes: old["solidityInitcodeBytes"].as_u64().unwrap() as usize,
            runtime_compilation: None,
            construction: Some(info),
        };
        let reference = deployment::decode_hex(&baseline.deployed_bytecode).unwrap();
        let prefix = checked_prefix(&p, &baseline.solidity_source, &reference).unwrap();
        assert!(!prefix.is_empty());
        let mut wrong_runtime = reference;
        wrong_runtime[10] ^= 1;
        assert!(checked_prefix(&p, &baseline.solidity_source, &wrong_runtime).is_err());
        let candidate = finish(&p, baseline, Path::new(&file("BINIUS_SOLC"))).unwrap();
        assert!(candidate.runtime_compilation.is_some());
        std::fs::write(
            file("BINIUS_SHA_STACK_OUTPUT"),
            serde_json::to_vec_pretty(&candidate).unwrap(),
        )
        .unwrap();
    }
}
