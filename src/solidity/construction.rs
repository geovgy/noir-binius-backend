//! Typed construction plan for deriving the complete outer matrix at deployment.
use super::{
    codec, deployment, hex,
    program::{ConstructedProgram, PrivateGroupingKind},
};
use anyhow::{Context, Result, ensure};
use serde::Serialize;

const FUNCTIONS: &str = include_str!("construct_matrix.sol");
const CONSTRUCTOR: &str = include_str!("construction.template.sol");
const STORAGE: &str = include_str!("storage.sol");
const PUBLIC_RUNTIME: &str = include_str!("public_wiring.sol");
const PUBLIC_EXPANSION: &str = include_str!("expand_public.sol");
const GROUPED_RUNTIME: &str = include_str!("grouped_wiring.sol");
const GROUPED_EMISSION: &str = include_str!("grouped_emission.yul");
const PRODUCT_RUNTIME: &str = include_str!("product_wiring.sol");
const PRODUCT_EMISSION: &str = include_str!("product_emission.yul");

/// Review data for the logical program and its optional storage encoding.
/// It is not a proof and is not passed to deployment or verification.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConstructionInfo {
    pub kind: &'static str,
    pub verification_program: String,
    pub program_keccak256: String,
    pub precursor_length: usize,
    pub matrix_length_offset: usize,
    pub matrix_input_offset: usize,
    pub matrix_output_offset: usize,
    pub affine_length: usize,
    pub matrix_length: usize,
    pub escaped_matrix_length: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_expansion: Option<PublicExpansionInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_grouping: Option<PrivateGroupingInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub precommit_grouping: Option<PrecommitGroupingInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_compression: Option<StorageInfo>,
    /// Optional calldata copy, authenticated against the constructor's hash.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program_input: Option<super::program_input::ProgramInputInfo>,
}

/// Exact constructor conversion of the public graph's child references.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicExpansionInfo {
    pub kind: &'static str,
    pub source_length: usize,
    pub instruction_offset: usize,
    pub fixed_length: usize,
}

/// Stable depth/code ordering of precisely the same private scalar DAG.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivateGroupingInfo {
    pub kind: &'static str,
    pub original_length: usize,
    pub nodes: usize,
    pub groups: usize,
    pub max_depth: usize,
}

/// Exact grouping of the fixed precommit graph, with its final instruction offset.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrecommitGroupingInfo {
    pub kind: &'static str,
    pub instruction_offset: usize,
    pub original_length: usize,
    pub nodes: usize,
    pub groups: usize,
    pub max_depth: usize,
}

/// Optional storage encoding. The logical verification program above remains
/// byte-identical after its checked decompression in the contract.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageInfo {
    pub kind: &'static str,
    pub minimum_match: usize,
    pub stored_program: String,
    pub stored_program_keccak256: String,
    pub packing_headers: String,
}

pub(super) fn metadata(plan: &ConstructedProgram) -> ConstructionInfo {
    ConstructionInfo {
        kind: "affine-matrix-v1",
        verification_program: format!("0x{}", hex(&plan.bytes)),
        program_keccak256: program_hash(plan),
        precursor_length: plan
            .public_expansion
            .as_ref()
            .map_or(plan.precursor.bytes.len(), |public| {
                public.expanded_precursor_length
            }),
        matrix_length_offset: plan.length_offset,
        matrix_input_offset: plan.input_offset,
        matrix_output_offset: plan.output_offset,
        affine_length: plan.affine_length,
        matrix_length: plan.matrix.bytes.len(),
        escaped_matrix_length: plan.escaped,
        public_expansion: plan
            .public_expansion
            .as_ref()
            .map(|public| PublicExpansionInfo {
                kind: "grouped-relative-u16-v1",
                source_length: plan.precursor.bytes.len(),
                instruction_offset: public.instruction_offset,
                fixed_length: public.fixed_length,
            }),
        private_grouping: plan
            .private_grouping
            .as_ref()
            .map(|grouping| PrivateGroupingInfo {
                kind: grouping.kind.as_str(),
                original_length: grouping.original_length,
                nodes: grouping.nodes,
                groups: grouping.groups,
                max_depth: grouping.max_depth,
            }),
        precommit_grouping: plan.precommit_grouping.as_ref().map(|grouping| {
            PrecommitGroupingInfo {
                kind: "code-grouped-u16-v1",
                instruction_offset: grouping.instruction_offset,
                original_length: grouping.original_length,
                nodes: grouping.nodes,
                groups: grouping.groups,
                max_depth: grouping.max_depth,
            }
        }),
        storage_compression: plan.storage.as_ref().map(|storage| StorageInfo {
            kind: "literal-copy-v1",
            minimum_match: storage.minimum_match,
            stored_program: format!("0x{}", hex(&storage.bytes)),
            stored_program_keccak256: hash_bytes(&storage.bytes),
            packing_headers: format!("0x{}", hex(&storage.headers)),
        }),
        program_input: super::program_input::metadata(plan),
    }
}

fn program_hash(plan: &ConstructedProgram) -> String {
    hash_bytes(&plan.bytes)
}

fn hash_bytes(bytes: &[u8]) -> String {
    format!(
        "0x{}",
        hex(&<sha3::Keccak256 as digest::Digest>::digest(bytes))
    )
}

pub(super) fn constructor(
    plan: &ConstructedProgram,
    payload: &[u8],
    joint_length: usize,
    runtime_length: Option<usize>,
) -> String {
    let matrix = &plan.matrix;
    let write_length = if plan.escaped {
        format!(
            "mstore(add(dest, {}), or(shl(240, 65535), shl(208, {})))",
            plan.length_offset,
            matrix.bytes.len()
        )
    } else {
        format!(
            "mstore(add(dest, {}), shl(240, {}))",
            plan.length_offset,
            matrix.bytes.len()
        )
    };
    let mut result = CONSTRUCTOR.to_owned();
    let (packing_headers, pack_program) = plan.storage.as_ref().map_or_else(
        || (String::new(), String::new()),
        |storage| {
            let headers = format!(
                "        bytes memory packingHeaders = new bytes({});\n        assembly (\"memory-safe\") {{ mcopy(add(packingHeaders, 32), add(add(joint, 32), ENCODED_PROGRAM_LENGTH), {}) }}",
                storage.headers.len(), storage.headers.len()
            );
            let packing = format!(
                "        data = _packStorage(data, packingHeaders, {});\n        require(data.length == {});\n        require(keccak256(data) == {});",
                storage.bytes.len(), storage.bytes.len(), hash_bytes(&storage.bytes)
            );
            (headers, packing)
        },
    );
    for (name, value) in [
        ("PAYLOAD", hex(payload)),
        ("JOINT_LENGTH", joint_length.to_string()),
        ("PRECURSOR_LENGTH", plan.precursor.bytes.len().to_string()),
        ("AFFINE_LENGTH", plan.affine_length.to_string()),
        ("INPUT_OFFSET", plan.input_offset.to_string()),
        ("OUTPUT_OFFSET", plan.output_offset.to_string()),
        ("LENGTH_OFFSET", plan.length_offset.to_string()),
        ("TAIL_LENGTH", plan.tail_length.to_string()),
        ("ORDER", hex(&matrix.order)),
        ("MAX_NODES", matrix.node_count.to_string()),
        ("NODE_SLOTS", matrix.node_hash_slots.to_string()),
        ("NX", matrix.nx.to_string()),
        ("NY", matrix.ny.to_string()),
        ("CHUNK_BITS", matrix.chunk_bits.to_string()),
        ("MAX_OPS", matrix.unpruned_operations.to_string()),
        ("OP_SLOTS", matrix.operation_hash_slots.to_string()),
        ("MATRIX_LENGTH", matrix.bytes.len().to_string()),
        ("WRITE_LENGTH", write_length),
        ("PROGRAM_HASH", program_hash(plan)),
        ("PACKING_HEADERS", packing_headers),
        ("PACK_PROGRAM", pack_program),
        (
            "RETURN_RUNTIME",
            runtime_length.map_or_else(String::new, |n| format!("return(executable, {n})")),
        ),
    ] {
        result = result.replace(&format!("{{{{{name}}}}}"), &value);
    }
    if let Some(storage) = &plan.storage {
        result = result.replace(
            "executable := add(add(joint, 32), ENCODED_PROGRAM_LENGTH)",
            &format!(
                "executable := add(add(add(joint, 32), ENCODED_PROGRAM_LENGTH), {})",
                storage.headers.len()
            ),
        );
    }
    if plan.public_expansion.is_some() {
        let old = format!(
            "bytes memory precursor = _expandProgram(joint, {});",
            plan.precursor.bytes.len()
        );
        let new = format!(
            "bytes memory precursor = _expandPublic(_expandProgram(joint, {}));",
            plan.precursor.bytes.len()
        );
        assert_eq!(
            result.matches(&old).count(),
            1,
            "missing compact public graph expansion"
        );
        result = result.replace(&old, &new);
    }
    assert!(!result.contains("{{"));
    if plan.authenticated_program {
        result = super::program_input::constructor(result, plan);
    }
    result
}

fn public_expansion(plan: &ConstructedProgram) -> Option<String> {
    let public = plan.public_expansion.as_ref()?;
    let start = public.instruction_offset + 5;
    let mut source = PUBLIC_EXPANSION.to_owned();
    for (name, value) in [
        ("NEW_LENGTH", public.expanded_precursor_length),
        ("NODE_START", start + public.prefix_length),
        ("LENGTH_OFFSET", start - 2),
        ("PUBLIC_LENGTH", public.fixed_length),
        ("PUBLIC_START", start),
        ("PREFIX_LENGTH", public.prefix_length),
        ("NODE_COUNT", public.nodes),
        ("LEAVES", public.leaves),
        ("NEW_END", start + public.fixed_length),
        ("OLD_END", start + public.original_length),
        (
            "TAIL_LENGTH",
            plan.precursor.bytes.len() - start - public.original_length,
        ),
    ] {
        source = source.replace(&format!("{{{{{name}}}}}"), &value.to_string());
    }
    assert!(!source.contains("{{"));
    Some(source)
}

pub(super) fn render_source(mut source: String, plan: &ConstructedProgram) -> Result<String> {
    source = super::short_wiring::render(source)?;
    order_sha_rounds(&mut source)?;
    let product_terminals = plan
        .private_grouping
        .as_ref()
        .is_some_and(|grouping| grouping.kind == PrivateGroupingKind::ProductTerminals);
    ensure!(
        !product_terminals || plan.precommit_grouping.is_some(),
        "product terminal references require both outer definitions to be grouped"
    );
    ensure!(
        plan.precommit_grouping.is_none() || plan.private_grouping.is_some(),
        "precommit grouping requires a grouped private graph"
    );
    let old = format!(
        "VERIFICATION_PROGRAM_LENGTH = {};",
        plan.precursor.bytes.len()
    );
    ensure!(
        source.matches(&old).count() == 1,
        "missing precursor program length"
    );
    source = source.replace(
        &old,
        &format!("VERIFICATION_PROGRAM_LENGTH = {};", plan.bytes.len()),
    );
    if plan.escaped {
        let before = "} else if (opcode == 21) {\n                    assembly (\"memory-safe\") { value := add(add(program, add(32, PROGRAM_WORD_BYTES)), cursor) }";
        let after = "} else if (opcode == 21) {\n                    if (a == 65535) {\n                        assembly (\"memory-safe\") { a := shr(224, mload(add(add(program, 32), add(cursor, PROGRAM_WORD_BYTES)))) }\n                        cursor += 4;\n                    }\n                    assembly (\"memory-safe\") { value := add(add(program, add(32, PROGRAM_WORD_BYTES)), cursor) }";
        ensure!(
            source.matches(before).count() == 1,
            "missing matrix data instruction"
        );
        source = source.replace(before, after);
    }
    let marker = "            if (factored != 0 && mode != 0 && mode != 3) {";
    ensure!(
        source.matches(marker).count() == 1,
        "missing factored matrix dispatch"
    );
    let preparation = r#"            // Both outer matrices now use complete graphs. The inner protocol's
            // affine matrices retain their original preparation and evaluation.
            if (factored != 0 && (mode == 0 || mode == 3)) {
                assembly ("memory-safe") {
                    result := mload(0x40)
                    mstore(0x40, add(result, 32))
                    switch mode
                    case 0 { mstore(result, pointX) }
                    default { mstore(result, pointY) }
                }
                return result;
            }
"#;
    source = source.replace(marker, &(preparation.to_owned() + marker));
    let (payload, decoded_length) = if let Some(storage) = &plan.storage {
        let mut joint = codec::operands(&plan.precursor.bytes, true, plan.precursor.word_bytes);
        joint.extend_from_slice(&storage.headers);
        (codec::compress(&joint), joint.len())
    } else {
        codec::pack(&plan.precursor.bytes, plan.precursor.word_bytes)
    };
    let range = deployment::constructor_range(&source)?;
    source.replace_range(range, &constructor(plan, &payload, decoded_length, None));
    let end = source.rfind('}').expect("complete verifier contract");
    source.insert_str(end, FUNCTIONS);
    if let Some(storage) = &plan.storage {
        for (old, new) in [
            (
                "mstore(program, VERIFICATION_PROGRAM_LENGTH)".to_owned(),
                format!("mstore(program, {})", storage.bytes.len()),
            ),
            (
                "let end := add(start, VERIFICATION_PROGRAM_LENGTH)".to_owned(),
                format!("let end := add(start, {})", storage.bytes.len()),
            ),
        ] {
            ensure!(
                source.matches(&old).count() == 1,
                "missing fixed-program storage load"
            );
            source = source.replace(&old, &new);
        }
        let marker = "        return _run(program, proof, hints);";
        ensure!(
            source.matches(marker).count() == 1,
            "missing direct program execution"
        );
        source = source.replace(marker, &(r#"        bytes memory expanded = _unpackStorage(program, VERIFICATION_PROGRAM_LENGTH);
        // Both buffers are dead after this move. Preserve the original runtime
        // allocation boundary and expose only the complete expanded program.
        assembly ("memory-safe") {
            let size := add(mload(expanded), 32)
            mcopy(program, expanded, size)
            mstore(0x40, and(add(add(program, size), 31), not(31)))
        }
"#.to_owned() + marker));
        let end = source.rfind('}').expect("complete verifier contract");
        source.insert_str(end, STORAGE);
    }
    if let Some(expansion) = public_expansion(plan) {
        let start = source
            .find("    function _publicWiring(")
            .context("missing public matrix evaluator")?;
        let brace = start
            + source[start..]
                .find('{')
                .context("missing public matrix function body")?;
        let mut depth = 0usize;
        let mut end = None;
        for (at, byte) in source.bytes().enumerate().skip(brace) {
            if byte == b'{' {
                depth += 1;
            }
            if byte == b'}' {
                depth -= 1;
            }
            if depth == 0 {
                end = Some(at + 1);
                break;
            }
        }
        source.replace_range(
            start..end.context("unterminated public matrix evaluator")?,
            PUBLIC_RUNTIME.trim_end(),
        );
        let end = source.rfind('}').context("missing verifier contract end")?;
        source.insert_str(end, &expansion);
    }
    if plan.private_grouping.is_some() {
        let range = function_range(&source, "_factoredWiring")?;
        let mut runtime = if product_terminals {
            PRODUCT_RUNTIME
        } else {
            GROUPED_RUNTIME
        }
        .to_owned();
        if plan.precommit_grouping.is_some() && !product_terminals {
            // The checked two-definition transition groups both outer graphs.
            // Constant folding removes the legacy path and its stream state.
            let marker = "grouped := shr(7, nx)";
            ensure!(
                runtime.matches(marker).count() == 1,
                "missing group format flag"
            );
            runtime = runtime.replace(marker, "grouped := 1");
        }
        source.replace_range(range, runtime.trim_end());
        let range = function_range(&source, "_expressions")?;
        let original = &source[range.clone()];
        let marker = "            if gt(add(initial, scalarCount), 65536) { revert(0, 0) }\n";
        ensure!(
            original.matches(marker).count() == 1,
            "missing scalar emission bound"
        );
        let keep = original.find(marker).expect("checked marker") + marker.len();
        let grouped = format!(
            "{}{}        }}\n    }}",
            &original[..keep],
            if product_terminals {
                PRODUCT_EMISSION
            } else {
                GROUPED_EMISSION
            }
        );
        source.replace_range(range, &grouped);
    }
    if plan.authenticated_program {
        source = super::program_input::runtime(source, plan)?;
    }
    Ok(source)
}

/// Release the old H/G/F/E/D values before computing Sigma0 and majority.
/// T1 has already consumed E/F/G/H; Sigma0 and majority only read A/B/C.
/// Every working word therefore has exactly the same value after each round.
/// Keep this compiler-sensitive schedule on the measured construction path.
fn order_sha_rounds(source: &mut String) -> Result<()> {
    const SIGMA0: &str = r#"                // ROTR2 can likewise retain the next lane's low two bits
                // at positions 35..36. Seven 32-bit summands stay below
                // 3*2^35 + 7*2^32 < 2^37. The final A mask clears them.
                let s0 := xor(or(shr(2, a), shl(30, and(a, mul(repeat, 3)))), xor(rr(a, 13, repeat), rr(a, 22, repeat)))
                let maj := xor(and(a, b), and(c, xor(a, b)))
"#;
    const MOVES: &str = r#"                h := g
                g := f
                f := e
                e := and(add(d, t1), mask)
                d := c
"#;
    let range = function_range(source, "_shaMix")?;
    let body = &source[range.clone()];
    let before = format!("{SIGMA0}{MOVES}");
    ensure!(
        body.matches(&before).count() == 1,
        "missing or ambiguous packed SHA round schedule"
    );
    let reordered = body.replace(&before, &format!("{MOVES}{SIGMA0}"));
    source.replace_range(range, &reordered);
    Ok(())
}

pub(super) fn pack_graph_values(mut source: String) -> Result<String> {
    let range = function_range(&source, "_factoredWiring")?;
    let packed = super::packed_wiring::render(source[range.clone()].to_owned())?;
    source.replace_range(range, &packed);
    Ok(source)
}

/// Share the byte permutation up to 128-bit halves. Proof fields and sampled
/// challenges consume at most 16 bytes; paired reads can exchange their stores
/// instead of exchanging the halves. Keep the full 256-bit wrapper for Noir
/// public inputs. This is selected only after compiling the complete constructor.
pub(super) fn share_read_reversal(mut source: String) -> Result<String> {
    fn replace_once(body: &mut String, before: &str, after: &str) -> Result<()> {
        ensure!(
            body.matches(before).count() == 1,
            "missing or ambiguous byte-reversal expression: {before}"
        );
        *body = body.replacen(before, after, 1);
        Ok(())
    }

    ensure!(
        !source.contains("function _reverseHalves("),
        "byte-reversal helper already exists"
    );
    let range = function_range(&source, "_reverse")?;
    let mut half = source[range.clone()].to_owned();
    replace_once(&mut half, "function _reverse(", "function _reverseHalves(")?;
    replace_once(&mut half, "r := or(shl(128, x), shr(128, x))", "r := x")?;
    half.push_str(
        r#"

    function _reverse(uint256 x) private pure returns (uint256 r) {
        r = _reverseHalves(x);
        assembly ("memory-safe") { r := or(shl(128, r), shr(128, r)) }
    }"#,
    );
    source.replace_range(range, &half);
    for (name, replacements) in [
        (
            "_readLE",
            vec![(
                "return _reverse(v) &",
                "return (_reverseHalves(v) >> 128) &",
            )],
        ),
        (
            "_readFields",
            vec![
                ("word = _reverse(word);", "word = _reverseHalves(word);"),
                (
                    r#"mstore(dest, and(word, 0xffffffffffffffffffffffffffffffff))
                    mstore(add(dest, 32), shr(128, word))"#,
                    r#"mstore(dest, shr(128, word))
                    mstore(add(dest, 32), and(word, 0xffffffffffffffffffffffffffffffff))"#,
                ),
            ],
        ),
        (
            "_sample",
            vec![(
                "_reverse(uint256(m.sample) << (m.sampleIndex * 8))",
                "_reverseHalves(uint256(m.sample) << (m.sampleIndex * 8)) >> 128",
            )],
        ),
    ] {
        let range = function_range(&source, name)?;
        let mut body = source[range.clone()].to_owned();
        for (before, after) in replacements {
            replace_once(&mut body, before, after)?;
        }
        source.replace_range(range, &body);
    }
    Ok(source)
}

/// Each oracle uses one challenge range for every coset. Compute its common
/// scale once, retaining the original final multiplication at both caller
/// assignments. In particular, r=1 still uses the XOR fold and scale factor one.
/// No comparison or field operation on an individual folded value is removed.
pub(super) fn share_fri_scale(mut source: String) -> Result<String> {
    fn replace_once(body: &mut String, before: &str, after: &str) -> Result<()> {
        ensure!(
            body.matches(before).count() == 1,
            "missing or ambiguous FRI scale expression: {before}"
        );
        *body = body.replacen(before, after, 1);
        Ok(())
    }
    ensure!(
        !source.contains("function _friScale("),
        "FRI scale helper already exists"
    );
    let range = function_range(&source, "_friCoset")?;
    let mut coset = source[range.clone()].to_owned();
    replace_once(&mut coset, "        uint256 scale = 1;\n", "")?;
    replace_once(
        &mut coset,
        "                scale = _mul(scale, scalar);\n",
        "",
    )?;
    replace_once(
        &mut coset,
        "return _mul(values[0], scale);",
        "return values[0];",
    )?;
    source.replace_range(
        range,
        &format!("{}\n{coset}", include_str!("fri_scale.sol")),
    );
    let range = function_range(&source, "_fri")?;
    let mut caller = source[range.clone()].to_owned();
    let query_loop = "                for (uint256 q; q < s.indices.length; ++q) {\n                    uint256 index = s.indices[q] >> o.leafLog;";
    replace_once(
        &mut caller,
        query_loop,
        &format!(
            "                uint256 scale = _friScale(s.challenges, challengeOffset, o.leafLog);\n{query_loop}"
        ),
    )?;
    let terminal = "            uint256 finalValue;";
    replace_once(
        &mut caller,
        terminal,
        &format!(
            "            uint256 terminalScale = _friScale(s.challenges, challengeOffset, s.finalCount);\n{terminal}"
        ),
    )?;
    for (call, scale) in [
        (
            "_friCoset(s.work, o.leafLog, index, s.challenges, challengeOffset, s.basis)",
            "scale",
        ),
        (
            "_friCoset(s.work, s.finalCount, i, s.challenges, challengeOffset, s.basis)",
            "terminalScale",
        ),
    ] {
        replace_once(&mut caller, call, &format!("_mul({call}, {scale})"))?;
    }
    source.replace_range(range, &caller);
    Ok(source)
}

/// Recover all inverses in an oracle segment from one inverse of its nonzero
/// denominator product. Each packed normalized challenge is identical to the
/// original. A zero denominator contributes one to the product and recovers
/// inverse zero. The returned product replaces the preceding scale helper.
pub(super) fn batch_fri_inverses(mut source: String) -> Result<String> {
    let range = function_range(&source, "_normalizeFriChallenges")?;
    source.replace_range(range, include_str!("fri_batch.sol").trim_end());
    let range = function_range(&source, "_friScale")?;
    source.replace_range(range, "");

    let range = function_range(&source, "_fri")?;
    let mut caller = source[range.clone()].to_owned();
    let old = "            _normalizeFriChallenges(s.challenges, challengeOffset);\n";
    ensure!(
        caller.matches(old).count() == 1 && caller.matches("_friScale(").count() == 2,
        "missing or ambiguous FRI normalization and scale calls"
    );
    caller = caller
        .replacen(old, "", 1)
        .replace("_friScale(", "_normalizeFriChallenges(");
    source.replace_range(range, &caller);

    // _friConfig allocates 1 << maximum work words. Even a zero-round coset
    // has one word, initialized by _friRead before its final value is read.
    let range = function_range(&source, "_friCoset")?;
    let body = &source[range.clone()];
    let old = "return values[0];";
    ensure!(
        body.matches(old).count() == 1,
        "missing or ambiguous final FRI coset value"
    );
    let body = body.replacen(
        old,
        r#"uint256 result;
            // _friConfig allocates 1 << maximum words, including count=0.
            assembly ("memory-safe") { result := mload(add(values, 32)) }
            return result;"#,
        1,
    );
    source.replace_range(range, &body);
    Ok(source)
}

/// Gather the identical seven big-endian input words in reverse lane order.
/// Successive 37-bit shifts leave five zero guard bits between each u32;
/// the highest occupied bit is 253, so no input bit is truncated.
pub(super) fn gather_sha_words(mut source: String) -> Result<String> {
    let range = function_range(&source, "_compressBatch")?;
    source.replace_range(range, include_str!("sha_gather.sol").trim_end());
    Ok(source)
}

/// Load each SHA state word once. Machine's state and digest arrays have
/// separate allocations, and gathering writes only the digest array.
pub(super) fn load_sha_digest_words(mut source: String) -> Result<String> {
    let range = function_range(&source, "_digestBatch")?;
    source.replace_range(range, include_str!("sha_digest.sol").trim_end());
    Ok(source)
}

/// The input rows are canonical 128-bit field values. The first butterfly
/// swaps their middle 64-bit quarters before packing; remaining stages use
/// the same pairs at byte offsets. Distinct pair addresses permit retaining
/// both loaded words until their writes, with the allocation unchanged.
pub(super) fn transpose_with_byte_offsets(mut source: String) -> Result<String> {
    let range = function_range(&source, "_transpose")?;
    source.replace_range(range, include_str!("transpose.sol").trim_end());
    Ok(source)
}

/// Replace x XOR (x AND mask) with x AND NOT(mask) in the packed SHA
/// rotation helper. This identity holds for all 256 input bits, so it
/// preserves the exact old word, including its lane and guard bits.
pub(super) fn mask_sha_rotations(mut source: String) -> Result<String> {
    let range = function_range(&source, "_shaMix")?;
    let body = &source[range.clone()];
    let old = r#"                let low := and(x, mul(rep, sub(shl(n, 1), 1)))
                z := or(shr(n, xor(x, low)), shl(sub(32, n), low))"#;
    let replacement = r#"                let lowMask := mul(rep, sub(shl(n, 1), 1))
                z := or(shr(n, and(x, not(lowMask))), shl(sub(32, n), and(x, lowMask)))"#;
    ensure!(
        body.matches(old).count() == 1,
        "missing or ambiguous packed SHA rotation"
    );
    let body = body.replacen(old, replacement, 1);
    source.replace_range(range, &body);
    Ok(source)
}

/// Keep the selected rotation identity and every round expression. The new
/// offset takes exactly 0, 32, ..., 2016, equal to the former index times 32.
pub(super) fn sha_round_byte_offsets(mut source: String) -> Result<String> {
    let range = function_range(&source, "_shaMix")?;
    let body = &source[range.clone()];
    let old = "for { let i := 0 } lt(i, 64) { i := add(i, 1) }";
    ensure!(
        body.matches(old).count() == 1
            && body.matches("shl(5, i)").count() == 2
            && body.contains("shr(n, and(x, not(lowMask)))"),
        "missing or ambiguous masked SHA round loop"
    );
    let body = body
        .replacen(old, "for { let p := 0 } lt(p, 2048) { p := add(p, 32) }", 1)
        .replace("shl(5, i)", "p");
    source.replace_range(range, &body);
    Ok(source)
}

/// Reserve an owned, call-local SHA arena before allocating the program. Fixed
/// addresses let the compiler remove pointer loads from the unchanged hash
/// expressions. The guard protects its low-memory stack-spill allocation.
pub(super) fn fixed_sha_arena(mut source: String) -> Result<String> {
    ensure!(
        !source.contains("_reserveSha("),
        "SHA arena already reserved"
    );
    let marker = "    struct Machine {";
    ensure!(
        source.matches(marker).count() == 1,
        "missing unique Machine"
    );
    let start = source.find(marker).unwrap() + marker.len();
    let end = start + source[start..].find('}').context("unterminated Machine")?;
    let fields: Vec<_> = source[start..end]
        .lines()
        .map(|line| line.split("//").next().unwrap().trim())
        .filter(|line| !line.is_empty())
        .collect();
    ensure!(
        fields
            == [
                "bytes observed;",
                "uint256 observedLength;",
                "bytes32 sample;",
                "uint256 sampleIndex;",
                "bool sampling;",
                "bytes scratch;",
                "uint256[80] hashConstants;",
                "uint256[64] schedule;",
                "uint256[8] hashState;",
                "bytes32[7] batchDigests;",
                "uint256 hashMask;",
                "uint256 hashRepeat;",
                "uint256[8] hashWork;",
                "uint256 nodeCache;",
                "uint256 hintAt;",
                "uint256 hintEnd;",
                "uint256 hintQueue;",
            ],
        "SHA arena requires the checked Machine field offsets"
    );
    for (name, expected) in [
        ("_machine", 1),
        ("_shaMix", 3),
        ("_shaMixScalar", 3),
        ("_shaRounds", 2),
        ("_hashInit", 2),
        ("_compress", 1),
        ("_compressBatch", 1),
        ("_digestBatch", 1),
    ] {
        let range = function_range(&source, name)?;
        let mut body = source[range.clone()].to_owned();
        let mut count = 0;
        for (before, after) in [
            (
                "uint256[80] memory constants = m.hashConstants;",
                "uint256 constants = 0x1000;",
            ),
            ("uint256[64] memory w = m.schedule;", "uint256 w = 0x1a00;"),
            (
                "uint256[8] memory state = m.hashState;",
                "uint256 state = 0x2200;",
            ),
            (
                "uint256[8] memory state = m.hashWork;",
                "uint256 state = 0x2300;",
            ),
            (
                "uint256[8] memory work = m.hashWork;",
                "uint256 work = 0x2300;",
            ),
        ] {
            let occurrences = body.matches(before).count();
            ensure!(occurrences <= 1, "ambiguous SHA pointer in {name}");
            count += occurrences;
            body = body.replace(before, after);
        }
        ensure!(count == expected, "missing SHA pointers in {name}");
        if name == "_machine" {
            let marker = "        m.hashMask = SHA_WORD_MASK;";
            ensure!(
                body.matches(marker).count() == 1,
                "missing SHA initialization"
            );
            body = body.replacen(
                marker,
                &format!(
                    r#"
        assembly ("memory-safe") {{
            mstore(add(m, 192), 0x1000)
            mstore(add(m, 224), 0x1a00)
            mstore(add(m, 256), 0x2200)
            mstore(add(m, 384), 0x2300)
        }}
{marker}"#
                ),
                1,
            );
        }
        source.replace_range(range, &body);
    }
    let entry = "external view override returns (bool)\n    {";
    ensure!(
        source.matches(entry).count() == 1,
        "missing unique verify body"
    );
    source = source.replacen(entry, &format!("{entry}\n        _reserveSha();\n"), 1);
    let mut source = source.trim_end().to_owned();
    ensure!(source.pop() == Some('}'), "missing verifier closing brace");
    source.push_str(
        r#"
    // The generated verifier has one Machine and performs no external calls.
    // Reserve before program decoding: constants [0x1000,0x1a00), schedule
    // [0x1a00,0x2200), state [0x2200,0x2300), work [0x2300,0x2400).
    // Own the prefix from the old free pointer, plus a final spare word, and
    // explicitly clear the arena rather than assuming recycled memory is zero.
    function _reserveSha() private pure {
        assembly ("memory-safe") {
            if gt(mload(0x40), 0x1000) { revert(0, 0) }
            mstore(0x40, 0x2420)
            calldatacopy(0x1000, calldatasize(), 5120)
        }
    }

}
"#,
    );
    Ok(source)
}

/// The pinned compiler starts these runtimes with PUSH2 free; PUSH1 0x40;
/// MSTORE. Accept only this known prologue and an aligned allocation below the
/// arena. An unfamiliar or larger allocation keeps the unmodified verifier.
pub(super) fn fixed_sha_entry_fits(runtime: &[u8]) -> bool {
    if runtime.len() < 6 || runtime[0] != 0x61 || runtime[3..6] != [0x60, 0x40, 0x52] {
        return false;
    }
    let free = u16::from_be_bytes([runtime[1], runtime[2]]);
    (128..=4096).contains(&free) && free % 32 == 0
}

/// Cache only the expanded schedule of a padding-only block shared by all seven
/// lanes. Its complete input is fixed by the circuit's bounded message length.
/// Never cache a digest or state: every compression still runs all 64 rounds.
pub(super) fn cache_sha_padding(mut source: String) -> Result<String> {
    let range = function_range(&source, "_reserveSha")?;
    let body = &source[range.clone()];
    let allocation = "mstore(0x40, 0x2420)";
    let clear = "calldatacopy(0x1000, calldatasize(), 5120)";
    ensure!(
        body.matches(allocation).count() == 1 && body.matches(clear).count() == 1,
        "padding cache requires the original fixed SHA allocation"
    );
    // Request/key words precede 48 cached schedule words. Keep a final guard.
    // Clearing the enlarged owned region also initializes the cache as invalid.
    let body = body
        .replace(allocation, "mstore(0x40, 0x2a80)")
        .replace(clear, "calldatacopy(0x1000, calldatasize(), 6784)");
    source.replace_range(range, &body);

    let range = function_range(&source, "_leavesBatch")?;
    let body = &source[range.clone()];
    let call = "                _compressBatch(m, data + blockOffset, padded);";
    ensure!(body.matches(call).count() == 1, "missing leaf compression");
    let replacement = r#"                if (count == 7 && (length & 63) == 0 && blockOffset + 64 == padded) {
                    assembly ("memory-safe") { mstore(0x2420, add(length, 1)) }
                }
                _compressBatch(m, data + blockOffset, padded);"#;
    let body = body.replacen(call, replacement, 1);
    source.replace_range(range, &body);

    let range = function_range(&source, "_shaMix")?;
    let body = &source[range.clone()];
    ensure!(
        body.contains("uint256 w = 0x1a00;") && !body.contains("paddingKey"),
        "padding cache requires the unchanged fixed SHA schedule"
    );
    let start_marker = "            for { let p := add(w, 512)";
    let end_marker = "            let a := mload(state)";
    ensure!(
        body.matches(start_marker).count() == 1 && body.matches(end_marker).count() == 1,
        "missing unique SHA expansion and rounds"
    );
    let start = body.find(start_marker).unwrap();
    let end = body.find(end_marker).unwrap();
    ensure!(start < end, "SHA expansion must precede compression rounds");
    let expansion = body[start..end].replacen(
        "let p := add(w, 512)",
        "let p := add(add(w, 512), mul(cached, 1536))",
        1,
    );
    let replacement = format!(
        r#"            {{
                let paddingKey := mload(0x2420)
                mstore(0x2420, 0)
                let requested := iszero(iszero(paddingKey))
                let cached := and(requested, eq(paddingKey, mload(0x2440)))
                if cached {{ mcopy(0x1c00, 0x2460, 1536) }}
{expansion}                if and(requested, iszero(cached)) {{
                    mcopy(0x2460, 0x1c00, 1536)
                    mstore(0x2440, paddingKey)
                }}
            }}
"#
    );
    let body = format!("{}{}{}", &body[..start], replacement, &body[end..]);
    source.replace_range(range, &body);
    Ok(source)
}

#[cfg(test)]
mod fixed_sha_tests {
    use super::{cache_sha_padding, fixed_sha_arena, fixed_sha_entry_fits};

    #[test]
    fn compiler_allocation_must_fit_before_the_arena() {
        for free in [128u16, 448, 512, 4096] {
            let [hi, lo] = free.to_be_bytes();
            assert!(fixed_sha_entry_fits(&[0x61, hi, lo, 0x60, 0x40, 0x52]));
        }
        for free in [0u16, 96, 449, 4097, 4128, 65504] {
            let [hi, lo] = free.to_be_bytes();
            assert!(!fixed_sha_entry_fits(&[0x61, hi, lo, 0x60, 0x40, 0x52]));
        }
    }

    #[test]
    fn unknown_or_truncated_entry_cannot_select_fixed_addresses() {
        let prologue = [0x61, 0x01, 0xc0, 0x60, 0x40, 0x52];
        for end in 0..prologue.len() {
            assert!(!fixed_sha_entry_fits(&prologue[..end]));
        }
        for at in [0, 3, 4, 5] {
            let mut changed = prologue;
            changed[at] ^= 1;
            assert!(!fixed_sha_entry_fits(&changed));
        }
    }

    #[test]
    fn padding_cache_rejects_incompatible_allocation_or_schedule() {
        let source = format!(
            "contract Test {{\n{}\n    function verify() external view override returns (bool)\n    {{ return true; }}\n}}",
            include_str!("runtime.sol")
        );
        let source = fixed_sha_arena(source).unwrap();
        let cached = cache_sha_padding(source.clone()).unwrap();
        assert!(cache_sha_padding(cached).is_err());
        for (before, after) in [
            ("mstore(0x40, 0x2420)", "mstore(0x40, 0x2400)"),
            (
                "calldatacopy(0x1000, calldatasize(), 5120)",
                "calldatacopy(0x1000, calldatasize(), 4096)",
            ),
            ("uint256 w = 0x1a00;", "uint256 w = 0x1800;"),
            (
                "_compressBatch(m, data + blockOffset, padded);",
                "_compressBatch(m, data, padded);",
            ),
        ] {
            assert!(source.contains(before));
            assert!(cache_sha_padding(source.replace(before, after)).is_err());
        }
    }
}

fn function_range(source: &str, name: &str) -> Result<std::ops::Range<usize>> {
    let marker = format!("    function {name}(");
    ensure!(
        source.matches(&marker).count() == 1,
        "missing unique function {name}"
    );
    let start = source.find(&marker).expect("checked function marker");
    let brace = start + source[start..].find('{').context("missing function body")?;
    let mut depth = 0usize;
    for (at, byte) in source.bytes().enumerate().skip(brace) {
        match byte {
            b'{' => depth += 1,
            b'}' => depth -= 1,
            _ => {}
        }
        if depth == 0 {
            return Ok(start..at + 1);
        }
    }
    anyhow::bail!("unterminated function {name}")
}
