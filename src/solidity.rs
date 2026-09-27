use anyhow::{Context, Result, bail, ensure};
use noir_binius_verifier::{FieldRef, VerificationKey, field_to_be_bytes};
use sha2::{Digest, Sha256};

mod codec;
mod construction;
mod deployment;
mod derived_wiring;
mod factor_wiring;
mod grouped_wiring;
mod hints;
mod packed_wiring;
mod product_wiring;
mod program;
mod program_input;
mod public_wiring;
mod sha_stack;
mod short_wiring;
mod storage;
mod yul_deployment;

pub use construction::{ConstructionInfo, PrivateGroupingInfo, PublicExpansionInfo, StorageInfo};
pub use hints::prepare_solidity_proof;
pub use program_input::{ProgramInputInfo, with_verifier_program};
pub use sha_stack::RuntimeCompilation;
pub use yul_deployment::VerifierDeployment;

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
    generate_verifier_inner(verification_key, verifier_target, false)
}

/// Generate the faster factored wiring representation, then compress the
/// complete compiler-produced runtime together with the fixed program. This
/// uses solc only during generation; deployment and verification are self-contained.
/// Compile the emitted source with the settings documented in its header.
pub fn generate_verifier_with_compiler(
    verification_key: &[u8],
    verifier_target: &str,
    compiler: &std::path::Path,
) -> Result<String> {
    ensure!(
        verifier_target == "evm",
        "runtime compression requires the direct evm target"
    );
    let key = VerificationKey::decode(verification_key)
        .context("cannot generate Solidity for an invalid Binius verification key")?;
    ensure!(
        key.metadata.calls.is_empty(),
        "direct EVM verification does not support delegated recursive proofs; use --verifier_target evm-sp1"
    );
    let key_hash = hex(&Sha256::digest(verification_key));
    let program = program::compile_with_factored_wiring(key.binius_verifier(), true)?;
    let source = render_direct_verifier(&key, &key_hash, true, &program)?;
    let baseline = deployment::compress_runtime_info(&source, compiler)?;
    let mut attempts = 0;
    for (saved_muls, candidate) in program::partition_candidates(&program) {
        let mut joint = codec::operands(&candidate.bytes, true, candidate.word_bytes);
        joint.extend_from_slice(&baseline.runtime);
        let estimate = baseline.creation_bytes as i64 + codec::compress(&joint).len() as i64
            - baseline.compressed_bytes as i64;
        // Constants can change compiler output and compression. Reserve margin
        // for that estimate, then compile the actual candidate independently.
        if estimate > 49_152 - 512 {
            continue;
        }
        let mut source = render_direct_verifier(&key, &key_hash, true, &candidate)?;
        source.insert_str(0, &format!("// Exact disjoint matrix partition; estimated saving: {saved_muls} generic field multiplications.\n"));
        match deployment::compress_runtime_info(&source, compiler) {
            Ok(compiled) => return Ok(compiled.source),
            Err(error) if error.downcast_ref::<deployment::SizeLimit>().is_some() => {
                attempts += 1;
                if attempts == 3 {
                    break;
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(baseline.source)
}

/// Generate an explicit deployment artifact with Solidity ABI/source and
/// compact Yul creation code. The runtime verifies the original Binius proof
/// directly. Deployment needs no arguments, verifier address or later uploads.
pub fn generate_verifier_deployment(
    verification_key: &[u8],
    compiler: &std::path::Path,
) -> Result<VerifierDeployment> {
    let key = VerificationKey::decode(verification_key)
        .context("cannot generate a deployment for an invalid Binius verification key")?;
    ensure!(
        key.metadata.calls.is_empty(),
        "direct EVM verification does not support delegated recursive proofs"
    );
    let key_hash = hex(&Sha256::digest(verification_key));
    let program = program::compile_with_factored_wiring(key.binius_verifier(), true)?;
    let source = render_direct_verifier(&key, &key_hash, true, &program)?;
    let baseline = yul_deployment::compile(&source, compiler)?;
    if let Some(mut plan) = program::with_constructed_matrix(&program) {
        let source = render_direct_verifier(&key, &key_hash, true, &plan.precursor)?;
        let source = construction::render_source(source, &plan)?;
        match yul_deployment::compile_with_construction(&source, compiler, Some(&plan)) {
            Ok(compiled) => {
                let baseline =
                    finish_constructed_deployment(&key, &key_hash, &mut plan, compiled, compiler)?;
                return finish_public_deployment(&key, &key_hash, &plan, baseline, compiler);
            }
            Err(error) if error.downcast_ref::<deployment::SizeLimit>().is_some() => {}
            Err(error) => return Err(error),
        }
    }
    let mut attempts = 0;
    for (saved_muls, candidate) in program::deployment_partition_candidates(&program) {
        let mut joint = codec::operands(&candidate.bytes, true, candidate.word_bytes);
        joint.extend_from_slice(&baseline.runtime);
        let estimate = baseline.artifact.initcode_bytes as i64
            + codec::compress(&joint).len() as i64
            - baseline.compressed_bytes as i64;
        if estimate > 49_152 - 512 {
            continue;
        }
        let mut source = render_direct_verifier(&key, &key_hash, true, &candidate)?;
        source.insert_str(0, &format!("// Exact disjoint matrix partition; estimated saving: {saved_muls} generic field multiplications.\n"));
        match yul_deployment::compile(&source, compiler) {
            Ok(compiled) => {
                return finish_deployment(&key, &key_hash, &candidate, compiled, compiler);
            }
            Err(error) if error.downcast_ref::<deployment::SizeLimit>().is_some() => {
                attempts += 1;
                if attempts == 3 {
                    break;
                }
            }
            Err(error) => return Err(error),
        }
    }
    finish_deployment(&key, &key_hash, &program, baseline, compiler)
}

fn finish_constructed_deployment(
    key: &VerificationKey,
    key_hash: &str,
    plan: &mut program::ConstructedProgram,
    baseline: yul_deployment::Compiled,
    compiler: &std::path::Path,
) -> Result<VerifierDeployment> {
    let encoded = codec::operands(&plan.precursor.bytes, true, plan.precursor.word_bytes);
    let mut candidates: Vec<_> = [8, 12, 16, 18, 20, 24, 32]
        .into_iter()
        .filter_map(|minimum| storage::construct(&plan.bytes, minimum))
        .filter(|candidate| candidate.estimated_saving > 0)
        .collect();
    candidates.sort_by(|a, b| {
        b.estimated_saving
            .cmp(&a.estimated_saving)
            .then(a.minimum_match.cmp(&b.minimum_match))
    });
    let mut attempts = 0;
    for candidate in candidates {
        let mut joint = encoded.clone();
        joint.extend_from_slice(&candidate.headers);
        joint.extend_from_slice(&baseline.runtime);
        let estimate = baseline.artifact.initcode_bytes as i64
            + codec::compress(&joint).len() as i64
            - baseline.compressed_bytes as i64
            + 512;
        // Reserve space for the copying constructor and runtime decoder. The
        // estimate never replaces compilation or its actual code-size checks.
        if estimate > 49_152 - 128 {
            continue;
        }
        plan.storage = Some(candidate);
        let source = render_direct_verifier(key, key_hash, true, &plan.precursor)?;
        let source = construction::render_source(source, plan)?;
        match yul_deployment::compile_with_construction(&source, compiler, Some(plan)) {
            Ok(compiled) => return Ok(compiled.artifact),
            Err(error) if error.downcast_ref::<deployment::SizeLimit>().is_some() => {
                attempts += 1;
                if attempts == 3 {
                    break;
                }
            }
            Err(error) => return Err(error),
        }
    }
    plan.storage = None;
    Ok(baseline.artifact)
}

fn finish_public_deployment(
    key: &VerificationKey,
    key_hash: &str,
    original: &program::ConstructedProgram,
    baseline: VerifierDeployment,
    compiler: &std::path::Path,
) -> Result<VerifierDeployment> {
    let Some(mut plan) = program::with_constructed_public(original) else {
        return finish_private_deployment(key, key_hash, original, baseline, compiler);
    };
    let public = plan
        .public_expansion
        .as_ref()
        .expect("expanded public graph");
    // The public evaluator removes two predictive varint decoders per node.
    // Use a conservative selection estimate, including the changed cold
    // storage and storage-record counts. This estimate is not a proof check.
    let evaluation_saving = public.nodes as u64 * 300;
    let storage_cost = |bytes: usize, headers: usize| {
        bytes.div_ceil(32) as u64 * 2100 + (headers / 4) as u64 * 650
    };
    let old_cost = original.storage.as_ref().map_or_else(
        || storage_cost(original.bytes.len(), 0),
        |storage| storage_cost(storage.bytes.len(), storage.headers.len()),
    );
    let mut candidates: Vec<_> = [8, 12, 16, 18, 20, 24, 32]
        .into_iter()
        .filter_map(|minimum| storage::construct(&plan.bytes, minimum))
        .filter(|storage| {
            storage_cost(storage.bytes.len(), storage.headers.len())
                < old_cost.saturating_add(evaluation_saving)
        })
        .collect();
    candidates.sort_by_key(|storage| {
        (
            storage_cost(storage.bytes.len(), storage.headers.len()),
            storage.minimum_match,
        )
    });
    let runtime = deployment::decode_hex(&baseline.deployed_bytecode)?;
    let payload = baseline
        .solidity_source
        .split_once("_unlzma(hex\"")
        .and_then(|(_, suffix)| suffix.split_once('"').map(|(hex, _)| hex))
        .context("missing baseline constructor payload")?;
    ensure!(
        payload.len() % 2 == 0,
        "invalid baseline constructor payload length"
    );
    let overhead = baseline.initcode_bytes.saturating_sub(payload.len() / 2);
    let encoded = codec::operands(&plan.precursor.bytes, true, plan.precursor.word_bytes);
    let mut attempts = 0;
    for candidate in candidates {
        let mut joint = encoded.clone();
        joint.extend_from_slice(&candidate.headers);
        joint.extend_from_slice(&runtime);
        // Public expansion changes constructor code and shrinks the evaluator.
        // Avoid clearly oversized candidates; compile borderline candidates
        // and enforce the normal size limits on their actual bytecode below.
        if overhead + codec::compress(&joint).len() > 49_152 + 512 {
            continue;
        }
        plan.storage = Some(candidate);
        let source = render_direct_verifier(key, key_hash, true, &plan.precursor)?;
        let source = construction::render_source(source, &plan)?;
        match yul_deployment::compile_with_construction(&source, compiler, Some(&plan)) {
            Ok(compiled) => {
                return finish_private_deployment(
                    key,
                    key_hash,
                    &plan,
                    compiled.artifact,
                    compiler,
                );
            }
            Err(error) if error.downcast_ref::<deployment::SizeLimit>().is_some() => {
                attempts += 1;
                if attempts == 3 {
                    break;
                }
            }
            Err(error) => return Err(error),
        }
    }
    finish_private_deployment(key, key_hash, original, baseline, compiler)
}

fn finish_private_deployment(
    key: &VerificationKey,
    key_hash: &str,
    original: &program::ConstructedProgram,
    baseline: VerifierDeployment,
    compiler: &std::path::Path,
) -> Result<VerifierDeployment> {
    let Some(mut plan) = program::with_grouped_private(original) else {
        return finish_program_input_deployment(key, key_hash, original, baseline, compiler);
    };
    let grouping = plan
        .private_grouping
        .as_ref()
        .expect("grouped private matrix");
    // Group headers amortize the opcode branch and point load. Include cold
    // storage and decoding in selection; final compilation enforces all sizes.
    let evaluation_saving = grouping.nodes.saturating_sub(grouping.groups) as u64 * 80;
    let storage_cost = |bytes: usize, headers: usize| {
        bytes.div_ceil(32) as u64 * 2100 + (headers / 4) as u64 * 650
    };
    let old_cost = original.storage.as_ref().map_or_else(
        || storage_cost(original.bytes.len(), 0),
        |storage| storage_cost(storage.bytes.len(), storage.headers.len()),
    );
    let mut candidates: Vec<_> = [8, 12, 16, 18, 20, 24, 32]
        .into_iter()
        .filter_map(|minimum| storage::construct(&plan.bytes, minimum))
        .map(Some)
        .chain(std::iter::once(None))
        .filter(|storage| {
            storage.as_ref().map_or_else(
                || storage_cost(plan.bytes.len(), 0),
                |s| storage_cost(s.bytes.len(), s.headers.len()),
            ) < old_cost.saturating_add(evaluation_saving)
        })
        .collect();
    candidates.sort_by_key(|storage| {
        storage.as_ref().map_or_else(
            || (storage_cost(plan.bytes.len(), 0), usize::MAX),
            |s| {
                (
                    storage_cost(s.bytes.len(), s.headers.len()),
                    s.minimum_match,
                )
            },
        )
    });
    let runtime = deployment::decode_hex(&baseline.deployed_bytecode)?;
    let payload = baseline
        .solidity_source
        .split_once("_unlzma(hex\"")
        .and_then(|(_, rest)| rest.split_once('"').map(|(payload, _)| payload))
        .context("missing baseline constructor payload")?;
    ensure!(payload.len() % 2 == 0, "invalid baseline payload length");
    let overhead = baseline.initcode_bytes.saturating_sub(payload.len() / 2);
    let encoded = codec::operands(&plan.precursor.bytes, true, plan.precursor.word_bytes);
    for candidate in candidates {
        let mut joint = encoded.clone();
        if let Some(storage) = &candidate {
            joint.extend_from_slice(&storage.headers);
        }
        joint.extend_from_slice(&runtime);
        // The fused constructor and dual-format evaluator change the overhead.
        // This only skips clearly oversized plans; it never admits an artifact.
        if overhead + codec::compress(&joint).len() > 49_152 + 512 {
            continue;
        }
        plan.storage = candidate;
        let source = render_direct_verifier(key, key_hash, true, &plan.precursor)?;
        let source = construction::render_source(source, &plan)?;
        match yul_deployment::compile_with_construction(&source, compiler, Some(&plan)) {
            Ok(compiled) => {
                return finish_precommit_deployment(
                    key,
                    key_hash,
                    &plan,
                    compiled.artifact,
                    compiler,
                );
            }
            // There are at most seven storage plans plus the plain program.
            // Keep trying bounded smaller headers when an earlier plan fails;
            // stopping after three failures can miss the first fitting plan.
            Err(error) if error.downcast_ref::<deployment::SizeLimit>().is_some() => {}
            Err(error) => return Err(error),
        }
    }
    finish_program_input_deployment(key, key_hash, original, baseline, compiler)
}

fn finish_precommit_deployment(
    key: &VerificationKey,
    key_hash: &str,
    original: &program::ConstructedProgram,
    baseline: VerifierDeployment,
    compiler: &std::path::Path,
) -> Result<VerifierDeployment> {
    let Some(mut plan) = program::with_grouped_precommit(original) else {
        return finish_program_input_deployment(key, key_hash, original, baseline, compiler);
    };
    let grouping = plan
        .precommit_grouping
        .as_ref()
        .expect("grouped precommit matrix");
    // The ready queues retain every ordered equation. Grouping only amortizes
    // opcode decoding; include cold storage and unpacking in the selection cost.
    let evaluation_saving = grouping.nodes.saturating_sub(grouping.groups) as u64 * 80;
    let storage_cost = |bytes: usize, headers: usize| {
        bytes.div_ceil(32) as u64 * 2100 + (headers / 4) as u64 * 650
    };
    let old_cost = original.storage.as_ref().map_or_else(
        || storage_cost(original.bytes.len(), 0),
        |storage| storage_cost(storage.bytes.len(), storage.headers.len()),
    );
    let mut candidates: Vec<_> = [8, 12, 16, 18, 20, 24, 32]
        .into_iter()
        .filter_map(|minimum| storage::construct(&plan.bytes, minimum))
        .map(Some)
        .chain(std::iter::once(None))
        .filter(|storage| {
            storage.as_ref().map_or_else(
                || storage_cost(plan.bytes.len(), 0),
                |s| storage_cost(s.bytes.len(), s.headers.len()),
            ) < old_cost.saturating_add(evaluation_saving)
        })
        .collect();
    candidates.sort_by_key(|storage| {
        storage.as_ref().map_or_else(
            || (storage_cost(plan.bytes.len(), 0), usize::MAX),
            |s| {
                (
                    storage_cost(s.bytes.len(), s.headers.len()),
                    s.minimum_match,
                )
            },
        )
    });
    let runtime = deployment::decode_hex(&baseline.deployed_bytecode)?;
    let payload = baseline
        .solidity_source
        .split_once("_unlzma(hex\"")
        .and_then(|(_, rest)| rest.split_once('"').map(|(payload, _)| payload))
        .context("missing baseline constructor payload")?;
    ensure!(payload.len() % 2 == 0, "invalid baseline payload length");
    let overhead = baseline.initcode_bytes.saturating_sub(payload.len() / 2);
    let encoded = codec::operands(&plan.precursor.bytes, true, plan.precursor.word_bytes);
    for candidate in candidates {
        let mut joint = encoded.clone();
        if let Some(storage) = &candidate {
            joint.extend_from_slice(&storage.headers);
        }
        joint.extend_from_slice(&runtime);
        // The evaluator shrinks, while the differently ordered key data can
        // compress less well. Only compilation admits a candidate for use.
        if overhead + codec::compress(&joint).len() > 49_152 + 512 {
            continue;
        }
        plan.storage = candidate;
        let source = render_direct_verifier(key, key_hash, true, &plan.precursor)?;
        let source = construction::render_source(source, &plan)?;
        match yul_deployment::compile_with_construction(&source, compiler, Some(&plan)) {
            Ok(compiled) => {
                return finish_product_deployment(
                    key,
                    key_hash,
                    &plan,
                    compiled.artifact,
                    compiler,
                );
            }
            Err(error) if error.downcast_ref::<deployment::SizeLimit>().is_some() => {}
            Err(error) => return Err(error),
        }
    }
    finish_program_input_deployment(key, key_hash, original, baseline, compiler)
}

fn finish_product_deployment(
    key: &VerificationKey,
    key_hash: &str,
    original: &program::ConstructedProgram,
    baseline: VerifierDeployment,
    compiler: &std::path::Path,
) -> Result<VerifierDeployment> {
    let Some(mut plan) = program::with_product_terminals(original) else {
        return finish_program_input_deployment(key, key_hash, original, baseline, compiler);
    };
    let grouping = plan
        .private_grouping
        .as_ref()
        .expect("product terminal groups");
    let precommit = plan.precommit_grouping.as_ref().expect("grouped precommit");
    // The extra per-group format branch trades decoding work for fewer cold
    // storage words. This is a selection model; actual compilation enforces
    // both code limits and full EVM measurements validate the selected output.
    let evaluation_overhead = (grouping.groups + precommit.groups) as u64 * 40;
    let storage_cost = |bytes: usize, headers: usize| {
        bytes.div_ceil(32) as u64 * 2100 + (headers / 4) as u64 * 650
    };
    let old_cost = original.storage.as_ref().map_or_else(
        || storage_cost(original.bytes.len(), 0),
        |s| storage_cost(s.bytes.len(), s.headers.len()),
    );
    let mut candidates: Vec<_> = [8, 12, 16, 18, 20, 24, 32]
        .into_iter()
        .filter_map(|minimum| storage::construct(&plan.bytes, minimum))
        .map(Some)
        .chain(std::iter::once(None))
        .filter(|s| {
            s.as_ref()
                .map_or_else(
                    || storage_cost(plan.bytes.len(), 0),
                    |s| storage_cost(s.bytes.len(), s.headers.len()),
                )
                .saturating_add(evaluation_overhead)
                < old_cost
        })
        .collect();
    candidates.sort_by_key(|s| {
        s.as_ref().map_or_else(
            || (storage_cost(plan.bytes.len(), 0), usize::MAX),
            |s| {
                (
                    storage_cost(s.bytes.len(), s.headers.len()),
                    s.minimum_match,
                )
            },
        )
    });
    let runtime = deployment::decode_hex(&baseline.deployed_bytecode)?;
    let payload = baseline
        .solidity_source
        .split_once("_unlzma(hex\"")
        .and_then(|(_, rest)| rest.split_once('"').map(|(payload, _)| payload))
        .context("missing baseline constructor payload")?;
    ensure!(payload.len() % 2 == 0, "invalid baseline payload length");
    let overhead = baseline.initcode_bytes.saturating_sub(payload.len() / 2);
    let encoded = codec::operands(&plan.precursor.bytes, true, plan.precursor.word_bytes);
    for candidate in candidates {
        let mut joint = encoded.clone();
        if let Some(storage) = &candidate {
            joint.extend_from_slice(&storage.headers);
        }
        joint.extend_from_slice(&runtime);
        if overhead + codec::compress(&joint).len() > 49_152 + 512 {
            continue;
        }
        plan.storage = candidate;
        let source = render_direct_verifier(key, key_hash, true, &plan.precursor)?;
        let source = construction::render_source(source, &plan)?;
        match yul_deployment::compile_with_construction(&source, compiler, Some(&plan)) {
            Ok(compiled) => {
                return finish_program_input_deployment(
                    key,
                    key_hash,
                    &plan,
                    compiled.artifact,
                    compiler,
                );
            }
            Err(error) if error.downcast_ref::<deployment::SizeLimit>().is_some() => {}
            Err(error) => return Err(error),
        }
    }
    finish_program_input_deployment(key, key_hash, original, baseline, compiler)
}

/// Optional public circuit data replaces cold SLOADs only after the constructor's
/// fixed digest is checked. The storage choice that fits without this input may
/// leave too little constructor space for it. Try the other lossless encodings
/// before retaining the complete ordinary artifact.
fn finish_program_input_deployment(
    key: &VerificationKey,
    key_hash: &str,
    original: &program::ConstructedProgram,
    baseline: VerifierDeployment,
    compiler: &std::path::Path,
) -> Result<VerifierDeployment> {
    let mut plan = original.clone();
    plan.authenticated_program = true;
    let compile = |plan: &program::ConstructedProgram| {
        let source = render_direct_verifier(key, key_hash, true, &plan.precursor)?;
        let source = construction::render_source(source, plan)?;
        yul_deployment::compile_with_construction(&source, compiler, Some(plan))
    };
    match compile(&plan) {
        Ok(compiled) => {
            return finish_packed_graph_deployment(
                key,
                key_hash,
                &plan,
                compiled.artifact,
                compiler,
            );
        }
        Err(error) if error.downcast_ref::<deployment::SizeLimit>().is_some() => {}
        Err(error) => return Err(error),
    }
    // Longer matches generally need fewer constructor headers. This is only a
    // bounded search order: every candidate must pass the actual compiler's
    // initcode/runtime limits, runtime identity, and storage round-trip checks.
    let mut tried = vec![plan.storage.clone()];
    for minimum in [32, 24, 20, 18, 16, 12, 8, 0] {
        let candidate = if minimum == 0 {
            None
        } else if let Some(storage) = storage::construct(&plan.bytes, minimum) {
            Some(storage)
        } else {
            continue;
        };
        if tried.iter().any(|previous| match (previous, &candidate) {
            (Some(a), Some(b)) => a.bytes == b.bytes && a.headers == b.headers,
            (None, None) => true,
            _ => false,
        }) {
            continue;
        }
        tried.push(candidate.clone());
        plan.storage = candidate;
        match compile(&plan) {
            Ok(compiled) => {
                return finish_packed_graph_deployment(
                    key,
                    key_hash,
                    &plan,
                    compiled.artifact,
                    compiler,
                );
            }
            Err(error) if error.downcast_ref::<deployment::SizeLimit>().is_some() => {}
            Err(error) => return Err(error),
        }
    }
    finish_packed_graph_deployment(key, key_hash, original, baseline, compiler)
}

/// A final optional memory-layout optimization, after the storage and input
/// formats are selected. A storage encoding that just fits the ordinary layout
/// can leave too little initcode room for packed graph values. Try the other
/// lossless encodings before retaining the complete ordinary artifact; never
/// trade away authenticated program input to add this layout.
fn finish_packed_graph_deployment(
    key: &VerificationKey,
    key_hash: &str,
    plan: &program::ConstructedProgram,
    baseline: VerifierDeployment,
    compiler: &std::path::Path,
) -> Result<VerifierDeployment> {
    let Some(grouping) = &plan.private_grouping else {
        return Ok(baseline);
    };
    // Small graphs can spend more on packing than they save in memory gas.
    // This conservative selection threshold targets the measured large graphs;
    // compilation still enforces both code-size limits on every selected key.
    if grouping.kind != program::PrivateGroupingKind::ProductTerminals
        || plan.precommit_grouping.is_none()
        || grouping.nodes < 12_000
    {
        return Ok(baseline);
    }
    let source = construction::pack_graph_values(baseline.solidity_source.clone())?;
    match yul_deployment::compile_with_construction(&source, compiler, Some(plan)) {
        Ok(compiled) => {
            return finish_shared_read_deployment(key, key_hash, plan, compiled.artifact, compiler);
        }
        Err(error) if error.downcast_ref::<deployment::SizeLimit>().is_some() => {}
        Err(error) => return Err(error),
    }
    let mut alternative = plan.clone();
    let mut tried = vec![plan.storage.clone()];
    // As in authenticated-program selection, longer matches can reduce the
    // constructor's header data. Every attempt retains the identical logical
    // program, grouping, and authenticated-input option. Only actual compiled
    // sizes admit an artifact; a failed attempt cannot replace the baseline.
    for minimum in [32, 24, 20, 18, 16, 12, 8] {
        let Some(candidate) = storage::construct(&plan.bytes, minimum) else {
            continue;
        };
        if tried.iter().flatten().any(|previous| {
            previous.bytes == candidate.bytes && previous.headers == candidate.headers
        }) {
            continue;
        }
        tried.push(Some(candidate.clone()));
        alternative.storage = Some(candidate);
        let source = render_direct_verifier(key, key_hash, true, &alternative.precursor)?;
        let source = construction::render_source(source, &alternative)?;
        let source = construction::pack_graph_values(source)?;
        match yul_deployment::compile_with_construction(&source, compiler, Some(&alternative)) {
            Ok(compiled) => {
                return finish_shared_read_deployment(
                    key,
                    key_hash,
                    &alternative,
                    compiled.artifact,
                    compiler,
                );
            }
            Err(error) if error.downcast_ref::<deployment::SizeLimit>().is_some() => {}
            Err(error) => return Err(error),
        }
    }
    Ok(baseline)
}

/// The shared field/challenge reader saves byte swaps but can change compressed
/// constructor size in either direction. Accept only a complete, size-checked
/// artifact; retain the already compiled verifier on a real size failure. No
/// program, storage encoding, proof parameter or verification check is changed
/// by this reader trial. The next stage independently selects its storage plan.
fn finish_shared_read_deployment(
    key: &VerificationKey,
    key_hash: &str,
    plan: &program::ConstructedProgram,
    baseline: VerifierDeployment,
    compiler: &std::path::Path,
) -> Result<VerifierDeployment> {
    let source = construction::share_read_reversal(baseline.solidity_source.clone())?;
    let baseline = match yul_deployment::compile_with_construction(&source, compiler, Some(plan)) {
        Ok(compiled) => compiled.artifact,
        Err(error) if error.downcast_ref::<deployment::SizeLimit>().is_some() => baseline,
        Err(error) => return Err(error),
    };
    finish_fri_scale_deployment(key, key_hash, plan, baseline, compiler)
}

/// Reuse the common normalized FRI scale across queries. The existing lossless
/// storage format with longer minimum matches leaves constructor room for this
/// helper. Render from the matching plan and check the complete artifact; if it
/// exceeds either code-size limit, retain the preceding compiled verifier.
fn finish_fri_scale_deployment(
    key: &VerificationKey,
    key_hash: &str,
    original: &program::ConstructedProgram,
    baseline: VerifierDeployment,
    compiler: &std::path::Path,
) -> Result<VerifierDeployment> {
    let Some(storage) = storage::construct(&original.bytes, 40) else {
        return Ok(baseline);
    };
    let mut plan = original.clone();
    plan.storage = Some(storage);
    let source = render_direct_verifier(key, key_hash, true, &plan.precursor)?;
    let source = construction::render_source(source, &plan)?;
    let source = construction::pack_graph_values(source)?;
    let source = construction::share_read_reversal(source)?;
    let source = construction::share_fri_scale(source)?;
    match yul_deployment::compile_with_construction(&source, compiler, Some(&plan)) {
        Ok(compiled) => {
            let baseline = finish_fri_batch_deployment(&plan, compiled.artifact, compiler)?;
            finish_factored_precommit_deployment(key, key_hash, &plan, baseline, compiler)
        }
        Err(error) if error.downcast_ref::<deployment::SizeLimit>().is_some() => Ok(baseline),
        Err(error) => Err(error),
    }
}

/// Compile the factored fixed polynomial only after retaining the complete
/// preceding pipeline. A larger compressed payload must not discard earlier
/// SHA/FRI improvements when the factored artifact exceeds a size limit.
fn finish_factored_precommit_deployment(
    key: &VerificationKey,
    key_hash: &str,
    original: &program::ConstructedProgram,
    baseline: VerifierDeployment,
    compiler: &std::path::Path,
) -> Result<VerifierDeployment> {
    let Some(mut plan) = program::with_factored_precommit(original) else {
        return finish_fixed_sha_deployment(original, baseline, compiler);
    };
    let Some(storage) = storage::construct(&plan.bytes, 40) else {
        return finish_fixed_sha_deployment(original, baseline, compiler);
    };
    plan.storage = Some(storage);
    let source = render_direct_verifier(key, key_hash, true, &plan.precursor)?;
    let source = construction::render_source(source, &plan)?;
    let source = construction::pack_graph_values(source)?;
    let source = construction::share_read_reversal(source)?;
    let source = construction::share_fri_scale(source)?;
    let source = construction::batch_fri_inverses(source)?;
    let source = construction::gather_sha_words(source)?;
    let source = construction::load_sha_digest_words(source)?;
    let source = construction::transpose_with_byte_offsets(source)?;
    let source = construction::mask_sha_rotations(source)?;
    let source = construction::sha_round_byte_offsets(source)?;
    let compiled = match yul_deployment::compile_with_construction(&source, compiler, Some(&plan)) {
        Err(error)
            if error
                .downcast_ref::<deployment::SizeLimit>()
                .is_some_and(deployment::SizeLimit::is_initcode) =>
        {
            // Retain every existing stage and equation. Only after a real
            // initcode failure, try one additional lossless compression search.
            yul_deployment::compile_with_compressor(
                &source,
                compiler,
                Some(&plan),
                codec::compress_size_retry,
            )
        }
        result => result,
    };
    match compiled {
        Ok(compiled) => finish_fixed_sha_deployment(&plan, compiled.artifact, compiler),
        Err(error) if error.downcast_ref::<deployment::SizeLimit>().is_some() => {
            finish_fixed_sha_deployment(original, baseline, compiler)
        }
        Err(error) => Err(error),
    }
}

/// Use fixed addresses for the same SHA scratch after retaining all earlier
/// optimizations. Both success and fallback carry their own exact construction
/// plan. A failed size trial returns the preceding complete verifier.
fn finish_fixed_sha_deployment(
    plan: &program::ConstructedProgram,
    baseline: VerifierDeployment,
    compiler: &std::path::Path,
) -> Result<VerifierDeployment> {
    let source = construction::fixed_sha_arena(baseline.solidity_source.clone())?;
    let compiled = match yul_deployment::compile_with_construction(&source, compiler, Some(plan)) {
        Err(error)
            if error
                .downcast_ref::<deployment::SizeLimit>()
                .is_some_and(deployment::SizeLimit::is_initcode) =>
        {
            yul_deployment::compile_with_compressor(
                &source,
                compiler,
                Some(plan),
                codec::compress_size_retry,
            )
        }
        result => result,
    };
    match compiled {
        Ok(compiled) if construction::fixed_sha_entry_fits(&compiled.runtime) => {
            finish_sha_padding_deployment(plan, compiled.artifact, compiler)
        }
        // The runtime guard prevents overlap, while this eligibility check
        // avoids selecting a verifier that would always fail that guard.
        Ok(_) => Ok(baseline),
        Err(error) if error.downcast_ref::<deployment::SizeLimit>().is_some() => Ok(baseline),
        Err(error) => Err(error),
    }
}

/// The checked arena owns a padding-schedule cache for this invocation. Keep
/// the complete fixed-arena artifact when the extra implementation does not fit.
fn finish_sha_padding_deployment(
    plan: &program::ConstructedProgram,
    baseline: VerifierDeployment,
    compiler: &std::path::Path,
) -> Result<VerifierDeployment> {
    let source = construction::cache_sha_padding(baseline.solidity_source.clone())?;
    let compiled = match yul_deployment::compile_with_construction(&source, compiler, Some(plan)) {
        Err(error)
            if error
                .downcast_ref::<deployment::SizeLimit>()
                .is_some_and(deployment::SizeLimit::is_initcode) =>
        {
            yul_deployment::compile_with_compressor(
                &source,
                compiler,
                Some(plan),
                codec::compress_size_retry,
            )
        }
        result => result,
    };
    match compiled {
        Ok(compiled) if construction::fixed_sha_entry_fits(&compiled.runtime) => {
            finish_shared_interpolation_deployment(plan, compiled.artifact, compiler)
        }
        Ok(_) => Ok(baseline),
        Err(error) if error.downcast_ref::<deployment::SizeLimit>().is_some() => Ok(baseline),
        Err(error) => Err(error),
    }
}

/// Share only the existing packed interpolation body. Preserve the preceding
/// artifact and its construction plan when the complete candidate does not fit.
fn finish_shared_interpolation_deployment(
    plan: &program::ConstructedProgram,
    baseline: VerifierDeployment,
    compiler: &std::path::Path,
) -> Result<VerifierDeployment> {
    let source = construction::share_packed_interpolation(baseline.solidity_source.clone())?;
    let compiled = match yul_deployment::compile_with_construction(&source, compiler, Some(plan)) {
        Err(error)
            if error
                .downcast_ref::<deployment::SizeLimit>()
                .is_some_and(deployment::SizeLimit::is_initcode) =>
        {
            yul_deployment::compile_with_compressor(
                &source,
                compiler,
                Some(plan),
                codec::compress_size_retry,
            )
        }
        result => result,
    };
    match compiled {
        Ok(compiled) if construction::fixed_sha_entry_fits(&compiled.runtime) => {
            sha_stack::finish(plan, compiled.artifact, compiler)
        }
        Ok(_) => Ok(baseline),
        Err(error) if error.downcast_ref::<deployment::SizeLimit>().is_some() => Ok(baseline),
        Err(error) => Err(error),
    }
}

/// Batch each oracle's exact challenge inverses while retaining the common
/// scale and every original comparison. This changes only the runtime math
/// implementation; the matching construction/storage plan is preserved.
fn finish_fri_batch_deployment(
    plan: &program::ConstructedProgram,
    baseline: VerifierDeployment,
    compiler: &std::path::Path,
) -> Result<VerifierDeployment> {
    let source = construction::batch_fri_inverses(baseline.solidity_source.clone())?;
    let baseline = match yul_deployment::compile_with_construction(&source, compiler, Some(plan)) {
        Ok(compiled) => compiled.artifact,
        Err(error) if error.downcast_ref::<deployment::SizeLimit>().is_some() => baseline,
        Err(error) => return Err(error),
    };
    finish_sha_gather_deployment(plan, baseline, compiler)
}

/// Gather each SHA schedule word with a common 37-bit shift. This preserves
/// the seven native u32 lanes and every hash round; compile the full artifact
/// before selecting it, with the same construction and storage plan.
fn finish_sha_gather_deployment(
    plan: &program::ConstructedProgram,
    baseline: VerifierDeployment,
    compiler: &std::path::Path,
) -> Result<VerifierDeployment> {
    let source = construction::gather_sha_words(baseline.solidity_source.clone())?;
    let baseline = match yul_deployment::compile_with_construction(&source, compiler, Some(plan)) {
        Ok(compiled) => compiled.artifact,
        Err(error) if error.downcast_ref::<deployment::SizeLimit>().is_some() => baseline,
        Err(error) => return Err(error),
    };
    finish_sha_digest_deployment(plan, baseline, compiler)
}

/// Retain the eight immutable SHA state words while gathering digest lanes.
/// The output array is separate from the state array. Each output word and
/// byte permutation stays identical, including partial and scalar batches.
fn finish_sha_digest_deployment(
    plan: &program::ConstructedProgram,
    baseline: VerifierDeployment,
    compiler: &std::path::Path,
) -> Result<VerifierDeployment> {
    let source = construction::load_sha_digest_words(baseline.solidity_source.clone())?;
    let baseline = match yul_deployment::compile_with_construction(&source, compiler, Some(plan)) {
        Ok(compiled) => compiled.artifact,
        Err(error) if error.downcast_ref::<deployment::SizeLimit>().is_some() => baseline,
        Err(error) => return Err(error),
    };
    finish_transpose_deployment(plan, baseline, compiler)
}

/// Evaluate the same bit transpose using byte offsets and saved butterfly
/// inputs. Select it only after compiling its complete constructor/runtime.
fn finish_transpose_deployment(
    plan: &program::ConstructedProgram,
    baseline: VerifierDeployment,
    compiler: &std::path::Path,
) -> Result<VerifierDeployment> {
    let source = construction::transpose_with_byte_offsets(baseline.solidity_source.clone())?;
    let baseline = match yul_deployment::compile_with_construction(&source, compiler, Some(plan)) {
        Ok(compiled) => compiled.artifact,
        Err(error) if error.downcast_ref::<deployment::SizeLimit>().is_some() => baseline,
        Err(error) => return Err(error),
    };
    finish_sha_rotation_deployment(plan, baseline, compiler)
}

/// Clear rotation source bits with their complemented mask. The identity
/// x XOR (x AND mask) = x AND NOT(mask) holds for every EVM word; all SHA
/// rotations and lane guards remain identical. Check the complete artifact.
fn finish_sha_rotation_deployment(
    plan: &program::ConstructedProgram,
    baseline: VerifierDeployment,
    compiler: &std::path::Path,
) -> Result<VerifierDeployment> {
    let source = construction::mask_sha_rotations(baseline.solidity_source.clone())?;
    match yul_deployment::compile_with_construction(&source, compiler, Some(plan)) {
        Ok(compiled) => finish_sha_cursor_deployment(plan, compiled.artifact, compiler),
        Err(error) if error.downcast_ref::<deployment::SizeLimit>().is_some() => Ok(baseline),
        Err(error) => Err(error),
    }
}

/// After selecting the masked rotations, enumerate the same 64 round words
/// directly by byte offset. The previous rotation layout keeps its own path.
fn finish_sha_cursor_deployment(
    plan: &program::ConstructedProgram,
    baseline: VerifierDeployment,
    compiler: &std::path::Path,
) -> Result<VerifierDeployment> {
    let source = construction::sha_round_byte_offsets(baseline.solidity_source.clone())?;
    match yul_deployment::compile_with_construction(&source, compiler, Some(plan)) {
        Ok(compiled) => Ok(compiled.artifact),
        Err(error) if error.downcast_ref::<deployment::SizeLimit>().is_some() => Ok(baseline),
        Err(error) => Err(error),
    }
}

fn finish_deployment(
    key: &VerificationKey,
    key_hash: &str,
    program: &program::Program,
    baseline: yul_deployment::Compiled,
    compiler: &std::path::Path,
) -> Result<VerifierDeployment> {
    let Some(fixed) = program::with_fixed_factored_operands(program) else {
        return Ok(baseline.artifact);
    };
    let mut joint = codec::operands(&fixed.bytes, true, fixed.word_bytes);
    joint.extend_from_slice(&baseline.runtime);
    let estimate = baseline.artifact.initcode_bytes as i64 + codec::compress(&joint).len() as i64
        - baseline.compressed_bytes as i64;
    // This encoding removes two varint loops per matrix operation, but can
    // enlarge circuit data. Preserve the selected partition if it will not fit.
    // The estimate only avoids futile compiles; actual code limits still apply.
    if estimate > 49_152 - 256 {
        return Ok(baseline.artifact);
    }
    let source = render_direct_verifier(key, key_hash, true, &fixed)?;
    match yul_deployment::compile(&source, compiler) {
        Ok(compiled) => Ok(compiled.artifact),
        Err(error) if error.downcast_ref::<deployment::SizeLimit>().is_some() => {
            Ok(baseline.artifact)
        }
        Err(error) => Err(error),
    }
}

fn generate_verifier_inner(
    verification_key: &[u8],
    verifier_target: &str,
    factored_wiring: bool,
) -> Result<String> {
    let key = VerificationKey::decode(verification_key)
        .context("cannot generate Solidity for an invalid Binius verification key")?;
    let circuit_vkey_hash = hex(&Sha256::digest(verification_key));
    match verifier_target {
        "evm" => generate_direct_verifier(&key, &circuit_vkey_hash, factored_wiring),
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

fn generate_direct_verifier(
    key: &VerificationKey,
    key_hash: &str,
    factored_wiring: bool,
) -> Result<String> {
    ensure!(
        key.metadata.calls.is_empty(),
        "direct EVM verification does not support delegated recursive proofs; use --verifier_target evm-sp1"
    );
    let program = if factored_wiring {
        program::compile_with_factored_wiring(key.binius_verifier(), true)?
    } else {
        program::compile(key.binius_verifier())?
    };
    render_direct_verifier(key, key_hash, factored_wiring, &program)
}

fn render_direct_verifier(
    key: &VerificationKey,
    key_hash: &str,
    factored_wiring: bool,
    program: &program::Program,
) -> Result<String> {
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

    let header_length = public_word_count
        .checked_mul(8)
        .and_then(|length| length.checked_add(56))
        .context("Binius public-word region exceeds the address space")?;
    ensure!(
        program.proof_len > header_length,
        "Binius transcript must extend beyond its fixed public-word header"
    );
    let (compressed, encoded_length) = codec::pack(&program.bytes, program.word_bytes);
    // The compressed literal alone is a lower bound on creation bytecode.
    // Do not emit a purported single-deployment verifier when even its data
    // already exceeds the EVM initcode limit. Solc must check the final size.
    ensure!(
        compressed.len() < 49_152,
        "direct verifier circuit data compresses to {} bytes, exceeding the 49152-byte EVM initcode limit before executable code; this circuit cannot currently be generated for a single deployment",
        compressed.len()
    );
    let mut runtime = RUNTIME.replace(
        "true /* factored wiring */",
        if factored_wiring { "true" } else { "false" },
    );
    if program.fixed_factored_operands {
        // The recoding pass independently reconstructs every scalar equation
        // before this kernel is selected. Header varints retain their format;
        // only the two postorder back-reference streams become big-endian u16.
        for stream in ["A", "B"] {
            let old = format!("delta, stream{stream} := uv(stream{stream})");
            let new = format!(
                "delta := shr(240, mload(stream{stream}))\n                stream{stream} := add(stream{stream}, 2)"
            );
            ensure!(
                runtime.matches(&old).count() == 1,
                "missing factored operand decoder"
            );
            runtime = runtime.replace(&old, &new);
        }
    }
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
        .replace("{{PROGRAM_WORD_BYTES}}", &program.word_bytes.to_string())
        .replace("{{PROOF_LENGTH}}", &program.proof_len.to_string())
        .replace("{{HASH_CAPACITY}}", &program.hash_capacity.to_string())
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
                    // Envelope validation establishes this complete public-word
                    // region before calling the specialized input checks.
                    writeln!(code, "uint256 word{i};\nassembly (\"memory-safe\") {{ word{i} := calldataload(add(proof.offset, {start})) }}").unwrap();
                    format!("_reverse(word{i})")
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
        let error = super::prepare_solidity_proof(&test_key(true), &[]).unwrap_err();
        assert!(error.to_string().contains("delegated recursive proofs"));
        assert!(generate_verifier(&test_key(true), "evm-sp1").is_ok());
    }
}
