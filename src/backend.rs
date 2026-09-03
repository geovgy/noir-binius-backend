use std::{fs, path::Path};

use acir::{FieldElement, native_types::WitnessStack};
use anyhow::{Context, Result, ensure};
use binius_hash::StdHashSuite;
use binius_prover::{OptimalPackedB128, zk_config::ZKProver};
use binius_transcript::{ProverTranscript, VerifierTranscript};
use binius_verifier::{config::StdChallenger, zk_config::ZKVerifier};
use noir_binius_verifier::field_to_hex;

use crate::{
    artifact::LoadedArtifact,
    proof::ProofBundle,
    recursive::{self, RecursiveInputs, VerificationKey},
    translate::{compile_program, words_from_u64},
};

pub struct CircuitInfo {
    pub noir_version: String,
    pub opcodes: usize,
    pub public_field_elements: usize,
}

/// A proof bundle together with the Noir-level public inputs it proves.
pub struct ProofResult {
    pub proof: ProofBundle,
    pub public_inputs: Vec<String>,
}

pub fn info(artifact_path: &Path) -> Result<CircuitInfo> {
    let artifact = LoadedArtifact::read(artifact_path)?;
    let compiled = compile_program(&artifact.program)?;
    Ok(CircuitInfo {
        noir_version: artifact.noir_version,
        opcodes: compiled.opcode_count,
        public_field_elements: compiled.public_witnesses.len(),
    })
}

pub fn prove(
    artifact_path: &Path,
    witness_path: &Path,
    proof_path: &Path,
    log_inv_rate: u32,
) -> Result<ProofBundle> {
    Ok(prove_with_public_inputs(artifact_path, witness_path, proof_path, log_inv_rate)?.proof)
}

pub fn prove_with_public_inputs(
    artifact_path: &Path,
    witness_path: &Path,
    proof_path: &Path,
    log_inv_rate: u32,
) -> Result<ProofResult> {
    ensure!(log_inv_rate > 0, "log inverse rate must be at least one");
    let artifact = LoadedArtifact::read(artifact_path)?;
    let compiled = compile_program(&artifact.program)?;
    let witness_bytes = fs::read(witness_path)
        .with_context(|| format!("failed to read Nargo witness {}", witness_path.display()))?;
    let mut witness_stack = WitnessStack::<FieldElement>::deserialize(&witness_bytes)
        .with_context(|| format!("failed to decode Nargo witness {}", witness_path.display()))?;
    let values = compiled.populate_stack(&mut witness_stack)?;
    let public_words: Vec<_> = values.inout().iter().map(|word| word.as_u64()).collect();
    compiled
        .verify_recursive_calls(&public_words)
        .context("recursive proof preflight verification failed")?;
    let verifier = ZKVerifier::<StdHashSuite>::setup(
        compiled.circuit.constraint_system().clone(),
        log_inv_rate as usize,
    )
    .context("failed to set up the Binius ZK verifier")?;
    let prover = ZKProver::<OptimalPackedB128, StdHashSuite>::setup(&verifier)
        .context("failed to set up the Binius ZK prover")?;
    let mut transcript = ProverTranscript::new(StdChallenger::default());
    prover
        .prove(&values, rand::rng(), &mut transcript)
        .context("Binius ZK proof generation failed")?;
    let bundle = ProofBundle {
        circuit_digest: artifact.digest,
        log_inv_rate,
        public_words,
        transcript: transcript.finalize(),
    };
    bundle.write(proof_path)?;
    let public_inputs = noir_public_inputs(&compiled, &bundle.public_words)?;
    Ok(ProofResult {
        proof: bundle,
        public_inputs,
    })
}

pub fn verify(artifact_path: &Path, proof_path: &Path) -> Result<ProofBundle> {
    Ok(verify_with_public_inputs(artifact_path, proof_path)?.proof)
}

pub fn verify_with_public_inputs(artifact_path: &Path, proof_path: &Path) -> Result<ProofResult> {
    let artifact = LoadedArtifact::read(artifact_path)?;
    let bundle = ProofBundle::read(proof_path)?;
    ensure!(
        bundle.circuit_digest == artifact.digest,
        "proof was created for a different Noir artifact"
    );
    let compiled = compile_program(&artifact.program)?;
    ensure!(
        bundle.public_words.len() == compiled.expected_public_word_count(),
        "proof contains {} public words, translated circuit expects {}",
        bundle.public_words.len(),
        compiled.expected_public_word_count()
    );
    let verifier = ZKVerifier::<StdHashSuite>::setup(
        compiled.circuit.constraint_system().clone(),
        bundle.log_inv_rate as usize,
    )
    .context("failed to set up the Binius ZK verifier")?;
    let public_words = words_from_u64(&bundle.public_words);
    let mut transcript =
        VerifierTranscript::new(StdChallenger::default(), bundle.transcript.clone());
    verifier
        .verify(&public_words, &mut transcript)
        .context("Binius ZK proof verification failed")?;
    transcript
        .finalize()
        .context("Binius verifier did not consume the complete proof transcript")?;
    compiled
        .verify_recursive_calls(&bundle.public_words)
        .context("delegated recursive proof verification failed")?;
    let public_inputs = noir_public_inputs(&compiled, &bundle.public_words)?;
    Ok(ProofResult {
        proof: bundle,
        public_inputs,
    })
}

pub fn verification_key(artifact_path: &Path, log_inv_rate: u32) -> Result<Vec<u8>> {
    ensure!(log_inv_rate > 0, "log inverse rate must be at least one");
    let artifact = LoadedArtifact::read(artifact_path)?;
    let compiled = compile_program(&artifact.program)?;
    let verifier = ZKVerifier::<StdHashSuite>::setup(
        compiled.circuit.constraint_system().clone(),
        log_inv_rate as usize,
    )
    .context("failed to construct the Binius verification key")?;
    VerificationKey::new(artifact.digest, compiled.recursive.clone(), verifier).encode()
}

pub fn recursive_inputs(artifact_path: &Path, proof_path: &Path) -> Result<RecursiveInputs> {
    let artifact = LoadedArtifact::read(artifact_path)?;
    let bundle = verify(artifact_path, proof_path)?;
    let compiled = compile_program(&artifact.program)?;
    let verifier = ZKVerifier::<StdHashSuite>::setup(
        compiled.circuit.constraint_system().clone(),
        bundle.log_inv_rate as usize,
    )
    .context("failed to construct the recursive Binius verification key")?;
    let key = VerificationKey::new(artifact.digest, compiled.recursive.clone(), verifier);
    recursive::recursive_inputs(&key, &bundle)
}

fn noir_public_inputs(
    compiled: &crate::translate::CompiledCircuit,
    public_words: &[u64],
) -> Result<Vec<String>> {
    Ok(compiled
        .recursive
        .noir_public_values(public_words)?
        .into_iter()
        .map(field_to_hex)
        .collect())
}
