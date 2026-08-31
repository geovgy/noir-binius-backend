use std::{fs, path::Path};

use acir::{FieldElement, native_types::WitnessStack};
use anyhow::{Context, Result, ensure};
use binius_hash::StdHashSuite;
use binius_prover::{OptimalPackedB128, zk_config::ZKProver};
use binius_transcript::{ProverTranscript, VerifierTranscript};
use binius_verifier::{config::StdChallenger, zk_config::ZKVerifier};

use crate::{
    artifact::LoadedArtifact,
    proof::ProofBundle,
    translate::{compile, words_from_u64},
};

pub struct CircuitInfo {
    pub noir_version: String,
    pub opcodes: usize,
    pub public_field_elements: usize,
}

pub fn info(artifact_path: &Path) -> Result<CircuitInfo> {
    let artifact = LoadedArtifact::read(artifact_path)?;
    let compiled = compile(&artifact.program.functions[0])?;
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
    ensure!(log_inv_rate > 0, "log inverse rate must be at least one");
    let artifact = LoadedArtifact::read(artifact_path)?;
    let compiled = compile(&artifact.program.functions[0])?;
    let witness_bytes = fs::read(witness_path)
        .with_context(|| format!("failed to read Nargo witness {}", witness_path.display()))?;
    let mut witness_stack = WitnessStack::<FieldElement>::deserialize(&witness_bytes)
        .with_context(|| format!("failed to decode Nargo witness {}", witness_path.display()))?;
    ensure!(
        witness_stack.length() == 1,
        "only a one-frame Nargo witness stack is currently supported; found {} frames",
        witness_stack.length()
    );
    let stack_item = witness_stack.pop().expect("length was checked");
    ensure!(
        stack_item.index == 0,
        "witness stack is for ACIR function {}, expected function 0",
        stack_item.index
    );

    let public_words = compiled.public_words(&stack_item.witness)?;
    let values = compiled.populate(&stack_item.witness)?;
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
    Ok(bundle)
}

pub fn verify(artifact_path: &Path, proof_path: &Path) -> Result<ProofBundle> {
    let artifact = LoadedArtifact::read(artifact_path)?;
    let bundle = ProofBundle::read(proof_path)?;
    ensure!(
        bundle.circuit_digest == artifact.digest,
        "proof was created for a different Noir artifact"
    );
    let compiled = compile(&artifact.program.functions[0])?;
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
    Ok(bundle)
}
