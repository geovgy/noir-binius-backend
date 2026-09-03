use std::{fs, path::PathBuf};

use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand, ValueEnum};
use noir_binius_verifier::{ProofBundle, Sp1Proof, VerificationKey, field_to_be_bytes};
use sha2::{Digest, Sha256};
use sp1_sdk::{
    Elf, HashableKey, ProvingKey, SP1Stdin,
    blocking::{ProveRequest, Prover, ProverClient},
};

const SP1_PROGRAM_VKEY: &str = "0x007b717f916736f7e7262338cf6bd36aca5e9b93a390cf67ed11139db7c31aa7";
const SP1_PROGRAM_ELF_SHA256: [u8; 32] = [
    0x3f, 0x10, 0xd5, 0x4a, 0x4b, 0x7a, 0x11, 0x61, 0x0e, 0xb1, 0x56, 0x85, 0x2f, 0x66, 0x4a, 0x41,
    0x3c, 0xca, 0xe1, 0x43, 0x5e, 0x86, 0xc9, 0x75, 0xb5, 0x3a, 0x0d, 0x52, 0x4d, 0xc8, 0x76, 0x05,
];

#[derive(Parser)]
#[command(
    name = "noir-binius-sp1",
    version,
    about = "Generate an EVM-efficient SP1 wrapper around a noir-binius proof"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Execute the verifier guest without generating a proof.
    Execute(InputArgs),
    /// Generate a Groth16 or PLONK proof accepted by the SP1 Solidity verifier.
    Prove {
        #[command(flatten)]
        input: InputArgs,
        /// Output noir-binius Solidity proof envelope.
        #[arg(short = 'o', long = "output_path", alias = "output-path")]
        output: PathBuf,
        /// SP1 on-chain proof system.
        #[arg(long, value_enum, default_value = "groth16")]
        system: ProofSystem,
    },
}

#[derive(clap::Args)]
struct InputArgs {
    /// ELF built from `sp1/guest` with `cargo prove build`.
    #[arg(long)]
    elf: PathBuf,
    /// Portable verification key created by `noir-binius write-vk`.
    #[arg(short = 'k', long = "vk_path", alias = "vk-path")]
    verification_key: PathBuf,
    /// Native Binius proof created by `noir-binius prove`.
    #[arg(short = 'p', long = "proof_path", alias = "proof-path")]
    proof: PathBuf,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ProofSystem {
    Groth16,
    Plonk,
}

struct PreparedInput {
    elf: Elf,
    stdin: SP1Stdin,
    public_inputs: Vec<[u64; 4]>,
    expected_public_values: Vec<u8>,
}

fn main() -> Result<()> {
    sp1_sdk::utils::setup_logger();
    match Cli::parse().command {
        Command::Execute(input) => {
            let prepared = prepare(input)?;
            let client = ProverClient::from_env();
            let (public_values, report) = client
                .execute(prepared.elf, prepared.stdin)
                .run()
                .context("SP1 guest execution failed")?;
            ensure!(
                public_values.as_slice() == prepared.expected_public_values,
                "SP1 guest committed unexpected public values"
            );
            println!(
                "SP1 guest verified the Binius proof in {} instructions",
                report.total_instruction_count()
            );
        }
        Command::Prove {
            input,
            output,
            system,
        } => {
            let prepared = prepare(input)?;
            let client = ProverClient::from_env();
            let proving_key = client
                .setup(prepared.elf)
                .context("failed to set up the SP1 guest")?;
            ensure!(
                proving_key.verifying_key().bytes32() == SP1_PROGRAM_VKEY,
                "SP1 guest verification key changed; rebuild the backend constants"
            );
            let proof = match system {
                ProofSystem::Groth16 => client.prove(&proving_key, prepared.stdin).groth16().run(),
                ProofSystem::Plonk => client.prove(&proving_key, prepared.stdin).plonk().run(),
            }
            .context("SP1 wrapper proof generation failed")?;
            ensure!(
                proof.public_values.as_slice() == prepared.expected_public_values,
                "SP1 proof contains unexpected public values"
            );
            client
                .verify(&proof, proving_key.verifying_key(), None)
                .context("generated SP1 proof did not verify")?;
            let sp1_proof = proof.bytes();
            ensure!(
                !sp1_proof.is_empty(),
                "the SP1 mock prover cannot produce an on-chain proof; use cpu, cuda, or network"
            );
            Sp1Proof {
                public_inputs: prepared.public_inputs,
                sp1_proof,
            }
            .write(&output)?;
            println!("Solidity proof written to {}", output.display());
        }
    }
    Ok(())
}

fn prepare(input: InputArgs) -> Result<PreparedInput> {
    let elf_bytes = fs::read(&input.elf)
        .with_context(|| format!("failed to read SP1 guest ELF {}", input.elf.display()))?;
    ensure!(
        Sha256::digest(&elf_bytes)[..] == SP1_PROGRAM_ELF_SHA256,
        "SP1 guest ELF does not match this backend release; build sp1/guest with SP1 6.6.0 and --locked"
    );
    let verification_key_bytes = fs::read(&input.verification_key).with_context(|| {
        format!(
            "failed to read Binius verification key {}",
            input.verification_key.display()
        )
    })?;
    let proof_bytes = fs::read(&input.proof)
        .with_context(|| format!("failed to read Binius proof {}", input.proof.display()))?;
    let verification_key = VerificationKey::decode(&verification_key_bytes)?;
    let proof = ProofBundle::decode(&proof_bytes)?;
    verification_key
        .verify_bundle(&proof)
        .context("refusing to wrap an invalid Binius proof")?;
    let public_inputs = verification_key.noir_public_values(&proof)?;
    let mut public_input_bytes = Vec::with_capacity(public_inputs.len() * 32);
    for &value in &public_inputs {
        public_input_bytes.extend_from_slice(&field_to_be_bytes(value));
    }
    let mut expected_public_values = Vec::with_capacity(64);
    expected_public_values.extend_from_slice(&Sha256::digest(&verification_key_bytes));
    expected_public_values.extend_from_slice(&Sha256::digest(&public_input_bytes));
    let mut stdin = SP1Stdin::new();
    stdin.write(&verification_key_bytes);
    stdin.write(&proof_bytes);
    Ok(PreparedInput {
        elf: Elf::from(elf_bytes),
        stdin,
        public_inputs,
        expected_public_values,
    })
}
