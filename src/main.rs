use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use noir_binius::backend;

#[derive(Parser)]
#[command(
    name = "noir-binius",
    version,
    about = "Prove Noir ACIR circuits with zero-knowledge Binius64 proofs"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Validate and summarize the supported portion of a compiled Noir circuit.
    Info {
        /// Nargo's target/<package>.json program artifact.
        #[arg(short = 'b', long = "bytecode")]
        artifact: PathBuf,
    },
    /// Generate a zero-knowledge Binius proof from a Noir artifact and Nargo witness.
    Prove {
        /// Nargo's target/<package>.json program artifact.
        #[arg(short = 'b', long = "bytecode")]
        artifact: PathBuf,
        /// Nargo's target/<witness>.gz witness stack.
        #[arg(short = 'w', long)]
        witness: PathBuf,
        /// Output proof bundle.
        #[arg(short = 'o', long, default_value = "target/proof.binius")]
        output: PathBuf,
        /// log2 of the inverse Reed-Solomon rate.
        #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..))]
        log_inv_rate: u32,
    },
    /// Verify a zero-knowledge Binius proof against its compiled Noir circuit.
    Verify {
        /// Nargo's target/<package>.json program artifact.
        #[arg(short = 'b', long = "bytecode")]
        artifact: PathBuf,
        /// Proof bundle created by `noir-binius prove`.
        #[arg(short = 'p', long)]
        proof: PathBuf,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Info { artifact } => {
            let info = backend::info(&artifact)?;
            println!("Noir version: {}", info.noir_version);
            println!("ACIR opcodes: {}", info.opcodes);
            println!("Public field elements: {}", info.public_field_elements);
            println!("Circuit is supported");
        }
        Command::Prove {
            artifact,
            witness,
            output,
            log_inv_rate,
        } => {
            let proof = backend::prove(&artifact, &witness, &output, log_inv_rate)?;
            println!(
                "Proof written to {} ({} bytes)",
                output.display(),
                proof.transcript.len()
            );
        }
        Command::Verify { artifact, proof } => {
            backend::verify(&artifact, &proof)?;
            println!("Proof verified successfully");
        }
    }
    Ok(())
}
