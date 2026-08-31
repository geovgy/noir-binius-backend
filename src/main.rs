use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
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
    /// Encode a proof and verification key for Noir's recursive-aggregation API.
    RecursiveInputs {
        /// Nargo artifact used to create the proof.
        #[arg(short = 'b', long = "bytecode")]
        artifact: PathBuf,
        /// Verified proof bundle to encode.
        #[arg(short = 'p', long)]
        proof: PathBuf,
        /// Optional JSON output path; stdout is used when omitted.
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,
        /// Render Nargo-compatible Prover.toml instead of JSON.
        #[arg(long)]
        toml: bool,
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
        Command::RecursiveInputs {
            artifact,
            proof,
            output,
            toml,
        } => {
            let inputs = backend::recursive_inputs(&artifact, &proof)?;
            let rendered = if toml {
                inputs.to_toml()
            } else {
                serde_json::to_string_pretty(&inputs)?
            };
            if let Some(output) = output {
                if let Some(parent) = output.parent()
                    && !parent.as_os_str().is_empty()
                {
                    fs::create_dir_all(parent).with_context(|| {
                        format!("failed to create output directory {}", parent.display())
                    })?;
                }
                fs::write(&output, rendered)
                    .with_context(|| format!("failed to write {}", output.display()))?;
                println!("Recursive inputs written to {}", output.display());
            } else {
                println!("{rendered}");
            }
        }
    }
    Ok(())
}
