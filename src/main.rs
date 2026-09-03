use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use noir_binius::backend;
use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonProofData<'a> {
    public_inputs: &'a [String],
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum SolidityVerifierTarget {
    Evm,
    EvmSp1,
}

impl SolidityVerifierTarget {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Evm => "evm",
            Self::EvmSp1 => "evm-sp1",
        }
    }
}

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
        /// Print the Noir public inputs as machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Verify a zero-knowledge Binius proof against its compiled Noir circuit.
    Verify {
        /// Nargo's target/<package>.json program artifact.
        #[arg(short = 'b', long = "bytecode")]
        artifact: PathBuf,
        /// Proof bundle created by `noir-binius prove`.
        #[arg(short = 'p', long)]
        proof: PathBuf,
        /// Print the verified Noir public inputs as machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Write the portable Binius verification key for a Noir circuit.
    #[command(name = "write_vk", visible_alias = "write-vk")]
    WriteVk {
        /// Nargo's target/<package>.json program artifact.
        #[arg(
            short = 'b',
            long = "bytecode_path",
            aliases = ["bytecode", "bytecode-path"]
        )]
        artifact: PathBuf,
        /// Output verification-key file.
        #[arg(
            short = 'o',
            long = "output_path",
            aliases = ["output", "output-path"]
        )]
        output: PathBuf,
        /// Accepted for Noir backend compatibility; both targets share the same Binius key.
        #[arg(
            short = 't',
            long = "verifier_target",
            alias = "verifier-target",
            default_value = "evm"
        )]
        verifier_target: SolidityVerifierTarget,
        /// log2 of the inverse Reed-Solomon rate.
        #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..))]
        log_inv_rate: u32,
    },
    /// Write a circuit-specific Solidity verifier for a Binius verification key.
    #[command(
        name = "write_solidity_verifier",
        visible_alias = "write-solidity-verifier"
    )]
    WriteSolidityVerifier {
        /// Portable verification key created by `write-vk`.
        #[arg(short = 'k', long = "vk_path", alias = "vk-path")]
        verification_key: PathBuf,
        /// Solidity source output path.
        #[arg(short = 'o', long = "output_path", alias = "output-path")]
        output: PathBuf,
        /// Verifier format: `evm` for a raw Binius proof or `evm-sp1` for its SP1 wrapper.
        #[arg(
            short = 't',
            long = "verifier_target",
            alias = "verifier-target",
            default_value = "evm"
        )]
        verifier_target: SolidityVerifierTarget,
        /// Accepted for compatibility; generated contracts use their optimized implementation.
        #[arg(long)]
        optimized: bool,
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
            json,
        } => {
            let result =
                backend::prove_with_public_inputs(&artifact, &witness, &output, log_inv_rate)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string(&JsonProofData {
                        public_inputs: &result.public_inputs,
                    })?
                );
            } else {
                println!(
                    "Proof written to {} ({} bytes)",
                    output.display(),
                    result.proof.transcript.len()
                );
            }
        }
        Command::Verify {
            artifact,
            proof,
            json,
        } => {
            let result = backend::verify_with_public_inputs(&artifact, &proof)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string(&JsonProofData {
                        public_inputs: &result.public_inputs,
                    })?
                );
            } else {
                println!("Proof verified successfully");
            }
        }
        Command::WriteVk {
            artifact,
            output,
            verifier_target: _,
            log_inv_rate,
        } => {
            let key = backend::verification_key(&artifact, log_inv_rate)?;
            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                fs::create_dir_all(parent).with_context(|| {
                    format!(
                        "failed to create verification-key directory {}",
                        parent.display()
                    )
                })?;
            }
            fs::write(&output, &key)
                .with_context(|| format!("failed to write {}", output.display()))?;
            println!(
                "Verification key written to {} ({} bytes)",
                output.display(),
                key.len()
            );
        }
        Command::WriteSolidityVerifier {
            verification_key,
            output,
            verifier_target,
            optimized: _,
        } => {
            let key = fs::read(&verification_key).with_context(|| {
                format!(
                    "failed to read Binius verification key {}",
                    verification_key.display()
                )
            })?;
            let source = noir_binius::solidity::generate_verifier(&key, verifier_target.as_str())?;
            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                fs::create_dir_all(parent).with_context(|| {
                    format!("failed to create Solidity directory {}", parent.display())
                })?;
            }
            fs::write(&output, source)
                .with_context(|| format!("failed to write {}", output.display()))?;
            println!("Solidity verifier written to {}", output.display());
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

#[cfg(test)]
mod tests {
    use super::{Cli, Command, SolidityVerifierTarget};
    use clap::Parser;

    #[test]
    fn solidity_command_uses_noir_compatible_names_and_default_target() {
        let cli = Cli::try_parse_from([
            "noir-binius",
            "write_solidity_verifier",
            "-k",
            "target/vk",
            "-o",
            "target/Verifier.sol",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::WriteSolidityVerifier {
                verifier_target: SolidityVerifierTarget::Evm,
                ..
            }
        ));

        let cli = Cli::try_parse_from([
            "noir-binius",
            "write-solidity-verifier",
            "--vk-path",
            "target/vk",
            "--output-path",
            "target/Verifier.sol",
            "--verifier-target",
            "evm-sp1",
            "--optimized",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::WriteSolidityVerifier {
                verifier_target: SolidityVerifierTarget::EvmSp1,
                optimized: true,
                ..
            }
        ));
    }

    #[test]
    fn write_vk_accepts_noir_compatible_paths_and_target() {
        let cli = Cli::try_parse_from([
            "noir-binius",
            "write_vk",
            "--bytecode_path",
            "target/circuit.json",
            "--output_path",
            "target/vk",
            "--verifier_target",
            "evm-sp1",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::WriteVk {
                verifier_target: SolidityVerifierTarget::EvmSp1,
                ..
            }
        ));
    }

    #[test]
    fn solidity_command_rejects_unknown_target() {
        assert!(
            Cli::try_parse_from([
                "noir-binius",
                "write_solidity_verifier",
                "-k",
                "target/vk",
                "-o",
                "target/Verifier.sol",
                "--verifier_target",
                "unknown",
            ])
            .is_err()
        );
    }
}
