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
        /// Use solc 0.8.35 to generate factored wiring and compress the complete
        /// runtime for one deployment. Trades higher deployment gas for lower
        /// verification gas; emitted source requires the documented settings.
        #[arg(
            long = "solidity_compiler",
            alias = "solidity-compiler",
            alias = "solc"
        )]
        solidity_compiler: Option<PathBuf>,
    },
    /// Write a direct verifier deployment artifact with Solidity ABI/source
    /// and compact Yul creation code. Deploy its bytecode with no arguments.
    #[command(
        name = "write_verifier_deployment",
        visible_alias = "write-verifier-deployment"
    )]
    WriteVerifierDeployment {
        #[arg(short = 'k', long = "vk_path", alias = "vk-path")]
        verification_key: PathBuf,
        /// JSON artifact containing ABI, bytecode and both source forms.
        #[arg(short = 'o', long = "output_path", alias = "output-path")]
        output: PathBuf,
        /// Path to the solc 0.8.35 executable used during generation.
        #[arg(
            long = "solidity_compiler",
            alias = "solidity-compiler",
            alias = "solc"
        )]
        solidity_compiler: PathBuf,
    },
    /// Add optional, contract-checked SHA hints to a native proof for direct Solidity verification.
    #[command(name = "write_solidity_proof", visible_alias = "write-solidity-proof")]
    WriteSolidityProof {
        /// Portable verification key created by `write-vk`.
        #[arg(short = 'k', long = "vk_path", alias = "vk-path")]
        verification_key: PathBuf,
        /// Original NBINZK01 proof created by `prove`.
        #[arg(short = 'p', long)]
        proof: PathBuf,
        /// Output proof with checked hash hints for the generated contract.
        #[arg(short = 'o', long = "output_path", alias = "output-path")]
        output: PathBuf,
        /// Optionally include the generated artifact's authenticated public circuit data.
        #[arg(long = "deployment_path", alias = "deployment-path")]
        deployment: Option<PathBuf>,
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
            solidity_compiler,
        } => {
            let key = fs::read(&verification_key).with_context(|| {
                format!(
                    "failed to read Binius verification key {}",
                    verification_key.display()
                )
            })?;
            let source = if let Some(compiler) = solidity_compiler {
                noir_binius::solidity::generate_verifier_with_compiler(
                    &key,
                    verifier_target.as_str(),
                    &compiler,
                )?
            } else {
                noir_binius::solidity::generate_verifier(&key, verifier_target.as_str())?
            };
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
        Command::WriteVerifierDeployment {
            verification_key,
            output,
            solidity_compiler,
        } => {
            let key = fs::read(&verification_key)
                .with_context(|| format!("failed to read {}", verification_key.display()))?;
            let artifact =
                noir_binius::solidity::generate_verifier_deployment(&key, &solidity_compiler)?;
            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create {}", parent.display()))?;
            }
            let json = serde_json::to_vec_pretty(&artifact)?;
            fs::write(&output, json)
                .with_context(|| format!("failed to write {}", output.display()))?;
            println!(
                "Verifier deployment written to {} ({} initcode bytes, {} runtime bytes; no constructor arguments)",
                output.display(),
                artifact.initcode_bytes,
                artifact.runtime_bytes
            );
        }
        Command::WriteSolidityProof {
            verification_key,
            proof,
            output,
            deployment,
        } => {
            let key = fs::read(&verification_key)
                .with_context(|| format!("failed to read {}", verification_key.display()))?;
            let native =
                fs::read(&proof).with_context(|| format!("failed to read {}", proof.display()))?;
            let prepared = noir_binius::solidity::prepare_solidity_proof(&key, &native)?;
            let hint_bytes = prepared.len() - native.len() - 8;
            let prepared = if let Some(path) = deployment {
                let artifact: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&path).with_context(|| {
                        format!("failed to read deployment {}", path.display())
                    })?)?;
                noir_binius::solidity::with_verifier_program(&artifact, &prepared)?
            } else {
                prepared
            };
            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create {}", parent.display()))?;
            }
            fs::write(&output, &prepared)
                .with_context(|| format!("failed to write {}", output.display()))?;
            println!(
                "Solidity proof written to {} ({} total bytes; {} native bytes; {} SHA hint bytes)",
                output.display(),
                prepared.len(),
                native.len(),
                hint_bytes
            );
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
    fn deployment_command_requires_compiler_and_accepts_path_aliases() {
        for name in ["write_verifier_deployment", "write-verifier-deployment"] {
            let cli = Cli::try_parse_from([
                "noir-binius",
                name,
                "--vk-path",
                "key",
                "--output-path",
                "deployment.json",
                "--solc",
                "/local tools/solc 0.8.35",
            ])
            .unwrap();
            let Command::WriteVerifierDeployment {
                verification_key,
                output,
                solidity_compiler,
            } = cli.command
            else {
                panic!("wrong command");
            };
            assert_eq!(verification_key.to_str(), Some("key"));
            assert_eq!(output.to_str(), Some("deployment.json"));
            assert_eq!(solidity_compiler.to_str(), Some("/local tools/solc 0.8.35"));
        }
        assert!(
            Cli::try_parse_from([
                "noir-binius",
                "write_verifier_deployment",
                "-k",
                "key",
                "-o",
                "deployment.json",
            ])
            .is_err()
        );
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
