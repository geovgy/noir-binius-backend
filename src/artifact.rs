use std::{fs, path::Path};

use acir::{FieldElement, circuit::Program};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Deserializer};

#[derive(Deserialize)]
struct NoirArtifact {
    noir_version: String,
    #[serde(deserialize_with = "deserialize_program")]
    bytecode: Program<FieldElement>,
}

fn deserialize_program<'de, D>(deserializer: D) -> Result<Program<FieldElement>, D::Error>
where
    D: Deserializer<'de>,
{
    Program::deserialize_program_base64(deserializer)
}

/// The parts of a Nargo program artifact needed by the backend.
pub struct LoadedArtifact {
    pub noir_version: String,
    pub program: Program<FieldElement>,
    pub digest: [u8; 32],
}

impl LoadedArtifact {
    pub fn read(path: &Path) -> Result<Self> {
        let bytes = fs::read(path)
            .with_context(|| format!("failed to read Noir artifact {}", path.display()))?;
        let parsed: NoirArtifact = serde_json::from_slice(&bytes)
            .with_context(|| format!("failed to decode Noir artifact {}", path.display()))?;
        ensure!(
            parsed.bytecode.functions.len() == 1,
            "only single-function ACIR programs are currently supported; artifact contains {} functions",
            parsed.bytecode.functions.len()
        );
        Ok(Self {
            noir_version: parsed.noir_version,
            program: parsed.bytecode,
            digest: *blake3::hash(&bytes).as_bytes(),
        })
    }
}
