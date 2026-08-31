use std::{fs, path::Path};

use anyhow::{Context, Result, bail, ensure};

const MAGIC: &[u8; 8] = b"NBINZK01";

/// Portable wrapper around the raw Binius transcript and the public ACIR statement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofBundle {
    pub circuit_digest: [u8; 32],
    pub log_inv_rate: u32,
    pub public_words: Vec<u64>,
    pub transcript: Vec<u8>,
}

impl ProofBundle {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let public_len =
            u32::try_from(self.public_words.len()).context("too many public words to encode")?;
        let proof_len =
            u64::try_from(self.transcript.len()).context("proof is too large to encode")?;
        let mut out = Vec::with_capacity(
            MAGIC.len() + 32 + 4 + 4 + self.public_words.len() * 8 + 8 + self.transcript.len(),
        );
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.circuit_digest);
        out.extend_from_slice(&self.log_inv_rate.to_le_bytes());
        out.extend_from_slice(&public_len.to_le_bytes());
        for word in &self.public_words {
            out.extend_from_slice(&word.to_le_bytes());
        }
        out.extend_from_slice(&proof_len.to_le_bytes());
        out.extend_from_slice(&self.transcript);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        ensure!(
            cursor.take(8)? == MAGIC,
            "not a noir-binius proof (bad magic)"
        );
        let circuit_digest = cursor.array::<32>()?;
        let log_inv_rate = u32::from_le_bytes(cursor.array()?);
        ensure!(log_inv_rate > 0, "invalid zero log inverse rate");
        let public_len = u32::from_le_bytes(cursor.array()?) as usize;
        let public_bytes = public_len
            .checked_mul(8)
            .context("public input length overflow")?;
        ensure!(
            public_bytes <= cursor.remaining(),
            "truncated public inputs in proof bundle"
        );
        let mut public_words = Vec::with_capacity(public_len);
        for _ in 0..public_len {
            public_words.push(u64::from_le_bytes(cursor.array()?));
        }
        let proof_len = usize::try_from(u64::from_le_bytes(cursor.array()?))
            .context("proof length does not fit this platform")?;
        ensure!(
            proof_len == cursor.remaining(),
            "invalid proof transcript length"
        );
        let transcript = cursor.take(proof_len)?.to_vec();
        Ok(Self {
            circuit_digest,
            log_inv_rate,
            public_words,
            transcript,
        })
    }

    pub fn read(path: &Path) -> Result<Self> {
        let bytes =
            fs::read(path).with_context(|| format!("failed to read proof {}", path.display()))?;
        Self::decode(&bytes).with_context(|| format!("failed to decode proof {}", path.display()))
    }

    pub fn write(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create proof directory {}", parent.display())
            })?;
        }
        fs::write(path, self.encode()?)
            .with_context(|| format!("failed to write proof {}", path.display()))
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let Some(end) = self.position.checked_add(len) else {
            bail!("proof bundle offset overflow")
        };
        ensure!(end <= self.bytes.len(), "truncated proof bundle");
        let result = &self.bytes[self.position..end];
        self.position = end;
        Ok(result)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().expect("slice length was checked"))
    }
}

#[cfg(test)]
mod tests {
    use super::ProofBundle;

    #[test]
    fn proof_bundle_round_trip() {
        let bundle = ProofBundle {
            circuit_digest: [7; 32],
            log_inv_rate: 1,
            public_words: vec![1, u64::MAX, 42],
            transcript: vec![4, 5, 6, 7],
        };
        assert_eq!(
            ProofBundle::decode(&bundle.encode().unwrap()).unwrap(),
            bundle
        );
    }

    #[test]
    fn proof_bundle_rejects_trailing_data() {
        let bundle = ProofBundle {
            circuit_digest: [0; 32],
            log_inv_rate: 1,
            public_words: vec![],
            transcript: vec![1],
        };
        let mut encoded = bundle.encode().unwrap();
        encoded.push(2);
        assert!(ProofBundle::decode(&encoded).is_err());
    }
}
