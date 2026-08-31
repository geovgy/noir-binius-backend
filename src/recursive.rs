use acir::{AcirField, FieldElement};
use anyhow::{Context, Result, bail, ensure};
use binius_core::word::Word;
use binius_hash::StdHashSuite;
use binius_transcript::VerifierTranscript;
use binius_utils::{DeserializeBytes, SerializeBytes};
use binius_verifier::{config::StdChallenger, zk_config::ZKVerifier};
use serde::Serialize;

use crate::{
    proof::ProofBundle,
    translate::{FIELD_LIMBS, words_from_u64},
};

const VK_MAGIC: &[u8; 8] = b"NBINVK01";
const FIELD_CHUNK_BYTES: usize = 31;
const MAX_RECURSION_DEPTH: usize = 32;

/// Backend-specific `proof_type` accepted by ACIR `RecursiveAggregation`.
pub const BINIUS_ZK_PROOF_TYPE: u32 = 0x4249_4e5a;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum FieldRef {
    Constant([u64; FIELD_LIMBS]),
    Public([u32; FIELD_LIMBS]),
}

impl FieldRef {
    pub(crate) fn constant(value: FieldElement) -> Self {
        Self::Constant(field_to_limbs(value))
    }

    pub(crate) const fn public(offsets: [u32; FIELD_LIMBS]) -> Self {
        Self::Public(offsets)
    }

    fn resolve(&self, public_words: &[u64]) -> Result<FieldElement> {
        let limbs = match self {
            Self::Constant(limbs) => *limbs,
            Self::Public(offsets) => {
                let mut limbs = [0; FIELD_LIMBS];
                for (limb, &offset) in limbs.iter_mut().zip(offsets) {
                    *limb = *public_words.get(offset as usize).with_context(|| {
                        format!("recursive public-word offset {offset} is missing")
                    })?;
                }
                limbs
            }
        };
        field_from_limbs(limbs)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RecursiveCallSpec {
    pub(crate) active_word: u32,
    pub(crate) proof_type: u32,
    pub(crate) verification_key: Vec<FieldRef>,
    pub(crate) proof: Vec<FieldRef>,
    pub(crate) public_inputs: Vec<FieldRef>,
    pub(crate) key_hash: FieldRef,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct RecursiveMetadata {
    pub(crate) noir_public_inputs: Vec<FieldRef>,
    pub(crate) calls: Vec<RecursiveCallSpec>,
}

impl RecursiveMetadata {
    pub(crate) fn noir_public_values(&self, public_words: &[u64]) -> Result<Vec<FieldElement>> {
        self.noir_public_inputs
            .iter()
            .map(|field| field.resolve(public_words))
            .collect()
    }

    pub(crate) fn verify_calls(&self, public_words: &[u64]) -> Result<()> {
        self.verify_calls_at_depth(public_words, 0)
    }

    fn verify_calls_at_depth(&self, public_words: &[u64], depth: usize) -> Result<()> {
        ensure!(
            depth < MAX_RECURSION_DEPTH,
            "recursive proof nesting exceeds {MAX_RECURSION_DEPTH} levels"
        );
        for (index, call) in self.calls.iter().enumerate() {
            let active = *public_words
                .get(call.active_word as usize)
                .with_context(|| format!("recursive call {index} has no activity word"))?;
            match active {
                0 => continue,
                value if value == Word::MSB_ONE.as_u64() => {}
                value => bail!("recursive call {index} has invalid activity word 0x{value:016x}"),
            }
            call.verify(public_words, depth)
                .with_context(|| format!("recursive call {index} failed"))?;
        }
        Ok(())
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        write_len(out, self.noir_public_inputs.len(), "Noir public-input")?;
        for field in &self.noir_public_inputs {
            field.encode(out);
        }
        write_len(out, self.calls.len(), "recursive-call")?;
        for call in &self.calls {
            out.extend_from_slice(&call.active_word.to_le_bytes());
            out.extend_from_slice(&call.proof_type.to_le_bytes());
            encode_field_refs(out, &call.verification_key)?;
            encode_field_refs(out, &call.proof)?;
            encode_field_refs(out, &call.public_inputs)?;
            call.key_hash.encode(out);
        }
        Ok(())
    }

    fn decode(cursor: &mut Cursor<'_>) -> Result<Self> {
        let noir_public_inputs = decode_field_refs(cursor)?;
        let call_count = cursor.u32()? as usize;
        ensure!(
            call_count <= cursor.remaining() / 10,
            "invalid recursive-call count"
        );
        let mut calls = Vec::with_capacity(call_count);
        for _ in 0..call_count {
            calls.push(RecursiveCallSpec {
                active_word: cursor.u32()?,
                proof_type: cursor.u32()?,
                verification_key: decode_field_refs(cursor)?,
                proof: decode_field_refs(cursor)?,
                public_inputs: decode_field_refs(cursor)?,
                key_hash: FieldRef::decode(cursor)?,
            });
        }
        Ok(Self {
            noir_public_inputs,
            calls,
        })
    }
}

impl RecursiveCallSpec {
    fn verify(&self, outer_public_words: &[u64], depth: usize) -> Result<()> {
        ensure!(
            self.proof_type == BINIUS_ZK_PROOF_TYPE,
            "unsupported recursive proof type 0x{:08x}",
            self.proof_type
        );
        let vk_fields = resolve_fields(&self.verification_key, outer_public_words)?;
        let proof_fields = resolve_fields(&self.proof, outer_public_words)?;
        let claimed_public_inputs = resolve_fields(&self.public_inputs, outer_public_words)?;
        let claimed_key_hash = self.key_hash.resolve(outer_public_words)?;
        let vk_bytes = unpack_bytes(&vk_fields, "verification key")?;
        ensure!(
            verification_key_hash(&vk_bytes) == claimed_key_hash,
            "recursive verification-key hash mismatch"
        );
        let key = VerificationKey::decode(&vk_bytes)?;
        let proof_bytes = unpack_bytes(&proof_fields, "proof")?;
        let proof = ProofBundle::decode(&proof_bytes).context("invalid recursive proof bundle")?;
        let actual_public_inputs = key
            .metadata
            .noir_public_values(&proof.public_words)
            .context("invalid recursive proof public inputs")?;
        ensure!(
            actual_public_inputs == claimed_public_inputs,
            "recursive proof public inputs do not match the ACIR inputs"
        );
        key.verify_bundle(&proof, depth + 1)
    }
}

impl FieldRef {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Constant(limbs) => {
                out.push(0);
                for limb in limbs {
                    out.extend_from_slice(&limb.to_le_bytes());
                }
            }
            Self::Public(offsets) => {
                out.push(1);
                for offset in offsets {
                    out.extend_from_slice(&offset.to_le_bytes());
                }
            }
        }
    }

    fn decode(cursor: &mut Cursor<'_>) -> Result<Self> {
        match cursor.u8()? {
            0 => {
                let mut limbs = [0; FIELD_LIMBS];
                for limb in &mut limbs {
                    *limb = cursor.u64()?;
                }
                field_from_limbs(limbs).context("non-canonical recursive constant")?;
                Ok(Self::Constant(limbs))
            }
            1 => {
                let mut offsets = [0; FIELD_LIMBS];
                for offset in &mut offsets {
                    *offset = cursor.u32()?;
                }
                Ok(Self::Public(offsets))
            }
            tag => bail!("invalid recursive field-reference tag {tag}"),
        }
    }
}

/// A portable verification key for delegated ACIR recursive aggregation.
pub(crate) struct VerificationKey {
    artifact_digest: [u8; 32],
    pub(crate) metadata: RecursiveMetadata,
    verifier: ZKVerifier<StdHashSuite>,
}

impl VerificationKey {
    pub(crate) const fn new(
        artifact_digest: [u8; 32],
        metadata: RecursiveMetadata,
        verifier: ZKVerifier<StdHashSuite>,
    ) -> Self {
        Self {
            artifact_digest,
            metadata,
            verifier,
        }
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let mut verifier_bytes = Vec::new();
        self.verifier
            .serialize(&mut verifier_bytes)
            .context("failed to serialize Binius ZK verifier")?;
        let mut out = Vec::new();
        out.extend_from_slice(VK_MAGIC);
        out.extend_from_slice(&self.artifact_digest);
        self.metadata.encode(&mut out)?;
        let len = u64::try_from(verifier_bytes.len()).context("verification key is too large")?;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&verifier_bytes);
        Ok(out)
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        ensure!(
            cursor.take(8)? == VK_MAGIC,
            "invalid Binius verification-key magic"
        );
        let artifact_digest = cursor.array::<32>()?;
        let metadata = RecursiveMetadata::decode(&mut cursor)?;
        let verifier_len = usize::try_from(cursor.u64()?)
            .context("verification-key length does not fit this platform")?;
        ensure!(
            verifier_len == cursor.remaining(),
            "invalid serialized verifier length"
        );
        let verifier = ZKVerifier::<StdHashSuite>::deserialize(cursor.take(verifier_len)?)
            .context("failed to deserialize Binius ZK verifier")?;
        Ok(Self {
            artifact_digest,
            metadata,
            verifier,
        })
    }

    fn verify_bundle(&self, proof: &ProofBundle, depth: usize) -> Result<()> {
        ensure!(
            proof.circuit_digest == self.artifact_digest,
            "recursive proof was created for a different circuit"
        );
        ensure!(
            proof.log_inv_rate as usize == self.verifier.log_inv_rate(),
            "recursive proof and verification key use different inverse rates"
        );
        ensure!(
            proof.public_words.len() == self.verifier.constraint_system().n_inout,
            "recursive proof has {} public words, expected {}",
            proof.public_words.len(),
            self.verifier.constraint_system().n_inout
        );
        let words = words_from_u64(&proof.public_words);
        let mut transcript =
            VerifierTranscript::new(StdChallenger::default(), proof.transcript.clone());
        self.verifier
            .verify(&words, &mut transcript)
            .context("recursive Binius ZK proof verification failed")?;
        transcript
            .finalize()
            .context("recursive verifier did not consume the complete proof")?;
        self.metadata
            .verify_calls_at_depth(&proof.public_words, depth)
    }
}

/// Copy-pasteable values for Noir's `verify_proof_with_type` API.
#[derive(Clone, Debug, Serialize)]
pub struct RecursiveInputs {
    pub verification_key: Vec<String>,
    pub proof: Vec<String>,
    pub public_inputs: Vec<String>,
    pub key_hash: String,
    pub proof_type: u32,
}

impl RecursiveInputs {
    /// Renders these fields as a Nargo `Prover.toml` file.
    pub fn to_toml(&self) -> String {
        fn array(out: &mut String, name: &str, values: &[String]) {
            out.push_str(name);
            out.push_str(" = [\n");
            for value in values {
                out.push_str("    \"");
                out.push_str(value);
                out.push_str("\",\n");
            }
            out.push_str("]\n\n");
        }

        let mut out = String::new();
        array(&mut out, "verification_key", &self.verification_key);
        array(&mut out, "proof", &self.proof);
        array(&mut out, "public_inputs", &self.public_inputs);
        out.push_str("key_hash = \"");
        out.push_str(&self.key_hash);
        out.push_str("\"\n");
        out
    }
}

pub(crate) fn recursive_inputs(
    key: &VerificationKey,
    proof: &ProofBundle,
) -> Result<RecursiveInputs> {
    let key_bytes = key.encode()?;
    let proof_bytes = proof.encode()?;
    let public_inputs = key.metadata.noir_public_values(&proof.public_words)?;
    Ok(RecursiveInputs {
        verification_key: fields_to_strings(&pack_bytes(&key_bytes)),
        proof: fields_to_strings(&pack_bytes(&proof_bytes)),
        public_inputs: fields_to_strings(&public_inputs),
        key_hash: verification_key_hash(&key_bytes).to_short_hex(),
        proof_type: BINIUS_ZK_PROOF_TYPE,
    })
}

fn resolve_fields(fields: &[FieldRef], public_words: &[u64]) -> Result<Vec<FieldElement>> {
    fields
        .iter()
        .map(|field| field.resolve(public_words))
        .collect()
}

fn encode_field_refs(out: &mut Vec<u8>, fields: &[FieldRef]) -> Result<()> {
    write_len(out, fields.len(), "recursive field")?;
    for field in fields {
        field.encode(out);
    }
    Ok(())
}

fn decode_field_refs(cursor: &mut Cursor<'_>) -> Result<Vec<FieldRef>> {
    let len = cursor.u32()? as usize;
    ensure!(len <= cursor.remaining(), "invalid recursive field count");
    (0..len).map(|_| FieldRef::decode(cursor)).collect()
}

fn write_len(out: &mut Vec<u8>, len: usize, what: &str) -> Result<()> {
    let len = u32::try_from(len).with_context(|| format!("too many {what} values"))?;
    out.extend_from_slice(&len.to_le_bytes());
    Ok(())
}

fn field_to_limbs(value: FieldElement) -> [u64; FIELD_LIMBS] {
    let mut bytes = value.to_le_bytes();
    bytes.resize(FIELD_LIMBS * 8, 0);
    std::array::from_fn(|index| {
        u64::from_le_bytes(bytes[index * 8..(index + 1) * 8].try_into().unwrap())
    })
}

fn field_from_limbs(limbs: [u64; FIELD_LIMBS]) -> Result<FieldElement> {
    let bytes: Vec<_> = limbs.into_iter().flat_map(u64::to_le_bytes).collect();
    let value = FieldElement::from_le_bytes_reduce(&bytes);
    ensure!(
        field_to_limbs(value) == limbs,
        "non-canonical BN254 field value"
    );
    Ok(value)
}

fn pack_bytes(bytes: &[u8]) -> Vec<FieldElement> {
    let mut fields = Vec::with_capacity(1 + bytes.len().div_ceil(FIELD_CHUNK_BYTES));
    fields.push(FieldElement::from(bytes.len() as u128));
    fields.extend(
        bytes
            .chunks(FIELD_CHUNK_BYTES)
            .map(FieldElement::from_le_bytes_reduce),
    );
    fields
}

fn unpack_bytes(fields: &[FieldElement], what: &str) -> Result<Vec<u8>> {
    let (length, chunks) = fields
        .split_first()
        .with_context(|| format!("recursive {what} encoding is empty"))?;
    let length = usize::try_from(
        length
            .try_to_u64()
            .with_context(|| format!("recursive {what} byte length is too large"))?,
    )?;
    let expected_chunks = length.div_ceil(FIELD_CHUNK_BYTES);
    ensure!(
        chunks.len() == expected_chunks,
        "recursive {what} has {} chunks, expected {expected_chunks}",
        chunks.len()
    );
    let mut bytes = Vec::with_capacity(chunks.len() * FIELD_CHUNK_BYTES);
    for chunk in chunks {
        let encoded = chunk.to_le_bytes();
        ensure!(
            encoded[FIELD_CHUNK_BYTES..].iter().all(|&byte| byte == 0),
            "recursive {what} chunk exceeds {FIELD_CHUNK_BYTES} bytes"
        );
        bytes.extend_from_slice(&encoded[..FIELD_CHUNK_BYTES]);
    }
    ensure!(
        bytes[length..].iter().all(|&byte| byte == 0),
        "recursive {what} has non-zero padding"
    );
    bytes.truncate(length);
    Ok(bytes)
}

fn verification_key_hash(bytes: &[u8]) -> FieldElement {
    FieldElement::from_le_bytes_reduce(&blake3::hash(bytes).as_bytes()[..FIELD_CHUNK_BYTES])
}

fn fields_to_strings(fields: &[FieldElement]) -> Vec<String> {
    fields.iter().map(|field| field.to_short_hex()).collect()
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
        let end = self
            .position
            .checked_add(len)
            .context("recursive data offset overflow")?;
        ensure!(end <= self.bytes.len(), "truncated recursive data");
        let bytes = &self.bytes[self.position..end];
        self.position = end;
        Ok(bytes)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().unwrap())
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }
}

#[cfg(test)]
mod tests {
    use super::{pack_bytes, unpack_bytes};

    #[test]
    fn byte_field_encoding_round_trips_boundaries() {
        for length in [0, 1, 30, 31, 32, 62, 63, 1000] {
            let bytes: Vec<_> = (0..length).map(|index| (index * 17) as u8).collect();
            assert_eq!(unpack_bytes(&pack_bytes(&bytes), "test").unwrap(), bytes);
        }
    }
}
