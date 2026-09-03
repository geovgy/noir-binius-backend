use std::{fs, path::Path};

use anyhow::{Context, Result, bail, ensure};
use binius_core::word::Word;
use binius_hash::StdHashSuite;
use binius_transcript::VerifierTranscript;
use binius_utils::{DeserializeBytes, SerializeBytes};
use binius_verifier::{config::StdChallenger, zk_config::ZKVerifier};

const PROOF_MAGIC: &[u8; 8] = b"NBINZK01";
const VK_MAGIC: &[u8; 8] = b"NBINVK01";
const SP1_PROOF_MAGIC: &[u8; 8] = b"NBINSP11";
const FIELD_CHUNK_BYTES: usize = 31;
const MAX_RECURSION_DEPTH: usize = 32;

/// The number of little-endian 64-bit words in one Noir BN254 field element.
pub const FIELD_LIMBS: usize = 4;

/// Backend-specific `proof_type` accepted by ACIR `RecursiveAggregation`.
pub const BINIUS_ZK_PROOF_TYPE: u32 = 0x4249_4e5a;

/// The BN254 scalar modulus as little-endian 64-bit limbs.
const BN254_SCALAR_MODULUS: FieldValue = [
    0x43e1_f593_f000_0001,
    0x2833_e848_79b9_7091,
    0xb850_45b6_8181_585d,
    0x3064_4e72_e131_a029,
];

/// Canonical little-endian representation of a Noir BN254 field element.
pub type FieldValue = [u64; FIELD_LIMBS];

/// Portable wrapper around the raw Binius transcript and public Binius statement.
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
            PROOF_MAGIC.len()
                + 32
                + 4
                + 4
                + self.public_words.len() * 8
                + 8
                + self.transcript.len(),
        );
        out.extend_from_slice(PROOF_MAGIC);
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
            cursor.take(PROOF_MAGIC.len())? == PROOF_MAGIC,
            "not a noir-binius proof (bad magic)"
        );
        let circuit_digest = cursor.array::<32>()?;
        let log_inv_rate = cursor.u32()?;
        ensure!(log_inv_rate > 0, "invalid zero log inverse rate");
        let public_len = cursor.u32()? as usize;
        let public_bytes = public_len
            .checked_mul(8)
            .context("public input length overflow")?;
        ensure!(
            public_bytes <= cursor.remaining(),
            "truncated public inputs in proof bundle"
        );
        let mut public_words = Vec::with_capacity(public_len);
        for _ in 0..public_len {
            public_words.push(cursor.u64()?);
        }
        let proof_len =
            usize::try_from(cursor.u64()?).context("proof length does not fit this platform")?;
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

/// EVM-facing proof envelope containing the public inputs and the succinct SP1 proof.
///
/// The public inputs are included so the CLI can inspect an EVM proof without a separate public
/// input file. The generated Solidity verifier requires them to exactly match its `publicInputs`
/// argument before forwarding the SP1 proof to the verifier gateway.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sp1Proof {
    pub public_inputs: Vec<FieldValue>,
    pub sp1_proof: Vec<u8>,
}

impl Sp1Proof {
    pub fn encode(&self) -> Result<Vec<u8>> {
        ensure!(!self.sp1_proof.is_empty(), "SP1 proof must not be empty");
        let public_len =
            u32::try_from(self.public_inputs.len()).context("too many public inputs to encode")?;
        let mut out = Vec::with_capacity(
            SP1_PROOF_MAGIC.len() + 4 + self.public_inputs.len() * 32 + self.sp1_proof.len(),
        );
        out.extend_from_slice(SP1_PROOF_MAGIC);
        out.extend_from_slice(&public_len.to_le_bytes());
        for &value in &self.public_inputs {
            ensure!(
                is_canonical_field(value),
                "non-canonical BN254 public input"
            );
            out.extend_from_slice(&field_to_be_bytes(value));
        }
        out.extend_from_slice(&self.sp1_proof);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        ensure!(
            cursor.take(SP1_PROOF_MAGIC.len())? == SP1_PROOF_MAGIC,
            "not a noir-binius SP1 proof (bad magic)"
        );
        let public_len = cursor.u32()? as usize;
        let public_bytes = public_len
            .checked_mul(32)
            .context("Solidity public-input length overflow")?;
        ensure!(
            public_bytes < cursor.remaining(),
            "truncated Solidity proof envelope"
        );
        let mut public_inputs = Vec::with_capacity(public_len);
        for _ in 0..public_len {
            public_inputs.push(field_from_be_bytes(cursor.array()?)?);
        }
        let sp1_proof = cursor.take(cursor.remaining())?.to_vec();
        ensure!(!sp1_proof.is_empty(), "SP1 proof must not be empty");
        Ok(Self {
            public_inputs,
            sp1_proof,
        })
    }

    pub fn read(path: &Path) -> Result<Self> {
        let bytes = fs::read(path)
            .with_context(|| format!("failed to read SP1 proof {}", path.display()))?;
        Self::decode(&bytes)
            .with_context(|| format!("failed to decode SP1 proof {}", path.display()))
    }

    pub fn write(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create SP1 proof directory {}", parent.display())
            })?;
        }
        fs::write(path, self.encode()?)
            .with_context(|| format!("failed to write SP1 proof {}", path.display()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FieldRef {
    Constant(FieldValue),
    Public([u32; FIELD_LIMBS]),
}

impl FieldRef {
    pub const fn constant(value: FieldValue) -> Self {
        Self::Constant(value)
    }

    pub const fn public(offsets: [u32; FIELD_LIMBS]) -> Self {
        Self::Public(offsets)
    }

    fn resolve(&self, public_words: &[u64]) -> Result<FieldValue> {
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
        ensure!(is_canonical_field(limbs), "non-canonical BN254 field value");
        Ok(limbs)
    }

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
                ensure!(
                    is_canonical_field(limbs),
                    "non-canonical recursive constant"
                );
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecursiveCallSpec {
    pub active_word: u32,
    pub proof_type: u32,
    pub verification_key: Vec<FieldRef>,
    pub proof: Vec<FieldRef>,
    pub public_inputs: Vec<FieldRef>,
    pub key_hash: FieldRef,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecursiveMetadata {
    pub noir_public_inputs: Vec<FieldRef>,
    pub calls: Vec<RecursiveCallSpec>,
}

impl RecursiveMetadata {
    pub fn noir_public_values(&self, public_words: &[u64]) -> Result<Vec<FieldValue>> {
        self.noir_public_inputs
            .iter()
            .map(|field| field.resolve(public_words))
            .collect()
    }

    pub fn verify_calls(&self, public_words: &[u64]) -> Result<()> {
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
            recursive_verification_key_hash(&vk_bytes) == claimed_key_hash,
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
        key.verify_bundle_at_depth(&proof, depth + 1)
    }
}

/// A portable Binius verification key, including Noir public-input and recursion metadata.
pub struct VerificationKey {
    artifact_digest: [u8; 32],
    pub metadata: RecursiveMetadata,
    verifier: ZKVerifier<StdHashSuite>,
}

impl VerificationKey {
    pub const fn new(
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

    pub const fn artifact_digest(&self) -> [u8; 32] {
        self.artifact_digest
    }

    /// Number of public Binius words encoded in every proof for this key.
    pub const fn public_word_count(&self) -> usize {
        self.verifier.constraint_system().n_inout
    }

    /// Base-2 logarithm of the inverse Reed-Solomon rate used by this key.
    pub fn log_inv_rate(&self) -> usize {
        self.verifier.log_inv_rate()
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
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

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        ensure!(
            cursor.take(VK_MAGIC.len())? == VK_MAGIC,
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

    pub fn verify_bundle(&self, proof: &ProofBundle) -> Result<()> {
        self.verify_bundle_at_depth(proof, 0)
    }

    fn verify_bundle_at_depth(&self, proof: &ProofBundle, depth: usize) -> Result<()> {
        ensure!(
            proof.circuit_digest == self.artifact_digest,
            "proof was created for a different circuit"
        );
        ensure!(
            proof.log_inv_rate as usize == self.verifier.log_inv_rate(),
            "proof and verification key use different inverse rates"
        );
        ensure!(
            proof.public_words.len() == self.verifier.constraint_system().n_inout,
            "proof has {} public words, expected {}",
            proof.public_words.len(),
            self.verifier.constraint_system().n_inout
        );
        let words = proof
            .public_words
            .iter()
            .copied()
            .map(Word::from_u64)
            .collect::<Vec<_>>();
        let mut transcript =
            VerifierTranscript::new(StdChallenger::default(), proof.transcript.clone());
        self.verifier
            .verify(&words, &mut transcript)
            .context("Binius ZK proof verification failed")?;
        transcript
            .finalize()
            .context("Binius verifier did not consume the complete proof transcript")?;
        self.metadata
            .verify_calls_at_depth(&proof.public_words, depth)
    }

    pub fn noir_public_values(&self, proof: &ProofBundle) -> Result<Vec<FieldValue>> {
        ensure!(
            proof.circuit_digest == self.artifact_digest,
            "proof was created for a different circuit"
        );
        self.metadata.noir_public_values(&proof.public_words)
    }
}

/// Converts a canonical little-endian field representation to Solidity's bytes32 ordering.
pub fn field_to_be_bytes(value: FieldValue) -> [u8; 32] {
    let mut little_endian = [0; 32];
    for (index, limb) in value.into_iter().enumerate() {
        little_endian[index * 8..(index + 1) * 8].copy_from_slice(&limb.to_le_bytes());
    }
    little_endian.reverse();
    little_endian
}

/// Decodes Solidity's bytes32 ordering into a canonical little-endian Noir field value.
pub fn field_from_be_bytes(mut encoded: [u8; 32]) -> Result<FieldValue> {
    encoded.reverse();
    let value = std::array::from_fn(|index| {
        u64::from_le_bytes(encoded[index * 8..(index + 1) * 8].try_into().unwrap())
    });
    ensure!(is_canonical_field(value), "non-canonical BN254 field value");
    Ok(value)
}

/// Formats a canonical field as the fixed-width hexadecimal representation used by Noir.js.
pub fn field_to_hex(value: FieldValue) -> String {
    use std::fmt::Write;

    let mut encoded = String::with_capacity(66);
    encoded.push_str("0x");
    for byte in field_to_be_bytes(value) {
        write!(&mut encoded, "{byte:02x}").expect("writing to a string cannot fail");
    }
    encoded
}

/// Returns the field encoding used by Noir recursive aggregation for a verification-key hash.
pub fn recursive_verification_key_hash(bytes: &[u8]) -> FieldValue {
    let mut encoded = [0; 32];
    encoded[..FIELD_CHUNK_BYTES]
        .copy_from_slice(&blake3::hash(bytes).as_bytes()[..FIELD_CHUNK_BYTES]);
    std::array::from_fn(|index| {
        u64::from_le_bytes(encoded[index * 8..(index + 1) * 8].try_into().unwrap())
    })
}

/// Packs bytes into canonical Noir fields for ACIR recursive aggregation.
pub fn pack_bytes(bytes: &[u8]) -> Vec<FieldValue> {
    let mut fields = Vec::with_capacity(1 + bytes.len().div_ceil(FIELD_CHUNK_BYTES));
    fields.push([bytes.len() as u64, 0, 0, 0]);
    fields.extend(bytes.chunks(FIELD_CHUNK_BYTES).map(|chunk| {
        let mut encoded = [0; 32];
        encoded[..chunk.len()].copy_from_slice(chunk);
        std::array::from_fn(|index| {
            u64::from_le_bytes(encoded[index * 8..(index + 1) * 8].try_into().unwrap())
        })
    }));
    fields
}

fn resolve_fields(fields: &[FieldRef], public_words: &[u64]) -> Result<Vec<FieldValue>> {
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

fn unpack_bytes(fields: &[FieldValue], what: &str) -> Result<Vec<u8>> {
    let (length, chunks) = fields
        .split_first()
        .with_context(|| format!("recursive {what} encoding is empty"))?;
    ensure!(
        length[1..].iter().all(|&limb| limb == 0),
        "recursive {what} byte length is too large"
    );
    let length = usize::try_from(length[0])
        .with_context(|| format!("recursive {what} byte length is too large"))?;
    let expected_chunks = length.div_ceil(FIELD_CHUNK_BYTES);
    ensure!(
        chunks.len() == expected_chunks,
        "recursive {what} has {} chunks, expected {expected_chunks}",
        chunks.len()
    );
    let mut bytes = Vec::with_capacity(chunks.len() * FIELD_CHUNK_BYTES);
    for chunk in chunks {
        let mut encoded = [0; 32];
        for (index, limb) in chunk.iter().enumerate() {
            encoded[index * 8..(index + 1) * 8].copy_from_slice(&limb.to_le_bytes());
        }
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

fn is_canonical_field(value: FieldValue) -> bool {
    for (&limb, &modulus) in value.iter().zip(BN254_SCALAR_MODULUS.iter()).rev() {
        if limb < modulus {
            return true;
        }
        if limb > modulus {
            return false;
        }
    }
    false
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
            .context("encoded data offset overflow")?;
        ensure!(end <= self.bytes.len(), "truncated encoded data");
        let bytes = &self.bytes[self.position..end];
        self.position = end;
        Ok(bytes)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().expect("slice length was checked"))
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
    use super::{
        BN254_SCALAR_MODULUS, ProofBundle, Sp1Proof, field_to_be_bytes, is_canonical_field,
        pack_bytes, unpack_bytes,
    };

    #[test]
    fn proof_bundle_round_trip_and_rejects_trailing_data() {
        let bundle = ProofBundle {
            circuit_digest: [7; 32],
            log_inv_rate: 1,
            public_words: vec![1, u64::MAX, 42],
            transcript: vec![4, 5, 6, 7],
        };
        let encoded = bundle.encode().unwrap();
        assert_eq!(ProofBundle::decode(&encoded).unwrap(), bundle);
        let mut trailing = encoded;
        trailing.push(2);
        assert!(ProofBundle::decode(&trailing).is_err());
    }

    #[test]
    fn byte_field_encoding_round_trips_boundaries() {
        for length in [0, 1, 30, 31, 32, 62, 63, 1000] {
            let bytes: Vec<_> = (0..length).map(|index| (index * 17) as u8).collect();
            assert_eq!(unpack_bytes(&pack_bytes(&bytes), "test").unwrap(), bytes);
        }
    }

    #[test]
    fn canonical_field_and_byte_order_are_exact() {
        assert!(is_canonical_field([0; 4]));
        let mut modulus_minus_one = BN254_SCALAR_MODULUS;
        modulus_minus_one[0] -= 1;
        assert!(is_canonical_field(modulus_minus_one));
        assert!(!is_canonical_field(BN254_SCALAR_MODULUS));
        assert_eq!(
            field_to_be_bytes([0x0102_0304_0506_0708, 0, 0, 0]),
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4,
                5, 6, 7, 8,
            ]
        );
    }

    #[test]
    fn solidity_proof_round_trip_and_validation() {
        let proof = Sp1Proof {
            public_inputs: vec![[14, 0, 0, 0], [42, 0, 0, 0]],
            sp1_proof: vec![1, 2, 3, 4],
        };
        let encoded = proof.encode().unwrap();
        assert_eq!(Sp1Proof::decode(&encoded).unwrap(), proof);
        assert!(Sp1Proof::decode(&encoded[..encoded.len() - 4]).is_err());

        let mut bad_magic = encoded.clone();
        bad_magic[0] ^= 1;
        assert!(Sp1Proof::decode(&bad_magic).is_err());

        let mut noncanonical = encoded;
        noncanonical[12..44].copy_from_slice(&field_to_be_bytes(BN254_SCALAR_MODULUS));
        assert!(Sp1Proof::decode(&noncanonical).is_err());

        assert!(
            Sp1Proof {
                public_inputs: vec![],
                sp1_proof: vec![],
            }
            .encode()
            .is_err()
        );
    }
}
