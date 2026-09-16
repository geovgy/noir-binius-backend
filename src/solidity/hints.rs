//! Optional, untrusted SHA-256 digest hints for the direct Solidity verifier.
//!
//! The contract recomputes every hinted digest before accepting a proof. Hints
//! only allow dependent Fiat-Shamir hashes to run in parallel SHA lanes; they
//! neither replace a verification equation nor change the native transcript.

use std::{cell::RefCell, marker::PhantomData, rc::Rc};

use anyhow::{Context, Result, ensure};
use binius_core::word::Word;
use binius_hash::StdDigest;
use binius_transcript::{VerifierTranscript, fiat_shamir::HasherChallenger};
use digest::{
    Digest, FixedOutput, FixedOutputReset, HashMarker, Output, OutputSizeUser, Reset, Update,
    block_api::BlockSizeUser,
};
use noir_binius_verifier::{ProofBundle, VerificationKey};

const HINT_MAGIC: &[u8; 8] = b"NBINH001";

/// Adds checked hash hints to an existing, valid native proof for `IVerifier.verify`.
///
/// The result is `NBINH001 || NBINZK01 proof || 32-byte digests`. The generated
/// contract also accepts the original proof. Native `verify` and recursive
/// aggregation continue to take the original proof, without this EVM envelope.
/// No witness is needed: hints are deterministic functions of public proof bytes.
pub fn prepare_solidity_proof(verification_key: &[u8], proof: &[u8]) -> Result<Vec<u8>> {
    let key = VerificationKey::decode(verification_key)
        .context("cannot prepare Solidity proof for an invalid Binius verification key")?;
    ensure!(
        key.metadata.calls.is_empty(),
        "direct Solidity proofs do not support delegated recursive proofs"
    );
    let bundle = ProofBundle::decode(proof).context("expected a raw NBINZK01 Binius proof")?;
    // Keep the portable verifier's metadata and transcript checks authoritative.
    // The second run below only captures the challenger's exact hash outputs.
    key.verify_bundle(&bundle)?;
    key.noir_public_values(&bundle)?;

    let capture = Capture::begin();
    let mut transcript = VerifierTranscript::new(
        HasherChallenger::<RecordingDigest>::default(),
        bundle.transcript.clone(),
    );
    let words: Vec<_> = bundle.public_words.iter().copied().map(Word).collect();
    key.binius_verifier()
        .verify(&words, &mut transcript)
        .context("Binius verification failed while recording SHA hints")?;
    transcript
        .finalize()
        .context("hint recording did not consume the complete Binius transcript")?;
    let digests = capture.finish();
    ensure!(
        digests.first().map(<[u8; 32]>::as_slice) == Some(StdDigest::digest([]).as_slice()),
        "unexpected initial Binius challenger digest"
    );
    ensure!(digests.len() > 1, "Binius proof used no Fiat-Shamir hashes");
    let mut output = Vec::with_capacity(HINT_MAGIC.len() + proof.len() + 32 * (digests.len() - 1));
    output.extend_from_slice(HINT_MAGIC);
    output.extend_from_slice(proof);
    // The initial SHA256(empty) is already a fixed constant in the contract.
    for digest in &digests[1..] {
        output.extend_from_slice(digest);
    }
    Ok(output)
}

thread_local! {
    static DIGESTS: RefCell<Option<Vec<[u8; 32]>>> = const { RefCell::new(None) };
}

// Scoped capture restores an enclosing recorder on both success and failure.
// It cannot move to another thread, whose digest buffer would be unrelated.
struct Capture {
    previous: Option<Vec<[u8; 32]>>,
    _thread: PhantomData<Rc<()>>,
}

impl Capture {
    fn begin() -> Self {
        Self {
            previous: DIGESTS.replace(Some(Vec::new())),
            _thread: PhantomData,
        }
    }

    fn finish(self) -> Vec<[u8; 32]> {
        DIGESTS
            .with_borrow_mut(|slot| std::mem::take(slot.as_mut().expect("active digest capture")))
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        DIGESTS.replace(self.previous.take());
    }
}

fn record(output: &Output<RecordingDigest>) {
    DIGESTS.with_borrow_mut(|slot| {
        if let Some(digests) = slot {
            digests.push(output.as_slice().try_into().expect("SHA-256 output length"));
        }
    });
}

// Use the pinned backend's SHA implementation and digest 0.11 traits. The
// application also uses sha2 0.10 elsewhere; its digest traits are different.
#[derive(Clone, Debug, Default)]
struct RecordingDigest(StdDigest);

impl BlockSizeUser for RecordingDigest {
    type BlockSize = <StdDigest as BlockSizeUser>::BlockSize;
}
impl OutputSizeUser for RecordingDigest {
    type OutputSize = <StdDigest as OutputSizeUser>::OutputSize;
}
impl HashMarker for RecordingDigest {}
impl Update for RecordingDigest {
    fn update(&mut self, input: &[u8]) {
        Update::update(&mut self.0, input);
    }
}
impl Reset for RecordingDigest {
    fn reset(&mut self) {
        Reset::reset(&mut self.0);
    }
}
impl FixedOutput for RecordingDigest {
    fn finalize_into(self, output: &mut Output<Self>) {
        FixedOutput::finalize_into(self.0, output);
        record(output);
    }
}
impl FixedOutputReset for RecordingDigest {
    fn finalize_into_reset(&mut self, output: &mut Output<Self>) {
        FixedOutputReset::finalize_into_reset(&mut self.0, output);
        record(output);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_exact_sha_outputs_and_reset_state() {
        let capture = Capture::begin();
        let mut expected = Vec::<[u8; 32]>::new();
        let mut recorder = RecordingDigest::default();
        for length in [0, 1, 31, 32, 55, 56, 63, 64, 72, 128, 4097, 8192] {
            let bytes: Vec<u8> = (0..length).map(|i| (i * 71 + 13) as u8).collect();
            let reference: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(&bytes).into();
            expected.push(reference);
            for chunk in bytes.chunks(17) {
                Digest::update(&mut recorder, chunk);
            }
            assert_eq!(recorder.finalize_reset().as_slice(), reference);
        }
        assert_eq!(capture.finish(), expected);
        assert!(DIGESTS.with_borrow(Option::is_none));
    }

    #[test]
    fn captures_are_isolated_across_scopes_failures_and_threads() {
        let threads: Vec<_> = (0..4)
            .map(|id| {
                std::thread::spawn(move || {
                    let capture = Capture::begin();
                    let first: [u8; 32] = RecordingDigest::digest([id]).into();
                    let nested = Capture::begin();
                    let inner: [u8; 32] = RecordingDigest::digest([id, 1]).into();
                    assert_eq!(nested.finish(), vec![inner]);
                    let failed = std::panic::catch_unwind(|| {
                        let _capture = Capture::begin();
                        let _ = RecordingDigest::digest([id, 2]);
                        panic!("simulate interrupted verification");
                    });
                    assert!(failed.is_err());
                    let last: [u8; 32] = RecordingDigest::digest([id, 3]).into();
                    assert_eq!(capture.finish(), vec![first, last]);
                    assert!(DIGESTS.with_borrow(Option::is_none));
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
    }
}
