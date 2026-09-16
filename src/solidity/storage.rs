//! Lossless storage representation of an already constructed verifier program.
//!
//! The backend searches for matches; the constructor only copies fixed literal
//! ranges. Neither this plan nor its cost estimate participates in proof checks.
use std::collections::HashMap;

const DEPTH: usize = 64;
const MAX_PROGRAM: usize = 1 << 20;
const MAX_SEARCH: usize = 1 << 24;

#[derive(Clone, Debug)]
pub(super) struct StoragePlan {
    pub bytes: Vec<u8>,
    pub headers: Vec<u8>,
    pub minimum_match: usize,
    pub estimated_saving: u64,
}

fn record(chains: &mut HashMap<[u8; 4], Vec<usize>>, data: &[u8], at: usize) {
    let positions = chains
        .entry(data[at..at + 4].try_into().unwrap())
        .or_default();
    positions.push(at);
    if positions.len() > 2 * DEPTH {
        positions.drain(..positions.len() - DEPTH);
    }
}

fn emit(
    data: &[u8],
    output: &mut Vec<u8>,
    headers: &mut Vec<u8>,
    mut begin: usize,
    end: usize,
    count: usize,
    distance: usize,
) {
    while end - begin > 255 {
        headers.extend_from_slice(&[255, 0, 0, 0]);
        output.extend_from_slice(&[255, 0, 0, 0]);
        output.extend_from_slice(&data[begin..begin + 255]);
        begin += 255;
    }
    let [high, low] = u16::try_from(distance).unwrap().to_be_bytes();
    let header = [
        u8::try_from(end - begin).unwrap(),
        u8::try_from(count).unwrap(),
        high,
        low,
    ];
    headers.extend_from_slice(&header);
    output.extend_from_slice(&header);
    output.extend_from_slice(&data[begin..end]);
}

/// Independently decode records using bytewise, initialized-history copying.
fn expand(input: &[u8], length: usize) -> Option<Vec<u8>> {
    if length > MAX_PROGRAM {
        return None;
    }
    let mut output = Vec::with_capacity(length);
    let mut at = 0usize;
    while at < input.len() {
        let header = input.get(at..at.checked_add(4)?)?;
        let literal = usize::from(header[0]);
        let count = usize::from(header[1]);
        let distance = usize::from(u16::from_be_bytes([header[2], header[3]]));
        at += 4;
        if output.len().checked_add(literal)?.checked_add(count)? > length {
            return None;
        }
        output.extend_from_slice(input.get(at..at.checked_add(literal)?)?);
        at += literal;
        if count == 0 {
            if distance != 0 {
                return None;
            }
        } else {
            if distance == 0 || distance > output.len() {
                return None;
            }
            for _ in 0..count {
                output.push(output[output.len() - distance]);
            }
        }
    }
    (output.len() == length).then_some(output)
}

/// Reproduce construction without relying on the encoder's match search.
fn copy_literals(input: &[u8], headers: &[u8], length: usize) -> Option<Vec<u8>> {
    if headers.len() % 4 != 0 {
        return None;
    }
    let mut output = Vec::with_capacity(length);
    let mut at = 0usize;
    for header in headers.chunks_exact(4) {
        let literal = usize::from(header[0]);
        let count = usize::from(header[1]);
        output.extend_from_slice(header);
        output.extend_from_slice(input.get(at..at.checked_add(literal)?)?);
        at = at.checked_add(literal)?.checked_add(count)?;
        if at > input.len() || output.len() > length {
            return None;
        }
    }
    (at == input.len() && output.len() == length).then_some(output)
}

pub(super) fn construct(data: &[u8], minimum_match: usize) -> Option<StoragePlan> {
    if data.len() > MAX_PROGRAM || !(4..=40).contains(&minimum_match) {
        return None;
    }
    let mut chains = HashMap::<[u8; 4], Vec<usize>>::new();
    let mut output = Vec::new();
    let mut headers = Vec::new();
    let mut at = 0usize;
    let mut anchor = 0usize;
    let mut work = 0usize;
    while at + minimum_match <= data.len() {
        let mut best = 0usize;
        let mut offset = 0usize;
        let limit = (data.len() - at).min(255);
        if let Some(positions) = chains.get(&<[u8; 4]>::try_from(&data[at..at + 4]).unwrap()) {
            for &reference in positions.iter().rev().take(DEPTH) {
                work += 1;
                if work > MAX_SEARCH {
                    return None;
                }
                if at - reference > 65535 {
                    break;
                }
                if data[reference..reference + minimum_match] != data[at..at + minimum_match] {
                    continue;
                }
                let mut count = minimum_match;
                while count < limit && data[reference + count] == data[at + count] {
                    count += 1;
                }
                if count > best {
                    best = count;
                    offset = at - reference;
                }
                if best == limit {
                    break;
                }
            }
        }
        if best != 0 {
            emit(data, &mut output, &mut headers, anchor, at, best, offset);
            for i in at..(at + best).min(data.len().saturating_sub(3)) {
                record(&mut chains, data, i);
            }
            at += best;
            anchor = at;
        } else {
            record(&mut chains, data, at);
            at += 1;
        }
    }
    emit(data, &mut output, &mut headers, anchor, data.len(), 0, 0);
    assert_eq!(
        expand(&output, data.len()).as_deref(),
        Some(data),
        "storage encoding changed the verifier program"
    );
    assert_eq!(
        copy_literals(data, &headers, output.len()).as_deref(),
        Some(output.as_slice()),
        "constructor packing plan differs from encoded storage"
    );
    let words_saved = data
        .len()
        .div_ceil(32)
        .saturating_sub(output.len().div_ceil(32)) as u64;
    // Includes cold SLOAD savings and conservative per-record decoding overhead.
    // This only selects a candidate; actual compiler/code-size checks follow.
    let estimated_saving =
        (words_saved * 2100).saturating_sub((headers.len() / 4) as u64 * 650 + 100_000);
    Some(StoragePlan {
        bytes: output,
        headers,
        minimum_match,
        estimated_saving,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_records_preserve_boundaries_and_overlapping_history() {
        let mut random = 0x0123456789abcdefu64;
        for size in [
            0, 1, 3, 4, 7, 31, 32, 254, 255, 256, 511, 2048, 65535, 65536, 70000,
        ] {
            let mut input = Vec::with_capacity(size);
            for i in 0..size {
                random ^= random << 13;
                random ^= random >> 7;
                random ^= random << 17;
                input.push(if i % 1024 < 512 {
                    (i % 7) as u8
                } else {
                    random as u8
                });
            }
            for minimum in [4, 8, 12, 20, 32, 40] {
                let plan = construct(&input, minimum).unwrap();
                assert_eq!(expand(&plan.bytes, input.len()).unwrap(), input);
                assert_eq!(
                    copy_literals(&input, &plan.headers, plan.bytes.len()).unwrap(),
                    plan.bytes
                );
            }
        }
        // Forward overlapping copies must read the newly initialized prefix.
        assert_eq!(expand(&[1, 255, 0, 1, 0xab], 256), Some(vec![0xab; 256]));
        assert_eq!(
            expand(&[2, 6, 0, 2, 1, 2], 8),
            Some(vec![1, 2, 1, 2, 1, 2, 1, 2])
        );
    }

    #[test]
    fn storage_decoding_rejects_invalid_bounds_and_plans() {
        for (data, size) in [
            (&[0][..], 0),
            (&[1, 0, 0, 0][..], 1),
            (&[0, 1, 0, 0][..], 1),
            (&[1, 1, 0, 2, 1][..], 2),
            (&[0, 0, 0, 1][..], 0),
            (&[1, 0, 0, 0, 1][..], 0),
            (&[1, 0, 0, 0, 1][..], 2),
            (&[][..], 1),
        ] {
            assert!(expand(data, size).is_none());
        }
        assert!(copy_literals(&[1], &[0], 0).is_none());
        assert!(copy_literals(&[1], &[2, 0, 0, 0], 6).is_none());
        assert!(copy_literals(&[1], &[1, 0, 0, 0], 4).is_none());
        assert!(copy_literals(&[1, 2], &[1, 0, 0, 0], 5).is_none());
        assert!(construct(&[0; 8], 3).is_none());
        assert!(construct(&[0; 8], 41).is_none());
        assert!(construct(&vec![0; MAX_PROGRAM + 1], 20).is_none());
    }
}
