//! Exact recoding of the public matrix's topologically ordered decision graph.
//! This changes only the encoding of fixed child references, never equations.

const MAX_BYTES: usize = 1 << 20;

#[derive(Clone, Debug)]
pub(super) struct Recoded {
    pub bytes: Vec<u8>,
    pub prefix_length: usize,
    pub leaves: usize,
    pub nodes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Node {
    bit: u8,
    low: usize,
    high: usize,
}

fn word(data: &[u8], at: usize) -> Option<usize> {
    Some(u32::from_be_bytes(data.get(at..at.checked_add(4)?)?.try_into().ok()?) as usize)
}

fn number(data: &[u8], at: &mut usize) -> Option<u32> {
    let mut value = 0u64;
    for shift in (0..35).step_by(7) {
        let byte = *data.get(*at)?;
        *at += 1;
        value |= u64::from(byte & 127) << shift;
        if byte & 128 == 0 {
            return u32::try_from(value).ok();
        }
    }
    None
}

fn advance(previous: &mut i64, encoded: u32) -> Option<usize> {
    let delta = i64::from(encoded >> 1);
    *previous = previous.checked_add(if encoded & 1 == 0 { delta } else { -delta - 1 })?;
    usize::try_from(u32::try_from(*previous).ok()?).ok()
}

fn decode(data: &[u8]) -> Option<(usize, usize, Vec<Node>)> {
    if data.len() > MAX_BYTES {
        return None;
    }
    let leaves = word(data, 0)?;
    let count = word(data, 4)?;
    let dimensions = usize::from(*data.get(8)?);
    if leaves == 0 || leaves > data.len() || count > data.len() / 3 || dimensions > 64 {
        return None;
    }
    let total = leaves.checked_add(count)?;
    for at in [9, 13, 17] {
        if word(data, at)? >= total {
            return None;
        }
    }
    let mut at = 25usize.checked_add(4 * dimensions)?;
    data.get(..at)?;
    let mut previous_leaf = [0i64; 2];
    for _ in 0..leaves {
        let code = number(data, &mut at)?;
        let kind = (code & 1) as usize;
        advance(&mut previous_leaf[kind], code >> 1)?;
        if kind != 0 {
            if *data.get(at)? >= 128 {
                return None;
            }
            at += 1;
        }
    }
    let prefix_length = at;
    let mut previous = [0i64; 4];
    let mut nodes = Vec::with_capacity(count);
    for i in 0..count {
        let code = *data.get(at)?;
        at += 1;
        if usize::from(code >> 2) >= dimensions {
            return None;
        }
        let mut children = [0; 2];
        for (position, child) in children.iter_mut().enumerate() {
            let kind = usize::from((code >> position) & 1);
            *child = advance(&mut previous[2 * position + kind], number(data, &mut at)?)?;
            if *child >= leaves + i || usize::from(*child >= leaves) != kind {
                return None;
            }
        }
        nodes.push(Node {
            bit: code >> 2,
            low: children[0],
            high: children[1],
        });
    }
    (at == data.len()).then_some((prefix_length, leaves, nodes))
}

/// Preserve every leaf and node, storing equal-coordinate runs as
/// `[point bit, u16 count, (u16 distance to low, u16 distance to high)*]`.
/// The generated compact deployment still uses two-byte instruction lengths.
pub(super) fn recode(data: &[u8]) -> Option<Recoded> {
    let (prefix_length, leaves, nodes) = decode(data)?;
    let minimum_size = prefix_length.checked_add(nodes.len().checked_mul(4)?)?;
    if minimum_size > usize::from(u16::MAX) {
        return None;
    }
    let mut bytes = Vec::with_capacity(
        prefix_length
            .checked_add(nodes.len().checked_mul(7)?)?
            .min(usize::from(u16::MAX)),
    );
    bytes.extend_from_slice(&data[..prefix_length]);
    let mut i = 0;
    while i < nodes.len() {
        let start = i;
        let bit = nodes[i].bit;
        while i < nodes.len() && nodes[i].bit == bit && i - start < usize::from(u16::MAX) {
            i += 1;
        }
        let count = i - start;
        if bytes.len().checked_add(3 + 4 * count)? > usize::from(u16::MAX) {
            return None;
        }
        bytes.push(bit);
        bytes.extend_from_slice(&u16::try_from(count).ok()?.to_be_bytes());
        for (j, node) in nodes[start..i].iter().enumerate() {
            for child in [node.low, node.high] {
                let distance = u16::try_from((leaves + start + j).checked_sub(child)?).ok()?;
                if distance == 0 {
                    return None;
                }
                bytes.extend_from_slice(&distance.to_be_bytes());
            }
        }
    }
    // Independently walk the serialized group boundaries and reconstruct
    // every coordinate and child. Topological induction then preserves the
    // field polynomial for every input, including zero and one coordinates.
    let mut at = prefix_length;
    let mut index = 0;
    while index < nodes.len() {
        let bit = bytes[at];
        let count = usize::from(u16::from_be_bytes([bytes[at + 1], bytes[at + 2]]));
        assert!(count > 0 && count <= nodes.len() - index);
        at += 3;
        for _ in 0..count {
            let low = usize::from(u16::from_be_bytes([bytes[at], bytes[at + 1]]));
            let high = usize::from(u16::from_be_bytes([bytes[at + 2], bytes[at + 3]]));
            let actual = Node {
                bit,
                low: (leaves + index).checked_sub(low)?,
                high: (leaves + index).checked_sub(high)?,
            };
            assert_eq!(
                &actual, &nodes[index],
                "public graph grouping changed a node"
            );
            index += 1;
            at += 4;
        }
    }
    assert_eq!(at, bytes.len(), "public graph grouping left trailing bytes");
    Some(Recoded {
        bytes,
        prefix_length,
        leaves,
        nodes: nodes.len(),
    })
}

#[cfg(test)]
pub(super) fn test_graph(leaves: usize, count: usize) -> Vec<u8> {
    tests::fixture(leaves, count).0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uv(out: &mut Vec<u8>, mut value: u64) {
        while value >= 128 {
            out.push((value as u8) | 128);
            value >>= 7;
        }
        out.push(value as u8);
    }

    fn zz(value: i64) -> u64 {
        if value < 0 {
            (-2 * value - 1) as u64
        } else {
            (2 * value) as u64
        }
    }

    pub(super) fn fixture(leaves: usize, count: usize) -> (Vec<u8>, Vec<Node>) {
        fixture_runs(leaves, count, 1)
    }

    fn fixture_runs(leaves: usize, count: usize, run: usize) -> (Vec<u8>, Vec<Node>) {
        let mut data = Vec::new();
        data.extend_from_slice(&(leaves as u32).to_be_bytes());
        data.extend_from_slice(&(count as u32).to_be_bytes());
        data.push(6);
        for _ in 0..3 {
            data.extend_from_slice(&((leaves + count - 1) as u32).to_be_bytes());
        }
        data.extend_from_slice(&7u32.to_be_bytes());
        for i in 0..6u32 {
            data.extend_from_slice(&i.to_be_bytes());
        }
        let mut previous = [0i64; 2];
        for i in 0..leaves {
            let kind = i & 1;
            let id = ((i * 701) % 4096) as i64;
            uv(&mut data, 2 * zz(id - previous[kind]) + kind as u64);
            previous[kind] = id;
            if kind != 0 {
                data.push((i % 128) as u8);
            }
        }
        let mut previous = [0i64; 4];
        let mut nodes = Vec::new();
        for i in 0..count {
            let low = if i % 3 == 0 { 0 } else { leaves + i - 1 };
            let high = if i % 5 == 0 {
                leaves - 1
            } else {
                (i * 871) % (leaves + i)
            };
            let bit = ((i / run) % 6) as u8;
            data.push(bit * 4 + u8::from(low >= leaves) + 2 * u8::from(high >= leaves));
            for (position, child) in [low, high].into_iter().enumerate() {
                let lane = position * 2 + usize::from(child >= leaves);
                uv(&mut data, zz(child as i64 - previous[lane]));
                previous[lane] = child as i64;
            }
            nodes.push(Node { bit, low, high });
        }
        (data, nodes)
    }

    #[test]
    fn references_preserve_all_nodes_across_group_and_varint_boundaries() {
        for (leaves, count) in [
            (1, 0),
            (1, 1),
            (2, 128),
            (129, 511),
            (257, 1024),
            (3, 12000),
        ] {
            for run in [1, 2, 3, 7, 128, 255, 256, 1024, 65535] {
                let (data, expected) = fixture_runs(leaves, count, run);
                let (prefix, actual_leaves, decoded) = decode(&data).unwrap();
                assert_eq!(decoded, expected);
                assert_eq!(actual_leaves, leaves);
                let expected_size = prefix + count * 4 + count.div_ceil(run) * 3;
                if expected_size > usize::from(u16::MAX) {
                    assert!(recode(&data).is_none());
                    continue;
                }
                let fixed = recode(&data).unwrap();
                assert_eq!(fixed.bytes.len(), expected_size);
                assert_eq!(fixed.bytes[..prefix], data[..prefix]);
                assert_eq!(
                    (fixed.prefix_length, fixed.leaves, fixed.nodes),
                    (prefix, leaves, count)
                );
                let mut at = prefix;
                let mut consumed = 0;
                while at < fixed.bytes.len() {
                    let bit = fixed.bytes[at];
                    let n = usize::from(u16::from_be_bytes([
                        fixed.bytes[at + 1],
                        fixed.bytes[at + 2],
                    ]));
                    at += 3;
                    assert!(n > 0 && n <= run);
                    for node in &expected[consumed..consumed + n] {
                        assert_eq!(bit, node.bit);
                        for (offset, child) in [(0, node.low), (2, node.high)] {
                            let distance = usize::from(u16::from_be_bytes([
                                fixed.bytes[at + offset],
                                fixed.bytes[at + offset + 1],
                            ]));
                            assert_eq!(distance, leaves + consumed - child);
                        }
                        at += 4;
                        consumed += 1;
                    }
                }
                assert_eq!((at, consumed), (fixed.bytes.len(), count));
            }
        }
    }

    #[test]
    fn malformed_graphs_and_oversized_fixed_encodings_are_rejected() {
        let (data, _) = fixture(2, 20);
        for end in 0..data.len() {
            assert!(recode(&data[..end]).is_none());
        }
        let mut extra = data.clone();
        extra.push(0);
        assert!(recode(&extra).is_none());
        let mut root = data.clone();
        root[9..13].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(recode(&root).is_none());
        let mut dimensions = data.clone();
        dimensions[8] = 65;
        assert!(recode(&dimensions).is_none());
        let mut count = data.clone();
        count[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(recode(&count).is_none());
        let (prefix, _, _) = decode(&data).unwrap();
        let mut bit = data.clone();
        bit[prefix] = 255;
        assert!(recode(&bit).is_none());
        let mut forward = data.clone();
        forward[prefix + 1] = 126;
        assert!(recode(&forward).is_none());
        let mut wrong_kind = data.clone();
        wrong_kind[prefix] ^= 1;
        assert!(recode(&wrong_kind).is_none());
        let (too_large, _) = fixture(3, 14000);
        assert!(decode(&too_large).is_some());
        assert!(recode(&too_large).is_none());
        let (too_many_pairs, _) = fixture_runs(3, 17000, 65535);
        assert!(decode(&too_many_pairs).is_some());
        assert!(recode(&too_many_pairs).is_none());
        for invalid in [
            &[128][..],
            &[255, 255, 255, 255, 127][..],
            &[128, 128, 128, 128, 128, 0][..],
        ] {
            assert!(number(invalid, &mut 0).is_none());
        }
    }
}
