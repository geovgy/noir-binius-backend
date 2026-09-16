//! Reorder the same scalar DAG into groups with a common operation code.
//! Every node and both ordered edges survive under a checked bijection.

const MAX_DEPTH: usize = 4096;
const MAX_TOTAL: usize = 65_536;

#[derive(Clone, Debug)]
pub(super) struct Recoded {
    pub bytes: Vec<u8>,
    pub nodes: usize,
    pub groups: usize,
    pub max_depth: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Operation {
    code: u8,
    a: usize,
    b: usize,
}

fn number(data: &[u8], at: &mut usize) -> Option<usize> {
    let mut value = 0usize;
    for shift in (0..28).step_by(7) {
        let byte = *data.get(*at)?;
        *at += 1;
        value |= usize::from(byte & 127) << shift;
        if byte & 128 == 0 {
            return Some(value);
        }
    }
    None
}

fn uv(out: &mut Vec<u8>, mut value: usize) {
    while value >= 128 {
        out.push((value as u8) | 128);
        value >>= 7;
    }
    out.push(value as u8);
}

fn word(data: &[u8], at: usize) -> Option<usize> {
    Some(u16::from_be_bytes(data.get(at..at.checked_add(2)?)?.try_into().ok()?) as usize)
}

pub(super) fn recode(data: &[u8]) -> Option<Recoded> {
    recode_with_order(data, false)
}

pub(super) fn recode_ready(data: &[u8]) -> Option<Recoded> {
    recode_with_order(data, true)
}

fn ready_order(operations: &[Operation], initial: usize, codes: usize) -> Option<Vec<usize>> {
    let total = initial + operations.len();
    let mut successors = vec![Vec::new(); total];
    let mut pending = vec![0u8; total];
    let mut ready = vec![std::collections::VecDeque::new(); codes];
    for (index, op) in operations.iter().enumerate() {
        let id = initial + index;
        for child in [op.a, op.b] {
            if child >= initial {
                successors[child].push(id);
                pending[id] += 1;
            }
        }
        if pending[id] == 0 {
            ready[usize::from(op.code)].push_back(id);
        }
    }
    let mut order = Vec::with_capacity(operations.len());
    loop {
        // Prefer the largest ready queue, breaking ties by the lower code.
        // Drain it, including same-code successors made ready during emission.
        let code = (0..ready.len()).max_by_key(|&c| (ready[c].len(), std::cmp::Reverse(c)))?;
        if ready[code].is_empty() {
            break;
        }
        while let Some(id) = ready[code].pop_front() {
            order.push(id);
            for &successor in &successors[id] {
                pending[successor] = pending[successor].checked_sub(1)?;
                if pending[successor] == 0 {
                    ready[usize::from(operations[successor - initial].code)].push_back(successor);
                }
            }
        }
    }
    assert_eq!(
        order.len(),
        operations.len(),
        "grouping omitted an operation"
    );
    Some(order)
}

fn recode_with_order(data: &[u8], use_ready_order: bool) -> Option<Recoded> {
    if data.len() > 5 * MAX_TOTAL + 16 || *data.first()? != 255 {
        return None;
    }
    let nx = usize::from(*data.get(1)?);
    let ny = usize::from(*data.get(2)?);
    let n = nx + ny;
    if n == 0 || n > 36 {
        return None;
    }
    let initial = 8 + 2 * n;
    let mut at = 3;
    let count = number(data, &mut at)?;
    let root = number(data, &mut at)?;
    let a_bytes = number(data, &mut at)?;
    let total = initial.checked_add(count)?;
    if total > MAX_TOTAL
        || root >= total
        || a_bytes != count.checked_mul(2)?
        || at.checked_add(count.checked_mul(5)?)? != data.len()
    {
        return None;
    }
    let a_start = at + count;
    let b_start = a_start + a_bytes;
    let mut operations = Vec::with_capacity(count);
    let mut depths = vec![0usize; initial];
    for i in 0..count {
        let id = initial + i;
        let code = data[at + i];
        let da = word(data, a_start + 2 * i)?;
        let db = word(data, b_start + 2 * i)?;
        if usize::from(code) > 2 * n || da == 0 || db == 0 {
            return None;
        }
        let a = id.checked_sub(da)?;
        let b = id.checked_sub(db)?;
        let depth = 1 + depths[a].max(depths[b]);
        if depth > MAX_DEPTH {
            return None;
        }
        operations.push(Operation { code, a, b });
        depths.push(depth);
    }
    let max_depth = depths.iter().copied().max().unwrap_or(0);
    let order = if use_ready_order {
        ready_order(&operations, initial, 2 * n + 1)?
    } else {
        let mut order: Vec<_> = (initial..total).collect();
        order.sort_unstable_by_key(|&id| (depths[id], operations[id - initial].code, id));
        order
    };
    let mut mapping: Vec<_> = (0..initial).chain(std::iter::repeat_n(0, count)).collect();
    let mut reverse: Vec<_> = (0..initial).collect();
    let mut reordered = Vec::with_capacity(count);
    for (index, &old_id) in order.iter().enumerate() {
        let id = initial + index;
        let old = operations[old_id - initial];
        assert!(depths[old.a] < depths[old_id] && depths[old.b] < depths[old_id]);
        for child in [old.a, old.b] {
            assert!(child < initial || mapping[child] >= initial);
            assert!(mapping[child] < id);
        }
        mapping[old_id] = id;
        reverse.push(old_id);
        reordered.push(Operation {
            code: old.code,
            a: mapping[old.a],
            b: mapping[old.b],
        });
    }
    for (index, op) in reordered.iter().enumerate() {
        assert_eq!(
            Operation {
                code: op.code,
                a: reverse[op.a],
                b: reverse[op.b]
            },
            operations[reverse[initial + index] - initial],
            "grouping changed an equation"
        );
    }
    assert_eq!(reverse[mapping[root]], root, "grouping changed the root");

    let mut bytes = vec![255, (nx as u8) | 128, ny as u8];
    uv(&mut bytes, count);
    uv(&mut bytes, mapping[root]);
    uv(&mut bytes, a_bytes);
    let prefix = bytes.len();
    let mut groups = 0;
    let mut i = 0;
    while i < count {
        let start = i;
        let code = reordered[i].code;
        while i < count && reordered[i].code == code {
            i += 1;
        }
        bytes.push(code);
        bytes.extend_from_slice(&u16::try_from(i - start).ok()?.to_be_bytes());
        for (offset, op) in reordered[start..i].iter().enumerate() {
            let id = initial + start + offset;
            for child in [op.a, op.b] {
                let distance = u16::try_from(id.checked_sub(child)?).ok()?;
                assert_ne!(distance, 0);
                bytes.extend_from_slice(&distance.to_be_bytes());
            }
        }
        groups += 1;
    }
    // Independently decode the actual bytes, including group boundaries and
    // node IDs. Together with the bijection above this establishes equality
    // for all field inputs, rather than only sampled evaluation points.
    at = prefix;
    i = 0;
    while i < count {
        let code = bytes[at];
        let length = word(&bytes, at + 1)?;
        assert!(length > 0 && length <= count - i);
        at += 3;
        for _ in 0..length {
            let id = initial + i;
            let actual = Operation {
                code,
                a: id.checked_sub(word(&bytes, at)?)?,
                b: id.checked_sub(word(&bytes, at + 2)?)?,
            };
            assert_eq!(
                actual, reordered[i],
                "group serialization changed an operand"
            );
            i += 1;
            at += 4;
        }
    }
    assert_eq!(at, bytes.len());
    Some(Recoded {
        bytes,
        nodes: count,
        groups,
        max_depth,
    })
}

#[cfg(test)]
fn encode(nx: u8, ny: u8, ops: &[Operation], root: usize) -> Vec<u8> {
    let initial = 8 + 2 * usize::from(nx + ny);
    let mut bytes = vec![255, nx, ny];
    uv(&mut bytes, ops.len());
    uv(&mut bytes, root);
    uv(&mut bytes, 2 * ops.len());
    bytes.extend(ops.iter().map(|op| op.code));
    for high in [false, true] {
        for (i, op) in ops.iter().enumerate() {
            bytes.extend_from_slice(
                &u16::try_from(initial + i - if high { op.b } else { op.a })
                    .unwrap()
                    .to_be_bytes(),
            );
        }
    }
    bytes
}

#[cfg(test)]
pub(super) fn test_graph(count: usize) -> Vec<u8> {
    let ops: Vec<_> = (0..count)
        .map(|i| Operation {
            code: (i % 5) as u8,
            a: 1,
            b: 2,
        })
        .collect();
    encode(1, 1, &ops, 12 + count / 2)
}

#[cfg(test)]
mod tests {
    use super::*;
    type Recode = fn(&[u8]) -> Option<Recoded>;

    #[test]
    fn grouping_preserves_ordered_operands_and_nonlast_roots() {
        for recode in [super::recode as Recode, super::recode_ready] {
            let mut state = 0xa55a1213u64;
            for count in [0, 1, 127, 128, 1024, 16384] {
                let mut ops = Vec::new();
                for i in 0..count {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    let a = state as usize % (80 + i);
                    let b = (state >> 24) as usize % (80 + i);
                    ops.push(Operation {
                        code: (state % 73) as u8,
                        a,
                        b,
                    });
                }
                for root in [0, 79, 79 + count / 2, 79 + count] {
                    let result = recode(&encode(18, 18, &ops, root)).unwrap();
                    assert_eq!(result.nodes, count);
                    assert!(result.max_depth <= MAX_DEPTH);
                    assert_eq!(result.bytes[1], 128 | 18);
                }
            }
        }
    }

    #[test]
    fn grouping_checks_maximum_ids_distances_and_depth() {
        for recode in [super::recode as Recode, super::recode_ready] {
            let count = MAX_TOTAL - 10;
            let ops = vec![
                Operation {
                    code: 0,
                    a: 0,
                    b: 1
                };
                count
            ];
            let result = recode(&encode(1, 0, &ops, 65535)).unwrap();
            assert_eq!(result.groups, 1);
            assert_eq!(
                &result.bytes[result.bytes.len() - 4..],
                &[255, 255, 255, 254]
            );
            let chain: Vec<_> = (0..=MAX_DEPTH)
                .map(|i| Operation {
                    code: 1,
                    a: 9 + i,
                    b: 9 + i,
                })
                .collect();
            assert_eq!(
                recode(&encode(1, 0, &chain[..MAX_DEPTH], 9 + MAX_DEPTH))
                    .unwrap()
                    .max_depth,
                MAX_DEPTH
            );
            assert!(recode(&encode(1, 0, &chain, 10 + MAX_DEPTH)).is_none());
        }
    }

    #[test]
    fn grouping_rejects_invalid_headers_codes_and_references() {
        for recode in [super::recode as Recode, super::recode_ready] {
            let valid = encode(
                1,
                0,
                &[Operation {
                    code: 1,
                    a: 1,
                    b: 2,
                }],
                10,
            );
            assert!(recode(&valid).is_some());
            for (at, byte) in [
                (0, 254),
                (1, 128),
                (1, 37),
                (4, 11),
                (5, 3),
                (6, 3),
                (7, 255),
                (8, 0),
            ] {
                let mut bad = valid.clone();
                bad[at] = byte;
                assert!(recode(&bad).is_none(), "invalid byte at {at}");
            }
            for end in 0..valid.len() {
                assert!(recode(&valid[..end]).is_none());
            }
            let mut trailing = valid;
            trailing.push(0);
            assert!(recode(&trailing).is_none());
        }
    }

    #[test]
    fn ready_queues_drain_new_successors_and_keep_a_nonlast_root() {
        let operations = [
            Operation {
                code: 1,
                a: 0,
                b: 1,
            },
            Operation {
                code: 2,
                a: 0,
                b: 1,
            },
            Operation {
                code: 1,
                a: 12,
                b: 12,
            },
            Operation {
                code: 0,
                a: 14,
                b: 13,
            },
            Operation {
                code: 2,
                a: 13,
                b: 13,
            },
        ];
        assert_eq!(
            ready_order(&operations, 12, 5).unwrap(),
            [12, 14, 13, 16, 15]
        );
        let recoded = recode_ready(&encode(1, 1, &operations, 15)).unwrap();
        assert_eq!(&recoded.bytes[..6], &[255, 129, 1, 5, 16, 10]);
        assert_eq!(recoded.groups, 3);
        assert_eq!(recoded.max_depth, 3);
    }
}
