//! Narrow terminal references in product nodes without changing any equation.

const MAX_TOTAL: usize = 65_536;
const MAX_DEPTH: usize = 4096;

pub(super) struct Recoded {
    pub bytes: Vec<u8>,
    pub nodes: usize,
    pub groups: usize,
    pub max_depth: usize,
    pub short_products: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Operation {
    code: u8,
    a: usize,
    b: usize,
}

fn number(data: &[u8], at: &mut usize) -> Option<usize> {
    let mut value = 0;
    for shift in (0..28).step_by(7) {
        let byte = *data.get(*at)?;
        *at += 1;
        value |= usize::from(byte & 127) << shift;
        if byte < 128 {
            return Some(value);
        }
    }
    None
}

fn uv(output: &mut Vec<u8>, mut value: usize) {
    while value >= 128 {
        output.push((value as u8) | 128);
        value >>= 7;
    }
    output.push(value as u8);
}

fn word(data: &[u8], at: usize) -> Option<usize> {
    Some(u16::from_be_bytes(data.get(at..at.checked_add(2)?)?.try_into().ok()?) as usize)
}

/// Input is the existing grouped-u16 graph. Stable depth/code ordering before
/// this pass preserves the original scalar order within every such bucket.
/// Sorting by one extra terminal flag therefore matches constructor emission.
pub(super) fn recode(data: &[u8]) -> Option<Recoded> {
    if data.len() > 7 * MAX_TOTAL + 16 || *data.first()? != 255 {
        return None;
    }
    let encoded_nx = *data.get(1)?;
    if encoded_nx & 128 == 0 {
        return None;
    }
    let nx = usize::from(encoded_nx & 127);
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
    if total > MAX_TOTAL || root >= total || a_bytes != count.checked_mul(2)? {
        return None;
    }
    let mut operations = Vec::with_capacity(count);
    let mut depths = vec![0; initial];
    let mut previous = (0, 0);
    while operations.len() < count {
        let code = *data.get(at)?;
        let length = word(data, at + 1)?;
        if usize::from(code) > 2 * n || length == 0 || length > count - operations.len() {
            return None;
        }
        at += 3;
        for _ in 0..length {
            let id = initial + operations.len();
            let da = word(data, at)?;
            let db = word(data, at + 2)?;
            if da == 0 || db == 0 {
                return None;
            }
            let a = id.checked_sub(da)?;
            let b = id.checked_sub(db)?;
            let depth = 1 + depths[a].max(depths[b]);
            if depth > MAX_DEPTH || (depth, code) < previous {
                return None;
            }
            previous = (depth, code);
            depths.push(depth);
            operations.push(Operation { code, a, b });
            at += 4;
        }
    }
    if at != data.len() {
        return None;
    }
    let max_depth = depths.iter().copied().max().unwrap_or(0);
    let mut order: Vec<_> = (initial..total).collect();
    order.sort_unstable_by_key(|&id| {
        let op = operations[id - initial];
        (depths[id], op.code, op.code == 0 && op.a < initial, id)
    });
    let mut mapping: Vec<_> = (0..initial)
        .chain(std::iter::repeat_n(usize::MAX, count))
        .collect();
    let mut reverse: Vec<_> = (0..initial).collect();
    let mut changed = Vec::with_capacity(count);
    for (id, &old_id) in (initial..total).zip(&order) {
        let op = operations[old_id - initial];
        assert!(depths[op.a] < depths[old_id] && depths[op.b] < depths[old_id]);
        let a = mapping[op.a];
        let b = mapping[op.b];
        assert!(
            a < id && b < id,
            "operand was not emitted before its parent"
        );
        mapping[old_id] = id;
        reverse.push(old_id);
        changed.push(Operation {
            code: op.code,
            a,
            b,
        });
    }
    for (id, op) in (initial..total).zip(&changed) {
        assert_eq!(
            Operation {
                code: op.code,
                a: reverse[op.a],
                b: reverse[op.b]
            },
            operations[reverse[id] - initial],
            "terminal grouping changed an ordered equation"
        );
    }
    assert_eq!(
        reverse[mapping[root]], root,
        "terminal grouping changed the root"
    );

    let mut bytes = vec![255, encoded_nx, ny as u8];
    uv(&mut bytes, count);
    uv(&mut bytes, mapping[root]);
    uv(&mut bytes, a_bytes);
    let prefix = bytes.len();
    let mut index = 0;
    let mut groups = 0;
    let mut short_products = 0;
    while index < count {
        let start = index;
        let op = changed[start];
        let short = op.code == 0 && op.a < initial;
        while index < count {
            let next = changed[index];
            if next.code != op.code || (next.code == 0 && next.a < initial) != short {
                break;
            }
            index += 1;
        }
        bytes.push(if short { 128 } else { op.code });
        bytes.extend_from_slice(&u16::try_from(index - start).ok()?.to_be_bytes());
        for (offset, node) in changed[start..index].iter().enumerate() {
            let id = initial + start + offset;
            if short {
                bytes.push(u8::try_from(node.a).ok()?);
                short_products += 1;
            } else {
                bytes.extend_from_slice(&u16::try_from(id - node.a).ok()?.to_be_bytes());
            }
            bytes.extend_from_slice(&u16::try_from(id - node.b).ok()?.to_be_bytes());
        }
        groups += 1;
    }
    // Decode the actual byte stream independently of the writer. Only tag128
    // is narrow; interpolation references retain their complete two-byte form.
    at = prefix;
    index = 0;
    while index < count {
        let code = bytes[at];
        let length = word(&bytes, at + 1)?;
        assert!(length > 0 && length <= count - index);
        assert!(usize::from(code) <= 2 * n || code == 128);
        at += 3;
        for _ in 0..length {
            let id = initial + index;
            let a = if code == 128 {
                let value = usize::from(bytes[at]);
                at += 1;
                assert!(value < initial);
                value
            } else {
                let value = id.checked_sub(word(&bytes, at)?)?;
                at += 2;
                value
            };
            let b = id.checked_sub(word(&bytes, at)?)?;
            at += 2;
            assert_eq!(
                Operation {
                    code: code & 127,
                    a,
                    b
                },
                changed[index]
            );
            index += 1;
        }
    }
    assert_eq!(at, bytes.len());
    Some(Recoded {
        bytes,
        nodes: count,
        groups,
        max_depth,
        short_products,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(nx: u8, ny: u8, operations: &[Operation], root: usize) -> Vec<u8> {
        let first = 8 + 2 * usize::from(nx + ny);
        let mut bytes = vec![255, nx | 128, ny];
        uv(&mut bytes, operations.len());
        uv(&mut bytes, root);
        uv(&mut bytes, 2 * operations.len());
        let mut start = 0;
        while start < operations.len() {
            let code = operations[start].code;
            let end = (start..operations.len())
                .find(|&i| operations[i].code != code)
                .unwrap_or(operations.len());
            bytes.push(code);
            bytes.extend_from_slice(&u16::try_from(end - start).unwrap().to_be_bytes());
            for (i, op) in operations[start..end].iter().enumerate() {
                bytes.extend_from_slice(
                    &u16::try_from(first + start + i - op.a)
                        .unwrap()
                        .to_be_bytes(),
                );
                bytes.extend_from_slice(
                    &u16::try_from(first + start + i - op.b)
                        .unwrap()
                        .to_be_bytes(),
                );
            }
            start = end;
        }
        bytes
    }

    #[test]
    fn retains_operand_roles_and_moves_a_nonlast_root() {
        // IDs12,13 have depth1. IDs14..17 have depth2/code0; narrow nodes
        // move after wide nodes. ID18 uses both remapped children at depth3.
        let ops = [
            Operation {
                code: 0,
                a: 0,
                b: 2,
            },
            Operation {
                code: 1,
                a: 3,
                b: 4,
            },
            Operation {
                code: 0,
                a: 1,
                b: 12,
            },
            Operation {
                code: 0,
                a: 12,
                b: 1,
            },
            Operation {
                code: 0,
                a: 2,
                b: 13,
            },
            Operation {
                code: 0,
                a: 13,
                b: 12,
            },
            Operation {
                code: 2,
                a: 14,
                b: 17,
            },
        ];
        let changed = recode(&encode(1, 1, &ops, 14)).unwrap();
        let mut at = 3;
        assert_eq!(number(&changed.bytes, &mut at), Some(7));
        assert_eq!(number(&changed.bytes, &mut at), Some(16));
        assert_eq!(changed.short_products, 3);
        assert_eq!(changed.max_depth, 3);
        assert!(changed.bytes.windows(6).any(|w| w == [128, 0, 1, 0, 0, 10]));
        assert!(
            recode(&changed.bytes).is_none(),
            "a tagged graph must not be recoded as ordinary groups"
        );
    }

    #[test]
    fn handles_full_u16_group_counts_and_terminal_roots() {
        let ops = vec![
            Operation {
                code: 0,
                a: 0,
                b: 1
            };
            65526
        ];
        let changed = recode(&encode(1, 0, &ops, 65535)).unwrap();
        assert_eq!(
            (changed.nodes, changed.groups, changed.short_products),
            (65526, 1, 65526)
        );
        let mut at = 3;
        assert_eq!(number(&changed.bytes, &mut at), Some(65526));
        assert_eq!(number(&changed.bytes, &mut at), Some(65535));
        assert_eq!(number(&changed.bytes, &mut at), Some(131052));
        assert_eq!(&changed.bytes[at..at + 3], &[128, 255, 246]);
        let empty = recode(&encode(1, 0, &[], 7)).unwrap();
        assert_eq!((empty.nodes, empty.groups, empty.short_products), (0, 0, 0));
    }

    #[test]
    fn keeps_interpolation_terminals_wide_and_enforces_depth() {
        let ops = [Operation {
            code: 1,
            a: 0,
            b: 1,
        }];
        let input = encode(1, 0, &ops, 10);
        let output = recode(&input).unwrap();
        assert_eq!(output.bytes, input);
        assert_eq!(output.short_products, 0);
        let mut chain = Vec::new();
        for i in 0..4097 {
            chain.push(Operation {
                code: 0,
                a: 1,
                b: if i == 0 { 2 } else { 9 + i },
            });
        }
        assert_eq!(
            recode(&encode(1, 0, &chain[..4096], 4105))
                .unwrap()
                .max_depth,
            4096
        );
        assert!(recode(&encode(1, 0, &chain, 4106)).is_none());
    }

    #[test]
    fn rejects_malformed_groups_and_unstable_input_order() {
        let ops = [Operation {
            code: 0,
            a: 1,
            b: 2,
        }];
        let input = encode(1, 0, &ops, 10);
        for end in 0..input.len() {
            assert!(recode(&input[..end]).is_none());
        }
        let mut invalid = input.clone();
        invalid.push(0);
        assert!(recode(&invalid).is_none());
        let mut invalid = input.clone();
        let n = invalid.len();
        invalid[n - 4..n - 2].fill(0);
        assert!(recode(&invalid).is_none());
        let mut invalid = input.clone();
        invalid[1] = 128;
        invalid[2] = 0;
        assert!(recode(&invalid).is_none());
        let mut invalid = input;
        invalid[1] = 128 | 37;
        assert!(recode(&invalid).is_none());
        let unordered = [
            Operation {
                code: 1,
                a: 1,
                b: 2,
            },
            Operation {
                code: 0,
                a: 2,
                b: 3,
            },
        ];
        assert!(recode(&encode(1, 0, &unordered, 11)).is_none());
    }
}
