//! Exact factorization of a fixed sparse matrix's multilinear extension.
//!
//! The eight terminals are coefficient masks for 1, lambda and lambda^2.
//! A reduced decision node evaluates lo + x * (lo + hi). Literal products
//! shared by both edges are factored out, with no inversions. In particular,
//! coordinates equal to zero or one need no exceptional verification rule.

use std::collections::{BTreeSet, HashMap};

pub(super) const MARKER: u8 = 255;

#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
struct Edge {
    ones: u64,
    zeros: u64,
    node: usize,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct Branch {
    axis: u8,
    low: Edge,
    high: Edge,
}

struct Factored {
    branches: Vec<Branch>,
    root: Edge,
}

fn factor(points: &[(u64, u8)], order: &[u8]) -> Factored {
    let mut column: Vec<_> = points
        .iter()
        .map(|&(key, mask)| {
            let permuted = order
                .iter()
                .enumerate()
                .fold(0, |value, (i, &axis)| value | (((key >> axis) & 1) << i));
            (permuted, usize::from(mask))
        })
        .collect();
    column.sort_unstable();
    let mut nodes = Vec::new();
    let mut unique = HashMap::new();
    for rank in 0..order.len() {
        let mut next = Vec::new();
        for group in column.chunk_by(|a, b| a.0 >> 1 == b.0 >> 1) {
            let mut children = [0; 2];
            for &(key, id) in group {
                children[(key & 1) as usize] = id;
            }
            let [low, high] = children;
            // A missing high edge in a zero-suppressed diagram fixes this
            // coordinate to zero. The conversion below restores that literal.
            let id = if high == 0 {
                low
            } else {
                *unique.entry((rank, low, high)).or_insert_with(|| {
                    let id = 8 + nodes.len();
                    nodes.push((rank, low, high));
                    id
                })
            };
            if id != 0 {
                next.push((group[0].0 >> 1, id));
            }
        }
        column = next;
    }
    assert!(column.len() <= 1);
    let top = column.first().map_or(0, |&(key, id)| {
        assert_eq!(key, 0);
        id
    });
    let mut prefix = vec![0];
    for &axis in order {
        prefix.push(prefix.last().unwrap() | (1u64 << axis));
    }
    let gap = |edge: Edge, child_rank: usize, parent_rank: usize| {
        if edge.node == 0 {
            Edge::default()
        } else {
            Edge {
                zeros: edge.zeros | (prefix[parent_rank] ^ prefix[child_rank]),
                ..edge
            }
        }
    };
    let mut edges: Vec<_> = (0..8)
        .map(|node| Edge {
            node,
            ..Edge::default()
        })
        .collect();
    // A terminal precedes rank zero; other entries store rank + 1.
    let mut ranks = vec![0; 8];
    let mut branches = Vec::new();
    let mut unique = HashMap::new();
    for (rank, low, high) in nodes {
        assert!(ranks[low] <= rank && ranks[high] <= rank);
        let mut a = gap(edges[low], ranks[low], rank);
        let mut b = gap(edges[high], ranks[high], rank);
        let axis = order[rank];
        let edge = if a.node == 0 {
            Edge {
                ones: b.ones | (1u64 << axis),
                ..b
            }
        } else if b.node == 0 {
            Edge {
                zeros: a.zeros | (1u64 << axis),
                ..a
            }
        } else if a == b {
            a
        } else {
            let ones = a.ones & b.ones;
            let zeros = a.zeros & b.zeros;
            a.ones ^= ones;
            b.ones ^= ones;
            a.zeros ^= zeros;
            b.zeros ^= zeros;
            let branch = Branch {
                axis,
                low: a,
                high: b,
            };
            let node = *unique.entry(branch).or_insert_with(|| {
                let id = branches.len() + 8;
                branches.push(branch);
                id
            });
            Edge { ones, zeros, node }
        };
        assert_eq!(edge.ones & edge.zeros, 0);
        edges.push(edge);
        ranks.push(rank + 1);
    }
    let root = gap(edges[top], ranks[top], order.len());
    // Prune before choosing shared literal products so unused intermediates
    // cannot influence the deterministic product decomposition.
    let mut live = BTreeSet::new();
    let mut stack = vec![root.node];
    while let Some(id) = stack.pop() {
        if id >= 8 && live.insert(id) {
            stack.extend([branches[id - 8].low.node, branches[id - 8].high.node]);
        }
    }
    let mut mapping: HashMap<_, _> = (0..8).map(|id| (id, id)).collect();
    mapping.extend(live.iter().enumerate().map(|(i, &id)| (id, i + 8)));
    let remap = |edge: Edge| Edge {
        node: mapping[&edge.node],
        ..edge
    };
    Factored {
        branches: live
            .into_iter()
            .map(|id| {
                let b = branches[id - 8];
                Branch {
                    low: remap(b.low),
                    high: remap(b.high),
                    ..b
                }
            })
            .collect(),
        root: remap(root),
    }
}

impl Factored {
    /// Check the complete support, not a sample of Boolean evaluations. Also
    /// reject every repeated coordinate on a path: support equality alone
    /// would miss erroneous powers such as x^2 in a binary extension field.
    fn check(&self, points: &[(u64, u8)], dimensions: usize) {
        let domain = u64::MAX >> (64 - dimensions);
        let mut recovered = Vec::new();
        let mut stack = vec![(self.root, 0u64, 0u64)];
        while let Some((edge, mut used, mut key)) = stack.pop() {
            if edge.node == 0 {
                continue;
            }
            let literals = edge.ones | edge.zeros;
            assert_eq!(edge.ones & edge.zeros, 0);
            assert_eq!(literals & used, 0, "factored matrix repeats a coordinate");
            assert_eq!(literals & !domain, 0);
            used |= literals;
            key |= edge.ones;
            if edge.node < 8 {
                let free = domain ^ used;
                // The input support is bounded; a larger free cube could not
                // possibly equal it and must be rejected before enumeration.
                assert!((1u128 << free.count_ones()) <= points.len() as u128);
                let mut subset = free;
                loop {
                    recovered.push((key | subset, edge.node as u8));
                    assert!(recovered.len() <= points.len());
                    if subset == 0 {
                        break;
                    }
                    subset = subset.wrapping_sub(1) & free;
                }
            } else {
                let branch = self.branches[edge.node - 8];
                let bit = 1u64 << branch.axis;
                assert_eq!(used & bit, 0, "factored matrix repeats a decision");
                stack.push((branch.low, used | bit, key));
                stack.push((branch.high, used | bit, key | bit));
            }
        }
        recovered.sort_unstable();
        assert_eq!(recovered, points, "factorization changed the native matrix");
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct Operation {
    code: u8,
    a: usize,
    b: usize,
}

struct Expressions {
    initial: usize,
    ops: Vec<Operation>,
    unique: HashMap<Operation, usize>,
    subsets: HashMap<(usize, u64, bool), usize>,
    dimensions: usize,
}
impl Expressions {
    fn node(&mut self, code: u8, a: usize, b: usize) -> usize {
        let op = Operation { code, a, b };
        *self.unique.entry(op).or_insert_with(|| {
            let id = self.initial + self.ops.len();
            self.ops.push(op);
            id
        })
    }
    fn mul(&mut self, a: usize, b: usize) -> usize {
        if a == 0 || b == 0 {
            return 0;
        }
        if a == 1 {
            return b;
        }
        if b == 1 {
            return a;
        }
        self.node(0, a.min(b), a.max(b))
    }
    fn subset(&mut self, start: usize, mask: u64, zero: bool) -> usize {
        if mask == 0 {
            return 1;
        }
        let key = (start, mask, zero);
        if let Some(&id) = self.subsets.get(&key) {
            return id;
        }
        let bit = mask.trailing_zeros() as usize;
        let rest = self.subset(start, mask & (mask - 1), zero);
        let point = 8 + usize::from(zero) * self.dimensions + start + bit;
        let result = self.mul(point, rest);
        self.subsets.insert(key, result);
        result
    }
}

fn expressions(graph: &Factored, dimensions: usize, width: usize) -> (Vec<Operation>, usize) {
    let mut e = Expressions {
        initial: 8 + 2 * dimensions,
        dimensions,
        ops: Vec::new(),
        unique: HashMap::new(),
        subsets: HashMap::new(),
    };
    let cubes: BTreeSet<_> = [(0, 0), (graph.root.ones, graph.root.zeros)]
        .into_iter()
        .chain(
            graph
                .branches
                .iter()
                .flat_map(|b| [b.low, b.high])
                .map(|r| (r.ones, r.zeros)),
        )
        .collect();
    let mut factors = HashMap::new();
    for (ones, zeros) in cubes {
        let mut chunks = Vec::new();
        for start in (0..dimensions).step_by(width) {
            let mask = (1 << width) - 1;
            let a = e.subset(start, (ones >> start) & mask, false);
            let b = e.subset(start, (zeros >> start) & mask, true);
            chunks.push(e.mul(a, b));
        }
        let mut product = 1;
        for chunk in chunks.into_iter().rev() {
            product = e.mul(product, chunk);
        }
        factors.insert((ones, zeros), product);
    }
    let mut values: Vec<_> = (0..8).collect();
    for branch in &graph.branches {
        let edge =
            |e: &mut Expressions, r: Edge| e.mul(factors[&(r.ones, r.zeros)], values[r.node]);
        let mut a = edge(&mut e, branch.low);
        let mut b = edge(&mut e, branch.high);
        let mut code = branch.axis + 1;
        if a > b {
            std::mem::swap(&mut a, &mut b);
            code += dimensions as u8;
        }
        let value = if a == b {
            a
        } else if a == 0 {
            e.mul(7 + usize::from(code), b)
        } else {
            e.node(code, a, b)
        };
        values.push(value);
    }
    let root = e.mul(
        factors[&(graph.root.ones, graph.root.zeros)],
        values[graph.root.node],
    );
    let mut live = BTreeSet::new();
    let mut stack = vec![root];
    while let Some(id) = stack.pop() {
        if id >= e.initial && live.insert(id) {
            let op = e.ops[id - e.initial];
            stack.extend([op.a, op.b]);
        }
    }
    let mut mapping: HashMap<_, _> = (0..e.initial).map(|i| (i, i)).collect();
    mapping.extend(live.iter().enumerate().map(|(i, &id)| (id, i + e.initial)));
    let ops = live
        .into_iter()
        .map(|id| {
            let op = e.ops[id - e.initial];
            Operation {
                a: mapping[&op.a],
                b: mapping[&op.b],
                ..op
            }
        })
        .collect();
    (ops, mapping[&root])
}

fn uv(out: &mut Vec<u8>, mut value: usize) {
    while value >= 128 {
        out.push((value as u8) | 128);
        value >>= 7;
    }
    out.push(value as u8);
}
fn number(input: &[u8], p: &mut usize) -> usize {
    let mut value = 0;
    let mut shift = 0;
    loop {
        let octet = input[*p];
        *p += 1;
        value |= usize::from(octet & 127) << shift;
        if octet & 128 == 0 {
            return value;
        }
        shift += 7;
    }
}

fn serialize(nx: usize, ny: usize, ops: &[Operation], root: usize) -> Vec<u8> {
    let initial = 8 + 2 * (nx + ny);
    let mut codes = Vec::new();
    let mut a = Vec::new();
    let mut b = Vec::new();
    for (i, op) in ops.iter().enumerate() {
        assert!(usize::from(op.code) <= 2 * (nx + ny));
        assert!(op.a < initial + i && op.b < initial + i);
        codes.push(op.code);
        uv(&mut a, initial + i - op.a);
        uv(&mut b, initial + i - op.b);
    }
    let mut output = vec![MARKER, nx as u8, ny as u8];
    uv(&mut output, ops.len());
    uv(&mut output, root);
    uv(&mut output, a.len());
    output.extend(codes);
    output.extend(a);
    output.extend(b);
    let (decoded, decoded_root) = deserialize(&output);
    assert_eq!(decoded, ops, "factored operand encoding changed equations");
    assert_eq!(decoded_root, root);
    output
}

fn deserialize(input: &[u8]) -> (Vec<Operation>, usize) {
    assert_eq!(input[0], MARKER);
    let n = usize::from(input[1]) + usize::from(input[2]);
    let initial = 8 + 2 * n;
    let mut codes = 3;
    let count = number(input, &mut codes);
    let root = number(input, &mut codes);
    let a_bytes = number(input, &mut codes);
    let mut a = codes + count;
    let mut b = a + a_bytes;
    let end_a = b;
    let ops = (0..count)
        .map(|i| {
            let code = input[codes + i];
            assert!(usize::from(code) <= 2 * n);
            let da = number(input, &mut a);
            let db = number(input, &mut b);
            assert!(da > 0 && da <= initial + i && db > 0 && db <= initial + i);
            Operation {
                code,
                a: initial + i - da,
                b: initial + i - db,
            }
        })
        .collect();
    assert_eq!(a, end_a);
    assert_eq!(b, input.len());
    assert!(root < initial + count);
    (ops, root)
}

pub(super) fn operation_count(data: &[u8]) -> usize {
    assert_eq!(data[0], MARKER);
    number(data, &mut 3)
}

/// Recode the same postorder equations for the fixed-u16 runtime. Only the
/// constructor's circuit data changes; no transcript or field value is recoded.
/// Return None rather than truncating a back-reference larger than u16.
pub(super) fn fixed_operands(input: &[u8]) -> Option<Vec<u8>> {
    let (ops, root) = deserialize(input);
    let initial = 8 + 2 * (usize::from(input[1]) + usize::from(input[2]));
    let mut codes = Vec::with_capacity(ops.len());
    let mut a = Vec::with_capacity(2 * ops.len());
    let mut b = Vec::with_capacity(2 * ops.len());
    for (i, op) in ops.iter().enumerate() {
        codes.push(op.code);
        a.extend_from_slice(&u16::try_from(initial + i - op.a).ok()?.to_be_bytes());
        b.extend_from_slice(&u16::try_from(initial + i - op.b).ok()?.to_be_bytes());
    }
    let mut output = input[..3].to_vec();
    uv(&mut output, ops.len());
    uv(&mut output, root);
    uv(&mut output, a.len());
    output.extend(codes);
    output.extend(a);
    output.extend(b);
    // Independently recover every operation from its fixed offsets. Equality
    // of the complete scalar DAG preserves the polynomial at every field point.
    assert_eq!(decode_fixed_operands(&output), (ops, root));
    Some(output)
}

fn decode_fixed_operands(input: &[u8]) -> (Vec<Operation>, usize) {
    assert_eq!(input[0], MARKER);
    let initial = 8 + 2 * (usize::from(input[1]) + usize::from(input[2]));
    let mut at = 3;
    let count = number(input, &mut at);
    let root = number(input, &mut at);
    assert_eq!(number(input, &mut at), 2 * count);
    assert_eq!(input.len(), at + 5 * count);
    assert!(root < initial + count);
    let references = &input[at + count..];
    let ops = (0..count)
        .map(|i| {
            let da = usize::from(u16::from_be_bytes(
                references[2 * i..2 * i + 2].try_into().unwrap(),
            ));
            let db = usize::from(u16::from_be_bytes(
                references[2 * (count + i)..2 * (count + i + 1)]
                    .try_into()
                    .unwrap(),
            ));
            assert!(da > 0 && da <= initial + i && db > 0 && db <= initial + i);
            Operation {
                code: input[at + i],
                a: initial + i - da,
                b: initial + i - db,
            }
        })
        .collect();
    (ops, root)
}

/// Bound specialization work and data growth. Large private matrices retain
/// affine contractions; this representation targets the smaller fixed matrix.
pub(super) fn encode(points: &[(u32, u32, u8)], nx: usize, ny: usize) -> Option<Vec<u8>> {
    encode_bounded(points, nx, ny, 16_384)
}

/// The compact Yul constructor can accommodate larger fixed matrix regions.
/// The same complete support and multilinearity checks apply at both bounds.
pub(super) fn encode_for_deployment(
    points: &[(u32, u32, u8)],
    nx: usize,
    ny: usize,
) -> Option<Vec<u8>> {
    encode_bounded(points, nx, ny, 32_768)
}

fn encode_bounded(
    points: &[(u32, u32, u8)],
    nx: usize,
    ny: usize,
    max_points: usize,
) -> Option<Vec<u8>> {
    if nx > 32 || ny > 32 || nx + ny == 0 || points.len() > max_points {
        return None;
    }
    let mut canonical: Vec<_> = points
        .iter()
        .map(|&(r, c, mask)| {
            assert!(
                u64::from(r) < 1u64 << nx && u64::from(c) < 1u64 << ny && (1..8).contains(&mask)
            );
            (u64::from(r) | (u64::from(c) << nx), mask)
        })
        .collect();
    canonical.sort_unstable();
    let mut combined: Vec<(u64, u8)> = Vec::new();
    for (key, mask) in canonical {
        if let Some(last) = combined.last_mut().filter(|p| p.0 == key) {
            last.1 ^= mask;
        } else {
            combined.push((key, mask));
        }
    }
    combined.retain(|p| p.1 != 0);
    let dimensions = nx + ny;
    let mut best: Option<(usize, Vec<u8>)> = None;
    for shift in -8i32..=10 {
        let mut order = Vec::new();
        for i in -12i32..50 {
            if i >= 0 && i < nx as i32 {
                order.push(i as u8);
            }
            let y = i + shift;
            if y >= 0 && y < ny as i32 {
                order.push((nx as i32 + y) as u8);
            }
        }
        assert_eq!(order.len(), dimensions);
        let graph = factor(&combined, &order);
        graph.check(&combined, dimensions);
        for width in 4..=10 {
            let (ops, root) = expressions(&graph, dimensions, width);
            let encoded = serialize(nx, ny, &ops, root);
            if best
                .as_ref()
                .is_none_or(|(count, data)| (ops.len(), encoded.len()) < (*count, data.len()))
            {
                best = Some((ops.len(), encoded));
            }
        }
    }
    best.map(|(_, data)| data)
}

#[cfg(test)]
pub(super) fn evaluate(data: &[u8], x: &[super::F], y: &[super::F], lambda: super::F) -> super::F {
    use super::{Field, Square};
    let (ops, root) = deserialize(data);
    assert_eq!(x.len(), usize::from(data[1]));
    assert_eq!(y.len(), usize::from(data[2]));
    let square = lambda.square();
    let mut v = vec![
        super::F::ZERO,
        super::F::ONE,
        lambda,
        lambda + super::F::ONE,
        square,
        square + super::F::ONE,
        square + lambda,
        square + lambda + super::F::ONE,
    ];
    v.extend(x.iter().chain(y).copied());
    v.extend(x.iter().chain(y).map(|&r| r + super::F::ONE));
    for op in ops {
        let a = v[op.a];
        let b = v[op.b];
        v.push(if op.code == 0 {
            a * b
        } else {
            a + v[7 + usize::from(op.code)] * (a + b)
        });
    }
    v[root]
}

#[cfg(test)]
mod tests {
    use super::super::{F, Field};
    use super::*;

    #[test]
    fn fixed_operands_preserve_complete_graphs_and_u16_boundary() {
        for points in [vec![], vec![(0, 0, 1), (1, 2, 7), (3, 1, 5)]] {
            let original = encode(&points, 2, 2).unwrap();
            let fixed = fixed_operands(&original).unwrap();
            assert_eq!(deserialize(&original), decode_fixed_operands(&fixed));
        }
        // The last valid back-reference is 65535, independent of its value.
        // Adding one more operation must return None, never wrap it to zero.
        let initial = 12;
        let mut ops = vec![
            Operation {
                code: 0,
                a: 0,
                b: 1
            };
            65536 - initial
        ];
        let valid = serialize(1, 1, &ops, initial + ops.len() - 1);
        assert!(fixed_operands(&valid).is_some());
        ops.push(Operation {
            code: 0,
            a: 0,
            b: 1,
        });
        let too_wide = serialize(1, 1, &ops, initial + ops.len() - 1);
        assert!(fixed_operands(&too_wide).is_none());
    }

    fn direct(points: &[(u32, u32, u8)], x: &[F], y: &[F], lambda: F) -> F {
        points
            .iter()
            .map(|&(r, c, mask)| {
                let indicator = x
                    .iter()
                    .enumerate()
                    .map(|(i, &v)| if r >> i & 1 == 0 { v + F::ONE } else { v })
                    .chain(
                        y.iter()
                            .enumerate()
                            .map(|(i, &v)| if c >> i & 1 == 0 { v + F::ONE } else { v }),
                    )
                    .product::<F>();
                let a = if mask & 1 != 0 { F::ONE } else { F::ZERO };
                let b = if mask & 2 != 0 { lambda } else { F::ZERO };
                let c = if mask & 4 != 0 {
                    lambda * lambda
                } else {
                    F::ZERO
                };
                indicator * (a + b + c)
            })
            .sum()
    }

    #[test]
    fn sparse_factorization_preserves_native_field_polynomial() {
        let mut state = 0x123456789abcdef00123456789abcdefu128;
        let mut random = || {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 43;
            state
        };
        for case in 0..12 {
            let (nx, ny) = if case == 0 { (32, 32) } else { (5, 4) };
            let points: Vec<_> = (0..case * 7)
                .map(|_| {
                    (
                        (random() as u32) & (u32::MAX >> (32 - nx)),
                        (random() as u32) & (u32::MAX >> (32 - ny)),
                        (random() % 7 + 1) as u8,
                    )
                })
                .collect();
            let data = encode(&points, nx, ny).unwrap();
            for sample in 0..24 {
                let mut point: Vec<F> = (0..nx + ny).map(|_| random().into()).collect();
                if sample < 2 {
                    point.fill(F::from(sample as u128));
                }
                if sample == 2 {
                    for (i, p) in point.iter_mut().enumerate() {
                        if i % 3 == 0 {
                            *p = F::from((i % 2) as u128);
                        }
                    }
                }
                let lambda = F::from(if sample < 2 { sample as u128 } else { random() });
                assert_eq!(
                    evaluate(&data, &point[..nx], &point[nx..], lambda),
                    direct(&points, &point[..nx], &point[nx..], lambda)
                );
            }
        }
        let repeated = vec![(3, 2, 7), (3, 2, 7), (1, 0, 2), (1, 0, 4), (0, 3, 1)];
        let data = encode(&repeated, 2, 2).unwrap();
        let point = [F::from(0), F::from(1), F::from(0xab), F::from(0xcd)];
        assert_eq!(
            evaluate(&data, &point[..2], &point[2..], F::from(3)),
            direct(&repeated, &point[..2], &point[2..], F::from(3))
        );
        let wide = vec![
            (u32::MAX, 0, 7),
            (0, u32::MAX, 3),
            (0x80000000, 0x80000000, 5),
        ];
        let data = encode(&wide, 32, 32).unwrap();
        let point: Vec<F> = (0..64).map(|_| random().into()).collect();
        assert_eq!(
            evaluate(&data, &point[..32], &point[32..], F::from(3)),
            direct(&wide, &point[..32], &point[32..], F::from(3))
        );
    }

    #[test]
    #[should_panic(expected = "factored matrix repeats a coordinate")]
    fn support_check_rejects_boolean_equivalent_non_multilinear_expression() {
        // (1 + x)^2 agrees with (1 + x) on {0,1}, but not in GF(2^128).
        let graph = Factored {
            root: Edge {
                node: 8,
                ..Edge::default()
            },
            branches: vec![Branch {
                axis: 0,
                low: Edge {
                    zeros: 1,
                    node: 1,
                    ..Edge::default()
                },
                high: Edge::default(),
            }],
        };
        graph.check(&[(0, 1)], 1);
    }
}
