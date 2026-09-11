//! Outline repeated operations on complete 128-element vectors. This is a
//! data-independent graph rewrite: every scalar result remains the same field
//! operation on the same inputs. Transcript observations retain identical bytes.
use super::*;

fn remap(op: &Op, map: &[u32]) -> Op {
    let r = |id: u32| map[id as usize];
    match op {
        Op::Add(a, b) => Op::Add(r(*a), r(*b)),
        Op::Mul(a, b) => Op::Mul(r(*a), r(*b)),
        Op::Inverse(a) => Op::Inverse(r(*a)),
        Op::Assert(a) => Op::Assert(r(*a)),
        Op::Shr(a, b) => Op::Shr(r(*a), *b),
        Op::Shl(a, b) => Op::Shl(r(*a), *b),
        Op::Bit(a, b) => Op::Bit(r(*a), *b),
        Op::LowBits(a, b) => Op::LowBits(r(*a), *b),
        Op::Layer(a, b, c) => Op::Layer(r(*a), *b, *c),
        Op::Path(a, b, c, d, e) => Op::Path(r(*a), *b, *c, *d, *e),
        Op::Vector(a, b, c, d) => Op::Vector(r(*a), *b, *c, *d),
        Op::Transpose(v) => Op::Transpose(v.iter().map(|&i| r(i)).collect()),
        Op::Array(v) => Op::Array(v.iter().map(|&i| r(i)).collect()),
        Op::SmallEq(v) => Op::SmallEq(v.iter().map(|&i| r(i)).collect()),
        Op::Frobenius(a) => Op::Frobenius(r(*a)),
        Op::TransposeOf(a) => Op::TransposeOf(r(*a)),
        Op::Row(a, b) => Op::Row(r(*a), *b),
        Op::Lookup(a, b, c) => Op::Lookup(r(*a), r(*b), *c),
        Op::Wiring(a, b, c, d, e) => Op::Wiring(r(*a), r(*b), r(*c), r(*d), *e),
        Op::PublicWiring(config) => Op::PublicWiring(config.remap(r).into()),
        Op::Fri(config) => Op::Fri(config.remap(r).into()),
        Op::InnerWiring(config) => Op::InnerWiring(config.remap(r).into()),
        Op::VectorBinary(a, b, kind, shift) => Op::VectorBinary(r(*a), r(*b), *kind, *shift),
        _ => op.clone(),
    }
}
fn push(ops: &mut Vec<Op>, op: Op) -> u32 {
    let id = ops.len() as u32;
    ops.push(op);
    id
}

fn samples(graph: Graph) -> Graph {
    let mut ops = vec![];
    let mut map = vec![0; graph.ops.len()];
    let mut i = 0;
    while i < graph.ops.len() {
        if i + 128 <= graph.ops.len()
            && graph.ops[i..i + 128]
                .iter()
                .all(|op| matches!(op, Op::Sample))
        {
            let array = push(&mut ops, Op::SampleFields);
            for j in 0..128 {
                map[i + j] = push(&mut ops, Op::Row(array, j));
            }
            i += 128;
        } else {
            map[i] = push(&mut ops, remap(&graph.ops[i], &map));
            i += 1;
        }
    }
    Graph {
        ops,
        cse: HashMap::new(),
        replay_cursor: None,
    }
}
fn reads(graph: Graph) -> Graph {
    let mut ops = vec![];
    let mut map = vec![0; graph.ops.len()];
    let mut i = 0;
    while i < graph.ops.len() {
        let start = match graph.ops[i] {
            Op::Observe(offset, 16) => Some(offset),
            _ => None,
        };
        if let Some(start) = start {
            let complete = i + 256 <= graph.ops.len()
                && (0..128).all(|j| {
                    graph.ops[i + 2 * j] == Op::Observe(start + 16 * j, 16)
                        && graph.ops[i + 2 * j + 1] == Op::Read(start + 16 * j, 16)
                });
            if complete {
                let observe = push(&mut ops, Op::Observe(start, 2048));
                let array = push(&mut ops, Op::ReadFields(start));
                for j in 0..128 {
                    map[i + 2 * j] = observe;
                    map[i + 2 * j + 1] = push(&mut ops, Op::Row(array, j));
                }
                i += 256;
                continue;
            }
        }
        map[i] = push(&mut ops, remap(&graph.ops[i], &map));
        i += 1;
    }
    Graph {
        ops,
        cse: HashMap::new(),
        replay_cursor: None,
    }
}
fn array_views(graph: Graph) -> Graph {
    let mut ops = vec![];
    let mut map = vec![0; graph.ops.len()];
    for (i, op) in graph.ops.iter().enumerate() {
        let mut op = remap(op, &map);
        if let Op::Transpose(values) = &op {
            let parent = match ops[values[0] as usize] {
                Op::Row(parent, 0) => Some(parent),
                _ => None,
            };
            if let Some(parent) = parent.filter(|&parent| {
                values
                    .iter()
                    .enumerate()
                    .all(|(i, &id)| ops[id as usize] == Op::Row(parent, i))
            }) {
                if let Op::TransposeOf(source) = ops[parent as usize] {
                    map[i] = source;
                    continue;
                }
                op = Op::TransposeOf(parent);
            }
        }
        map[i] = push(&mut ops, op);
    }
    Graph {
        ops,
        cse: HashMap::new(),
        replay_cursor: None,
    }
}

fn squares(graph: Graph) -> Graph {
    let mut chains = vec![None; graph.ops.len()];
    let mut longest = HashMap::<u32, usize>::new();
    for (i, op) in graph.ops.iter().enumerate() {
        if let Op::Mul(a, b) = op {
            if a == b {
                let (base, exponent) = chains[*a as usize].unwrap_or((*a, 0));
                chains[i] = Some((base, exponent + 1));
                longest
                    .entry(base)
                    .and_modify(|n| *n = (*n).max(exponent + 1))
                    .or_insert(exponent + 1);
            }
        }
    }
    let mut ops = vec![];
    let mut map = vec![0; graph.ops.len()];
    let mut arrays = HashMap::new();
    for (i, op) in graph.ops.iter().enumerate() {
        if let Some((base, exponent)) = chains[i].filter(|(base, _)| longest[base] >= 8) {
            if exponent % 128 == 0 {
                map[i] = map[base as usize];
                continue;
            }
            let array = *arrays
                .entry(base)
                .or_insert_with(|| push(&mut ops, Op::Frobenius(map[base as usize])));
            map[i] = push(&mut ops, Op::Row(array, exponent % 128));
        } else {
            map[i] = push(&mut ops, remap(op, &map));
        }
    }
    Graph {
        ops,
        cse: HashMap::new(),
        replay_cursor: None,
    }
}

// Recognize equality-basis products, including p + p*r = p*(1+r).
// This replaces the expanded tensor by its original multilinear definition.
fn tensors(graph: Graph) -> Graph {
    type Term = Vec<(u32, bool)>;
    fn merge(a: &Term, b: &Term) -> Option<Term> {
        if a.len() + b.len() > 7 {
            return None;
        }
        let mut merged = a.clone();
        merged.extend(b);
        merged.sort_unstable();
        if merged.windows(2).any(|p| p[0].0 == p[1].0) {
            None
        } else {
            Some(merged)
        }
    }
    let mut terms: Vec<Option<Term>> = vec![None; graph.ops.len()];
    let mut groups = HashMap::<Vec<u32>, u128>::new();
    for (i, op) in graph.ops.iter().enumerate() {
        let term = match op {
            Op::Constant(1) => Some(vec![]),
            Op::Sample | Op::Row(..) | Op::Read(_, 16) => Some(vec![(i as u32, true)]),
            Op::Mul(a, b) => terms[*a as usize]
                .as_ref()
                .zip(terms[*b as usize].as_ref())
                .and_then(|(a, b)| merge(a, b)),
            Op::Add(a, b) => {
                if graph.ops[*a as usize] == Op::Constant(1) {
                    Some(vec![(*b, false)])
                } else if graph.ops[*b as usize] == Op::Constant(1) {
                    Some(vec![(*a, false)])
                } else {
                    let mut result = None;
                    for (base, product) in [(*a, *b), (*b, *a)] {
                        if let Op::Mul(left, right) = graph.ops[product as usize] {
                            let factor = if left == base {
                                Some(right)
                            } else if right == base {
                                Some(left)
                            } else {
                                None
                            };
                            if let Some(factor) = factor {
                                if let Some(term) = &terms[base as usize] {
                                    result = merge(term, &vec![(factor, false)]);
                                }
                            }
                        }
                    }
                    result
                }
            }
            _ => None,
        };
        if let Some(term) = &term {
            if term.len() >= 4 {
                let point = term.iter().map(|p| p.0).collect::<Vec<_>>();
                let index = term
                    .iter()
                    .enumerate()
                    .fold(0, |a, (i, p)| a | ((p.1 as usize) << i));
                *groups.entry(point).or_default() |= 1u128 << index;
            }
        }
        terms[i] = term;
    }
    groups.retain(|_, lanes| lanes.count_ones() >= 16);
    let mut ops = vec![];
    let mut map = vec![0; graph.ops.len()];
    let mut arrays = HashMap::new();
    for (i, op) in graph.ops.iter().enumerate() {
        let replacement = terms[i].as_ref().and_then(|term| {
            let point = term.iter().map(|p| p.0).collect::<Vec<_>>();
            if !groups.contains_key(&point) {
                return None;
            }
            let array = *arrays.entry(point.clone()).or_insert_with(|| {
                push(
                    &mut ops,
                    Op::SmallEq(point.iter().map(|&id| map[id as usize]).collect()),
                )
            });
            let index = term
                .iter()
                .enumerate()
                .fold(0, |a, (i, p)| a | ((p.1 as usize) << i));
            Some(Op::Row(array, index))
        });
        map[i] = push(&mut ops, replacement.unwrap_or_else(|| remap(op, &map)));
    }
    Graph {
        ops,
        cse: HashMap::new(),
        replay_cursor: None,
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct Group(u32, u32, u8, u8);
fn row(ops: &[Op], id: u32) -> Option<(u32, usize)> {
    let Op::Row(array, index) = ops[id as usize] else {
        return None;
    };
    match ops[array as usize] {
        Op::SampleFields
        | Op::Transpose(_)
        | Op::ReadFields(_)
        | Op::VectorBinary(..)
        | Op::Frobenius(_)
        | Op::SmallEq(_)
        | Op::TransposeOf(_) => Some((array, index)),
        _ => None,
    }
}
fn candidate(ops: &[Op], op: &Op) -> Option<(Group, usize)> {
    let (a, b, kind) = match op {
        Op::Add(a, b) => (*a, *b, 0),
        Op::Mul(a, b) => (*a, *b, 1),
        _ => return None,
    };
    match (row(ops, a), row(ops, b)) {
        (Some((x, i)), Some((y, j))) => {
            if x < y || (x == y && i <= j) {
                Some((Group(x, y, kind, ((j + 128 - i) % 128) as u8), i))
            } else {
                Some((Group(y, x, kind, ((i + 128 - j) % 128) as u8), j))
            }
        }
        (Some((x, i)), None) => Some((Group(x, b, kind | 2, 0), i)),
        (None, Some((y, j))) => Some((Group(y, a, kind | 2, 0), j)),
        _ => None,
    }
}
pub(super) fn lower(graph: Graph) -> Graph {
    let mut graph = array_views(tensors(reads(samples(squares(graph)))));
    loop {
        let mut groups = HashMap::<Group, u128>::new();
        for op in &graph.ops {
            if let Some((group, index)) = candidate(&graph.ops, op) {
                *groups.entry(group).or_default() |= 1u128 << index;
            }
        }
        // Only existing scalar results are referenced. Computing the other
        // lanes has no transcript effects and does not add or remove checks.
        groups.retain(|_, lanes| lanes.count_ones() >= 32);
        if groups.is_empty() {
            for i in 0..graph.ops.len() {
                if let Op::PublicWiring(mut config) = graph.ops[i].clone() {
                    config.use_array_sources(&graph.ops);
                    graph.ops[i] = Op::PublicWiring(config);
                }
            }
            return graph;
        }
        let mut ops = vec![];
        let mut map = vec![0; graph.ops.len()];
        let mut arrays = HashMap::new();
        for (i, op) in graph.ops.iter().enumerate() {
            let transformed = if let Some((group, index)) =
                candidate(&graph.ops, op).filter(|(g, _)| groups.contains_key(g))
            {
                let array = *arrays.entry(group).or_insert_with(|| {
                    push(
                        &mut ops,
                        Op::VectorBinary(
                            map[group.0 as usize],
                            map[group.1 as usize],
                            group.2,
                            group.3,
                        ),
                    )
                });
                Op::Row(array, index)
            } else {
                remap(op, &map)
            };
            map[i] = push(&mut ops, transformed);
        }
        graph = array_views(Graph {
            ops,
            cse: HashMap::new(),
            replay_cursor: None,
        });
    }
}
