//! Construct a complete factored outer matrix from its compact affine runs.
//!
//! The constructor performs the same circuit-only construction. The emitted
//! scalar equations are fixed before any proof or transcript is available.
//! Bounds limit generation/deployment work; unsupported matrices retain the
//! existing verifier representation.

use std::collections::{BTreeMap, BTreeSet, HashMap};

const ID_BITS: usize = 20;
const ID_MASK: u128 = (1 << ID_BITS) - 1;
const MAX_POINTS: usize = 262_144;
const MAX_NODES: usize = 65_536;
const MAX_RUN_CALLS: usize = 131_072;
const MAX_XOR_CALLS: usize = 524_288;
const MAX_IRREGULAR_POINTS: usize = 32_768;
const CHUNK_BITS: usize = 6;
const MAX_ORDER_CANDIDATES: usize = 256;
const MAX_ORDER_SWEEPS: usize = 16;

#[derive(Clone, Debug)]
pub(super) struct ConstructedMatrix {
    pub bytes: Vec<u8>,
    pub nx: usize,
    pub ny: usize,
    pub order: Vec<u8>,
    pub node_count: usize,
    pub node_hash_slots: usize,
    pub unpruned_operations: usize,
    pub operation_hash_slots: usize,
    pub operations: usize,
    pub chunk_bits: usize,
}

#[derive(Clone, Copy, Debug)]
struct Run {
    mask: u8,
    count: usize,
    row: u64,
    column: u64,
    dr: i64,
    dc: i64,
}

fn number(input: &[u8], at: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    for shift in (0..=63).step_by(7) {
        let byte = *input.get(*at)?;
        *at += 1;
        let digit = u64::from(byte & 127);
        if digit > u64::MAX >> shift {
            return None;
        }
        value |= digit << shift;
        if byte < 128 {
            return Some(value);
        }
    }
    None
}

fn decode(input: &[u8]) -> Option<(usize, usize, Vec<Run>)> {
    let mut at = 0;
    let nx = usize::try_from(number(input, &mut at)?).ok()?;
    let ny = usize::try_from(number(input, &mut at)?).ok()?;
    let count = usize::try_from(number(input, &mut at)?).ok()?;
    if nx > 32 || ny > 32 || nx + ny == 0 || nx + ny > 36 || count > MAX_POINTS {
        return None;
    }
    let mut previous = [0i128; 6];
    let mut runs = Vec::with_capacity(count);
    let mut entries = 0usize;
    for _ in 0..count {
        previous[2] += previous[1] * previous[4];
        previous[3] += previous[1] * previous[5];
        for value in &mut previous {
            let encoded = number(input, &mut at)?;
            let delta = i128::from(encoded >> 1);
            *value += if encoded & 1 == 0 { delta } else { -delta - 1 };
        }
        let run = Run {
            mask: u8::try_from(previous[0]).ok()?,
            count: usize::try_from(previous[1]).ok()?,
            row: u64::try_from(previous[2]).ok()?,
            column: u64::try_from(previous[3]).ok()?,
            dr: i64::try_from(previous[4]).ok()?,
            dc: i64::try_from(previous[5]).ok()?,
        };
        entries = entries.checked_add(run.count)?;
        if !(1..8).contains(&run.mask) || run.count == 0 || entries > MAX_POINTS {
            return None;
        }
        for (start, step, bits) in [(run.row, run.dr, nx), (run.column, run.dc, ny)] {
            let last = i128::from(start) + (run.count as i128 - 1) * i128::from(step);
            if start >= 1u64 << bits || !(0..1i128 << bits).contains(&last) {
                return None;
            }
        }
        if run.count > 1 && run.dr == 0 && run.dc == 0 {
            return None;
        }
        runs.push(run);
    }
    (at == input.len()).then_some((nx, ny, runs))
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct Branch {
    axis: u8,
    low: u128,
    high: u128,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct Interval {
    mask: u8,
    count: usize,
    row: u64,
    column: u64,
    dr: u64,
    dc: u64,
}

struct Builder {
    nx: usize,
    n: usize,
    domain: u64,
    order: Vec<u8>,
    rank: Vec<usize>,
    nodes: Vec<Branch>,
    unique: HashMap<Branch, usize>,
    runs: HashMap<Interval, u128>,
    sums: HashMap<(u128, u128), u128>,
    run_calls: usize,
    xor_calls: usize,
}

impl Builder {
    fn new(nx: usize, ny: usize) -> Self {
        // Increasing coordinates within each axis make each selected interval
        // bit change once. Interleave columns before rows, as in the prototype.
        let mut order = Vec::new();
        for i in 0..nx.max(ny) {
            if i < ny {
                order.push((nx + i) as u8);
            }
            if i < nx {
                order.push(i as u8);
            }
        }
        let mut rank = vec![0; nx + ny];
        for (i, &axis) in order.iter().enumerate() {
            rank[usize::from(axis)] = i + 1;
        }
        Self {
            nx,
            n: nx + ny,
            domain: (1u64 << (nx + ny)) - 1,
            order,
            rank,
            nodes: Vec::new(),
            unique: HashMap::new(),
            runs: HashMap::new(),
            sums: HashMap::new(),
            run_calls: 0,
            xor_calls: 0,
        }
    }

    fn reorder(&mut self, order: &[u8]) -> Option<()> {
        if order.len() != self.n {
            return None;
        }
        // Interval splitting and top() rely on increasing coordinates within
        // each axis. Only their interleaving may change. Validate before any
        // graph construction or rank-table access.
        let mut seen = [0usize; 2];
        for &axis in order {
            let axis = usize::from(axis);
            let side = usize::from(axis >= self.nx);
            if axis >= self.n || axis != seen[side] + if side == 1 { self.nx } else { 0 } {
                return None;
            }
            seen[side] += 1;
        }
        if seen != [self.nx, self.n - self.nx] {
            return None;
        }
        self.order = order.to_vec();
        for (rank, &axis) in order.iter().enumerate() {
            self.rank[usize::from(axis)] = rank + 1;
        }
        Some(())
    }

    fn edge(&self, on: u64, off: u64, node: usize) -> u128 {
        assert_eq!(on & off, 0);
        assert_eq!((on | off) & !self.domain, 0);
        assert!((node as u128) <= ID_MASK);
        if node == 0 {
            0
        } else {
            node as u128 | (u128::from(on) << ID_BITS) | (u128::from(off) << (ID_BITS + self.n))
        }
    }

    fn parts(&self, edge: u128) -> (u64, u64, usize) {
        (
            (edge >> ID_BITS) as u64 & self.domain,
            (edge >> (ID_BITS + self.n)) as u64 & self.domain,
            (edge & ID_MASK) as usize,
        )
    }

    fn branch(&mut self, axis: u8, a: u128, b: u128) -> Option<u128> {
        if a == b {
            return Some(a);
        }
        let (ao, az, ai) = self.parts(a);
        let (bo, bz, bi) = self.parts(b);
        let bit = 1u64 << axis;
        assert_eq!((ao | az | bo | bz) & bit, 0);
        if ai == 0 {
            return Some(self.edge(bo | bit, bz, bi));
        }
        if bi == 0 {
            return Some(self.edge(ao, az | bit, ai));
        }
        let common = (a & b) & !ID_MASK;
        let key = Branch {
            axis,
            low: a ^ common,
            high: b ^ common,
        };
        let id = if let Some(&id) = self.unique.get(&key) {
            id
        } else {
            if self.nodes.len() == MAX_NODES {
                return None;
            }
            let id = self.nodes.len() + 8;
            self.nodes.push(key);
            self.unique.insert(key, id);
            id
        };
        Some(common | id as u128)
    }

    fn top(&self, edge: u128) -> usize {
        let (on, off, node) = self.parts(edge);
        let mut rank = if node < 8 {
            0
        } else {
            self.rank[usize::from(self.nodes[node - 8].axis)]
        };
        let literals = on | off;
        for bits in [
            literals & ((1u64 << self.nx) - 1),
            literals & !((1u64 << self.nx) - 1),
        ] {
            if bits != 0 {
                rank = rank.max(self.rank[63 - bits.leading_zeros() as usize]);
            }
        }
        rank
    }

    fn cofactor(&self, edge: u128, axis: u8, high: bool) -> u128 {
        let (on, off, node) = self.parts(edge);
        let bit = 1u64 << axis;
        if node == 0 || (if high { off } else { on }) & bit != 0 {
            return 0;
        }
        if (on | off) & bit != 0 {
            return self.edge(on & !bit, off & !bit, node);
        }
        if node >= 8 && self.nodes[node - 8].axis == axis {
            let b = self.nodes[node - 8];
            let (x, y, id) = self.parts(if high { b.high } else { b.low });
            assert_eq!((on | off) & (x | y), 0);
            return self.edge(on | x, off | y, id);
        }
        edge
    }

    fn sum(&mut self, mut a: u128, mut b: u128) -> Option<u128> {
        self.xor_calls += 1;
        if self.xor_calls > MAX_XOR_CALLS {
            return None;
        }
        if a == 0 {
            return Some(b);
        }
        if b == 0 {
            return Some(a);
        }
        if a == b {
            return Some(0);
        }
        let common = (a & b) & !ID_MASK;
        a ^= common;
        b ^= common;
        if a > b {
            std::mem::swap(&mut a, &mut b);
        }
        let key = (a, b);
        let value = if let Some(&value) = self.sums.get(&key) {
            value
        } else {
            let rank = self.top(a).max(self.top(b));
            let value = if rank == 0 {
                assert!(a < 8 && b < 8);
                a ^ b
            } else {
                let axis = self.order[rank - 1];
                let low = self.sum(self.cofactor(a, axis, false), self.cofactor(b, axis, false))?;
                let high = self.sum(self.cofactor(a, axis, true), self.cofactor(b, axis, true))?;
                self.branch(axis, low, high)?
            };
            self.sums.insert(key, value);
            value
        };
        if value == 0 {
            Some(0)
        } else {
            let (on, off, _) = self.parts(value);
            let (x, y, _) = self.parts(common | 1);
            assert_eq!((on | off) & (x | y), 0);
            Some(value | common)
        }
    }

    fn point(&self, row: u64, column: u64, mask: u8) -> u128 {
        assert!(row < 1u64 << self.nx && column < 1u64 << (self.n - self.nx));
        let on = row | (column << self.nx);
        self.edge(on, self.domain ^ on, usize::from(mask))
    }

    fn interval(&mut self, run: Interval) -> Option<u128> {
        self.run_calls += 1;
        if self.run_calls > MAX_RUN_CALLS {
            return None;
        }
        let Interval {
            mask,
            count,
            row,
            column,
            dr,
            dc,
        } = run;
        if count == 1 {
            return Some(self.point(row, column, mask));
        }
        let varying = |start: u64, stride: u64| {
            if stride == 0 {
                0
            } else {
                let difference = start ^ (start + (count as u64 - 1) * stride);
                ((1u64 << (64 - difference.leading_zeros())) - 1) & !(stride - 1)
            }
        };
        let vr = varying(row, dr);
        let vc = varying(column, dc);
        let fixed = self.domain ^ (vr | (vc << self.nx));
        let point = row | (column << self.nx);
        let on = point & fixed;
        let off = (self.domain ^ point) & fixed;
        let nr = row & vr;
        let nc = column & vc;
        let key = Interval {
            row: nr,
            column: nc,
            ..run
        };
        let core = if let Some(&value) = self.runs.get(&key) {
            value
        } else {
            let axis = [
                (vr != 0).then(|| (63 - vr.leading_zeros()) as u8),
                (vc != 0).then(|| (self.nx + 63 - vc.leading_zeros() as usize) as u8),
            ]
            .into_iter()
            .flatten()
            .max_by_key(|&axis| self.rank[usize::from(axis)])
            .unwrap();
            let (first, stride, bit) = if usize::from(axis) < self.nx {
                (nr, dr, usize::from(axis))
            } else {
                (nc, dc, usize::from(axis) - self.nx)
            };
            let boundary = ((first >> bit) + 1) << bit;
            let split = (boundary - first).div_ceil(stride) as usize;
            assert!(split > 0 && split < count);
            let a = self.interval(Interval {
                count: split,
                ..key
            })?;
            let b = self.interval(Interval {
                count: count - split,
                row: nr + split as u64 * dr,
                column: nc + split as u64 * dc,
                ..key
            })?;
            assert_ne!(self.parts(a).1 & (1 << axis), 0);
            assert_ne!(self.parts(b).0 & (1 << axis), 0);
            let value = self.branch(
                axis,
                self.cofactor(a, axis, false),
                self.cofactor(b, axis, true),
            )?;
            let (x, y, id) = self.parts(value);
            assert_eq!(x & fixed, 0);
            assert_eq!(y & fixed, fixed);
            let core = self.edge(x, y ^ fixed, id);
            self.runs.insert(key, core);
            core
        };
        let (x, y, id) = self.parts(core);
        assert_eq!((x | y) & fixed, 0);
        Some(self.edge(x | on, y | off, id))
    }

    fn reduce(&mut self, mut row: Vec<u128>) -> Option<u128> {
        while row.len() > 1 {
            let mut next = Vec::with_capacity(row.len().div_ceil(2));
            for pair in row.chunks(2) {
                next.push(if pair.len() == 1 {
                    pair[0]
                } else {
                    self.sum(pair[0], pair[1])?
                });
            }
            row = next;
        }
        Some(row.first().copied().unwrap_or(0))
    }

    fn matrix(&mut self, runs: &[Run]) -> Option<u128> {
        let mut roots = Vec::new();
        let mut irregular = 0;
        for &run in runs {
            let Run {
                mask,
                count,
                row,
                column,
                dr,
                dc,
            } = run;
            let dyadic =
                |stride: i64| stride == 0 || (stride > 0 && (stride as u64).is_power_of_two());
            let root = if count == 1 || (dyadic(dr) && dyadic(dc)) {
                self.interval(Interval {
                    mask,
                    count,
                    row,
                    column,
                    dr: dr as u64,
                    dc: dc as u64,
                })?
            } else {
                irregular += count;
                if irregular > MAX_IRREGULAR_POINTS {
                    return None;
                }
                let points = (0..count)
                    .map(|i| {
                        self.point(
                            (i128::from(row) + i as i128 * i128::from(dr)) as u64,
                            (i128::from(column) + i as i128 * i128::from(dc)) as u64,
                            mask,
                        )
                    })
                    .collect();
                self.reduce(points)?
            };
            let end_row = (i128::from(row) + (count - 1) as i128 * i128::from(dr)) as u64;
            let end_col = (i128::from(column) + (count - 1) as i128 * i128::from(dc)) as u64;
            let minimum = (row | (column << self.nx)).min(end_row | (end_col << self.nx));
            let key = self
                .order
                .iter()
                .enumerate()
                .fold(0u64, |key, (rank, &axis)| {
                    key | (((minimum >> axis) & 1) << rank)
                });
            roots.push((key, root));
        }
        roots.sort_unstable();
        self.reduce(roots.into_iter().map(|(_, root)| root).collect())
    }

    fn check_support(&self, root: u128, runs: &[Run]) {
        let mut expected = BTreeMap::<u64, u8>::new();
        for run in runs {
            for i in 0..run.count {
                let row = (i128::from(run.row) + i as i128 * i128::from(run.dr)) as u64;
                let col = (i128::from(run.column) + i as i128 * i128::from(run.dc)) as u64;
                *expected.entry(row | (col << self.nx)).or_default() ^= run.mask;
            }
        }
        expected.retain(|_, mask| *mask != 0);
        let mut recovered = Vec::new();
        let mut stack = vec![(root, 0u64, 0u64)];
        while let Some((edge, mut used, mut key)) = stack.pop() {
            let (on, off, node) = self.parts(edge);
            if node == 0 {
                continue;
            }
            assert_eq!((on | off) & used, 0, "derived graph repeats a coordinate");
            assert_eq!(on & off, 0);
            used |= on | off;
            key |= on;
            if node < 8 {
                let free = self.domain ^ used;
                assert!(1u64 << free.count_ones() <= expected.len() as u64);
                let mut subset = free;
                loop {
                    recovered.push((key | subset, node as u8));
                    assert!(recovered.len() <= expected.len());
                    if subset == 0 {
                        break;
                    }
                    subset = subset.wrapping_sub(1) & free;
                }
            } else {
                let branch = self.nodes[node - 8];
                let bit = 1u64 << branch.axis;
                assert_eq!(used & bit, 0, "derived graph repeats a decision");
                stack.push((branch.low, used | bit, key));
                stack.push((branch.high, used | bit, key | bit));
            }
        }
        recovered.sort_unstable();
        assert_eq!(
            recovered,
            expected.into_iter().collect::<Vec<_>>(),
            "constructor graph changed the native matrix"
        );
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
    subsets: Vec<Vec<usize>>,
    factors: HashMap<(u64, u64), usize>,
}

impl Expressions {
    fn node(&mut self, code: u8, a: usize, b: usize) -> Option<usize> {
        let op = Operation { code, a, b };
        if let Some(&id) = self.unique.get(&op) {
            return Some(id);
        }
        let id = self.initial + self.ops.len();
        if id >= 65_536 {
            return None;
        }
        assert!(a < id && b < id);
        self.ops.push(op);
        self.unique.insert(op, id);
        Some(id)
    }

    fn mul(&mut self, a: usize, b: usize) -> Option<usize> {
        if a == 0 || b == 0 {
            Some(0)
        } else if a == 1 {
            Some(b)
        } else if b == 1 {
            Some(a)
        } else {
            self.node(0, a.min(b), a.max(b))
        }
    }

    fn cube(&mut self, builder: &Builder, edge: u128) -> Option<usize> {
        let (on, off, _) = builder.parts(edge);
        if let Some(&id) = self.factors.get(&(on, off)) {
            return Some(id);
        }
        let mut product = 1;
        let mask = (1 << CHUNK_BITS) - 1;
        for chunk in (0..builder.n.div_ceil(CHUNK_BITS)).rev() {
            let a = self.subsets[2 * chunk][(on as usize >> (chunk * CHUNK_BITS)) & mask];
            let b = self.subsets[2 * chunk + 1][(off as usize >> (chunk * CHUNK_BITS)) & mask];
            let factor = self.mul(a, b)?;
            product = self.mul(product, factor)?;
        }
        self.factors.insert((on, off), product);
        Some(product)
    }
}

fn expressions(builder: &Builder, root: u128) -> Option<(Vec<u8>, usize, usize)> {
    let initial = 8 + 2 * builder.n;
    let mut e = Expressions {
        initial,
        ops: Vec::new(),
        unique: HashMap::new(),
        subsets: Vec::new(),
        factors: HashMap::new(),
    };
    for start in (0..builder.n).step_by(CHUNK_BITS) {
        for zero in [false, true] {
            let mut row = vec![1];
            for mask in 1usize..1 << CHUNK_BITS.min(builder.n - start) {
                let bit = mask.trailing_zeros() as usize;
                row.push(e.mul(
                    8 + usize::from(zero) * builder.n + start + bit,
                    row[mask & (mask - 1)],
                )?);
            }
            e.subsets.push(row);
        }
    }
    let mut live = vec![false; builder.nodes.len() + 8];
    live[(root & ID_MASK) as usize] = true;
    for id in (8..live.len()).rev() {
        if live[id] {
            let branch = builder.nodes[id - 8];
            live[(branch.low & ID_MASK) as usize] = true;
            live[(branch.high & ID_MASK) as usize] = true;
        }
    }
    let mut values: Vec<_> = (0..8)
        .chain(std::iter::repeat_n(0, builder.nodes.len()))
        .collect();
    for id in 8..live.len() {
        if !live[id] {
            continue;
        }
        let branch = builder.nodes[id - 8];
        let low = e.cube(builder, branch.low)?;
        let mut a = e.mul(low, values[(branch.low & ID_MASK) as usize])?;
        let high = e.cube(builder, branch.high)?;
        let mut b = e.mul(high, values[(branch.high & ID_MASK) as usize])?;
        let mut code = branch.axis + 1;
        if a > b {
            std::mem::swap(&mut a, &mut b);
            code += builder.n as u8;
        }
        values[id] = if a == b {
            a
        } else if a == 0 {
            e.mul(7 + usize::from(code), b)?
        } else {
            e.node(code, a, b)?
        };
    }
    let factor = e.cube(builder, root)?;
    let root = e.mul(factor, values[(root & ID_MASK) as usize])?;
    let mut live = vec![false; initial + e.ops.len()];
    live[root] = true;
    for id in (initial..live.len()).rev() {
        if live[id] {
            let op = e.ops[id - initial];
            live[op.a] = true;
            live[op.b] = true;
        }
    }
    let mut mapping: Vec<_> = (0..initial)
        .chain(std::iter::repeat_n(0, e.ops.len()))
        .collect();
    let mut ops = Vec::new();
    for (i, &op) in e.ops.iter().enumerate() {
        if live[initial + i] {
            mapping[initial + i] = initial + ops.len();
            ops.push(Operation {
                a: mapping[op.a],
                b: mapping[op.b],
                ..op
            });
        }
    }
    let root = mapping[root];
    let mut encoded = vec![255, builder.nx as u8, (builder.n - builder.nx) as u8];
    uv(&mut encoded, ops.len());
    uv(&mut encoded, root);
    uv(&mut encoded, 2 * ops.len());
    encoded.extend(ops.iter().map(|op| op.code));
    for b in [false, true] {
        for (i, op) in ops.iter().enumerate() {
            let offset = initial + i - if b { op.b } else { op.a };
            encoded.extend_from_slice(&u16::try_from(offset).ok()?.to_be_bytes());
        }
    }
    // Recover every serialized operation independently from its fixed offsets.
    let mut at = 3;
    assert_eq!(number(&encoded, &mut at)? as usize, ops.len());
    assert_eq!(number(&encoded, &mut at)? as usize, root);
    assert_eq!(number(&encoded, &mut at)? as usize, 2 * ops.len());
    for (i, op) in ops.iter().enumerate() {
        let a = at + ops.len() + 2 * i;
        let b = a + 2 * ops.len();
        assert_eq!(encoded[at + i], op.code);
        assert_eq!(
            initial + i - usize::from(u16::from_be_bytes(encoded[a..a + 2].try_into().unwrap())),
            op.a
        );
        assert_eq!(
            initial + i - usize::from(u16::from_be_bytes(encoded[b..b + 2].try_into().unwrap())),
            op.b
        );
    }
    Some((encoded, e.ops.len(), ops.len()))
}

fn uv(out: &mut Vec<u8>, mut value: usize) {
    while value >= 128 {
        out.push(value as u8 | 128);
        value >>= 7;
    }
    out.push(value as u8);
}

fn slots(count: usize) -> usize {
    ((count * 4).div_ceil(3)).max(count + 1).next_power_of_two()
}

fn construct_ordered(
    nx: usize,
    ny: usize,
    runs: &[Run],
    order: &[u8],
) -> Option<ConstructedMatrix> {
    let mut builder = Builder::new(nx, ny);
    builder.reorder(order)?;
    let root = builder.matrix(runs)?;
    builder.check_support(root, runs);
    let (bytes, unpruned_operations, operations) = expressions(&builder, root)?;
    Some(ConstructedMatrix {
        bytes,
        nx,
        ny,
        order: builder.order,
        node_count: builder.nodes.len(),
        node_hash_slots: slots(builder.nodes.len()),
        unpruned_operations,
        operation_hash_slots: slots(unpruned_operations),
        operations,
        chunk_bits: CHUNK_BITS,
    })
}

pub(super) fn construct(input: &[u8]) -> Option<ConstructedMatrix> {
    let (nx, ny, runs) = decode(input)?;
    let original_order = Builder::new(nx, ny).order;
    let mut best = construct_ordered(nx, ny, &runs, &original_order)?;
    if best.operations < 1024 {
        return Some(best);
    }
    // Search only circuit constants. Every candidate independently checks the
    // full native support, multilinearity, and serialized scalar operations.
    // Fewer operations also means fewer fixed program bytes. Actual runtime
    // and initcode size checks still decide whether deployment uses this plan.
    let mut orders = Vec::new();
    for bias in -6i32..=6 {
        for tie in [false, true] {
            let mut order: Vec<_> = (0..nx + ny).map(|axis| axis as u8).collect();
            order.sort_by_key(|&axis| {
                let axis = usize::from(axis);
                if axis < nx {
                    (axis as i32, tie)
                } else {
                    ((axis - nx) as i32 + bias, !tie)
                }
            });
            orders.push(order);
        }
    }
    let mut seen = BTreeSet::from([original_order]);
    for sweep in 0..MAX_ORDER_SWEEPS {
        let previous_cost = best.operations;
        for order in std::mem::take(&mut orders) {
            if seen.len() == MAX_ORDER_CANDIDATES {
                break;
            }
            if !seen.insert(order.clone()) {
                continue;
            }
            if let Some(candidate) = construct_ordered(nx, ny, &runs, &order)
                && candidate.operations < best.operations
            {
                best = candidate;
            }
        }
        // The initial biased orders may retain the original order. Still try
        // its adjacent swaps before deciding that local search has converged.
        if (sweep != 0 && best.operations == previous_cost) || seen.len() == MAX_ORDER_CANDIDATES {
            break;
        }
        for i in 1..best.order.len() {
            if (usize::from(best.order[i - 1]) < nx) != (usize::from(best.order[i]) < nx) {
                let mut order = best.order.clone();
                order.swap(i - 1, i);
                orders.push(order);
            }
        }
    }
    Some(best)
}

#[cfg(test)]
mod tests {
    use super::*;
    use binius_field::{Field, Ghash128b as F, arithmetic_traits::Square};

    fn encode(nx: usize, ny: usize, runs: &[[i64; 6]]) -> Vec<u8> {
        let mut out = Vec::new();
        uv(&mut out, nx);
        uv(&mut out, ny);
        uv(&mut out, runs.len());
        let mut previous = [0i64; 6];
        for &run in runs {
            previous[2] += previous[1] * previous[4];
            previous[3] += previous[1] * previous[5];
            for (old, next) in previous.into_iter().zip(run) {
                let delta = next - old;
                uv(
                    &mut out,
                    if delta >= 0 {
                        (2 * delta) as usize
                    } else {
                        (-2 * delta - 1) as usize
                    },
                );
            }
            previous = run;
        }
        out
    }

    fn evaluate(data: &[u8], x: &[F], y: &[F], lambda: F) -> F {
        let mut at = 3;
        let count = number(data, &mut at).unwrap() as usize;
        let root = number(data, &mut at).unwrap() as usize;
        assert_eq!(number(data, &mut at).unwrap() as usize, 2 * count);
        let square = lambda.square();
        let mut values = vec![
            F::ZERO,
            F::ONE,
            lambda,
            lambda + F::ONE,
            square,
            square + F::ONE,
            square + lambda,
            square + lambda + F::ONE,
        ];
        values.extend(x.iter().chain(y).copied());
        values.extend(x.iter().chain(y).map(|&r| r + F::ONE));
        for i in 0..count {
            let offset = |column| {
                let p = at + count + 2 * (column * count + i);
                usize::from(u16::from_be_bytes(data[p..p + 2].try_into().unwrap()))
            };
            let a = values[values.len() - offset(0)];
            let b = values[values.len() - offset(1)];
            let code = usize::from(data[at + i]);
            values.push(if code == 0 {
                a * b
            } else {
                a + values[7 + code] * (a + b)
            });
        }
        values[root]
    }

    fn explicit(runs: &[[i64; 6]], x: &[F], y: &[F], lambda: F) -> F {
        let equality = |point: &[F], index: i64| {
            point.iter().enumerate().fold(F::ONE, |p, (i, &r)| {
                p * (r + F::new(((index >> i) & 1 ^ 1) as u128))
            })
        };
        let mut result = F::ZERO;
        for &[mask, count, row, col, dr, dc] in runs {
            let mut coefficient = F::ZERO;
            if mask & 1 != 0 {
                coefficient += F::ONE;
            }
            if mask & 2 != 0 {
                coefficient += lambda;
            }
            if mask & 4 != 0 {
                coefficient += lambda.square();
            }
            for i in 0..count {
                result += coefficient * equality(x, row + i * dr) * equality(y, col + i * dc);
            }
        }
        result
    }

    #[test]
    fn constructed_scalar_graph_matches_explicit_native_field_polynomial() {
        let runs = [
            [7, 8, 0, 0, 1, 1],
            [3, 4, 12, 9, -3, -2],
            [5, 4, 1, 0, 3, 4],
            [2, 8, 0, 5, 2, 0],
            [6, 4, 1, 0, 0, 4],
            [6, 4, 1, 0, 0, 4],
        ];
        let model = construct(&encode(4, 4, &runs)).unwrap();
        // Every Boolean coordinate and special lambda values, plus full-width
        // extension-field points. The reference expands each original run.
        for index in 0..256 {
            let x: Vec<_> = (0..4).map(|i| F::new((index >> i) & 1)).collect();
            let y: Vec<_> = (4..8).map(|i| F::new((index >> i) & 1)).collect();
            for lambda in [F::ZERO, F::ONE, F::new(0x891273456abcdef)] {
                assert_eq!(
                    evaluate(&model.bytes, &x, &y, lambda),
                    explicit(&runs, &x, &y, lambda)
                );
            }
        }
        let mut seed = 0x92c57831f04892389d87dc65a0981276u128;
        for _ in 0..64 {
            let mut sample = || {
                seed ^= seed << 23;
                seed ^= seed >> 17;
                seed ^= seed << 26;
                F::new(seed)
            };
            let x: Vec<_> = (0..4).map(|_| sample()).collect();
            let y: Vec<_> = (0..4).map(|_| sample()).collect();
            let lambda = sample();
            assert_eq!(
                evaluate(&model.bytes, &x, &y, lambda),
                explicit(&runs, &x, &y, lambda)
            );
        }
    }

    #[test]
    fn alternate_axis_orders_preserve_the_native_extension_polynomial() {
        let runs = [
            [7, 8, 0, 0, 1, 1],
            [3, 4, 6, 5, -2, -1],
            [5, 3, 1, 0, 3, 2],
            [2, 4, 0, 5, 2, 0],
            [6, 4, 1, 0, 0, 2],
        ];
        let (_, _, decoded) = decode(&encode(3, 3, &runs)).unwrap();
        // Every interleaving of three row and three column coordinates.
        for mask in 0u32..64 {
            if mask.count_ones() != 3 {
                continue;
            }
            let mut next = [0u8, 3];
            let order: Vec<_> = (0..6)
                .map(|i| {
                    let side = ((mask >> i) & 1) as usize;
                    let axis = next[side];
                    next[side] += 1;
                    axis
                })
                .collect();
            let matrix = construct_ordered(3, 3, &decoded, &order).unwrap();
            for seed in [0u128, 1, 0x9174618958fa4d83bc42ef619, u128::MAX] {
                let x: Vec<_> = (0..3).map(|i| F::new(seed.rotate_left(29 * i))).collect();
                let y: Vec<_> = (0..3)
                    .map(|i| F::new(seed.rotate_right(17 * i) ^ 1))
                    .collect();
                for lambda in [F::ZERO, F::ONE, F::new(seed)] {
                    assert_eq!(
                        evaluate(&matrix.bytes, &x, &y, lambda),
                        explicit(&runs, &x, &y, lambda),
                        "axis order {order:?} changed the extension polynomial"
                    );
                }
            }
        }
        for order in [
            vec![],
            vec![0, 1, 2],
            vec![0, 1, 2, 3, 4, 6],
            vec![1, 0, 2, 3, 4, 5],
            vec![0, 1, 2, 3, 3, 5],
            vec![u8::MAX; 6],
        ] {
            assert!(construct_ordered(3, 3, &decoded, &order).is_none());
        }
    }

    #[test]
    fn construction_checks_malformed_inputs_and_work_bounds() {
        for input in [
            vec![],
            vec![4],
            vec![255; 20],
            encode(32, 32, &[]),
            encode(4, 4, &[[0, 1, 0, 0, 0, 0]]),
            encode(4, 4, &[[8, 1, 0, 0, 0, 0]]),
            encode(4, 4, &[[1, 0, 0, 0, 1, 1]]),
            encode(4, 4, &[[1, 2, 0, 0, 0, 0]]),
            encode(4, 4, &[[1, 2, 0, 0, -1, 0]]),
            encode(4, 4, &[[1, 2, 15, 0, 1, 0]]),
            encode(19, 0, &[[1, MAX_POINTS as i64 + 1, 0, 0, 1, 0]]),
        ] {
            assert!(construct(&input).is_none());
        }
        let mut valid = encode(4, 4, &[[1, 2, 0, 0, 1, 1]]);
        assert!(construct(&valid).is_some());
        valid.push(0);
        assert!(construct(&valid).is_none());
        valid.pop();
        valid.pop();
        assert!(construct(&valid).is_none());
        let empty = construct(&encode(0, 4, &[])).unwrap();
        assert_eq!(empty.operations, 0);
        assert_eq!(evaluate(&empty.bytes, &[], &[F::ONE; 4], F::ONE), F::ZERO);
        let cancelled =
            construct(&encode(0, 4, &[[7, 16, 0, 0, 0, 1], [7, 16, 0, 0, 0, 1]])).unwrap();
        assert_eq!(cancelled.operations, 0);
        assert_eq!(
            evaluate(&cancelled.bytes, &[], &[F::ONE; 4], F::ONE),
            F::ZERO
        );
    }
}
