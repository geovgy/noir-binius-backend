//! The pinned Spartan interaction schedule with exact sparse wiring evaluation.
//! Repeated affine index sequences are a lossless representation of the final
//! native matrices. The EVM contracts their equality polynomials algebraically.
use super::*;
use binius_ip::mlecheck;
use binius_spartan_frontend::constraint_system::{MulConstraint, WitnessIndex, WitnessSegment};
use binius_spartan_verifier::IOPVerifier;
use std::collections::BTreeMap;

fn varint(out: &mut Vec<u8>, mut value: u32) {
    while value >= 128 {
        out.push((value as u8) | 128);
        value >>= 7;
    }
    out.push(value as u8);
}
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub(super) struct PublicWiring {
    point: Vec<u32>,
    values: Vec<u32>,
    rows: Vec<Option<u8>>,
    nodes: Vec<(u8, u32, u32)>,
    roots: [u32; 3],
    lambda: u32,
}
impl PublicWiring {
    fn build(columns: [Vec<E>; 3], point: &[E], lambda: E) -> Self {
        let mut values: Vec<_> = columns.iter().flatten().map(|v| v.0).collect();
        values.sort_unstable();
        values.dedup();
        let ids: HashMap<_, _> = values
            .iter()
            .enumerate()
            .map(|(i, &id)| (id, i as u32))
            .collect();
        let columns =
            columns.map(|column| column.into_iter().map(|v| ids[&v.0]).collect::<Vec<_>>());
        let mut nodes = vec![];
        let mut unique = HashMap::new();
        let roots = columns.map(|mut column| {
            for bit in 0..point.len() {
                let half = column.len() / 2;
                for i in 0..half {
                    let low = column[2 * i];
                    let high = column[2 * i + 1];
                    column[i] = if low == high {
                        low
                    } else {
                        *unique.entry((bit as u8, low, high)).or_insert_with(|| {
                            let id = (values.len() + nodes.len()) as u32;
                            nodes.push((bit as u8, low, high));
                            id
                        })
                    };
                }
                column.truncate(half);
            }
            assert_eq!(column.len(), 1);
            column[0]
        });
        Self {
            point: point.iter().map(|e| e.0).collect(),
            rows: vec![None; values.len()],
            values,
            nodes,
            roots,
            lambda: lambda.0,
        }
    }
    pub(super) fn use_array_sources(&mut self, ops: &[Op]) {
        for (id, row) in self.values.iter_mut().zip(&mut self.rows) {
            if row.is_none() {
                if let Op::Row(parent, index) = ops[*id as usize] {
                    *id = parent;
                    *row = Some(index as u8);
                }
            }
        }
    }
    pub(super) fn remap(&self, f: impl Fn(u32) -> u32) -> Self {
        let mut result = self.clone();
        result
            .point
            .iter_mut()
            .chain(&mut result.values)
            .for_each(|id| *id = f(*id));
        result.lambda = f(result.lambda);
        result
    }
    pub(super) fn operands(&self) -> Vec<u32> {
        self.point
            .iter()
            .chain(&self.values)
            .copied()
            .chain([self.lambda])
            .collect()
    }
    pub(super) fn encode(&self, slot: impl Fn(u32) -> usize) -> Vec<u8> {
        let mut data = vec![];
        fn u(data: &mut Vec<u8>, n: usize) {
            data.extend_from_slice(&u32::try_from(n).unwrap().to_be_bytes());
        }
        u(&mut data, self.values.len());
        u(&mut data, self.nodes.len());
        data.push(self.point.len() as u8);
        for root in self.roots {
            u(&mut data, root as usize);
        }
        u(&mut data, slot(self.lambda));
        for &i in &self.point {
            u(&mut data, slot(i));
        }
        let mut previous_leaf = [0i64; 2];
        for (&id, row) in self.values.iter().zip(&self.rows) {
            let kind = usize::from(row.is_some());
            let value = slot(id) as i64;
            let delta = value - previous_leaf[kind];
            previous_leaf[kind] = value;
            let zigzag = if delta < 0 { -2 * delta - 1 } else { 2 * delta };
            varint(&mut data, u32::try_from(2 * zigzag + kind as i64).unwrap());
            if let Some(row) = row {
                data.push(*row);
            }
        }
        // Predict leaf and internal children separately. Crossing between
        // those ID ranges must not destroy the local delta pattern.
        let mut previous = [0i64; 4];
        for &(bit, low, high) in &self.nodes {
            let low_kind = usize::from(low as usize >= self.values.len());
            let high_kind = usize::from(high as usize >= self.values.len());
            data.push(bit * 4 + low_kind as u8 + 2 * high_kind as u8);
            for (position, id) in [low, high].into_iter().enumerate() {
                let lane = position * 2 + usize::from(id as usize >= self.values.len());
                let delta = i64::from(id) - previous[lane];
                previous[lane] = i64::from(id);
                varint(
                    &mut data,
                    u32::try_from(if delta < 0 { -2 * delta - 1 } else { 2 * delta }).unwrap(),
                );
            }
        }
        data
    }
    #[cfg(test)]
    pub(super) fn evaluate(&self, f: impl Fn(u32) -> F) -> F {
        assert!(
            self.rows.iter().all(Option::is_none),
            "reference uses the scalar graph"
        );
        let mut v: Vec<_> = self.values.iter().map(|&i| f(i)).collect();
        for &(bit, low, high) in &self.nodes {
            v.push(
                v[low as usize]
                    + f(self.point[bit as usize]) * (v[low as usize] + v[high as usize]),
            );
        }
        let [a, b, c] = self.roots.map(|id| v[id as usize]);
        let lambda = f(self.lambda);
        a + lambda * (b + lambda * c)
    }
}

// mask, count, first row, first column, row stride, column stride.
type Run = [i64; 6];
fn runs(mask: u8, points: &[(u32, u32)], out: &mut Vec<Run>) {
    let mut p = 0;
    while p < points.len() {
        let mut end = p + 1;
        let (mut dr, mut dc) = (0, 0);
        if end < points.len() {
            dr = i64::from(points[end].0) - i64::from(points[p].0);
            dc = i64::from(points[end].1) - i64::from(points[p].1);
            end += 1;
            while end < points.len()
                && i64::from(points[end].0) - i64::from(points[end - 1].0) == dr
                && i64::from(points[end].1) - i64::from(points[end - 1].1) == dc
            {
                end += 1;
            }
        }
        out.push([
            i64::from(mask),
            (end - p) as i64,
            i64::from(points[p].0),
            i64::from(points[p].1),
            dr,
            dc,
        ]);
        p = end;
    }
}

pub(super) fn encode_matrix(
    rows: &[MulConstraint<WitnessIndex>],
    segment: WitnessSegment,
    nx: usize,
    ny: usize,
) -> Vec<u8> {
    let mut entries = vec![];
    for (r, row) in rows.iter().enumerate() {
        for (side, operand) in [&row.a, &row.b, &row.c].iter().enumerate() {
            for index in operand.wires().iter().filter(|i| i.segment == segment) {
                entries.push((r as u32, index.index, 1u8 << side));
            }
        }
    }
    encode_points(entries, nx, ny)
}

pub(super) fn encode_points(mut entries: Vec<(u32, u32, u8)>, nx: usize, ny: usize) -> Vec<u8> {
    entries.sort_unstable();
    let mut original: Vec<(u32, u32, u8)> = vec![];
    for (r, c, mask) in entries {
        if let Some(last) = original.last_mut().filter(|p| p.0 == r && p.1 == c) {
            last.2 ^= mask;
        } else {
            original.push((r, c, mask));
        }
    }
    original.retain(|p| p.2 != 0);
    let mut streams = BTreeMap::<(u8, usize), Vec<(u32, u32)>>::new();
    let mut fragments = vec![];
    for row in original.chunk_by(|a, b| a.0 == b.0) {
        let mut groups: [Vec<(u32, u32)>; 8] = Default::default();
        for &(r, c, mask) in row {
            groups[mask as usize].push((r, c));
        }
        for (mask, points) in groups.iter().enumerate().skip(1) {
            if points.len() >= 8 {
                runs(mask as u8, points, &mut fragments);
            } else {
                for (position, &point) in points.iter().enumerate() {
                    streams
                        .entry((mask as u8, position))
                        .or_default()
                        .push(point);
                }
            }
        }
    }
    for ((mask, _), points) in streams {
        runs(mask, &points, &mut fragments);
    }
    let mut recovered = vec![];
    for &[mask, n, r, c, dr, dc] in &fragments {
        for i in 0..n {
            recovered.push((
                u32::try_from(r + i * dr).unwrap(),
                u32::try_from(c + i * dc).unwrap(),
                mask as u8,
            ));
        }
    }
    recovered.sort_unstable();
    original.sort_unstable();
    assert_eq!(
        recovered, original,
        "sparse wiring encoding changed the native matrix"
    );
    let mut data = vec![];
    varint(&mut data, nx as u32);
    varint(&mut data, ny as u32);
    varint(&mut data, fragments.len() as u32);
    let mut previous = [0; 6];
    for run in fragments {
        for i in 0..6 {
            let delta = run[i] - previous[i];
            previous[i] = run[i];
            varint(
                &mut data,
                u32::try_from(if delta < 0 { -2 * delta - 1 } else { 2 * delta }).unwrap(),
            );
        }
    }
    data
}

pub(super) fn verify(
    outer: &IOPVerifier<F>,
    precommit: BaseFoldOracle,
    public: &[E],
    channel: &mut BaseFoldVerifierChannel<'_, F, Channel>,
) -> Result<()> {
    let cs = outer.constraint_system();
    assert_eq!(public.len(), 1 << cs.log_public());
    let private = channel.recv_oracle(cs.log_private() as usize, true)?;
    let (mn, md) = cs.mask_dims();
    let mask = channel.recv_oracle(mn + md, true)?;
    let nx = cs.mul_constraints().len().ilog2() as usize;
    let random = channel.sample_many(nx);
    let mlecheck::VerifyZKOutput {
        eval,
        mask_eval,
        challenges: mut x,
    } = mlecheck::verify_zk(&random, 2, E::zero(), channel)?;
    x.reverse();
    let [a, b, c] = channel.recv_array()?;
    channel.assert_zero(a * b + c + eval)?;
    let lambda = channel.sample();
    let columns = std::array::from_fn(|side| {
        cs.mul_constraints()
            .iter()
            .map(|row| {
                [&row.a, &row.b, &row.c][side]
                    .wires()
                    .iter()
                    .filter(|i| i.segment == WitnessSegment::Public)
                    .map(|i| public[i.index as usize])
                    .sum()
            })
            .collect()
    });
    let public_eval = E::node(Op::PublicWiring(
        PublicWiring::build(columns, &x, lambda).into(),
    ));
    let x_array = E::node(Op::Array(x.iter().map(|v| v.0).collect()));
    let precommit_claim = channel.recv_one()?;
    let private_claim = a + lambda * (b + lambda * c) + public_eval + precommit_claim;
    for (oracle, claim, segment, ny) in [
        (
            precommit,
            precommit_claim,
            WitnessSegment::Precommit,
            cs.log_precommit() as usize,
        ),
        (
            private,
            private_claim,
            WitnessSegment::Private,
            cs.log_private() as usize,
        ),
    ] {
        let matrix = E::node(Op::Bytes(encode_matrix(
            cs.mul_constraints(),
            segment,
            nx,
            ny,
        )));
        channel.verify_oracle_relation(
            oracle,
            Box::new(move |y| {
                let y_array = E::node(Op::Array(y.iter().map(|v| v.0).collect()));
                E::node(Op::Wiring(matrix.0, x_array.0, y_array.0, lambda.0, 1))
            }),
            claim,
        )?;
    }
    channel.verify_oracle_relation(
        mask,
        Box::new(move |point| {
            let (k, j) = point.split_at(md);
            mlecheck::libra_eval(&x, j, k, nx, 2)
        }),
        mask_eval,
    )?;
    Ok(())
}

#[cfg(test)]
pub(super) fn evaluate_matrix(data: &[u8], x: &[F], y: &[F], lambda: F, _target: u8) -> F {
    fn read(data: &mut &[u8]) -> usize {
        let mut value = 0;
        let mut shift = 0;
        loop {
            let b = data[0];
            *data = &data[1..];
            value |= usize::from(b & 127) << shift;
            if b & 128 == 0 {
                return value;
            }
            shift += 7;
        }
    }
    fn tensor(point: &[F]) -> Vec<F> {
        let mut v = vec![F::ONE];
        for &r in point {
            let n = v.len();
            for i in 0..n {
                let high = v[i] * r;
                v.push(high);
                v[i] += high;
            }
        }
        v
    }
    let mut data = data;
    assert_eq!(read(&mut data), x.len());
    assert_eq!(read(&mut data), y.len());
    let count = read(&mut data);
    let x = tensor(x);
    let y = tensor(y);
    let mut run = [0i64; 6];
    let mut result = [F::ZERO; 3];
    for _ in 0..count {
        for item in &mut run {
            let n = read(&mut data) as i64;
            *item += if n & 1 == 0 { n / 2 } else { -n / 2 - 1 };
        }
        let [mask, n, r, c, dr, dc] = run;
        let mut sum = F::ZERO;
        for i in 0..n {
            sum += x[(r + i * dr) as usize] * y[(c + i * dc) as usize];
        }
        for (side, value) in result.iter_mut().enumerate() {
            if mask & (1 << side) != 0 {
                *value += sum;
            }
        }
    }
    assert!(data.is_empty());
    result[0] + lambda * (result[1] + lambda * result[2])
}
