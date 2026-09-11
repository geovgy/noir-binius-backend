//! Direct contraction of the inner circuit's sparse wiring tensor. Before
//! lowering, the scalar replay must reproduce the pinned WiringEvalFn graph
//! exactly; the matrix codec also checks every tensor entry by roundtrip.
use super::*;
use anyhow::ensure;
use binius_core::constraint_system::{ConstraintSystem, InoutSegment};
use binius_field::util::FieldFn;
use binius_math::multilinear::eq::{
    eq_ind_partial_eval_scalars, eq_ind_zero, eq_one_var, scaled_eq_ind_partial_eval_scalars,
};
use binius_verifier::protocols::shift::{OperationEvalFn, WiringEntry};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct Group {
    operation: u8,
    inner: u16,
    outer: u16,
    matrix: Vec<u8>,
}
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub(super) struct Config {
    inputs: Vec<u32>,
    nx: [usize; 4],
    ny: usize,
    groups: Vec<Group>,
}
impl Config {
    pub(super) fn operands(&self) -> Vec<u32> {
        self.inputs.clone()
    }
    pub(super) fn remap(&self, f: impl Fn(u32) -> u32) -> Self {
        let mut result = self.clone();
        result.inputs.iter_mut().for_each(|id| *id = f(*id));
        result
    }
    pub(super) fn encode(&self, slot: impl Fn(u32) -> usize) -> Vec<u8> {
        let mut out: Vec<u8> = self.nx.iter().map(|&n| u8::try_from(n).unwrap()).collect();
        out.push(self.ny as u8);
        out.extend_from_slice(&u16::try_from(self.inputs.len()).unwrap().to_be_bytes());
        out.extend_from_slice(&u16::try_from(self.groups.len()).unwrap().to_be_bytes());
        for &id in &self.inputs {
            out.extend_from_slice(&u32::try_from(slot(id)).unwrap().to_be_bytes());
        }
        for group in &self.groups {
            out.push(group.operation);
            out.extend_from_slice(&group.inner.to_be_bytes());
            out.extend_from_slice(&group.outer.to_be_bytes());
            out.extend_from_slice(&u32::try_from(group.matrix.len()).unwrap().to_be_bytes());
            out.extend_from_slice(&group.matrix);
        }
        out
    }
    #[cfg(test)]
    pub(super) fn evaluate(&self, f: impl Fn(u32) -> F) -> F {
        let input: Vec<_> = self.inputs.iter().map(|&id| f(id)).collect();
        let shift = 5 + self.nx.iter().sum::<usize>();
        let y = &input[shift + 18..];
        let weight = |start: usize, n: usize, index: usize| {
            input[start..start + n]
                .iter()
                .enumerate()
                .fold(F::ONE, |v, (i, &r)| {
                    v * (r + F::new(((index >> i) & 1 ^ 1) as u128))
                })
        };
        let mut result = F::ZERO;
        for group in &self.groups {
            let operation = group.operation as usize;
            let start = 5 + self.nx[..operation].iter().sum::<usize>();
            let scalar = weight(0, 2, operation)
                * weight(2, 3, group.inner as usize & 7)
                * weight(shift, 9, group.inner as usize >> 3)
                * weight(shift + 9, 9, group.outer as usize);
            result += scalar
                * compact_outer::evaluate_matrix(
                    &group.matrix,
                    &input[start..start + self.nx[operation]],
                    y,
                    F::ZERO,
                    1,
                );
        }
        result
    }
}

fn scalar_replay(
    cs: &ConstraintSystem,
    nx: [usize; 4],
    entries: &[Vec<WiringEntry>; 4],
    input: &[E],
) -> E {
    let mut offset = 5;
    let points = nx.map(|n| {
        let part = &input[offset..offset + n];
        offset += n;
        part
    });
    let inner = &input[offset..offset + 9];
    let outer = &input[offset + 9..offset + 18];
    let y = &input[offset + 18..input.len() - 1];
    let segment = input[input.len() - 1];
    let log_public = cs.log_public_words(InoutSegment::Public);
    let public_scale = eq_one_var(segment, E::zero()) * eq_ind_zero(&y[log_public..]);
    let public = scaled_eq_ind_partial_eval_scalars(&y[..log_public], public_scale);
    let hidden = scaled_eq_ind_partial_eval_scalars(y, segment);
    let inner_operand = eq_ind_partial_eval_scalars(&[&input[2..5], inner].concat());
    let outer = eq_ind_partial_eval_scalars(outer);
    let operations = eq_ind_partial_eval_scalars(&input[..2]);
    let counts = [
        cs.zero_constraints.len(),
        cs.and_constraints.len(),
        cs.imul_constraints.len(),
        cs.bmul_constraints.len(),
    ];
    let tables: [Vec<E>; 4] = std::array::from_fn(|op| {
        if counts[op] == 0 {
            vec![]
        } else {
            scaled_eq_ind_partial_eval_scalars(points[op], operations[op])
        }
    });
    let results: [E; 4] = std::array::from_fn(|op| {
        let mut result = E::zero();
        let mut position = 0;
        for row in 0..counts[op] {
            let mut sum = E::zero();
            while position < entries[op].len() && entries[op][position].constraint == row {
                let entry = entries[op][position];
                position += 1;
                let index = entry.value.index() as usize;
                let value = match entry.value.segment() as usize {
                    0 => public[index],
                    1 => public[cs.offset_inout() + index],
                    2 => hidden[index],
                    _ => unreachable!(),
                };
                sum += inner_operand[(entry.inner_shift << 3) | entry.operand]
                    * outer[entry.outer_shift]
                    * value;
            }
            result += sum * tables[op][row];
        }
        result
    });
    results[0] + results[1] + results[2] + results[3]
}

pub(super) fn verify(
    cs: &ConstraintSystem,
    claim: WiringEvalClaim<'_, E>,
    channel: &mut BaseFoldVerifierChannel<'_, F, Channel>,
) -> Result<()> {
    let nx = [
        cs.log_zero_constraints(),
        cs.log_and_constraints(),
        cs.log_imul_constraints(),
        cs.log_bmul_constraints(),
    ]
    .map(|n| n.unwrap_or(0));
    let fixed = 5 + nx.iter().sum::<usize>() + 18 + 1;
    ensure!(
        claim.inputs.len() >= fixed,
        "inner wiring challenge layout changed"
    );
    let ny = claim.inputs.len() - fixed;
    ensure!(
        ny >= cs.log_public_words(InoutSegment::Public) && ny < 31,
        "unsupported inner wiring dimensions"
    );
    let entries = [
        OperationEvalFn::new(&cs.zero_constraints)
            .entries()
            .collect::<Vec<_>>(),
        OperationEvalFn::new(&cs.and_constraints)
            .entries()
            .collect(),
        OperationEvalFn::new(&cs.imul_constraints)
            .entries()
            .collect(),
        OperationEvalFn::new(&cs.bmul_constraints)
            .entries()
            .collect(),
    ];
    let prefix = GRAPH.with_borrow(Clone::clone);
    let native = FieldFn::<F>::call::<E>(&claim.eval_fn, &claim.inputs);
    channel.assert_zero(native - claim.claimed)?;
    let mut native_graph = GRAPH.with_borrow_mut(std::mem::take);
    // Keep the native nodes as the comparison buffer and reuse the lookup
    // allocation. E::node checks each independently replayed instruction before
    // exposing its ID, so no second multi-million-node graph is needed.
    native_graph.cse.clear();
    native_graph
        .cse
        .extend(prefix.cse.iter().map(|(op, &id)| (op.clone(), id)));
    native_graph.replay_cursor = Some(prefix.ops.len());
    GRAPH.with_borrow_mut(|g| *g = native_graph);
    let replay = scalar_replay(cs, nx, &entries, &claim.inputs);
    channel.assert_zero(replay - claim.claimed)?;
    let replay_graph = GRAPH.with_borrow_mut(std::mem::take);
    ensure!(
        replay_graph.replay_cursor == Some(replay_graph.ops.len()),
        "inner wiring replay ended before the pinned verifier graph"
    );
    drop(replay_graph);
    let mut groups = BTreeMap::<(u8, u16, u16), Vec<(u32, u32, u8)>>::new();
    for (operation, entries) in entries.iter().enumerate() {
        for entry in entries {
            let column = entry.value.index()
                + match entry.value.segment() as usize {
                    0 => 0,
                    1 => cs.offset_inout() as u32,
                    2 => 1u32 << ny,
                    _ => unreachable!(),
                };
            groups
                .entry((
                    operation as u8,
                    ((entry.inner_shift << 3) | entry.operand) as u16,
                    entry.outer_shift as u16,
                ))
                .or_default()
                .push((entry.constraint as u32, column, 1));
        }
    }
    let groups = groups
        .into_iter()
        .map(|((operation, inner, outer), points)| Group {
            operation,
            inner,
            outer,
            matrix: compact_outer::encode_points(points, nx[operation as usize], ny + 1),
        })
        .collect();
    let config = Config {
        inputs: claim.inputs.iter().map(|v| v.0).collect(),
        nx,
        ny,
        groups,
    };
    GRAPH.with_borrow_mut(|g| *g = prefix);
    let value = E::node(Op::InnerWiring(config.into()));
    channel.assert_zero(value - claim.claimed)?;
    Ok(())
}
