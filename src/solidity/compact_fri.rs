//! Replace the repeated FRI query graph with one loop operation.
//! Before replacing it, replay the pinned FRI verifier and require exact graph
//! equality. A changed transcript schedule fails generation instead of silently
//! selecting a different set of challenges or omitting a check.
use super::*;
use anyhow::{Context, ensure};
use binius_iop::fri::verify::FRIQueryVerifier;

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub(super) struct Oracle {
    root: u32,
    leaf: usize,
    depth: usize,
    early: usize,
    later: usize,
    lift: usize,
}
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub(super) struct Config {
    offset: usize,
    end: usize,
    queries: usize,
    index_bits: usize,
    inverse_rate: usize,
    final_challenges: usize,
    inputs: Vec<Oracle>,
    rounds: Vec<Oracle>,
    challenges: Vec<u32>,
    basis: Vec<u128>,
}
impl Config {
    pub(super) fn remap(&self, f: impl Fn(u32) -> u32) -> Self {
        let mut result = self.clone();
        result.challenges.iter_mut().for_each(|id| *id = f(*id));
        result
            .inputs
            .iter_mut()
            .chain(&mut result.rounds)
            .for_each(|o| o.root = f(o.root));
        result
    }
    pub(super) fn operands(&self) -> Vec<u32> {
        self.challenges
            .iter()
            .copied()
            .chain(self.inputs.iter().chain(&self.rounds).map(|o| o.root))
            .collect()
    }
    pub(super) fn encode(&self, slot: impl Fn(u32) -> usize) -> Vec<u8> {
        fn u(v: &mut Vec<u8>, n: usize) {
            v.extend_from_slice(&u32::try_from(n).unwrap().to_be_bytes());
        }
        fn b(v: &mut Vec<u8>, n: usize) {
            v.push(u8::try_from(n).unwrap());
        }
        let mut out = vec![];
        u(&mut out, self.offset);
        u(&mut out, self.end);
        out.extend_from_slice(&u16::try_from(self.queries).unwrap().to_be_bytes());
        for n in [
            self.index_bits,
            self.inverse_rate,
            self.final_challenges,
            self.inputs.len(),
            self.rounds.len(),
            self.challenges.len(),
        ] {
            b(&mut out, n);
        }
        for &value in &self.challenges {
            u(&mut out, slot(value));
        }
        for &value in &self.basis {
            out.extend_from_slice(&value.to_be_bytes());
        }
        for oracle in &self.inputs {
            u(&mut out, slot(oracle.root));
            for n in [
                oracle.leaf.ilog2() as usize,
                oracle.depth,
                oracle.early,
                oracle.later,
                oracle.lift,
            ] {
                b(&mut out, n);
            }
        }
        for oracle in &self.rounds {
            u(&mut out, slot(oracle.root));
            b(&mut out, oracle.leaf.ilog2() as usize);
            b(&mut out, oracle.depth);
        }
        out
    }
}

pub(super) fn lower(
    graph: Graph,
    channel: &Channel,
    verifier: &ZKVerifier<StdHashSuite>,
) -> Result<Graph> {
    let (start, offset) = channel.query_start.context("missing FRI query phase")?;
    let compiler = verifier.basefold_compiler();
    let params = compiler.fri_params();
    let inputs = params.input_oracles().len();
    ensure!(
        channel.commitments.len() == inputs + params.n_oracles(),
        "FRI commitment schedule changed"
    );
    let n = compiler
        .oracle_specs()
        .iter()
        .map(|s| s.log_msg_len)
        .max()
        .unwrap();
    let outer_bits = inputs.next_power_of_two().ilog2() as usize;
    let masking = compiler.oracle_specs().iter().any(|s| s.is_zk);
    let samples = &channel.samples;
    let mut challenges = vec![];
    if masking {
        challenges.push(samples[samples.len() - 2 * n - outer_bits - 2]);
    }
    challenges.extend_from_slice(&samples[samples.len() - n - outer_bits..]);
    ensure!(
        challenges.len() == params.n_fold_rounds(),
        "FRI challenge schedule changed"
    );
    let Some(Op::Assert(last)) = graph.ops.last() else {
        anyhow::bail!("missing final FRI equality");
    };
    let Op::Add(a, b) = graph.ops[*last as usize] else {
        anyhow::bail!("unexpected final FRI equality");
    };
    let sum = if (a as usize) < start && (b as usize) >= start {
        E(a)
    } else if (b as usize) < start && (a as usize) >= start {
        E(b)
    } else {
        anyhow::bail!("unexpected final FRI operands");
    };
    let prefix = Graph {
        ops: graph.ops[..start].to_vec(),
        cse: graph
            .cse
            .iter()
            .filter(|(_, v)| (**v as usize) < start)
            .map(|(k, v)| (k.clone(), *v))
            .collect(),
        replay_cursor: None,
    };
    GRAPH.with_borrow_mut(|g| *g = prefix.clone());
    let fri = FRIQueryVerifier::new_batch(
        params,
        &channel.commitments[..inputs],
        &channel.commitments[inputs..],
        &challenges,
    );
    let mut replay = Channel {
        offset,
        ..Default::default()
    };
    let value = fri.verify(&mut replay)?;
    replay.assert_zero(sum - value)?;
    let replay_graph = GRAPH.with_borrow_mut(std::mem::take);
    ensure!(
        replay.offset == channel.offset && replay_graph.ops == graph.ops,
        "compact FRI lowering did not reproduce the pinned verifier graph"
    );
    let convert = |c: &Commitment| Oracle {
        root: c.root.0,
        leaf: c.leaf,
        depth: c.depth,
        early: 0,
        later: 0,
        lift: 0,
    };
    let input_oracles = channel.commitments[..inputs]
        .iter()
        .zip(params.input_oracles())
        .map(|(c, s)| Oracle {
            early: s.log_early_batch_size,
            later: s.log_later_batch_size,
            lift: s.log_lift,
            ..convert(c)
        })
        .collect();
    let mut beta = <F as binius_field::BinaryField>::TRACE_ONE_ELEMENT;
    for _ in 0..128 - params.index_bits() {
        beta = beta.square() + beta;
    }
    let mut basis = vec![F::ZERO; params.index_bits()];
    *basis.last_mut().unwrap() = beta;
    for i in (1..basis.len()).rev() {
        basis[i - 1] = basis[i].square() + basis[i];
    }
    let config = Config {
        offset,
        end: channel.offset,
        queries: params.n_test_queries(),
        index_bits: params.index_bits(),
        inverse_rate: params.rs_code().log_inv_rate(),
        final_challenges: params.n_final_challenges(),
        inputs: input_oracles,
        rounds: channel.commitments[inputs..].iter().map(convert).collect(),
        challenges: challenges.iter().map(|v| v.0).collect(),
        basis: basis.into_iter().map(u128::from).collect(),
    };
    GRAPH.with_borrow_mut(|g| *g = prefix);
    let value = E::node(Op::Fri(config.into()));
    E::node(Op::Assert((sum - value).0));
    Ok(GRAPH.with_borrow_mut(std::mem::take))
}
