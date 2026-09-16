//! Extract common polynomial factors only when the live DAG loses products.
//! phi(r, G*A, G*B) = G*phi(r, A, B), including G=0 and arbitrary field points.
//! Factors are multisets: no division or Boolean idempotence is used.
use std::collections::{HashMap, HashSet};

type Op = [usize; 3];
type Form = Option<Vec<usize>>;
type Atom = (usize, Vec<usize>, Vec<usize>);
const MAX_TOTAL: usize = 65_536;
const MAX_FACTORS: usize = 128;
const MAX_DEPTH: usize = 256;

/// Reuse the grouped evaluator and its existing wire format. This pass is
/// restricted to the fixed precommit graph; private matrix construction is
/// unchanged. Bounds only select whether to optimize an otherwise valid graph.
pub(super) fn recode(data: &[u8]) -> Option<super::grouped_wiring::Recoded> {
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
    fn word(data: &[u8], at: usize) -> Option<usize> {
        Some(u16::from_be_bytes(data.get(at..at.checked_add(2)?)?.try_into().ok()?) as usize)
    }
    fn uv(out: &mut Vec<u8>, mut value: usize) {
        while value >= 128 {
            out.push((value as u8) | 128);
            value >>= 7;
        }
        out.push(value as u8);
    }
    if data.len() > 7 * MAX_TOTAL + 16 || *data.first()? != 255 {
        return None;
    }
    let nx = *data.get(1)?;
    let ny = *data.get(2)?;
    let n = usize::from(nx & 127) + usize::from(ny);
    if nx & 128 == 0 || n == 0 || n > 36 {
        return None;
    }
    let first = 8 + 2 * n;
    let mut at = 3;
    let count = number(data, &mut at)?;
    let root = number(data, &mut at)?;
    if count > MAX_TOTAL - first || root >= first + count || number(data, &mut at)? != count * 2 {
        return None;
    }
    let mut ops = Vec::with_capacity(count);
    while ops.len() < count {
        let code = usize::from(*data.get(at)?);
        let size = word(data, at + 1)?;
        at += 3;
        if code > 2 * n || size == 0 || size > count - ops.len() {
            return None;
        }
        for _ in 0..size {
            let here = first + ops.len();
            let da = word(data, at)?;
            let db = word(data, at + 2)?;
            at += 4;
            if da == 0 || db == 0 {
                return None;
            }
            ops.push([code, here.checked_sub(da)?, here.checked_sub(db)?]);
        }
    }
    if at != data.len() {
        return None;
    }
    let (ops, root) = optimize(n, &ops, root)?;
    let mut flat = vec![255, nx & 127, ny];
    uv(&mut flat, ops.len());
    uv(&mut flat, root);
    uv(&mut flat, ops.len() * 2);
    flat.extend(ops.iter().map(|op| op[0] as u8));
    for column in [1, 2] {
        for (i, op) in ops.iter().enumerate() {
            flat.extend_from_slice(&u16::try_from(first + i - op[column]).ok()?.to_be_bytes());
        }
    }
    let grouped = super::grouped_wiring::recode_ready(&flat)?;
    (grouped.bytes.len() < data.len()).then_some(grouped)
}

fn split(a: &[usize], b: &[usize]) -> (Vec<usize>, Vec<usize>, Vec<usize>) {
    let (mut common, mut low, mut high) = (Vec::new(), Vec::new(), Vec::new());
    let (mut i, mut j) = (0, 0);
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Equal => {
                common.push(a[i]);
                i += 1;
                j += 1;
            }
            std::cmp::Ordering::Less => {
                low.push(a[i]);
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                high.push(b[j]);
                j += 1;
            }
        }
    }
    low.extend_from_slice(&a[i..]);
    high.extend_from_slice(&b[j..]);
    (common, low, high)
}

struct Normalizer {
    n: usize,
    first: usize,
    atoms: Vec<Atom>,
    ids: HashMap<Atom, usize>,
}
impl Normalizer {
    fn new(n: usize) -> Self {
        Self {
            n,
            first: 8 + 2 * n,
            atoms: Vec::new(),
            ids: HashMap::new(),
        }
    }
    fn product(a: &Form, b: &Form) -> Option<Form> {
        match (a, b) {
            (Some(a), Some(b)) => {
                if a.len() + b.len() > MAX_FACTORS {
                    return None;
                }
                let mut value = a.clone();
                value.extend_from_slice(b);
                value.sort_unstable();
                Some(Some(value))
            }
            _ => Some(None),
        }
    }
    fn evaluate(&mut self, ops: &[Op]) -> Option<Vec<Form>> {
        // lambda^2+1=(lambda+1)^2 and lambda^2+lambda=lambda*(lambda+1).
        let mut values = vec![
            None,
            Some(vec![]),
            Some(vec![2]),
            Some(vec![3]),
            Some(vec![2, 2]),
            Some(vec![3, 3]),
            Some(vec![2, 3]),
            Some(vec![7]),
        ];
        values.extend((8..self.first).map(|i| Some(vec![i])));
        let mut depths = vec![0; self.first];
        for &[mut code, a, b] in ops {
            if a >= values.len() || b >= values.len() || code > 2 * self.n {
                return None;
            }
            let depth = 1 + depths[a].max(depths[b]);
            if depth > MAX_DEPTH {
                return None;
            }
            depths.push(depth);
            let (mut low, mut high) = (values[a].clone(), values[b].clone());
            let value = if code == 0 {
                Self::product(&low, &high)?
            } else {
                if code > self.n {
                    code -= self.n;
                    std::mem::swap(&mut low, &mut high);
                }
                if low == high {
                    low
                } else if low.is_none() {
                    Self::product(&values[code + 7], &high)?
                } else if high.is_none() {
                    Self::product(&values[code + self.n + 7], &low)?
                } else {
                    let (mut common, low, high) = split(low.as_ref()?, high.as_ref()?);
                    let key = (code, low, high);
                    let id = if let Some(&id) = self.ids.get(&key) {
                        id
                    } else {
                        if self.atoms.len() >= MAX_TOTAL {
                            return None;
                        }
                        let id = self.first + self.atoms.len();
                        self.atoms.push(key.clone());
                        self.ids.insert(key, id);
                        id
                    };
                    common.push(id);
                    common.sort_unstable();
                    if common.len() > MAX_FACTORS {
                        return None;
                    }
                    Some(common)
                }
            };
            values.push(value);
        }
        Some(values)
    }
}

struct Proposal<'a> {
    here: usize,
    first: usize,
    nodes: &'a mut Vec<Op>,
    atoms: &'a [Atom],
    originals: &'a HashMap<Form, usize>,
    old_ops: &'a HashMap<Op, usize>,
    accepted_forms: &'a HashMap<Vec<usize>, (usize, usize)>,
    accepted_ops: &'a HashMap<Op, (usize, usize)>,
    local_forms: HashMap<Vec<usize>, usize>,
    local_ops: HashMap<Op, usize>,
}
impl Proposal<'_> {
    fn available(&self, key: &[usize]) -> bool {
        self.local_forms.contains_key(key)
            || self
                .accepted_forms
                .get(key)
                .is_some_and(|&(_, owner)| owner < self.here)
            || self
                .originals
                .get(&Some(key.to_vec()))
                .is_some_and(|&id| id < self.here)
    }
    fn make(&mut self, code: usize, mut a: usize, mut b: usize) -> Option<usize> {
        if code == 0 && a > b {
            std::mem::swap(&mut a, &mut b);
        }
        let key = [code, a, b];
        if let Some(&id) = self.local_ops.get(&key) {
            return Some(id);
        }
        if let Some(&(id, owner)) = self.accepted_ops.get(&key) {
            if owner < self.here {
                return Some(id);
            }
        }
        if let Some(&id) = self.old_ops.get(&key) {
            if id < self.here {
                return Some(id);
            }
        }
        if self.nodes.len() >= MAX_TOTAL {
            return None;
        }
        let id = self.nodes.len();
        self.nodes.push(key);
        self.local_ops.insert(key, id);
        Some(id)
    }
    fn materialize(&mut self, key: &[usize], depth: usize) -> Option<usize> {
        if depth > MAX_DEPTH {
            return None;
        }
        if let Some(&id) = self.local_forms.get(key) {
            return Some(id);
        }
        if let Some(&(id, owner)) = self.accepted_forms.get(key) {
            if owner < self.here {
                return Some(id);
            }
        }
        if let Some(&id) = self.originals.get(&Some(key.to_vec())) {
            if id < self.here {
                return Some(id);
            }
        }
        let result = if key.len() == 1 {
            let &(code, ref low, ref high) = self.atoms.get(key[0].checked_sub(self.first)?)?;
            let (low, high) = (low.clone(), high.clone());
            let a = self.materialize(&low, depth + 1)?;
            let b = self.materialize(&high, depth + 1)?;
            self.make(code, a, b)?
        } else {
            let at = (1..key.len()).min_by_key(|&at| {
                (
                    usize::from(!self.available(&key[..at]))
                        + usize::from(!self.available(&key[at..])),
                    std::cmp::Reverse(at),
                )
            })?;
            let a = self.materialize(&key[..at], depth + 1)?;
            let b = self.materialize(&key[at..], depth + 1)?;
            self.make(0, a, b)?
        };
        self.local_forms.insert(key.to_vec(), result);
        Some(result)
    }
}

fn add_ref(id: usize, first: usize, nodes: &[Op], refs: &mut [usize], live: &mut usize) {
    let mut pending = vec![id];
    while let Some(id) = pending.pop() {
        refs[id] += 1;
        if id >= first && refs[id] == 1 {
            *live += 1;
            pending.extend_from_slice(&nodes[id][1..]);
        }
    }
}
fn remove_ref(id: usize, first: usize, nodes: &[Op], refs: &mut [usize], live: &mut usize) {
    let mut pending = vec![id];
    while let Some(id) = pending.pop() {
        assert!(refs[id] > 0);
        refs[id] -= 1;
        if id >= first && refs[id] == 0 {
            *live -= 1;
            pending.extend_from_slice(&nodes[id][1..]);
        }
    }
}

pub(super) fn optimize(n: usize, old: &[Op], root: usize) -> Option<(Vec<Op>, usize)> {
    let first = 8 + 2 * n;
    if n == 0 || n > 36 || first + old.len() > MAX_TOTAL || root >= first + old.len() {
        return None;
    }
    let mut normalizer = Normalizer::new(n);
    let forms = normalizer.evaluate(old)?;
    let mut originals = HashMap::new();
    for (i, form) in forms.iter().enumerate() {
        originals.entry(form.clone()).or_insert(i);
    }
    let mut old_ops = HashMap::new();
    for (i, &op) in old.iter().enumerate() {
        old_ops.entry(op).or_insert(first + i);
    }
    let mut nodes = vec![[0; 3]; first];
    nodes.extend_from_slice(old);
    let mut refs = vec![0; nodes.len()];
    let mut live = 0;
    add_ref(root, first, &nodes, &mut refs, &mut live);
    if live != old.len() {
        return None;
    }
    let mut accepted_forms: HashMap<Vec<usize>, (usize, usize)> = HashMap::new();
    let mut accepted_ops: HashMap<Op, (usize, usize)> = HashMap::new();
    let mut saved = 0;
    for _ in 0..8 {
        let mut changed = false;
        for here in first..first + old.len() {
            let [mut code, a, b] = nodes[here];
            if refs[here] == 0 || code == 0 {
                continue;
            }
            let previous = nodes[here];
            let (mut low, mut high) = (forms.get(a)?.as_ref(), forms.get(b)?.as_ref());
            if code > n {
                code -= n;
                std::mem::swap(&mut low, &mut high);
            }
            let (Some(low), Some(high)) = (low, high) else {
                continue;
            };
            if low == high {
                continue;
            }
            let (common, low, high) = split(low, high);
            if common.is_empty() {
                continue;
            }
            let atom = *normalizer.ids.get(&(code, low, high))?;
            let start = nodes.len();
            let before = live;
            let mut proposal = Proposal {
                here,
                first,
                nodes: &mut nodes,
                atoms: &normalizer.atoms,
                originals: &originals,
                old_ops: &old_ops,
                accepted_forms: &accepted_forms,
                accepted_ops: &accepted_ops,
                local_forms: HashMap::new(),
                local_ops: HashMap::new(),
            };
            let c = proposal.materialize(&common, 0)?;
            let r = proposal.materialize(&[atom], 0)?;
            let Proposal {
                local_forms,
                local_ops,
                ..
            } = proposal;
            assert_ne!(c, here);
            assert_ne!(r, here);
            refs.resize(nodes.len(), 0);
            nodes[here] = [0, c, r];
            add_ref(c, first, &nodes, &mut refs, &mut live);
            add_ref(r, first, &nodes, &mut refs, &mut live);
            remove_ref(a, first, &nodes, &mut refs, &mut live);
            remove_ref(b, first, &nodes, &mut refs, &mut live);
            if live < before {
                changed = true;
                saved += before - live;
                for (key, id) in local_forms {
                    let entry = accepted_forms.entry(key).or_insert((id, here));
                    if here < entry.1 {
                        *entry = (id, here);
                    }
                }
                for (key, id) in local_ops {
                    let entry = accepted_ops.entry(key).or_insert((id, here));
                    if here < entry.1 {
                        *entry = (id, here);
                    }
                }
            } else {
                add_ref(a, first, &nodes, &mut refs, &mut live);
                add_ref(b, first, &nodes, &mut refs, &mut live);
                remove_ref(c, first, &nodes, &mut refs, &mut live);
                remove_ref(r, first, &nodes, &mut refs, &mut live);
                nodes[here] = previous;
                assert_eq!(live, before);
                assert!(refs[start..].iter().all(|&n| n == 0));
                nodes.truncate(start);
                refs.truncate(start);
            }
        }
        if !changed {
            break;
        }
    }
    if saved == 0 {
        return None;
    }
    fn emit(
        id: usize,
        first: usize,
        nodes: &[Op],
        mapping: &mut [usize],
        visiting: &mut HashSet<usize>,
        result: &mut Vec<Op>,
        depth: usize,
    ) -> Option<usize> {
        if mapping[id] != usize::MAX {
            return Some(mapping[id]);
        }
        if depth > MAX_DEPTH || !visiting.insert(id) {
            return None;
        }
        let [code, a, b] = nodes[id];
        let a = emit(a, first, nodes, mapping, visiting, result, depth + 1)?;
        let b = emit(b, first, nodes, mapping, visiting, result, depth + 1)?;
        visiting.remove(&id);
        mapping[id] = first + result.len();
        result.push([code, a, b]);
        Some(mapping[id])
    }
    let mut mapping: Vec<_> = (0..first)
        .chain(std::iter::repeat_n(usize::MAX, nodes.len() - first))
        .collect();
    let mut result = Vec::new();
    let new_root = emit(
        root,
        first,
        &nodes,
        &mut mapping,
        &mut HashSet::new(),
        &mut result,
        0,
    )?;
    assert_eq!(result.len(), live);
    assert_eq!(old.len() - result.len(), saved);
    // A separate normalization of the actual final graph must reproduce the
    // old root for all field inputs, irrespective of the cost-selection logic.
    let checked = normalizer.evaluate(&result)?;
    assert_eq!(
        checked[new_root], forms[root],
        "factoring changed the fixed polynomial"
    );
    Some((result, new_root))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mul(mut a: u128, mut b: u128) -> u128 {
        let mut out = 0;
        while b != 0 {
            if b & 1 != 0 {
                out ^= a;
            }
            b >>= 1;
            let carry = a >> 127;
            a = (a << 1) ^ (carry * 0x87);
        }
        out
    }

    fn evaluate(ops: &[Op], root: usize, point: &[u128], lambda: u128) -> u128 {
        let square = mul(lambda, lambda);
        let mut values: Vec<u128> = (0..8)
            .map(|i| {
                (i & 1) ^ if i & 2 != 0 { lambda } else { 0 } ^ if i & 4 != 0 { square } else { 0 }
            })
            .collect();
        values.extend_from_slice(point);
        values.extend(point.iter().map(|x| x ^ 1));
        for &[code, a, b] in ops {
            values.push(if code == 0 {
                mul(values[a], values[b])
            } else {
                values[a] ^ mul(values[code + 7], values[a] ^ values[b])
            });
        }
        values[root]
    }

    fn check(n: usize, old: &[Op], root: usize) {
        let (new, new_root) = optimize(n, old, root).expect("strictly fewer live products");
        assert!(new.len() < old.len());
        let mut seed = 0xc9349845be83949f873843ed93283932u128;
        for sample in 0..64 {
            let mut next = || {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                seed
            };
            let lambda = match sample {
                0 => 0,
                1 => 1,
                2 => u128::MAX,
                _ => next(),
            };
            let point: Vec<_> = (0..n)
                .map(|_| match sample {
                    0 => 0,
                    1 => 1,
                    2 => u128::MAX,
                    _ => next(),
                })
                .collect();
            assert_eq!(
                evaluate(old, root, &point, lambda),
                evaluate(&new, new_root, &point, lambda)
            );
        }
    }

    #[test]
    fn factoring_retains_squares_zero_factors_and_complemented_axes() {
        // (x*x)*phi(r,lambda,lambda+1). Neither repeated x nor lambda
        // may be treated as a Boolean value at the verifier's random point.
        for code in 1..=4 {
            let ops = [[0, 8, 8], [0, 12, 2], [0, 12, 3], [code, 13, 14]];
            check(2, &ops, 15);
            let point = [0x123456789abcdef0123456789abcdef0, 0xfedcba9876543210];
            let expected = mul(
                mul(point[0], point[0]),
                evaluate(&[[code, 2, 3]], 12, &point, 0x42),
            );
            assert_eq!(evaluate(&ops, 15, &point, 0x42), expected);
        }
    }

    #[test]
    fn factoring_accounts_for_shared_subgraphs_and_coefficient_products() {
        for n in [2, 4, 8] {
            let first = 8 + 2 * n;
            let mut ops = Vec::new();
            let mut root = 1;
            for i in 0..12 {
                let a = first + ops.len();
                let common = 8 + i % n;
                ops.push([0, common, 2 + i % 6]);
                ops.push([0, common, 2 + (i + 1) % 6]);
                ops.push([1 + i % (2 * n), a, a + 1]);
                if root != 1 {
                    ops.push([0, root, a + 2]);
                }
                root = first + ops.len() - 1;
            }
            check(n, &ops, root);
        }
        // Shared branch products must remain live if another use needs them.
        let shared = [[0, 8, 2], [0, 8, 3], [1, 12, 13], [0, 12, 14]];
        if let Some((new, root)) = optimize(2, &shared, 15) {
            assert_eq!(
                evaluate(&shared, 15, &[2, 3], 4),
                evaluate(&new, root, &[2, 3], 4)
            );
        }
    }

    #[test]
    fn unsupported_or_oversized_factor_graphs_keep_the_existing_plan() {
        assert!(optimize(0, &[], 0).is_none());
        assert!(optimize(37, &[], 0).is_none());
        assert!(optimize(2, &[[0, 12, 8]], 12).is_none());
        assert!(optimize(2, &[[5, 8, 9]], 12).is_none());
        let mut squares = vec![[0, 8, 8]];
        for i in 0..16 {
            squares.push([0, 12 + i, 12 + i]);
        }
        assert!(optimize(2, &squares, 12 + squares.len() - 1).is_none());
        let mut chain = vec![[0, 1, 1]];
        for i in 0..MAX_DEPTH {
            chain.push([0, 12 + i, 1]);
        }
        assert!(optimize(2, &chain, 12 + chain.len() - 1).is_none());
        for data in [
            &[][..],
            &[255, 1, 1],
            &[255, 129, 1, 1, 12, 2, 0, 0, 0],
            &[255, 129, 1, 1, 12, 2, 0, 0, 1, 0, 0, 0, 1],
        ] {
            assert!(recode(data).is_none());
        }
    }

    #[test]
    fn grouped_encoding_factors_only_after_validating_all_references() {
        // Flat graph of three operations: x*lambda, x*(lambda+1), phi.
        let flat = [
            255, 1, 1, 3, 14, 6, 0, 0, 1, 0, 4, 0, 5, 0, 2, 0, 10, 0, 10, 0, 1,
        ];
        let grouped = super::super::grouped_wiring::recode_ready(&flat).unwrap();
        let changed = recode(&grouped.bytes).unwrap();
        assert_eq!(changed.nodes, 2);
        assert!(changed.bytes.len() < grouped.bytes.len());
        let mut bad = grouped.bytes.clone();
        bad.push(0);
        assert!(recode(&bad).is_none());
        for length in 0..grouped.bytes.len() {
            assert!(recode(&grouped.bytes[..length]).is_none());
        }
    }
}
