//! Specializes the pinned verifier over symbolic field elements. The resulting program
//! contains verifier arithmetic and transcript operations, never a proof or witness.
//! The Solidity interpreter implements its primitive operations in the same contract.

use anyhow::Result;
use binius_core::word::Word;
use binius_field::{
    ExtensionField, Field, Ghash128b as F,
    arithmetic_traits::{InvertOrZero, Square},
    field::FieldOps,
};
use binius_hash::StdHashSuite;
use binius_iop::{
    basefold::channel::{BaseFoldOracle, BaseFoldVerifierChannel},
    channel::{IOPVerifierChannel, OracleSpec, TransparentEvalFn},
    merkle_channel::MerkleIPVerifierChannel,
};
use binius_ip::channel::{IPVerifierChannel, WordIPVerifierChannel};
use binius_spartan_frontend::{
    circuit_builder::WireAllocator,
    constraint_system::{ConstraintWire, WireKind, WitnessLayout},
};
use binius_verifier::{protocols::shift::WiringEvalClaim, zk_config::ZKVerifier};
use std::{
    cell::RefCell,
    collections::HashMap,
    iter::{Product, Sum},
    ops::*,
    sync::Arc,
};

#[path = "compact_fri.rs"]
mod compact_fri;
#[path = "compact_inner.rs"]
mod compact_inner;
#[path = "compact_outer.rs"]
mod compact_outer;
#[path = "factored_wiring.rs"]
mod factored_wiring;
#[path = "partition_wiring.rs"]
mod partition_wiring;
#[path = "vectorize.rs"]
mod vectorize;
#[path = "wiring_cost.rs"]
mod wiring_cost;

// Large circuit configurations occur only a few times. Keep their payloads
// boxed so millions of scalar instructions do not reserve space for them.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
enum Op {
    Constant(u128),
    Add(u32, u32),
    Mul(u32, u32),
    Inverse(u32),
    Read(usize, usize),
    ReadDigest(usize),
    Sample,
    SampleBits(usize),
    Observe(usize, usize),
    Assert(u32),
    Shr(u32, u32),
    Bit(u32, u32),
    LowBits(u32, u32),
    Shl(u32, u32),
    Layer(u32, usize, usize),
    Path(u32, usize, usize, usize, usize),
    Vector(u32, usize, usize, usize),
    Transpose(Vec<u32>),
    Row(u32, usize),
    Array(Vec<u32>),
    Lookup(u32, u32, usize),
    Bytes(Vec<u8>),
    PublicWiring(Box<compact_outer::PublicWiring>),
    Wiring(u32, u32, u32, u32, u8),
    Fri(Box<compact_fri::Config>),
    VectorBinary(u32, u32, u8, u8),
    ReadFields(usize),
    SampleFields,
    Frobenius(u32),
    SmallEq(Vec<u32>),
    InnerWiring(Box<compact_inner::Config>),
    TransposeOf(u32),
}

#[derive(Default, Clone)]
struct Graph {
    ops: Vec<Op>,
    cse: HashMap<Op, u32>,
    // During a lowering check, compare each new node with this existing graph.
    replay_cursor: Option<usize>,
}
thread_local! {
    static GRAPH: RefCell<Graph> = RefCell::new(Graph::default());
    static INSTANCE: RefCell<Option<Instance>> = const { RefCell::new(None) };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct E(u32);
impl E {
    fn node(op: Op) -> Self {
        GRAPH.with_borrow_mut(|g| {
            let pure = matches!(
                op,
                Op::Constant(_)
                    | Op::Add(..)
                    | Op::Mul(..)
                    | Op::Inverse(_)
                    | Op::Shr(..)
                    | Op::Shl(..)
                    | Op::Bit(..)
                    | Op::LowBits(..)
                    | Op::Array(..)
            );
            if pure && let Some(&id) = g.cse.get(&op) {
                return E(id);
            }
            let position = g.replay_cursor.unwrap_or(g.ops.len());
            let id = u32::try_from(position).expect("verifier program exceeds u32");
            if g.replay_cursor.is_some() {
                assert!(
                    g.ops.get(position) == Some(&op),
                    "inner wiring replay differs from the pinned verifier at operation {position}"
                );
                g.replay_cursor = Some(position + 1);
            }
            if pure {
                g.cse.insert(op.clone(), id);
            }
            if g.replay_cursor.is_none() {
                g.ops.push(op);
            }
            E(id)
        })
    }
    fn constant(self) -> Option<u128> {
        GRAPH.with_borrow(|g| match g.ops[self.0 as usize] {
            Op::Constant(v) => Some(v),
            _ => None,
        })
    }
    fn bit(self, n: u32) -> Self {
        if let Some(v) = self.constant() {
            return E::from(F::new((v >> n) & 1));
        }
        Self::node(Op::Bit(self.0, n))
    }
    fn low_bits(self, n: u32) -> Self {
        if n == 128 {
            return self;
        }
        if let Some(v) = self.constant() {
            return E::from(F::new(v & ((1u128 << n) - 1)));
        }
        Self::node(Op::LowBits(self.0, n))
    }
    fn left(self, n: u32) -> Self {
        if n == 0 {
            return self;
        }
        if let Some(v) = self.constant() {
            return E::from(F::new(v << n));
        }
        Self::node(Op::Shl(self.0, n))
    }
    fn add_impl(self, rhs: Self) -> Self {
        if self == rhs {
            return Self::zero();
        }
        match (self.constant(), rhs.constant()) {
            (Some(a), Some(b)) => Self::from(F::new(a ^ b)),
            (Some(0), _) => rhs,
            (_, Some(0)) => self,
            _ => Self::node(Op::Add(self.0.min(rhs.0), self.0.max(rhs.0))),
        }
    }
    fn mul_impl(self, rhs: Self) -> Self {
        if self == rhs && GRAPH.with_borrow(|g| matches!(g.ops[self.0 as usize], Op::Bit(..))) {
            return self;
        }
        for (bit, constant) in [(self, rhs), (rhs, self)] {
            if let Some(value) = constant.constant() {
                if value.is_power_of_two()
                    && GRAPH.with_borrow(|g| matches!(g.ops[bit.0 as usize], Op::Bit(..)))
                {
                    return bit.left(value.trailing_zeros());
                }
            }
        }
        match (self.constant(), rhs.constant()) {
            (Some(a), Some(b)) => Self::from(F::new(a) * F::new(b)),
            (Some(0), _) | (_, Some(0)) => Self::zero(),
            (Some(1), _) => rhs,
            (_, Some(1)) => self,
            _ => Self::node(Op::Mul(self.0.min(rhs.0), self.0.max(rhs.0))),
        }
    }
    fn inverse(self) -> Self {
        if let Some(v) = self.constant() {
            return Self::from(F::new(v).invert_or_zero());
        }
        Self::node(Op::Inverse(self.0))
    }
}
impl From<F> for E {
    fn from(v: F) -> Self {
        Self::node(Op::Constant(v.into()))
    }
}
impl From<Word> for E {
    fn from(v: Word) -> Self {
        Self::from(F::new(v.as_u64() as u128))
    }
}
impl Shr<u32> for E {
    type Output = Self;
    fn shr(self, n: u32) -> Self {
        if n == 0 {
            return self;
        }
        if let Some(v) = self.constant() {
            return Self::from(F::new(v >> n));
        }
        Self::node(Op::Shr(self.0, n))
    }
}

macro_rules! arithmetic {
    ($e:ty) => {
        impl Neg for $e { type Output=Self; fn neg(self)->Self {self} }
        impl Add for $e { type Output=Self; fn add(self,r:Self)->Self { self.add_impl(r) } }
        impl Sub for $e { type Output=Self; fn sub(self,r:Self)->Self { self.add_impl(r) } }
        impl Mul for $e { type Output=Self; fn mul(self,r:Self)->Self { self.mul_impl(r) } }
        impl Add<&Self> for $e { type Output=Self; fn add(self,r:&Self)->Self {self+*r} }
        impl Sub<&Self> for $e { type Output=Self; fn sub(self,r:&Self)->Self {self-*r} }
        impl Mul<&Self> for $e { type Output=Self; fn mul(self,r:&Self)->Self {self**r} }
        impl AddAssign for $e {fn add_assign(&mut self,r:Self){*self=*self+r;} }
        impl SubAssign for $e {fn sub_assign(&mut self,r:Self){*self=*self-r;} }
        impl MulAssign for $e {fn mul_assign(&mut self,r:Self){*self=*self*r;} }
        impl AddAssign<&Self> for $e {fn add_assign(&mut self,r:&Self){*self+=*r;} }
        impl SubAssign<&Self> for $e {fn sub_assign(&mut self,r:&Self){*self-=*r;} }
        impl MulAssign<&Self> for $e {fn mul_assign(&mut self,r:&Self){*self*=*r;} }
        impl Sum for $e {fn sum<I:Iterator<Item=Self>>(i:I)->Self {i.fold(Self::zero(),|a,b|a+b)} }
        impl<'a> Sum<&'a Self> for $e {fn sum<I:Iterator<Item=&'a Self>>(i:I)->Self {i.copied().sum()} }
        impl Product for $e {fn product<I:Iterator<Item=Self>>(i:I)->Self {i.fold(Self::one(),|a,b|a*b)} }
        impl<'a> Product<&'a Self> for $e {fn product<I:Iterator<Item=&'a Self>>(i:I)->Self {i.copied().product()} }
        impl Square for $e {fn square(self)->Self {self.mul_impl(self)} }
        impl InvertOrZero for $e {fn invert_or_zero(self)->Self {self.inverse()} }
    }
}
arithmetic!(E);
impl FieldOps for E {
    type Scalar = F;
    fn zero() -> Self {
        F::ZERO.into()
    }
    fn one() -> Self {
        F::ONE.into()
    }
    fn square_transpose<S: Field>(elems: &mut [Self])
    where
        F: ExtensionField<S>,
    {
        let degree = <F as ExtensionField<S>>::DEGREE;
        assert_eq!(elems.len(), degree);
        if degree == 128 {
            let matrix = E::node(Op::Transpose(elems.iter().map(|v| v.0).collect()));
            for (j, elem) in elems.iter_mut().enumerate() {
                *elem = E::node(Op::Row(matrix.0, j));
            }
            return;
        }
        let input = elems.to_vec();
        for j in 0..degree {
            elems[j] = (0..degree)
                .map(|i| extract::<S>(input[i], j) * E::from(<F as ExtensionField<S>>::basis(i)))
                .sum();
        }
    }
}

// The subfield projection is an F2-linear map; specialize its matrix on the
// canonical 128-bit basis, with no input-dependent host computation.
fn extract<S: Field>(value: E, j: usize) -> E
where
    F: ExtensionField<S>,
{
    (0..128)
        .map(|bit| value.bit(bit) * E::from(F::from(F::get_base(&F::new(1 << bit), j))))
        .sum()
}

struct Instance {
    layout: Arc<WitnessLayout<F>>,
    public: Vec<E>,
    written: Vec<bool>,
    frozen: bool,
    inout: WireAllocator,
    derived: WireAllocator,
}
impl Instance {
    fn write(&mut self, wire: ConstraintWire, value: E) {
        if self.frozen {
            return;
        }
        if let Some(index) = self.layout.get(&wire) {
            self.public[index.index as usize] = value;
            self.written[index.index as usize] = true;
        }
    }
    fn inout(value: E) -> Z {
        INSTANCE.with_borrow_mut(|v| {
            let s = v.as_mut().unwrap();
            let wire = s.inout.alloc();
            s.write(wire, value);
        });
        Z::Wire(Some(value))
    }
    fn derived(value: E) -> Z {
        INSTANCE.with_borrow_mut(|v| {
            let s = v.as_mut().unwrap();
            let wire = s.derived.alloc();
            s.write(wire, value);
        });
        Z::Wire(Some(value))
    }
}

/// Mirrors CircuitElem<GHASH, InstanceGenerator>, including allocation of alive
/// public intermediates in the *original* outer Spartan witness layout.
#[derive(Clone, Copy, Debug)]
enum Z {
    Constant(F),
    Wire(Option<E>),
}
impl Z {
    fn public(self) -> E {
        match self {
            Self::Constant(c) => c.into(),
            Self::Wire(Some(v)) => v,
            Self::Wire(None) => panic!("verifier requested a secret as a public expression"),
        }
    }
    fn add_impl(self, r: Self) -> Self {
        match (self, r) {
            (Self::Constant(a), Self::Constant(b)) => Self::Constant(a + b),
            (Self::Wire(None), _) | (_, Self::Wire(None)) => Self::Wire(None),
            _ => Instance::derived(self.public() + r.public()),
        }
    }
    fn mul_impl(self, r: Self) -> Self {
        if matches!(self,Self::Constant(c) if c==F::ZERO)
            || matches!(r,Self::Constant(c) if c==F::ZERO)
        {
            return Self::Constant(F::ZERO);
        }
        match (self, r) {
            (Self::Constant(a), Self::Constant(b)) => Self::Constant(a * b),
            (Self::Wire(None), _) | (_, Self::Wire(None)) => Self::Wire(None),
            _ => Instance::derived(self.public() * r.public()),
        }
    }
    fn inverse(self) -> Self {
        match self {
            Self::Constant(c) => Self::Constant(c.invert_or_zero()),
            Self::Wire(None) => Self::Wire(None),
            Self::Wire(Some(v)) => {
                let inv = Instance::derived(v.inverse());
                // CircuitElem::invert allocates a hint and its constraining product.
                let _product = self.mul_impl(inv);
                inv
            }
        }
    }
}
impl From<F> for Z {
    fn from(v: F) -> Self {
        Self::Constant(v)
    }
}
arithmetic!(Z);
impl FieldOps for Z {
    type Scalar = F;
    fn zero() -> Self {
        Self::Constant(F::ZERO)
    }
    fn one() -> Self {
        Self::Constant(F::ONE)
    }
    fn square_transpose<S: Field>(elems: &mut [Self])
    where
        F: ExtensionField<S>,
    {
        let d = <F as ExtensionField<S>>::DEGREE;
        assert_eq!(elems.len(), d);
        if d == 1 {
            return;
        }
        if INSTANCE.with_borrow(|s| s.as_ref().is_some_and(|s| s.frozen)) {
            let mut values: Vec<E> = elems.iter().map(|v| v.public()).collect();
            E::square_transpose::<S>(&mut values);
            for (elem, value) in elems.iter_mut().zip(values) {
                *elem = Self::Wire(Some(value));
            }
            return;
        }
        if elems.iter().all(|e| matches!(e, Self::Constant(_))) {
            let mut values: Vec<F> = elems
                .iter()
                .map(|e| match e {
                    Self::Constant(v) => *v,
                    _ => unreachable!(),
                })
                .collect();
            <F as ExtensionField<S>>::square_transpose(&mut values);
            for (e, v) in elems.iter_mut().zip(values) {
                *e = Self::Constant(v);
            }
            return;
        }
        if d == 128 && elems.iter().all(|e| !matches!(e, Self::Wire(None))) {
            // Preserve every native derived-wire allocation, but compute its
            // value with the identities sum(bit_j(v)*X^j,j<=k)=low_{k+1}(v)
            // and transpose(transpose(v))=v. These are exact GF(2) identities.
            let input: Vec<E> = elems.iter().map(|e| e.public()).collect();
            let mut transposed = input.clone();
            E::square_transpose::<S>(&mut transposed);
            let coefficients: Vec<Vec<Z>> = input
                .iter()
                .map(|&v| (0..128).map(|j| Instance::derived(v.bit(j))).collect())
                .collect();
            for row in &coefficients {
                for &bit in row {
                    let _ = bit.square();
                }
            }
            // Native row reconstruction allocates one product and one partial
            // sum for each nontrivial basis coefficient, in this exact order.
            for (row, &value) in input.iter().enumerate() {
                for j in 1..128 {
                    let _ = Instance::derived(coefficients[row][j].public().left(j as u32));
                    let _ = Instance::derived(value.low_bits(j as u32 + 1));
                }
            }
            for j in 0..128 {
                for i in 1..128 {
                    let _ = Instance::derived(coefficients[i][j].public().left(i as u32));
                    let _ = Instance::derived(transposed[j].low_bits(i as u32 + 1));
                }
                elems[j] = Self::Wire(Some(transposed[j]));
            }
            return;
        }
        // Exact allocation sequence of wrapper::gadgets::square_transpose. Once
        // any input is a wire, constants are materialized as public builder wires.
        let coeffs: Vec<Vec<Z>> = elems
            .iter()
            .map(|&e| {
                (0..d)
                    .map(|j| match e {
                        Self::Wire(None) => Self::Wire(None),
                        _ => Instance::derived(extract::<S>(e.public(), j)),
                    })
                    .collect()
            })
            .collect();
        for row in &coeffs {
            for &c in row {
                let mut p = c;
                for _ in 0..(128 / d) {
                    p = p.square();
                }
                // InstanceGenerator::assert_eq allocates no wires.
            }
        }
        let combine = |values: Vec<Z>| {
            values
                .iter()
                .enumerate()
                .skip(1)
                .fold(values[0], |sum, (j, &v)| {
                    // Builder constants are Wire(Some), even when equal to zero/one.
                    let basis = Self::Wire(Some(E::from(<F as ExtensionField<S>>::basis(j))));
                    sum + v * basis
                })
        };
        for row in &coeffs {
            let _ = combine(row.clone());
        }
        for j in 0..d {
            elems[j] = combine(coeffs.iter().map(|r| r[j]).collect());
        }
    }
}

#[derive(Clone)]
struct Commitment {
    root: E,
    leaf: usize,
    depth: usize,
}
#[derive(Default)]
struct Channel {
    offset: usize,
    samples: Vec<E>,
    commitments: Vec<Commitment>,
    query_start: Option<(usize, usize)>,
}
impl Channel {
    fn take(&mut self, n: usize) -> usize {
        let o = self.offset;
        self.offset += n;
        o
    }
    fn read(&mut self, n: usize) -> E {
        let o = self.take(n);
        E::node(Op::Read(o, n))
    }
    fn select(elems: &[E], word: E) -> E {
        assert!(elems.len().is_power_of_two());
        if let Some(v) = word.constant() {
            return elems[v as usize & (elems.len() - 1)];
        }
        let array = E::node(Op::Array(elems.iter().map(|e| e.0).collect()));
        E::node(Op::Lookup(word.0, array.0, elems.len()))
    }
    fn pack(words: &[E]) -> Vec<E> {
        words
            .chunks(2)
            .map(|c| c[0] + c.get(1).copied().unwrap_or_else(E::zero).left(64))
            .collect()
    }
}
impl IPVerifierChannel<F> for Channel {
    type Elem = E;
    fn recv_one(&mut self) -> Result<E, binius_ip::channel::Error> {
        E::node(Op::Observe(self.offset, 16));
        Ok(self.read(16))
    }
    fn sample(&mut self) -> E {
        let value = E::node(Op::Sample);
        self.samples.push(value);
        value
    }
    fn observe_one(&mut self, _v: F) -> E {
        panic!("unexpected field observation; extend symbolic channel")
    }
    fn assert_zero(&mut self, v: E) -> Result<(), binius_ip::channel::Error> {
        E::node(Op::Assert(v.0));
        Ok(())
    }
}
impl WordIPVerifierChannel<F> for Channel {
    type Word = E;
    fn observe_words(&mut self, words: &[Word]) -> Vec<E> {
        E::node(Op::Observe(48, words.len() * 8));
        (0..words.len())
            .map(|i| E::node(Op::Read(48 + i * 8, 8)))
            .collect()
    }
    fn subset_sum(&mut self, elems: &[E], word: &E) -> E {
        assert!(elems.len() <= 64);
        elems
            .iter()
            .enumerate()
            .map(|(i, &v)| v * word.bit(i as u32))
            .sum()
    }
    fn select(&mut self, elems: &[E], word: &E) -> E {
        Self::select(elems, *word)
    }
    fn sample_bits(&mut self, bits: usize) -> E {
        if self.query_start.is_none() {
            self.query_start = Some((GRAPH.with_borrow(|g| g.ops.len()), self.offset));
        }
        E::node(Op::SampleBits(bits.min(32)))
    }
    fn pack_words(&mut self, words: &[E]) -> Vec<E> {
        Self::pack(words)
    }
}
impl MerkleIPVerifierChannel<F> for Channel {
    type Commitment = Commitment;
    fn recv_merkle_commitment(
        &mut self,
        leaf: usize,
        depth: usize,
    ) -> Result<Commitment, binius_iop::merkle_channel::Error> {
        E::node(Op::Observe(self.offset, 32));
        let root = E::node(Op::ReadDigest(self.take(32)));
        let commitment = Commitment { root, leaf, depth };
        self.commitments.push(commitment.clone());
        Ok(commitment)
    }
    fn recv_openings(
        &mut self,
        c: &Commitment,
        indices: &[E],
    ) -> Result<Vec<E>, binius_iop::merkle_channel::Error> {
        let layer_depth = (indices.len().next_power_of_two().ilog2() as usize).min(c.depth);
        let layer = self.take(32 << layer_depth);
        E::node(Op::Layer(c.root.0, layer, layer_depth));
        let mut values = Vec::new();
        for &index in indices {
            let offset = self.offset;
            values.extend((0..c.leaf).map(|_| self.read(16)));
            self.take(32 * (c.depth - layer_depth));
            E::node(Op::Path(
                index.0,
                layer,
                offset,
                c.leaf,
                c.depth - layer_depth,
            ));
        }
        Ok(values)
    }
    fn recv_committed_vector(
        &mut self,
        c: &Commitment,
    ) -> Result<Vec<E>, binius_iop::merkle_channel::Error> {
        let offset = self.offset;
        let values = (0..(c.leaf << c.depth)).map(|_| self.read(16)).collect();
        E::node(Op::Vector(c.root.0, offset, c.leaf, c.depth));
        Ok(values)
    }
}

struct Wrapped<'a> {
    inner: BaseFoldVerifierChannel<'a, F, Channel>,
    suffix: usize,
}
impl IPVerifierChannel<F> for Wrapped<'_> {
    type Elem = Z;
    fn recv_one(&mut self) -> Result<Z, binius_ip::channel::Error> {
        let value = self.inner.recv_one()?;
        Ok(Instance::inout(value) - Z::Wire(None))
    }
    fn recv_public_claim(&mut self) -> Result<Z, binius_ip::channel::Error> {
        Ok(Instance::inout(self.inner.recv_one()?))
    }
    fn sample(&mut self) -> Z {
        Instance::inout(self.inner.sample())
    }
    fn observe_one(&mut self, v: F) -> Z {
        Instance::inout(self.inner.observe_one(v))
    }
    fn assert_zero(&mut self, v: Z) -> Result<(), binius_ip::channel::Error> {
        if let Z::Constant(c) = v {
            assert_eq!(c, F::ZERO, "unsatisfiable constant assertion");
        }
        Ok(())
    }
}
impl WordIPVerifierChannel<F> for Wrapped<'_> {
    type Word = E;
    fn observe_words(&mut self, v: &[Word]) -> Vec<E> {
        self.inner.observe_words(v)
    }
    fn subset_sum(&mut self, elems: &[Z], word: &E) -> Z {
        // In the inner verifier only fixed constraint-system words are inspected
        // this way; statement words enter through pack_words instead.
        let word = word
            .constant()
            .expect("dynamic inner subset sum needs wrapper allocation support");
        elems
            .iter()
            .enumerate()
            .filter(|(i, _)| word & (1 << i) != 0)
            .map(|(_, v)| *v)
            .sum()
    }
    fn select(&mut self, elems: &[Z], word: &E) -> Z {
        elems[word.constant().expect("dynamic inner selection") as usize & (elems.len() - 1)]
    }
    fn sample_bits(&mut self, bits: usize) -> E {
        self.inner.sample_bits(bits)
    }
    fn pack_words(&mut self, v: &[E]) -> Vec<Z> {
        Channel::pack(v).into_iter().map(Instance::inout).collect()
    }
}
impl IOPVerifierChannel<F> for Wrapped<'_> {
    type Oracle = BaseFoldOracle;
    fn remaining_oracle_specs(&self) -> &[OracleSpec] {
        let all = self.inner.remaining_oracle_specs();
        &all[..all.len() - self.suffix]
    }
    fn recv_oracle(
        &mut self,
        log: usize,
        witness: bool,
    ) -> Result<Self::Oracle, binius_iop::channel::Error> {
        self.inner.recv_oracle(log, witness)
    }
    fn verify_oracle_relation(
        &mut self,
        o: Self::Oracle,
        t: TransparentEvalFn<Z>,
        claim: Z,
    ) -> Result<(), binius_iop::channel::Error> {
        let value = self.inner.recv_one()?;
        let decrypted = Instance::inout(value);
        self.assert_zero(claim - decrypted)?;
        // The native wrapper evaluates transparent functions outside its Spartan
        // circuit. Here they emit ordinary verifier equations; the public instance
        // is frozen before opening, so this arithmetic cannot change that instance.
        self.inner.verify_oracle_relation(
            o,
            Box::new(move |p: &[E]| {
                let point: Vec<Z> = p.iter().copied().map(|v| Z::Wire(Some(v))).collect();
                t(&point).public()
            }),
            value,
        )
    }
}

#[derive(Clone)]
pub(super) struct Program {
    pub bytes: Vec<u8>,
    pub word_bytes: usize,
    pub proof_len: usize,
    pub hash_capacity: usize,
    pub registers: usize,
    pub used_opcodes: u32,
    pub fixed_factored_operands: bool,
    partition_input: Option<PartitionInput>,
    #[cfg(test)]
    ops: Vec<Op>,
}

/// The ordinary precursor uses the existing operand codec. Only construction
/// installs the final program with its explicit large-matrix length escape.
#[derive(Clone)]
pub(super) struct ConstructedProgram {
    pub precursor: Program,
    pub bytes: Vec<u8>,
    pub matrix: super::derived_wiring::ConstructedMatrix,
    pub length_offset: usize,
    pub input_offset: usize,
    pub output_offset: usize,
    pub affine_length: usize,
    pub tail_length: usize,
    pub escaped: bool,
    pub storage: Option<super::storage::StoragePlan>,
    pub authenticated_program: bool,
    pub public_expansion: Option<PublicExpansion>,
    pub private_grouping: Option<PrivateGrouping>,
    pub precommit_grouping: Option<PrecommitGrouping>,
}

#[derive(Clone, Debug)]
pub(super) struct PrivateGrouping {
    pub kind: PrivateGroupingKind,
    pub original_length: usize,
    pub nodes: usize,
    pub groups: usize,
    pub max_depth: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PrivateGroupingKind {
    DepthCode,
    ProductTerminals,
}

impl PrivateGroupingKind {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::DepthCode => "depth-code-grouped-u16-v1",
            Self::ProductTerminals => "depth-code-product-terminal-u16-v1",
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct PrecommitGrouping {
    pub instruction_offset: usize,
    pub original_length: usize,
    pub nodes: usize,
    pub groups: usize,
    pub max_depth: usize,
}

#[derive(Clone, Debug)]
pub(super) struct PublicExpansion {
    pub instruction_offset: usize,
    pub prefix_length: usize,
    pub leaves: usize,
    pub nodes: usize,
    pub original_length: usize,
    pub fixed_length: usize,
    pub expanded_precursor_length: usize,
}

#[derive(Clone)]
struct PartitionInput {
    wide: Vec<u8>,
    sites: Vec<PartitionSite>,
}
#[derive(Clone)]
struct PartitionSite {
    data: std::ops::Range<usize>,
    evaluation: std::ops::Range<usize>,
    matrix_slot: usize,
}

/// The SSA liveness check in encode establishes that the matrix register dies
/// at this evaluation. Reuse it only between this instruction and the next
/// original instruction. All original register assignments and checks remain.
pub(super) fn partition_candidates(program: &Program) -> Vec<(u64, Program)> {
    partition_candidates_inner(program, false)
}

pub(super) fn deployment_partition_candidates(program: &Program) -> Vec<(u64, Program)> {
    partition_candidates_inner(program, true)
}

fn partition_candidates_inner(program: &Program, larger: bool) -> Vec<(u64, Program)> {
    assert!(
        !program.fixed_factored_operands,
        "partition before operand recoding"
    );
    let Some(input) = &program.partition_input else {
        return vec![];
    };
    let mut result = vec![];
    for site in &input.sites {
        let original = &input.wide[site.data.start + 9..site.data.end];
        let parts = if larger {
            partition_wiring::deployment_candidates(original)
        } else {
            partition_wiring::candidates(original)
        };
        for part in parts {
            let mut bytes = input.wide[..site.data.start + 5].to_vec();
            bytes.extend_from_slice(&u32::try_from(part.affine.len()).unwrap().to_be_bytes());
            bytes.extend_from_slice(&part.affine);
            bytes.extend_from_slice(&input.wide[site.data.end..site.evaluation.end]);
            let matrix = u32::try_from(site.matrix_slot).unwrap().to_be_bytes();
            let wiring = &input.wide[site.evaluation.clone()];
            assert_eq!(wiring.len(), 22);
            assert_eq!(wiring[0], 24);
            assert_eq!(wiring[21], 4);
            assert_eq!(wiring[5..9], matrix);
            bytes.push(21);
            bytes.extend_from_slice(&matrix);
            bytes.extend_from_slice(&u32::try_from(part.factored.len()).unwrap().to_be_bytes());
            bytes.extend_from_slice(&part.factored);
            bytes.push(24);
            bytes.extend_from_slice(&matrix);
            bytes.extend_from_slice(&wiring[5..]);
            bytes.push(1);
            bytes.extend_from_slice(&wiring[1..5]);
            bytes.extend_from_slice(&wiring[1..5]);
            bytes.extend_from_slice(&matrix);
            bytes.extend_from_slice(&input.wide[site.evaluation.end..]);
            let (bytes, word_bytes) = super::codec::narrow(&bytes);
            result.push((
                part.saved_muls,
                Program {
                    bytes,
                    word_bytes,
                    proof_len: program.proof_len,
                    hash_capacity: program.hash_capacity,
                    registers: program.registers,
                    used_opcodes: program.used_opcodes | (1 << 1),
                    fixed_factored_operands: false,
                    partition_input: None,
                    // Retain the original equations as the native reference. The
                    // partition encoders check their complete polynomial identity;
                    // EVM tests separately execute the changed serialized program.
                    #[cfg(test)]
                    ops: program.ops.clone(),
                },
            ));
        }
    }
    result.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.bytes.cmp(&b.1.bytes)));
    result
}

/// Terminal serialization pass: every factored table uses the same operand
/// format as the selected runtime. Widen first so growing a table cannot
/// truncate its length, then select the smallest lossless instruction width.
pub(super) fn with_fixed_factored_operands(program: &Program) -> Option<Program> {
    assert!(!program.fixed_factored_operands);
    let encoded = super::codec::operands(&program.bytes, true, program.word_bytes);
    let mut wide = super::codec::operands(&encoded, false, 4);
    let mut changed = false;
    for range in super::codec::byte_ranges(&wide, 4).into_iter().rev() {
        let data = &wide[range.start + 4..range.end];
        if data.first() == Some(&factored_wiring::MARKER) {
            let fixed = factored_wiring::fixed_operands(data)?;
            let mut replacement = u32::try_from(fixed.len()).ok()?.to_be_bytes().to_vec();
            replacement.extend(fixed);
            wide.splice(range, replacement);
            changed = true;
        }
    }
    if !changed {
        return None;
    }
    let (bytes, word_bytes) = super::codec::narrow(&wide);
    Some(Program {
        bytes,
        word_bytes,
        proof_len: program.proof_len,
        hash_capacity: program.hash_capacity,
        registers: program.registers,
        used_opcodes: program.used_opcodes,
        fixed_factored_operands: true,
        partition_input: None,
        #[cfg(test)]
        ops: program.ops.clone(),
    })
}

pub(super) fn with_constructed_matrix(program: &Program) -> Option<ConstructedProgram> {
    // These sites come from SSA liveness and typed Wiring operations, including
    // all references inside opaque configurations. Do not discover matrix uses
    // by searching arbitrary byte contents for an opcode or a marker.
    let input = program.partition_input.as_ref()?;
    let [site] = input.sites.as_slice() else {
        return None;
    };
    let ranges = super::codec::byte_ranges(&input.wide, 4);
    let index = ranges
        .iter()
        .position(|range| range.start == site.data.start + 5 && range.end == site.data.end)?;
    let original = &input.wide[site.data.start + 9..site.data.end];
    let matrix = super::derived_wiring::construct(original)?;
    let old_muls = wiring_cost::multiplications(original);
    let extra_words = matrix
        .bytes
        .len()
        .saturating_sub(original.len())
        .div_ceil(32) as u64;
    // A conservative selection estimate includes cold storage for the larger
    // graph. This is not a proof check or an exact gas prediction.
    let saved = old_muls.saturating_sub(matrix.operations as u64 + 3 * extra_words);
    if saved == 0 {
        return None;
    }
    let precursor = with_fixed_factored_operands(program)?;
    if precursor.word_bytes != 2 {
        return None;
    }
    let ranges = super::codec::byte_ranges(&precursor.bytes, 2);
    if ranges
        .iter()
        .enumerate()
        .any(|(i, range)| i != index && range.len() - 2 == 65535)
    {
        return None;
    }
    let range = ranges.get(index)?.clone();
    assert_eq!(&precursor.bytes[range.start + 2..range.end], original);
    // The outer protocol shares its row descriptor between the precommit and
    // private matrices. Simplify that descriptor only once both are graphs.
    // Inner matrices remain inside opcode-30 configs and keep affine decoding.
    if ranges.len() != 2
        || ranges
            .iter()
            .enumerate()
            .any(|(i, r)| i != index && precursor.bytes[r.start + 2] != factored_wiring::MARKER)
    {
        return None;
    }
    let escaped = matrix.bytes.len() >= 65535;
    let mut replacement = Vec::new();
    if escaped {
        replacement.extend_from_slice(&u16::MAX.to_be_bytes());
        replacement.extend_from_slice(&u32::try_from(matrix.bytes.len()).ok()?.to_be_bytes());
    } else {
        replacement.extend_from_slice(&u16::try_from(matrix.bytes.len()).ok()?.to_be_bytes());
    }
    let output_offset = range.start + replacement.len();
    replacement.extend_from_slice(&matrix.bytes);
    let mut bytes = precursor.bytes[..range.start].to_vec();
    bytes.extend_from_slice(&replacement);
    bytes.extend_from_slice(&precursor.bytes[range.end..]);
    assert_eq!(&bytes[..range.start], &precursor.bytes[..range.start]);
    assert_eq!(
        &bytes[output_offset + matrix.bytes.len()..],
        &precursor.bytes[range.end..]
    );
    Some(ConstructedProgram {
        bytes,
        matrix,
        length_offset: range.start,
        input_offset: range.start + 2,
        output_offset,
        affine_length: original.len(),
        tail_length: precursor.bytes.len() - range.end,
        precursor,
        escaped,
        storage: None,
        authenticated_program: false,
        public_expansion: None,
        private_grouping: None,
        precommit_grouping: None,
    })
}

/// Keep the public graph's compact bytes in the constructor payload, and
/// install its checked fixed references before deriving the private matrix.
pub(super) fn with_constructed_public(plan: &ConstructedProgram) -> Option<ConstructedProgram> {
    if plan.public_expansion.is_some()
        || plan.precommit_grouping.is_some()
        || plan.precursor.word_bytes != 2
    {
        return None;
    }
    let ranges = super::codec::public_ranges(&plan.precursor.bytes, 2);
    let [range] = ranges.as_slice() else {
        return None;
    };
    // This layout converts the public graph before the private matrix's input
    // offset. Other layouts retain the existing exact evaluator.
    // Each four-byte child pair is written with MSTORE. Keep its 28-byte
    // overhang in the subsequently copied tail, away from the live counters
    // allocated after the output buffer.
    if range.end > plan.length_offset || plan.precursor.bytes.len() - range.end < 32 {
        return None;
    }
    let original = &plan.precursor.bytes[range.start + 2..range.end];
    let fixed = super::public_wiring::recode(original)?;
    if fixed.nodes < 1024 || fixed.bytes.len() <= original.len() {
        return None;
    }
    assert_eq!(&plan.bytes[range.start + 2..range.end], original);
    let delta = fixed.bytes.len() - original.len();
    let mut bytes = Vec::with_capacity(plan.bytes.len().checked_add(delta)?);
    bytes.extend_from_slice(&plan.bytes[..range.start]);
    bytes.extend_from_slice(&u16::try_from(fixed.bytes.len()).ok()?.to_be_bytes());
    bytes.extend_from_slice(&fixed.bytes);
    bytes.extend_from_slice(&plan.bytes[range.end..]);
    let public_expansion = PublicExpansion {
        instruction_offset: range.start.checked_sub(3)?,
        prefix_length: fixed.prefix_length,
        leaves: fixed.leaves,
        nodes: fixed.nodes,
        original_length: original.len(),
        fixed_length: fixed.bytes.len(),
        expanded_precursor_length: plan.precursor.bytes.len().checked_add(delta)?,
    };
    Some(ConstructedProgram {
        precursor: Program {
            bytes: plan.precursor.bytes.clone(),
            word_bytes: plan.precursor.word_bytes,
            proof_len: plan.precursor.proof_len,
            hash_capacity: plan.precursor.hash_capacity,
            registers: plan.precursor.registers,
            used_opcodes: plan.precursor.used_opcodes,
            fixed_factored_operands: plan.precursor.fixed_factored_operands,
            partition_input: None,
            #[cfg(test)]
            ops: plan.precursor.ops.clone(),
        },
        bytes,
        matrix: plan.matrix.clone(),
        length_offset: plan.length_offset.checked_add(delta)?,
        input_offset: plan.input_offset.checked_add(delta)?,
        output_offset: plan.output_offset.checked_add(delta)?,
        affine_length: plan.affine_length,
        tail_length: plan.tail_length,
        escaped: plan.escaped,
        storage: None,
        authenticated_program: false,
        public_expansion: Some(public_expansion),
        private_grouping: plan.private_grouping.clone(),
        precommit_grouping: None,
    })
}

/// Retain every private scalar equation, emitting a stable depth/code order.
/// The unchanged precursor still determines all equations in the constructor.
pub(super) fn with_grouped_private(plan: &ConstructedProgram) -> Option<ConstructedProgram> {
    if plan.private_grouping.is_some()
        || plan.precommit_grouping.is_some()
        || plan.precursor.word_bytes != 2
    {
        return None;
    }
    let grouped = super::grouped_wiring::recode(&plan.matrix.bytes)?;
    if grouped.nodes < 1024 || grouped.bytes.len() >= plan.matrix.bytes.len() {
        return None;
    }
    assert_eq!(grouped.nodes, plan.matrix.operations);
    let original_length = plan.matrix.bytes.len();
    let escaped = grouped.bytes.len() >= 65535;
    let mut bytes = plan.bytes[..plan.length_offset].to_vec();
    if escaped {
        bytes.extend_from_slice(&u16::MAX.to_be_bytes());
        bytes.extend_from_slice(&u32::try_from(grouped.bytes.len()).ok()?.to_be_bytes());
    } else {
        bytes.extend_from_slice(&u16::try_from(grouped.bytes.len()).ok()?.to_be_bytes());
    }
    let output_offset = bytes.len();
    bytes.extend_from_slice(&grouped.bytes);
    bytes.extend_from_slice(&plan.bytes[plan.output_offset + original_length..]);
    let mut matrix = plan.matrix.clone();
    matrix.bytes = grouped.bytes;
    Some(ConstructedProgram {
        precursor: Program {
            bytes: plan.precursor.bytes.clone(),
            word_bytes: plan.precursor.word_bytes,
            proof_len: plan.precursor.proof_len,
            hash_capacity: plan.precursor.hash_capacity,
            registers: plan.precursor.registers,
            used_opcodes: plan.precursor.used_opcodes,
            fixed_factored_operands: plan.precursor.fixed_factored_operands,
            partition_input: None,
            #[cfg(test)]
            ops: plan.precursor.ops.clone(),
        },
        bytes,
        matrix,
        length_offset: plan.length_offset,
        input_offset: plan.input_offset,
        output_offset,
        affine_length: plan.affine_length,
        tail_length: plan.tail_length,
        escaped,
        storage: None,
        authenticated_program: false,
        public_expansion: plan.public_expansion.clone(),
        private_grouping: Some(PrivateGrouping {
            kind: PrivateGroupingKind::DepthCode,
            original_length,
            nodes: grouped.nodes,
            groups: grouped.groups,
            max_depth: grouped.max_depth,
        }),
        precommit_grouping: None,
    })
}

/// Group the precommit graph only after the private graph is also grouped.
/// The exact two-definition layout then permits a single-format evaluator.
pub(super) fn with_grouped_precommit(plan: &ConstructedProgram) -> Option<ConstructedProgram> {
    if plan.private_grouping.as_ref()?.kind != PrivateGroupingKind::DepthCode
        || plan.precommit_grouping.is_some()
        || plan.precursor.word_bytes != 2
        || !plan.precursor.fixed_factored_operands
    {
        return None;
    }
    let ranges = super::codec::byte_ranges(&plan.precursor.bytes, 2);
    let [precommit, private] = ranges.as_slice() else {
        return None;
    };
    let expansion = if let Some(public) = &plan.public_expansion {
        let end = public
            .instruction_offset
            .checked_add(5 + public.original_length)?;
        if end > precommit.start {
            return None;
        }
        public.fixed_length.checked_sub(public.original_length)?
    } else {
        0
    };
    if private.start.checked_add(expansion)? != plan.length_offset
        || private.end - private.start != 2 + plan.affine_length
        || plan.matrix.bytes.get(..2)? != [255, 128 | plan.matrix.nx as u8]
    {
        return None;
    }
    let original = &plan.precursor.bytes[precommit.start + 2..precommit.end];
    let grouped = super::grouped_wiring::recode_ready(original)?;
    if grouped.bytes.len() >= original.len() {
        return None;
    }
    let start = precommit.start.checked_add(expansion)?;
    let end = precommit.end.checked_add(expansion)?;
    assert_eq!(&plan.bytes[start + 2..end], original);
    let saved = original.len() - grouped.bytes.len();
    let mut replacement = u16::try_from(grouped.bytes.len())
        .ok()?
        .to_be_bytes()
        .to_vec();
    replacement.extend_from_slice(&grouped.bytes);
    let mut bytes = plan.bytes[..start].to_vec();
    bytes.extend_from_slice(&replacement);
    bytes.extend_from_slice(&plan.bytes[end..]);
    let mut precursor_bytes = plan.precursor.bytes[..precommit.start].to_vec();
    precursor_bytes.extend_from_slice(&replacement);
    precursor_bytes.extend_from_slice(&plan.precursor.bytes[precommit.end..]);
    assert_eq!(&bytes[start + replacement.len()..], &plan.bytes[end..]);
    assert_eq!(
        &precursor_bytes[precommit.start + replacement.len()..],
        &plan.precursor.bytes[precommit.end..]
    );
    let mut public_expansion = plan.public_expansion.clone();
    if let Some(public) = &mut public_expansion {
        public.expanded_precursor_length = public.expanded_precursor_length.checked_sub(saved)?;
    }
    Some(ConstructedProgram {
        precursor: Program {
            bytes: precursor_bytes,
            word_bytes: plan.precursor.word_bytes,
            proof_len: plan.precursor.proof_len,
            hash_capacity: plan.precursor.hash_capacity,
            registers: plan.precursor.registers,
            used_opcodes: plan.precursor.used_opcodes,
            fixed_factored_operands: plan.precursor.fixed_factored_operands,
            partition_input: None,
            #[cfg(test)]
            ops: plan.precursor.ops.clone(),
        },
        bytes,
        matrix: plan.matrix.clone(),
        length_offset: plan.length_offset.checked_sub(saved)?,
        input_offset: plan.input_offset.checked_sub(saved)?,
        output_offset: plan.output_offset.checked_sub(saved)?,
        affine_length: plan.affine_length,
        tail_length: plan.tail_length,
        escaped: plan.escaped,
        storage: None,
        authenticated_program: false,
        public_expansion,
        private_grouping: plan.private_grouping.clone(),
        precommit_grouping: Some(PrecommitGrouping {
            instruction_offset: start.checked_sub(3)?,
            original_length: original.len(),
            nodes: grouped.nodes,
            groups: grouped.groups,
            max_depth: grouped.max_depth,
        }),
    })
}

/// Factor the fixed precommit polynomial without changing its evaluator or the
/// constructor's private matrix derivation. Its previous complete plan remains
/// available if the new payload does not fit an EVM code-size limit.
pub(super) fn with_factored_precommit(plan: &ConstructedProgram) -> Option<ConstructedProgram> {
    let grouping = plan.precommit_grouping.as_ref()?;
    plan.private_grouping.as_ref()?;
    if plan.precursor.word_bytes != 2 || !plan.precursor.fixed_factored_operands {
        return None;
    }
    let ranges = super::codec::byte_ranges(&plan.precursor.bytes, 2);
    let [precommit, private] = ranges.as_slice() else {
        return None;
    };
    let expansion = plan.public_expansion.as_ref().map_or(Some(0), |p| {
        if p.instruction_offset.checked_add(5 + p.original_length)? > precommit.start {
            return None;
        }
        p.fixed_length.checked_sub(p.original_length)
    })?;
    let start = precommit.start.checked_add(expansion)?;
    let end = precommit.end.checked_add(expansion)?;
    if start != grouping.instruction_offset.checked_add(3)?
        || private.start.checked_add(expansion)? != plan.length_offset
        || private.end - private.start != 2 + plan.affine_length
    {
        return None;
    }
    let original = &plan.precursor.bytes[precommit.start + 2..precommit.end];
    let factored = super::factor_wiring::recode(original)?;
    assert!(factored.nodes < grouping.nodes && factored.bytes.len() < original.len());
    assert_eq!(&plan.bytes[start + 2..end], original);
    let saved = original.len() - factored.bytes.len();
    let mut replacement = u16::try_from(factored.bytes.len())
        .ok()?
        .to_be_bytes()
        .to_vec();
    replacement.extend_from_slice(&factored.bytes);
    let mut result = plan.clone();
    result.bytes.splice(start..end, replacement.iter().copied());
    result
        .precursor
        .bytes
        .splice(precommit.clone(), replacement.iter().copied());
    result.length_offset = result.length_offset.checked_sub(saved)?;
    result.input_offset = result.input_offset.checked_sub(saved)?;
    result.output_offset = result.output_offset.checked_sub(saved)?;
    result.storage = None;
    if let Some(public) = &mut result.public_expansion {
        public.expanded_precursor_length = public.expanded_precursor_length.checked_sub(saved)?;
    }
    let grouping = result.precommit_grouping.as_mut()?;
    grouping.nodes = factored.nodes;
    grouping.groups = factored.groups;
    grouping.max_depth = factored.max_depth;
    assert_eq!(&result.bytes[..start], &plan.bytes[..start]);
    assert_eq!(
        &result.bytes[start + replacement.len()..],
        &plan.bytes[end..]
    );
    assert_eq!(
        &result.precursor.bytes[precommit.start + replacement.len()..],
        &plan.precursor.bytes[precommit.end..]
    );
    Some(result)
}

/// Re-encode product-node terminals only after both outer definitions are
/// grouped. The precursor and its derivation remain byte-for-byte unchanged.
pub(super) fn with_product_terminals(plan: &ConstructedProgram) -> Option<ConstructedProgram> {
    let grouping = plan.private_grouping.as_ref()?;
    let precommit = plan.precommit_grouping.as_ref()?;
    if grouping.kind != PrivateGroupingKind::DepthCode
        || plan.precursor.word_bytes != 2
        || !plan.precursor.fixed_factored_operands
    {
        return None;
    }
    let ranges = super::codec::byte_ranges(&plan.precursor.bytes, 2);
    let [first, private] = ranges.as_slice() else {
        return None;
    };
    let expansion = plan.public_expansion.as_ref().map_or(Some(0), |public| {
        if public
            .instruction_offset
            .checked_add(5 + public.original_length)?
            > first.start
        {
            return None;
        }
        public.fixed_length.checked_sub(public.original_length)
    })?;
    if first.start.checked_add(expansion)? != precommit.instruction_offset.checked_add(3)?
        || private.start.checked_add(expansion)? != plan.length_offset
        || private.end - private.start != 2 + plan.affine_length
        || plan.matrix.bytes.get(..2)? != [255, 128 | plan.matrix.nx as u8]
    {
        return None;
    }
    let original_length = plan.matrix.bytes.len();
    let tail_start = plan.output_offset.checked_add(original_length)?;
    if plan.bytes.get(plan.output_offset..tail_start)? != plan.matrix.bytes
        || plan.bytes.len().checked_sub(tail_start)? != plan.tail_length
    {
        return None;
    }
    let recoded = super::product_wiring::recode(&plan.matrix.bytes)?;
    if recoded.short_products == 0 || recoded.bytes.len() >= original_length {
        return None;
    }
    assert_eq!(recoded.nodes, grouping.nodes);
    assert_eq!(recoded.nodes, plan.matrix.operations);
    assert_eq!(recoded.max_depth, grouping.max_depth);
    let escaped = recoded.bytes.len() >= 65535;
    let mut bytes = plan.bytes[..plan.length_offset].to_vec();
    if escaped {
        bytes.extend_from_slice(&u16::MAX.to_be_bytes());
        bytes.extend_from_slice(&u32::try_from(recoded.bytes.len()).ok()?.to_be_bytes());
    } else {
        bytes.extend_from_slice(&u16::try_from(recoded.bytes.len()).ok()?.to_be_bytes());
    }
    let output_offset = bytes.len();
    bytes.extend_from_slice(&recoded.bytes);
    bytes.extend_from_slice(&plan.bytes[tail_start..]);
    let mut matrix = plan.matrix.clone();
    matrix.bytes = recoded.bytes;
    Some(ConstructedProgram {
        precursor: Program {
            bytes: plan.precursor.bytes.clone(),
            word_bytes: plan.precursor.word_bytes,
            proof_len: plan.precursor.proof_len,
            hash_capacity: plan.precursor.hash_capacity,
            registers: plan.precursor.registers,
            used_opcodes: plan.precursor.used_opcodes,
            fixed_factored_operands: plan.precursor.fixed_factored_operands,
            partition_input: None,
            #[cfg(test)]
            ops: plan.precursor.ops.clone(),
        },
        bytes,
        matrix,
        length_offset: plan.length_offset,
        input_offset: plan.input_offset,
        output_offset,
        affine_length: plan.affine_length,
        tail_length: plan.tail_length,
        escaped,
        storage: None,
        authenticated_program: false,
        public_expansion: plan.public_expansion.clone(),
        private_grouping: Some(PrivateGrouping {
            kind: PrivateGroupingKind::ProductTerminals,
            original_length: grouping.original_length,
            nodes: recoded.nodes,
            groups: recoded.groups,
            max_depth: recoded.max_depth,
        }),
        precommit_grouping: plan.precommit_grouping.clone(),
    })
}

pub(super) fn compile(verifier: &ZKVerifier<StdHashSuite>) -> Result<Program> {
    compile_with_factored_wiring(verifier, false)
}

pub(super) fn compile_with_factored_wiring(
    verifier: &ZKVerifier<StdHashSuite>,
    factored_wiring: bool,
) -> Result<Program> {
    GRAPH.with_borrow_mut(|g| *g = Graph::default());
    let layout = verifier.outer_layout_arc();
    let mut public = vec![E::zero(); layout.public_size()];
    let mut written = vec![false; layout.n_constants() + layout.n_inout() + layout.n_derived()];
    for (slot, &value) in public.iter_mut().zip(
        verifier
            .outer_iop_verifier()
            .constraint_system()
            .constants(),
    ) {
        *slot = value.into();
    }
    written[..layout.n_constants()].fill(true);
    INSTANCE.with_borrow_mut(|s| {
        *s = Some(Instance {
            layout,
            public,
            written,
            frozen: false,
            inout: WireAllocator::new(WireKind::InOut),
            derived: WireAllocator::new(WireKind::Derived),
        })
    });
    let result = (|| {
        let mut inner = verifier.basefold_compiler().create_channel(Channel {
            offset: 56 + 8 * verifier.constraint_system().n_inout,
            ..Default::default()
        });
        let outer = verifier.outer_iop_verifier();
        let specs = outer.oracle_specs();
        let precommit = inner.recv_oracle(specs[0].log_msg_len, true)?;
        let mut wrapper = Wrapped {
            inner,
            suffix: specs.len() - 1,
        };
        let words = wrapper.observe_words(&vec![Word::ZERO; verifier.constraint_system().n_inout]);
        let claim = verifier.inner_iop_verifier().verify(&words, &mut wrapper)?;
        // Native WiringEvalClaim::check_native and this symbolic call evaluate
        // the same FieldFn; the claimed public value is explicitly checked.
        compact_inner::verify(
            verifier.constraint_system(),
            WiringEvalClaim {
                inputs: claim.inputs.into_iter().map(Z::public).collect(),
                claimed: claim.claimed.public(),
                eval_fn: claim.eval_fn,
            },
            &mut wrapper.inner,
        )?;
        let public = INSTANCE.with_borrow_mut(|s| {
            let instance = s.as_mut().unwrap();
            assert!(
                instance.written.iter().all(|&v| v),
                "incomplete outer Spartan public instance"
            );
            instance.frozen = true;
            instance.public.clone()
        });
        compact_outer::verify(
            outer,
            precommit,
            &public,
            &mut wrapper.inner,
            factored_wiring,
        )?;
        let channel = wrapper.inner.finish()?;
        let graph = GRAPH.with_borrow_mut(std::mem::take);
        #[cfg(test)]
        let original_ops = graph.ops.clone();
        let graph = compact_fri::lower(graph, &channel, verifier)?;
        #[allow(unused_mut)]
        let mut program = encode(vectorize::lower(graph), channel.offset);
        #[cfg(test)]
        {
            program.ops = original_ops;
        }
        Ok(program)
    })();
    INSTANCE.with_borrow_mut(|s| *s = None);
    result
}

fn operands(op: &Op) -> Vec<u32> {
    match op {
        Op::Add(a, b) | Op::Mul(a, b) | Op::VectorBinary(a, b, ..) => vec![*a, *b],
        Op::Inverse(a)
        | Op::Frobenius(a)
        | Op::TransposeOf(a)
        | Op::Assert(a)
        | Op::Shr(a, _)
        | Op::Bit(a, _)
        | Op::LowBits(a, _)
        | Op::Shl(a, _)
        | Op::Layer(a, _, _)
        | Op::Path(a, _, _, _, _)
        | Op::Vector(a, _, _, _) => vec![*a],
        Op::Row(a, _) => vec![*a],
        Op::Transpose(v) => v.clone(),
        Op::Array(v) | Op::SmallEq(v) => v.clone(),
        Op::Lookup(a, b, _) => vec![*a, *b],
        Op::Wiring(a, b, c, d, _) => vec![*a, *b, *c, *d],
        Op::Fri(config) => config.operands(),
        Op::InnerWiring(config) => config.operands(),
        Op::PublicWiring(config) => config.operands(),
        _ => vec![],
    }
}

fn encode(graph: Graph, proof_len: usize) -> Program {
    #[cfg(test)]
    let ops = graph.ops.clone();
    // Drop unused arithmetic, but retain every transcript transition and check.
    let mut live: Vec<bool> = graph
        .ops
        .iter()
        .map(|op| {
            matches!(
                op,
                Op::Sample
                    | Op::SampleFields
                    | Op::SampleBits(_)
                    | Op::Observe(..)
                    | Op::Assert(_)
                    | Op::Layer(..)
                    | Op::Path(..)
                    | Op::Vector(..)
            )
        })
        .collect();
    for (i, op) in graph.ops.iter().enumerate().rev() {
        if live[i] {
            for a in operands(op) {
                live[a as usize] = true;
            }
        }
    }
    let mut last = vec![0; graph.ops.len()];
    for (i, op) in graph.ops.iter().enumerate() {
        if live[i] {
            for a in operands(op) {
                last[a as usize] = i;
            }
        }
    }
    let mut slots = vec![0; graph.ops.len()];
    let mut free = std::collections::BinaryHeap::new();
    let mut registers = 1; // slot zero is the discard slot for effect-only instructions.
    let mut bytes = Vec::new();
    let mut byte_definitions = HashMap::new();
    let mut partition_sites = vec![];
    let mut previous_uses_preserve_matrix = vec![true; graph.ops.len()];
    let mut used_opcodes = 0;
    // Each observation epoch starts with a 32-byte digest and an 8-byte
    // consumed-sample index. Sampling ends that epoch. The retained operation
    // schedule bounds this buffer without depending on proof contents.
    let mut observed_capacity = 40usize;
    let mut hash_capacity = observed_capacity;
    let mut pending_observation: Option<(usize, usize)> = None;
    fn u(out: &mut Vec<u8>, v: usize) {
        out.extend_from_slice(
            &u32::try_from(v)
                .expect("program operand exceeds u32")
                .to_be_bytes(),
        );
    }
    fn flush_observation(out: &mut Vec<u8>, pending: &mut Option<(usize, usize)>) {
        if let Some((offset, length)) = pending.take() {
            out.push(8);
            u(out, 0); // Observations have no result; slot zero is reserved.
            u(out, offset);
            u(out, length);
        }
    }
    for (i, op) in graph.ops.iter().enumerate() {
        if !live[i] {
            continue;
        }
        if let Op::Observe(offset, length) = op {
            assert!(last[i] <= i, "observation used as a field value");
            observed_capacity = observed_capacity
                .checked_add(*length)
                .expect("transcript buffer exceeds the address space");
            hash_capacity = hash_capacity.max(observed_capacity);
            used_opcodes |= 1 << 8;
            // Arithmetic does not touch the challenger. Coalesce contiguous
            // proof ranges without changing their order or crossing sampling
            // or verification checks. Noncontiguous ranges remain separate.
            if let Some((start, count)) = &mut pending_observation {
                if start.checked_add(*count) == Some(*offset) {
                    *count = count
                        .checked_add(*length)
                        .expect("observation exceeds usize");
                    continue;
                }
            }
            flush_observation(&mut bytes, &mut pending_observation);
            pending_observation = Some((*offset, *length));
            continue;
        }
        if matches!(
            op,
            Op::Sample
                | Op::SampleBits(_)
                | Op::SampleFields
                | Op::Fri(_)
                | Op::Assert(_)
                | Op::Layer(..)
                | Op::Path(..)
                | Op::Vector(..)
        ) {
            flush_observation(&mut bytes, &mut pending_observation);
        }
        if matches!(
            op,
            Op::Sample | Op::SampleBits(_) | Op::SampleFields | Op::Fri(_)
        ) {
            observed_capacity = 40;
        }
        // A prepared row descriptor can replace its raw-array register after
        // that array's last use. _run reads all operands before writing dest;
        // the descriptor keeps the array's immutable memory, not this slot.
        let reuse = match op {
            Op::Wiring(_, row, _, _, 0) if last[*row as usize] == i => Some(slots[*row as usize]),
            _ => None,
        };
        let dest = if last[i] > i && reuse.is_some() {
            reuse.unwrap()
        } else if last[i] > i {
            free.pop()
                .map(|v: std::cmp::Reverse<usize>| v.0)
                .unwrap_or_else(|| {
                    let n = registers;
                    registers += 1;
                    n
                })
        } else {
            0
        };
        slots[i] = dest;
        let mut instruction = Vec::new();
        let slot = |a: u32| {
            let index = slots[a as usize];
            assert!(
                index < registers,
                "encoded register exceeds the fixed allocation"
            );
            index
        };
        match op {
            Op::Constant(v) => {
                instruction.push(0);
                instruction.extend_from_slice(&v.to_be_bytes());
            }
            Op::Add(a, b) | Op::Mul(a, b) => {
                instruction.push(if matches!(op, Op::Add(..)) { 1 } else { 2 });
                u(&mut instruction, slot(*a));
                u(&mut instruction, slot(*b));
            }
            Op::Inverse(a) => {
                instruction.push(3);
                u(&mut instruction, slot(*a));
            }
            Op::Read(o, n) => {
                assert!(*n <= 16, "field read exceeds the 128-bit decoder");
                instruction.push(4);
                u(&mut instruction, *o);
                instruction.push(*n as u8);
            }
            Op::ReadDigest(o) => {
                instruction.push(5);
                u(&mut instruction, *o);
            }
            Op::Sample => instruction.push(6),
            Op::SampleBits(n) => {
                instruction.push(7);
                instruction.push(*n as u8);
            }
            Op::Observe(..) => unreachable!("observations are accumulated before encoding"),
            Op::Assert(a) => {
                instruction.push(9);
                u(&mut instruction, slot(*a));
            }
            Op::Shr(a, n) | Op::Bit(a, n) | Op::Shl(a, n) => {
                instruction.push(match op {
                    Op::Shr(..) => 10,
                    Op::Bit(..) => 11,
                    _ => 12,
                });
                u(&mut instruction, slot(*a));
                instruction.push(*n as u8);
            }
            Op::Layer(a, o, d) => {
                instruction.push(14);
                u(&mut instruction, slot(*a));
                u(&mut instruction, *o);
                u(&mut instruction, *d);
            }
            Op::Path(a, l, o, n, d) => {
                // Scalar paths hash one whole leaf in the same scratch buffer.
                // Batched paths/vectors grow their scratch buffer separately.
                hash_capacity = hash_capacity.max(
                    n.checked_mul(16)
                        .expect("Merkle leaf exceeds the address space"),
                );
                instruction.push(15);
                for x in [slot(*a), *l, *o, *n, *d] {
                    u(&mut instruction, x);
                }
            }
            Op::Vector(a, o, n, d) => {
                instruction.push(16);
                for x in [slot(*a), *o, *n, *d] {
                    u(&mut instruction, x);
                }
            }
            Op::Transpose(v) => {
                instruction.push(17);
                assert_eq!(v.len(), 128);
                for &a in v {
                    u(&mut instruction, slot(a));
                }
            }
            Op::Row(a, n) => {
                instruction.push(18);
                u(&mut instruction, slot(*a));
                instruction.push(*n as u8);
            }
            Op::Array(v) => {
                instruction.push(19);
                u(&mut instruction, v.len());
                for &a in v {
                    u(&mut instruction, slot(a));
                }
            }
            Op::Lookup(a, b, n) => {
                instruction.push(20);
                u(&mut instruction, slot(*a));
                u(&mut instruction, slot(*b));
                u(&mut instruction, *n);
            }
            Op::Bytes(data) => {
                instruction.push(21);
                u(&mut instruction, data.len());
                instruction.extend_from_slice(data);
            }
            Op::TransposeOf(a) => {
                instruction.push(31);
                u(&mut instruction, slot(*a));
            }
            Op::InnerWiring(config) => {
                instruction.push(30);
                let data = config.encode(slot);
                u(&mut instruction, data.len());
                instruction.extend_from_slice(&data);
            }
            Op::Frobenius(a) => {
                instruction.push(28);
                u(&mut instruction, slot(*a));
            }
            Op::SmallEq(point) => {
                instruction.push(29);
                instruction.push(point.len() as u8);
                for &a in point {
                    u(&mut instruction, slot(a));
                }
            }
            Op::VectorBinary(a, b, kind, shift) => {
                instruction.push(26);
                u(&mut instruction, slot(*a));
                u(&mut instruction, slot(*b));
                instruction.push(*kind);
                instruction.push(*shift);
            }
            Op::SampleFields => {
                instruction.push(13);
            }
            Op::ReadFields(offset) => {
                instruction.push(27);
                u(&mut instruction, *offset);
            }
            Op::LowBits(a, n) => {
                instruction.push(22);
                u(&mut instruction, slot(*a));
                instruction.push(*n as u8);
            }
            Op::PublicWiring(config) => {
                instruction.push(23);
                let data = config.encode(slot);
                u(&mut instruction, data.len());
                instruction.extend_from_slice(&data);
            }
            Op::Wiring(a, b, c, d, segment) => {
                instruction.push(24);
                for x in [a, b, c, d] {
                    u(&mut instruction, slot(*x));
                }
                instruction.push(*segment);
            }
            Op::Fri(config) => {
                instruction.push(25);
                let data = config.encode(slot);
                u(&mut instruction, data.len());
                instruction.extend_from_slice(&data);
            }
        }
        used_opcodes |= 1u32 << instruction[0];
        let start = bytes.len();
        bytes.push(instruction[0]);
        u(&mut bytes, dest);
        bytes.extend_from_slice(&instruction[1..]);
        if let Op::Bytes(_) = op {
            byte_definitions.insert(i as u32, start..bytes.len());
        }
        if let Op::Wiring(a, b, c, d, 4) = op
            && last[*a as usize] == i
            && previous_uses_preserve_matrix[*a as usize]
            && let Op::Bytes(data) = &graph.ops[*a as usize]
            && data.first() != Some(&factored_wiring::MARKER)
            && dest != 0
            && [a, b, c, d].iter().all(|&&id| slot(id) != dest)
            && [b, c, d].iter().all(|&&id| slot(id) != slot(*a))
        {
            // last[] includes operands inside FRI/public/inner opaque configs.
            // A top-level byte scan alone could miss those future reads.
            // Earlier uses must only prepare dimensions: replacing the data
            // would otherwise also change an earlier matrix evaluation.
            partition_sites.push(PartitionSite {
                data: byte_definitions[a].clone(),
                evaluation: start..bytes.len(),
                matrix_slot: slot(*a),
            });
        }
        let mut args = operands(op);
        args.sort_unstable();
        args.dedup();
        for a in args {
            if !matches!(op, Op::Wiring(matrix, row, column, lambda, 0 | 3)
                if a == *matrix && [row, column, lambda].iter().all(|&&id| id != a))
            {
                previous_uses_preserve_matrix[a as usize] = false;
            }
            if last[a as usize] == i && slot(a) != dest {
                free.push(std::cmp::Reverse(slot(a)));
            }
        }
    }
    flush_observation(&mut bytes, &mut pending_observation);
    let (narrowed, word_bytes) = super::codec::narrow(&bytes);
    let partition_input = (!partition_sites.is_empty()).then_some(PartitionInput {
        wide: bytes,
        sites: partition_sites,
    });
    Program {
        bytes: narrowed,
        word_bytes,
        proof_len,
        hash_capacity,
        registers,
        used_opcodes,
        fixed_factored_operands: false,
        partition_input,
        #[cfg(test)]
        ops,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use binius_hash::{compress::CompressionFunction, sha256::Sha256Compression};
    use binius_transcript::VerifierTranscript;
    use binius_verifier::config::StdChallenger;
    use sha2::{Digest, Sha256};

    #[test]
    fn fixed_factored_tables_widen_the_program_without_changing_other_instructions() {
        fn uv(output: &mut Vec<u8>, mut value: usize) {
            while value >= 128 {
                output.push((value as u8) | 128);
                value >>= 7;
            }
            output.push(value as u8);
        }
        // Compact one-byte references produce a 42KB graph. Fixed references
        // make it 70KB, requiring four-byte top-level lengths and registers.
        let count = 14000;
        let mut data = vec![255, 1, 1];
        uv(&mut data, count);
        uv(&mut data, 12 + count - 1);
        uv(&mut data, count);
        data.resize(data.len() + count, 0);
        data.resize(data.len() + 2 * count, 1);
        let graph = Graph {
            ops: vec![
                Op::Bytes(data),
                Op::Constant(1),
                Op::Array(vec![1]),
                Op::Wiring(0, 2, 2, 1, 4),
                Op::Assert(3),
            ],
            ..Default::default()
        };
        let original = encode(graph, 12345);
        assert_eq!(original.word_bytes, 2);
        let fixed = with_fixed_factored_operands(&original).unwrap();
        assert!(fixed.fixed_factored_operands);
        assert_eq!(fixed.word_bytes, 4);
        assert_eq!(fixed.proof_len, original.proof_len);
        assert_eq!(fixed.registers, original.registers);
        assert_eq!(fixed.used_opcodes, original.used_opcodes);
        assert_eq!(fixed.ops, original.ops);
        let before = super::super::codec::operands(
            &super::super::codec::operands(&original.bytes, true, original.word_bytes),
            false,
            4,
        );
        let ranges_before = super::super::codec::byte_ranges(&before, 4);
        let ranges_after = super::super::codec::byte_ranges(&fixed.bytes, 4);
        assert_eq!(ranges_before.len(), 1);
        assert_eq!(ranges_after.len(), 1);
        let a = &ranges_before[0];
        let b = &ranges_after[0];
        assert_eq!(before[..a.start], fixed.bytes[..b.start]);
        assert_eq!(before[a.end..], fixed.bytes[b.end..]);
    }

    #[test]
    fn constructed_program_preserves_instruction_bytes_and_large_matrix_lengths() {
        fn uv(output: &mut Vec<u8>, mut value: u64) {
            while value >= 128 {
                output.push((value as u8) | 128);
                value >>= 7;
            }
            output.push(value as u8);
        }
        let public = factored_wiring::encode(&[(0, 0, 1)], 17, 16).unwrap();
        // Adjacent dyadic fragments benefit from factoring together, while
        // enough independent runs make the graph cross the u16 length boundary.
        // Random isolated points would be rejected by the cost heuristic.
        let mut large = vec![17, 16];
        uv(&mut large, 2304 * 4);
        let mut seed = 0x987651u32;
        let mut previous = [0i64; 6];
        for i in 0..2304 {
            seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
            for offset in [0, 8, 16, 24] {
                let run = [
                    i % 7 + 1,
                    8,
                    i * 32 + offset,
                    i64::from((seed >> 16) % 65504) + offset,
                    1,
                    1,
                ];
                previous[2] += previous[1] * previous[4];
                previous[3] += previous[1] * previous[5];
                for k in 0..6 {
                    let delta = run[k] - previous[k];
                    previous[k] = run[k];
                    uv(
                        &mut large,
                        if delta < 0 { -2 * delta - 1 } else { 2 * delta } as u64,
                    );
                }
            }
        }
        let small = compact_outer::encode_points(vec![(0, 0, 1), (2, 2, 7)], 17, 16);
        for (affine, escaped) in [(small, false), (large, true)] {
            let program = encode(
                Graph {
                    ops: vec![
                        Op::Constant(1),
                        Op::Array(vec![0; 300]),
                        Op::Bytes(public.clone()),
                        Op::Wiring(2, 1, 1, 0, 0),
                        Op::Wiring(2, 3, 1, 0, 4),
                        Op::Assert(4),
                        Op::Bytes(affine),
                        Op::Wiring(6, 3, 1, 0, 4),
                        Op::Assert(7),
                    ],
                    ..Default::default()
                },
                12345,
            );
            let plan = with_constructed_matrix(&program).expect("beneficial bounded graph");
            assert_eq!(plan.precursor.word_bytes, 2);
            assert_eq!(plan.escaped, escaped);
            let input = &plan.precursor.bytes;
            let output = &plan.bytes;
            assert_eq!(input[..plan.length_offset], output[..plan.length_offset]);
            assert_eq!(
                input[plan.input_offset + plan.affine_length..],
                output[plan.output_offset + plan.matrix.bytes.len()..]
            );
            assert_eq!(
                &output[plan.output_offset..plan.output_offset + plan.matrix.bytes.len()],
                &plan.matrix.bytes
            );
            let short = u16::from_be_bytes(
                output[plan.length_offset..plan.length_offset + 2]
                    .try_into()
                    .unwrap(),
            );
            let decoded_length = if short == u16::MAX {
                assert_eq!(plan.output_offset, plan.length_offset + 6);
                u32::from_be_bytes(
                    output[plan.length_offset + 2..plan.length_offset + 6]
                        .try_into()
                        .unwrap(),
                ) as usize
            } else {
                assert_eq!(plan.output_offset, plan.length_offset + 2);
                usize::from(short)
            };
            assert_eq!(decoded_length, plan.matrix.bytes.len());
            assert_eq!(plan.precursor.ops, program.ops);
            assert_eq!(plan.precursor.registers, program.registers);
            assert_eq!(plan.precursor.proof_len, program.proof_len);
            assert_eq!(plan.precursor.used_opcodes, program.used_opcodes);
        }
    }

    #[test]
    fn private_grouping_preserves_instruction_tails_across_length_escape() {
        for count in [12000usize, 14000, 20000] {
            let matrix_bytes = super::super::grouped_wiring::test_graph(count);
            let mut input = vec![21, 0, 1, 0, 4, 1, 2, 3, 4];
            let tail = vec![0u8; 40];
            input.extend_from_slice(&tail);
            let escaped = matrix_bytes.len() >= 65535;
            let mut bytes = input[..3].to_vec();
            if escaped {
                bytes.extend_from_slice(&u16::MAX.to_be_bytes());
                bytes.extend_from_slice(&(matrix_bytes.len() as u32).to_be_bytes());
            } else {
                bytes.extend_from_slice(&(matrix_bytes.len() as u16).to_be_bytes());
            }
            let output_offset = bytes.len();
            bytes.extend_from_slice(&matrix_bytes);
            bytes.extend_from_slice(&tail);
            let original = ConstructedProgram {
                precursor: Program {
                    bytes: input,
                    word_bytes: 2,
                    proof_len: 12345,
                    hash_capacity: 128,
                    registers: 8,
                    used_opcodes: 1 << 21,
                    fixed_factored_operands: true,
                    partition_input: None,
                    ops: vec![],
                },
                bytes,
                matrix: super::super::derived_wiring::ConstructedMatrix {
                    bytes: matrix_bytes,
                    nx: 1,
                    ny: 1,
                    order: vec![0, 1],
                    node_count: 0,
                    node_hash_slots: 1,
                    unpruned_operations: count,
                    operation_hash_slots: 32768,
                    operations: count,
                    chunk_bits: 6,
                },
                length_offset: 3,
                input_offset: 5,
                output_offset,
                affine_length: 4,
                tail_length: 40,
                escaped,
                storage: None,
                authenticated_program: false,
                public_expansion: None,
                private_grouping: None,
                precommit_grouping: None,
            };
            let changed = with_grouped_private(&original).unwrap();
            assert_eq!(changed.precursor.bytes, original.precursor.bytes);
            assert_eq!(changed.input_offset, original.input_offset);
            assert_eq!(&changed.bytes[..3], &original.bytes[..3]);
            assert_eq!(
                &changed.bytes
                    [changed.output_offset..changed.output_offset + changed.matrix.bytes.len()],
                &changed.matrix.bytes
            );
            assert_eq!(
                &changed.bytes[changed.output_offset + changed.matrix.bytes.len()..],
                &tail
            );
            let (field_size, length) = if changed.escaped {
                assert_eq!(&changed.bytes[3..5], &[255, 255]);
                (
                    6,
                    u32::from_be_bytes(changed.bytes[5..9].try_into().unwrap()) as usize,
                )
            } else {
                (
                    2,
                    u16::from_be_bytes(changed.bytes[3..5].try_into().unwrap()) as usize,
                )
            };
            assert_eq!(changed.output_offset, 3 + field_size);
            assert_eq!(length, changed.matrix.bytes.len());
            if count == 14000 {
                assert!(original.escaped && !changed.escaped);
            }
            if count == 20000 {
                assert!(original.escaped && changed.escaped);
            }
            assert!(with_grouped_private(&changed).is_none());
        }
    }

    #[test]
    fn precommit_factoring_preserves_both_constructor_layouts_and_the_private_matrix() {
        for with_public in [false, true] {
            let precommit = super::super::grouped_wiring::recode_ready(&[
                255, 1, 1, 3, 14, 6, 0, 0, 1, 0, 4, 0, 5, 0, 2, 0, 10, 0, 10, 0, 1,
            ])
            .unwrap();
            let matrix = super::super::grouped_wiring::test_graph(1024);
            let mut precursor = Vec::new();
            if with_public {
                let public = super::super::public_wiring::test_graph(2, 1200);
                precursor.extend_from_slice(&[23, 0, 0]);
                precursor.extend_from_slice(&(public.len() as u16).to_be_bytes());
                precursor.extend_from_slice(&public);
            }
            let precommit_at = precursor.len();
            precursor.extend_from_slice(&[21, 0, 1]);
            precursor.extend_from_slice(&(precommit.bytes.len() as u16).to_be_bytes());
            precursor.extend_from_slice(&precommit.bytes);
            precursor.extend_from_slice(&[21, 0, 2]);
            let length_offset = precursor.len();
            precursor.extend_from_slice(&[0, 4, 1, 2, 3, 4]);
            let tail = [9, 0, 0, 0, 0];
            precursor.extend_from_slice(&tail);
            let mut bytes = precursor[..length_offset].to_vec();
            bytes.extend_from_slice(&(matrix.len() as u16).to_be_bytes());
            bytes.extend_from_slice(&matrix);
            bytes.extend_from_slice(&tail);
            let mut plan = ConstructedProgram {
                precursor: Program {
                    bytes: precursor,
                    word_bytes: 2,
                    proof_len: 12345,
                    hash_capacity: 128,
                    registers: 8,
                    used_opcodes: (1 << 21) | (1 << 23) | (1 << 9),
                    fixed_factored_operands: true,
                    partition_input: None,
                    ops: vec![],
                },
                bytes,
                matrix: super::super::derived_wiring::ConstructedMatrix {
                    bytes: matrix,
                    nx: 1,
                    ny: 1,
                    order: vec![0, 1],
                    node_count: 0,
                    node_hash_slots: 1,
                    unpruned_operations: 1024,
                    operation_hash_slots: 128,
                    operations: 1024,
                    chunk_bits: 6,
                },
                length_offset,
                input_offset: length_offset + 2,
                output_offset: length_offset + 2,
                affine_length: 4,
                tail_length: tail.len(),
                escaped: false,
                storage: None,
                authenticated_program: false,
                public_expansion: None,
                private_grouping: None,
                precommit_grouping: None,
            };
            if with_public {
                plan = with_constructed_public(&plan).unwrap();
            }
            plan = with_grouped_private(&plan).unwrap();
            let expansion = plan
                .public_expansion
                .as_ref()
                .map_or(0, |p| p.fixed_length - p.original_length);
            plan.precommit_grouping = Some(PrecommitGrouping {
                instruction_offset: precommit_at + expansion,
                original_length: 21,
                nodes: precommit.nodes,
                groups: precommit.groups,
                max_depth: precommit.max_depth,
            });
            let terminal = with_product_terminals(&plan).unwrap();
            for representation in [&plan, &terminal] {
                for authenticated in [false, true] {
                    let mut plan = representation.clone();
                    plan.authenticated_program = authenticated;
                    let changed = with_factored_precommit(&plan).unwrap();
                    assert_eq!(changed.authenticated_program, authenticated);
                    let saved = plan.bytes.len() - changed.bytes.len();
                    assert!(saved > 0);
                    assert_eq!(changed.precommit_grouping.as_ref().unwrap().nodes, 2);
                    assert_eq!(changed.length_offset + saved, plan.length_offset);
                    assert_eq!(changed.input_offset + saved, plan.input_offset);
                    assert_eq!(changed.output_offset + saved, plan.output_offset);
                    assert_eq!(
                        changed.precursor.bytes.len() + saved,
                        plan.precursor.bytes.len()
                    );
                    assert_eq!(changed.matrix.bytes, plan.matrix.bytes);
                    assert_eq!(changed.matrix.order, plan.matrix.order);
                    assert_eq!(
                        &changed.bytes[changed.output_offset..],
                        &plan.bytes[plan.output_offset..]
                    );
                    assert_eq!(
                        &changed.precursor.bytes[changed.input_offset - expansion..],
                        &plan.precursor.bytes[plan.input_offset - expansion..]
                    );
                    let grouped = changed.precommit_grouping.as_ref().unwrap();
                    assert_eq!(
                        &changed.bytes[..grouped.instruction_offset + 3],
                        &plan.bytes[..grouped.instruction_offset + 3]
                    );
                    let encoded = super::super::codec::operands(&changed.precursor.bytes, true, 2);
                    assert_eq!(
                        super::super::codec::operands(&encoded, false, 2),
                        changed.precursor.bytes
                    );
                    if let Some(public) = &plan.public_expansion {
                        assert_eq!(
                            changed
                                .public_expansion
                                .as_ref()
                                .unwrap()
                                .expanded_precursor_length
                                + saved,
                            public.expanded_precursor_length
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn precommit_grouping_preserves_public_private_and_instruction_boundaries() {
        for with_public in [false, true] {
            for count in [12000usize, 17000, 20000] {
                let mut input = Vec::new();
                if with_public {
                    let public = super::super::public_wiring::test_graph(2, 1200);
                    input.extend_from_slice(&[23, 0, 0]);
                    input.extend_from_slice(&(public.len() as u16).to_be_bytes());
                    input.extend_from_slice(&public);
                }
                let precommit = super::super::grouped_wiring::test_graph(757);
                input.extend_from_slice(&[21, 0, 1]);
                input.extend_from_slice(&(precommit.len() as u16).to_be_bytes());
                input.extend_from_slice(&precommit);
                input.extend_from_slice(&[21, 0, 2]);
                let length_offset = input.len();
                input.extend_from_slice(&[0, 4, 1, 2, 3, 4]);
                let mut tail = vec![9, 0, 0, 0, 0];
                tail.extend_from_slice(&[0, 0, 0]);
                tail.extend_from_slice(&[0; 16]);
                input.extend_from_slice(&tail);
                let matrix = super::super::grouped_wiring::test_graph(count);
                let escaped = matrix.len() >= 65535;
                let mut bytes = input[..length_offset].to_vec();
                if escaped {
                    bytes.extend_from_slice(&u16::MAX.to_be_bytes());
                    bytes.extend_from_slice(&(matrix.len() as u32).to_be_bytes());
                } else {
                    bytes.extend_from_slice(&(matrix.len() as u16).to_be_bytes());
                }
                let output_offset = bytes.len();
                bytes.extend_from_slice(&matrix);
                bytes.extend_from_slice(&tail);
                let mut plan = ConstructedProgram {
                    precursor: Program {
                        bytes: input,
                        word_bytes: 2,
                        proof_len: 12345,
                        hash_capacity: 128,
                        registers: 8,
                        used_opcodes: (1 << 21) | (1 << 23) | (1 << 9) | 1,
                        fixed_factored_operands: true,
                        partition_input: None,
                        ops: vec![],
                    },
                    bytes,
                    matrix: super::super::derived_wiring::ConstructedMatrix {
                        bytes: matrix,
                        nx: 1,
                        ny: 1,
                        order: vec![0, 1],
                        node_count: 0,
                        node_hash_slots: 1,
                        unpruned_operations: count,
                        operation_hash_slots: 32768,
                        operations: count,
                        chunk_bits: 6,
                    },
                    length_offset,
                    input_offset: length_offset + 2,
                    output_offset,
                    affine_length: 4,
                    tail_length: tail.len(),
                    escaped,
                    storage: None,
                    authenticated_program: false,
                    public_expansion: None,
                    private_grouping: None,
                    precommit_grouping: None,
                };
                assert!(with_grouped_precommit(&plan).is_none());
                if with_public {
                    plan = with_constructed_public(&plan).unwrap();
                }
                plan = with_grouped_private(&plan).unwrap();
                let changed = with_grouped_precommit(&plan).unwrap();
                let grouping = changed.precommit_grouping.as_ref().unwrap();
                let start = grouping.instruction_offset + 3;
                let saved = plan.bytes.len() - changed.bytes.len();
                assert_eq!(grouping.nodes, 757);
                assert_eq!(grouping.original_length, precommit.len());
                assert_eq!(
                    changed.precursor.bytes.len() + saved,
                    plan.precursor.bytes.len()
                );
                assert_eq!(changed.length_offset + saved, plan.length_offset);
                assert_eq!(changed.input_offset + saved, plan.input_offset);
                assert_eq!(changed.output_offset + saved, plan.output_offset);
                assert_eq!(&changed.bytes[..start], &plan.bytes[..start]);
                assert_eq!(
                    &changed.bytes[start + 2 + precommit.len() - saved..],
                    &plan.bytes[start + 2 + precommit.len()..]
                );
                assert_eq!(changed.matrix.bytes, plan.matrix.bytes);
                assert_eq!(changed.escaped, count >= 17000);
                assert_eq!(
                    &changed.bytes[changed.output_offset + changed.matrix.bytes.len()..],
                    &tail
                );
                assert_eq!(changed.precursor.proof_len, plan.precursor.proof_len);
                assert_eq!(changed.precursor.registers, plan.precursor.registers);
                assert_eq!(changed.precursor.used_opcodes, plan.precursor.used_opcodes);
                let encoded = super::super::codec::operands(&changed.precursor.bytes, true, 2);
                assert_eq!(
                    super::super::codec::operands(&encoded, false, 2),
                    changed.precursor.bytes
                );
                let ranges = super::super::codec::byte_ranges(&changed.precursor.bytes, 2);
                assert_eq!(ranges.len(), 2);
                assert_eq!(
                    &changed.precursor.bytes[ranges[1].start..ranges[1].end],
                    &[0, 4, 1, 2, 3, 4]
                );
                if let Some(public) = &changed.public_expansion {
                    assert_eq!(public.instruction_offset, 0);
                    assert_eq!(
                        public.expanded_precursor_length + saved,
                        plan.public_expansion
                            .as_ref()
                            .unwrap()
                            .expanded_precursor_length
                    );
                }
                assert!(with_grouped_precommit(&changed).is_none());
                assert!(with_constructed_public(&changed).is_none());
                assert!(
                    with_product_terminals(&plan).is_none(),
                    "precommit grouping is required"
                );
                let narrowed = with_product_terminals(&changed).unwrap();
                assert_eq!(narrowed.precursor.bytes, changed.precursor.bytes);
                assert_eq!(narrowed.precursor.registers, changed.precursor.registers);
                assert_eq!(narrowed.precursor.proof_len, changed.precursor.proof_len);
                assert_eq!(
                    narrowed.precursor.used_opcodes,
                    changed.precursor.used_opcodes
                );
                assert_eq!(narrowed.length_offset, changed.length_offset);
                assert_eq!(narrowed.input_offset, changed.input_offset);
                assert_eq!(
                    &narrowed.bytes[..narrowed.length_offset],
                    &changed.bytes[..changed.length_offset]
                );
                assert_eq!(
                    &narrowed.bytes[narrowed.output_offset + narrowed.matrix.bytes.len()..],
                    &tail
                );
                assert_eq!(
                    narrowed.private_grouping.as_ref().unwrap().kind,
                    PrivateGroupingKind::ProductTerminals
                );
                assert_eq!(
                    narrowed
                        .precommit_grouping
                        .as_ref()
                        .unwrap()
                        .instruction_offset,
                    changed
                        .precommit_grouping
                        .as_ref()
                        .unwrap()
                        .instruction_offset
                );
                assert!(narrowed.storage.is_none());
                let length = if narrowed.escaped {
                    assert_eq!(narrowed.output_offset, narrowed.length_offset + 6);
                    assert_eq!(
                        &narrowed.bytes[narrowed.length_offset..narrowed.length_offset + 2],
                        &[255, 255]
                    );
                    u32::from_be_bytes(
                        narrowed.bytes[narrowed.length_offset + 2..narrowed.output_offset]
                            .try_into()
                            .unwrap(),
                    ) as usize
                } else {
                    assert_eq!(narrowed.output_offset, narrowed.length_offset + 2);
                    u16::from_be_bytes(
                        narrowed.bytes[narrowed.length_offset..narrowed.output_offset]
                            .try_into()
                            .unwrap(),
                    ) as usize
                };
                assert_eq!(length, narrowed.matrix.bytes.len());
                if count == 17000 {
                    assert!(changed.escaped && !narrowed.escaped);
                }
                if count == 20000 {
                    assert!(changed.escaped && narrowed.escaped);
                }
                assert!(with_product_terminals(&narrowed).is_none());
                assert!(with_grouped_precommit(&narrowed).is_none());
                let mut invalid = narrowed;
                invalid.private_grouping.as_mut().unwrap().kind = PrivateGroupingKind::DepthCode;
                assert!(
                    with_product_terminals(&invalid).is_none(),
                    "tagged bytes cannot be parsed as wide references"
                );
                invalid
                    .precursor
                    .bytes
                    .extend_from_slice(&[21, 0, 7, 0, 1, 255]);
                assert!(
                    with_product_terminals(&invalid).is_none(),
                    "a third definition is unsupported"
                );
                plan.matrix.bytes[1] &= 127;
                assert!(with_grouped_precommit(&plan).is_none());
                plan.matrix.bytes[1] |= 128;
                plan.precursor
                    .bytes
                    .extend_from_slice(&[21, 0, 7, 0, 1, 255]);
                assert!(with_grouped_precommit(&plan).is_none());
            }
        }
    }

    #[test]
    fn public_expansion_preserves_payload_and_private_matrix_offsets() {
        let public = super::super::public_wiring::test_graph(2, 1200);
        let fixed = super::super::public_wiring::recode(&public).unwrap();
        for matrix_length in [7usize, 65536] {
            let mut input = vec![23, 0, 0];
            input.extend_from_slice(&(public.len() as u16).to_be_bytes());
            input.extend_from_slice(&public);
            input.extend_from_slice(&[21, 0, 1]);
            let length_offset = input.len();
            input.extend_from_slice(&4u16.to_be_bytes());
            input.extend_from_slice(&[1, 2, 3, 4]);
            let mut tail = vec![9, 0, 0, 0, 0];
            tail.extend_from_slice(&[0, 0, 0]);
            tail.extend_from_slice(&[0; 16]);
            input.extend_from_slice(&tail);
            let escaped = matrix_length >= 65535;
            let mut bytes = input[..length_offset].to_vec();
            if escaped {
                bytes.extend_from_slice(&u16::MAX.to_be_bytes());
                bytes.extend_from_slice(&(matrix_length as u32).to_be_bytes());
            } else {
                bytes.extend_from_slice(&(matrix_length as u16).to_be_bytes());
            }
            let output_offset = bytes.len();
            let matrix_bytes = vec![0x5a; matrix_length];
            bytes.extend_from_slice(&matrix_bytes);
            bytes.extend_from_slice(&tail);
            let original = ConstructedProgram {
                precursor: Program {
                    bytes: input,
                    word_bytes: 2,
                    proof_len: 12345,
                    hash_capacity: 128,
                    registers: 8,
                    used_opcodes: (1 << 23) | (1 << 21) | (1 << 9) | 1,
                    fixed_factored_operands: true,
                    partition_input: None,
                    ops: vec![],
                },
                bytes,
                matrix: super::super::derived_wiring::ConstructedMatrix {
                    bytes: matrix_bytes.clone(),
                    nx: 1,
                    ny: 1,
                    order: vec![0, 1],
                    node_count: 0,
                    node_hash_slots: 1,
                    unpruned_operations: 0,
                    operation_hash_slots: 1,
                    operations: 0,
                    chunk_bits: 6,
                },
                length_offset,
                input_offset: length_offset + 2,
                output_offset,
                affine_length: 4,
                tail_length: tail.len(),
                escaped,
                storage: None,
                authenticated_program: false,
                public_expansion: None,
                private_grouping: None,
                precommit_grouping: None,
            };
            let changed = with_constructed_public(&original).unwrap();
            let expansion = changed.public_expansion.as_ref().unwrap();
            let delta = fixed.bytes.len() - public.len();
            assert_eq!(
                changed.precursor.bytes, original.precursor.bytes,
                "compact constructor payload changed"
            );
            assert_eq!(expansion.instruction_offset, 0);
            assert_eq!(
                expansion.expanded_precursor_length,
                original.precursor.bytes.len() + delta
            );
            assert_eq!(&changed.bytes[5..5 + fixed.bytes.len()], &fixed.bytes);
            assert_eq!(changed.length_offset, original.length_offset + delta);
            assert_eq!(changed.input_offset, original.input_offset + delta);
            assert_eq!(changed.output_offset, original.output_offset + delta);
            assert_eq!(
                &changed.bytes[changed.output_offset..changed.output_offset + matrix_length],
                &matrix_bytes
            );
            assert_eq!(
                &changed.bytes[changed.output_offset + matrix_length..],
                &tail
            );
            assert_eq!(
                &changed.bytes[5 + fixed.bytes.len()..],
                &original.bytes[5 + public.len()..]
            );
            assert_eq!(changed.precursor.proof_len, original.precursor.proof_len);
            assert!(with_constructed_public(&changed).is_none());
            let mut short_tail = original;
            short_tail
                .precursor
                .bytes
                .truncate(short_tail.precursor.bytes.len() - 19);
            assert!(
                with_constructed_public(&short_tail).is_none(),
                "record store could overlap live constructor counters"
            );
        }
    }

    #[test]
    fn partition_requires_one_evaluation_and_its_last_live_matrix_read() {
        let data = compact_outer::encode_points(vec![(0, 0, 1)], 1, 1);
        let mut ops = vec![
            Op::Bytes(data),
            Op::Constant(1),
            Op::Array(vec![1]),
            Op::Wiring(0, 2, 2, 1, 0),
            Op::Wiring(0, 3, 2, 1, 4),
            Op::Assert(4),
        ];
        let program = encode(
            Graph {
                ops: ops.clone(),
                ..Default::default()
            },
            0,
        );
        let input = program.partition_input.unwrap();
        assert_eq!(input.sites.len(), 1);
        let site = &input.sites[0];
        assert_eq!(input.wide[site.evaluation.end], 9); // Original assertion.
        assert_eq!(site.evaluation.end + 9, input.wide.len());
        assert_ne!(
            &input.wide[site.evaluation.start + 1..site.evaluation.start + 5],
            &(site.matrix_slot as u32).to_be_bytes()
        );
        // Replacing the byte definition would alter an earlier evaluation too,
        // even if its register is dead after the final evaluation.
        ops.extend([Op::Wiring(0, 3, 2, 1, 4), Op::Assert(6)]);
        let program = encode(
            Graph {
                ops: ops.clone(),
                ..Default::default()
            },
            0,
        );
        assert!(program.partition_input.is_none());
        // A subsequent evaluation in another mode also keeps the matrix live.
        ops.truncate(6);
        ops.extend([Op::Wiring(0, 2, 2, 1, 1), Op::Assert(6)]);
        let program = encode(
            Graph {
                ops,
                ..Default::default()
            },
            0,
        );
        assert!(program.partition_input.is_none());
    }

    #[test]
    fn hash_workspace_follows_transcript_epochs_and_scalar_leaves() {
        let ops = vec![
            Op::Observe(0, 100),
            Op::Observe(100, 200),
            Op::Sample,
            Op::Observe(300, 250),
            Op::SampleBits(8),
            Op::Observe(550, 275),
            Op::SampleFields,
            Op::Observe(825, 280),
        ];
        let graph = Graph {
            ops,
            ..Graph::default()
        };
        let program = encode(graph.clone(), 1105);
        assert_eq!(program.hash_capacity, 340);

        let mut graph = graph;
        // A scalar Merkle leaf uses scratch independently of observations.
        graph.ops.push(Op::Path(2, 0, 0, 128, 0));
        assert_eq!(encode(graph, 2048).hash_capacity, 2048);
    }

    #[test]
    fn coalesced_observations_preserve_order_and_sampling_boundaries() {
        let graph = Graph {
            ops: vec![
                Op::Constant(0),
                Op::Observe(0, 16),
                Op::Add(0, 0),
                Op::Observe(16, 16),
                Op::Assert(2),
                Op::Observe(32, 8),
                Op::Observe(100, 8),
                Op::Sample,
                Op::Observe(108, 8),
                Op::SampleBits(8),
                Op::Observe(116, 8),
                Op::SampleFields,
                Op::Observe(124, 8),
            ],
            ..Graph::default()
        };
        let program = encode(graph, 132);
        let delta = super::super::codec::operands(&program.bytes, true, program.word_bytes);
        let wide = super::super::codec::operands(&delta, false, 4);
        let mut expected = vec![0, 0, 0, 0, 1]; // constant in register 1
        expected.extend_from_slice(&0u128.to_be_bytes());
        fn instruction(out: &mut Vec<u8>, opcode: u8, words: &[u32]) {
            out.push(opcode);
            for word in words {
                out.extend_from_slice(&word.to_be_bytes());
            }
        }
        instruction(&mut expected, 1, &[2, 1, 1]); // arithmetic remains before the check
        instruction(&mut expected, 8, &[0, 0, 32]); // contiguous observations combined
        instruction(&mut expected, 9, &[0, 2]);
        instruction(&mut expected, 8, &[0, 32, 8]);
        instruction(&mut expected, 8, &[0, 100, 8]); // preserve the gap and order
        instruction(&mut expected, 6, &[0]);
        instruction(&mut expected, 8, &[0, 108, 8]);
        instruction(&mut expected, 7, &[0]);
        expected.push(8);
        instruction(&mut expected, 8, &[0, 116, 8]);
        instruction(&mut expected, 13, &[0]);
        instruction(&mut expected, 8, &[0, 124, 8]); // final pending range is retained
        assert_eq!(wide, expected);
        assert_eq!(program.hash_capacity, 88);
    }

    #[test]
    fn streamed_replay_checks_each_new_node() {
        GRAPH.with_borrow_mut(|g| *g = Graph::default());
        let a = E::node(Op::Sample);
        let b = E::node(Op::Constant(17));
        let prefix = GRAPH.with_borrow(Clone::clone);
        let product = E::node(Op::Mul(a.0, b.0));
        E::node(Op::Assert(product.0));
        let expected = GRAPH.with_borrow(Clone::clone);
        let reset = || {
            GRAPH.with_borrow_mut(|g| {
                *g = expected.clone();
                g.cse = prefix.cse.clone();
                g.replay_cursor = Some(prefix.ops.len());
            })
        };
        reset();
        assert_eq!(E::node(Op::Mul(a.0, b.0)), product);
        // A deduplicated node must not consume the next expected instruction.
        assert_eq!(E::node(Op::Mul(a.0, b.0)), product);
        E::node(Op::Assert(product.0));
        assert!(GRAPH.with_borrow(|g| g.replay_cursor == Some(g.ops.len())));
        reset();
        let wrong = std::panic::catch_unwind(|| E::node(Op::Add(a.0, b.0)));
        assert!(
            wrong.is_err(),
            "a changed verification equation passed replay"
        );
        GRAPH.with_borrow_mut(|g| *g = Graph::default());
    }

    fn export_fixture(
        program: &Program,
        key: &noir_binius_verifier::VerificationKey,
        proof: &noir_binius_verifier::ProofBundle,
    ) {
        std::fs::write("target/solidity-test.vk", key.encode().unwrap()).unwrap();
        std::fs::write("target/solidity-test.binius", proof.encode().unwrap()).unwrap();
        std::fs::write("target/solidity-test.program", &program.bytes).unwrap();
        let encoded = crate::solidity::codec::operands(&program.bytes, true, program.word_bytes);
        let (packed, _) = crate::solidity::codec::pack(&program.bytes, program.word_bytes);
        std::fs::write("target/solidity-test.encoded", encoded).unwrap();
        std::fs::write("target/solidity-test.compressed", packed).unwrap();
        let inputs: Vec<u8> = key
            .noir_public_values(proof)
            .unwrap()
            .into_iter()
            .flat_map(noir_binius_verifier::field_to_be_bytes)
            .collect();
        std::fs::write("target/solidity-test.inputs", inputs).unwrap();
        let paths: Vec<_> = program
            .ops
            .iter()
            .filter_map(|op| {
                if let Op::Path(_, _, offset, leaf, depth) = op {
                    (*depth != 0).then_some(offset + 16 * leaf)
                } else {
                    None
                }
            })
            .collect();
        assert!(paths.len() >= 7);
        let mutations: Vec<_> = paths
            .iter()
            .take(7)
            .chain(paths.last())
            .flat_map(|&offset| u64::try_from(offset).unwrap().to_be_bytes())
            .collect();
        std::fs::write("target/solidity-test.corruptions", mutations).unwrap();
    }

    #[test]
    #[ignore = "requires a compiled Noir example and its matching native proof"]
    fn compiled_noir_fixture() {
        use noir_binius_verifier::{ProofBundle, VerificationKey};
        let name = std::env::var("NOIR_SOLIDITY_FIXTURE").unwrap_or_else(|_| "arithmetic".into());
        let dir = std::path::Path::new("examples").join(&name).join("target");
        let proof = ProofBundle::read(&dir.join(format!("{name}.binius"))).unwrap();
        let key = VerificationKey::decode(
            &crate::backend::verification_key(
                &dir.join(format!("{name}.json")),
                proof.log_inv_rate,
            )
            .unwrap(),
        )
        .unwrap();
        key.verify_bundle(&proof).unwrap();
        let program = compile_with_factored_wiring(
            key.binius_verifier(),
            std::env::var_os("BINIUS_FACTORED_WIRING").is_some(),
        )
        .unwrap();
        execute(&program, &proof.encode().unwrap()).unwrap();
        eprintln!(
            "{name}: {} program bytes, {} registers, {} proof bytes",
            program.bytes.len(),
            program.registers,
            program.proof_len
        );
        export_fixture(&program, &key, &proof);
    }

    fn compress(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
        Sha256Compression::default()
            .compress([a.into(), b.into()])
            .into()
    }
    fn fold(mut layer: Vec<[u8; 32]>) -> [u8; 32] {
        while layer.len() > 1 {
            layer = layer.chunks(2).map(|p| compress(p[0], p[1])).collect();
        }
        layer[0]
    }
    fn execute(program: &Program, proof: &[u8]) -> Result<()> {
        use anyhow::ensure;
        ensure!(proof.len() == program.proof_len, "proof length mismatch");
        let mut t = VerifierTranscript::new(StdChallenger::default(), vec![]);
        let mut v: Vec<[u8; 32]> = Vec::new();
        let mut raw = Vec::<u128>::new();
        let mut matrices: HashMap<usize, Vec<F>> = HashMap::new();
        for (pc, op) in program.ops.iter().enumerate() {
            let f = |i: u32| F::new(raw[i as usize]);
            let mut digest = [0u8; 32];
            let value = match op {
                Op::Constant(x) => *x,
                Op::Add(a, b) => raw[*a as usize] ^ raw[*b as usize],
                Op::Mul(a, b) => (f(*a) * f(*b)).into(),
                Op::Inverse(a) => f(*a).invert_or_zero().into(),
                Op::Transpose(input) => {
                    let mut rows: Vec<F> = input.iter().map(|&a| f(a)).collect();
                    <F as ExtensionField<binius_field::BinaryField1b>>::square_transpose(&mut rows);
                    matrices.insert(pc, rows);
                    0
                }
                Op::Row(a, n) => matrices[&(*a as usize)][*n].into(),
                Op::Array(input) => {
                    matrices.insert(pc, input.iter().map(|&a| f(a)).collect());
                    0
                }
                Op::Lookup(a, b, n) => {
                    matrices[&(*b as usize)][raw[*a as usize] as usize & (n - 1)].into()
                }
                Op::Bytes(_) => 0,
                Op::SampleFields
                | Op::Fri(_)
                | Op::VectorBinary(..)
                | Op::ReadFields(_)
                | Op::Frobenius(_)
                | Op::SmallEq(_)
                | Op::TransposeOf(_) => {
                    unreachable!("reference execution retains the expanded graph")
                }
                Op::PublicWiring(config) => config.evaluate(f).into(),
                Op::InnerWiring(config) => config.evaluate(f).into(),
                Op::Wiring(_, row, _, _, 0) => {
                    // The scalar reference retains the full point instead of
                    // Solidity's equality tables and memoization descriptor.
                    matrices.insert(pc, matrices[&(*row as usize)].clone());
                    0
                }
                Op::Wiring(a, b, c, d, segment) => {
                    let Op::Bytes(data) = &program.ops[*a as usize] else {
                        panic!("invalid matrix")
                    };
                    compact_outer::evaluate_matrix(
                        data,
                        &matrices[&(*b as usize)],
                        &matrices[&(*c as usize)],
                        f(*d),
                        *segment,
                    )
                    .into()
                }
                Op::Read(o, n) => {
                    let mut a = [0; 16];
                    a[..*n].copy_from_slice(&proof[*o..o + n]);
                    u128::from_le_bytes(a)
                }
                Op::ReadDigest(o) => {
                    digest.copy_from_slice(&proof[*o..o + 32]);
                    0
                }
                Op::Sample => IPVerifierChannel::<F>::sample(&mut t).into(),
                Op::SampleBits(n) => {
                    WordIPVerifierChannel::<F>::sample_bits(&mut t, *n).as_u64() as u128
                }
                Op::Observe(o, n) => {
                    t.observe().write_slice(&proof[*o..o + n]);
                    0
                }
                Op::Assert(a) => {
                    ensure!(
                        raw[*a as usize] == 0,
                        "assertion failed at operation {pc}: {op:?} = {:032x}",
                        raw[*a as usize]
                    );
                    0
                }
                Op::Shr(a, n) => raw[*a as usize] >> n,
                Op::Bit(a, n) => (raw[*a as usize] >> n) & 1,
                Op::LowBits(a, n) => raw[*a as usize] & ((1u128 << n) - 1),
                Op::Shl(a, n) => raw[*a as usize] << n,
                Op::Layer(a, o, d) => {
                    let layer = proof[*o..o + (32 << d)]
                        .chunks(32)
                        .map(|x| x.try_into().unwrap())
                        .collect();
                    ensure!(fold(layer) == v[*a as usize], "layer mismatch at {pc}");
                    0
                }
                Op::Path(a, l, o, n, d) => {
                    let mut index = raw[*a as usize] as usize;
                    let mut hash: [u8; 32] = Sha256::digest(&proof[*o..o + 16 * n]).into();
                    for k in 0..*d {
                        let off = o + 16 * n + 32 * k;
                        let s = proof[off..off + 32].try_into().unwrap();
                        hash = if index & 1 == 0 {
                            compress(hash, s)
                        } else {
                            compress(s, hash)
                        };
                        index >>= 1;
                    }
                    ensure!(
                        hash == proof[l + 32 * index..l + 32 * (index + 1)],
                        "path mismatch at {pc}"
                    );
                    0
                }
                Op::Vector(a, o, n, d) => {
                    let layer = proof[*o..o + 16 * (n << d)]
                        .chunks(16 * n)
                        .map(|p| Sha256::digest(p).into())
                        .collect();
                    ensure!(fold(layer) == v[*a as usize], "terminal mismatch at {pc}");
                    0
                }
            };
            raw.push(value);
            v.push(digest);
        }
        Ok(())
    }

    #[test]
    fn specialized_program_checks_real_zk_proofs() {
        use binius_frontend::CircuitBuilder;
        use binius_prover::{OptimalPackedB128, zk_config::ZKProver};
        use binius_transcript::ProverTranscript;
        let builder = CircuitBuilder::new();
        let a = builder.add_inout();
        let b = builder.add_witness();
        builder.assert_eq("public equals private", a, b);
        let circuit = builder.build();
        let verifier =
            ZKVerifier::<StdHashSuite>::setup(circuit.constraint_system().clone(), 1).unwrap();
        let program = compile_with_factored_wiring(
            &verifier,
            std::env::var_os("BINIUS_FACTORED_WIRING").is_some(),
        )
        .unwrap();
        eprintln!(
            "program: {} bytes, {} registers, {} proof bytes",
            program.bytes.len(),
            program.registers,
            program.proof_len
        );
        for public in [0, 123456789] {
            let mut witness = circuit.new_witness_filler();
            witness[a] = Word::from_u64(public);
            witness[b] = Word::from_u64(public);
            circuit.populate_wire_witness(&mut witness).unwrap();
            let prover = ZKProver::<OptimalPackedB128, StdHashSuite>::setup(&verifier).unwrap();
            let mut t = ProverTranscript::new(StdChallenger::default());
            prover
                .prove(&witness.into_value_vec(), rand::rng(), &mut t)
                .unwrap();
            let proof = noir_binius_verifier::ProofBundle {
                circuit_digest: [7; 32],
                log_inv_rate: 1,
                public_words: vec![public],
                transcript: t.finalize(),
            };
            let mut native =
                VerifierTranscript::new(StdChallenger::default(), proof.transcript.clone());
            verifier
                .verify(&[Word::from_u64(public)], &mut native)
                .unwrap();
            native.finalize().unwrap();
            let bytes = proof.encode().unwrap();
            execute(&program, &bytes).unwrap();
            let key = noir_binius_verifier::VerificationKey::new(
                [7; 32],
                noir_binius_verifier::RecursiveMetadata {
                    noir_public_inputs: vec![noir_binius_verifier::FieldRef::public([0; 4])],
                    calls: vec![],
                },
                verifier.clone(),
            );
            let key_bytes = key.encode().unwrap();
            let hinted = crate::solidity::prepare_solidity_proof(&key_bytes, &bytes).unwrap();
            assert_eq!(&hinted[..8], b"NBINH001");
            assert_eq!(&hinted[8..8 + bytes.len()], bytes);
            assert!(hinted.len() > 8 + bytes.len());
            assert_eq!((hinted.len() - 8 - bytes.len()) % 32, 0);
            assert!(crate::solidity::prepare_solidity_proof(&key_bytes, &hinted).is_err());
            // The preparer must reject invalid metadata and invalid proofs,
            // including authentication data the challenger never observes.
            for offset in [8, 40, bytes.len() - 1] {
                let mut bad = bytes.clone();
                bad[offset] ^= 1;
                assert!(crate::solidity::prepare_solidity_proof(&key_bytes, &bad).is_err());
            }
            if public != 0 && std::env::var_os("BINIUS_EVM_FIXTURE").is_some() {
                export_fixture(&program, &key, &proof);
            }
            // Corrupt both observed messages and unobserved Merkle advice.
            for offset in [48, 64, 96, bytes.len() / 2, bytes.len() - 1] {
                let mut bad = bytes.clone();
                bad[offset] ^= 1;
                assert!(
                    execute(&program, &bad).is_err(),
                    "accepted corruption at {offset}"
                );
            }
        }
    }
}
