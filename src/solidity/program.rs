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
#[path = "vectorize.rs"]
mod vectorize;

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

pub(super) struct Program {
    pub bytes: Vec<u8>,
    pub proof_len: usize,
    pub registers: usize,
    pub used_opcodes: u32,
    #[cfg(test)]
    ops: Vec<Op>,
}

pub(super) fn compile(verifier: &ZKVerifier<StdHashSuite>) -> Result<Program> {
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
        compact_outer::verify(outer, precommit, &public, &mut wrapper.inner)?;
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
    let mut used_opcodes = 0;
    fn u(out: &mut Vec<u8>, v: usize) {
        out.extend_from_slice(
            &u32::try_from(v)
                .expect("program operand exceeds u32")
                .to_be_bytes(),
        );
    }
    for (i, op) in graph.ops.iter().enumerate() {
        if !live[i] {
            continue;
        }
        let dest = if last[i] > i {
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
        let slot = |a: u32| slots[a as usize];
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
            Op::Observe(o, n) => {
                instruction.push(8);
                u(&mut instruction, *o);
                u(&mut instruction, *n);
            }
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
        bytes.push(instruction[0]);
        u(&mut bytes, dest);
        bytes.extend_from_slice(&instruction[1..]);
        let mut args = operands(op);
        args.sort_unstable();
        args.dedup();
        for a in args {
            if last[a as usize] == i {
                free.push(std::cmp::Reverse(slot(a)));
            }
        }
    }
    Program {
        bytes,
        proof_len,
        registers,
        used_opcodes,
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
        let encoded = crate::solidity::codec::operands(&program.bytes, true);
        let (packed, _) = crate::solidity::codec::pack(&program.bytes);
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
        assert!(paths.len() >= 4);
        let mutations: Vec<_> = paths
            .iter()
            .take(4)
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
        let program = compile(key.binius_verifier()).unwrap();
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
        let program = compile(&verifier).unwrap();
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
            if public != 0 && std::env::var_os("BINIUS_EVM_FIXTURE").is_some() {
                let key = noir_binius_verifier::VerificationKey::new(
                    [7; 32],
                    noir_binius_verifier::RecursiveMetadata {
                        noir_public_inputs: vec![noir_binius_verifier::FieldRef::public([0; 4])],
                        calls: vec![],
                    },
                    verifier.clone(),
                );
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
