use std::collections::{BTreeMap, BTreeSet, HashMap};

use acir::{
    AcirField, FieldElement,
    circuit::{
        Circuit as AcirCircuit, Opcode, Program,
        opcodes::{BlackBoxFuncCall, BlockId, FunctionInput, MemOp},
    },
    native_types::{Expression, Witness, WitnessMap, WitnessStack},
};
use anyhow::{Context, Result, ensure};
use binius_circuits::{
    bignum::{BigUint, PseudoMersennePrimeField, biguint_lt, select as select_biguint},
    blake2s::blake2s_compress,
    blake3::blake3_fixed,
    keccak::keccak_f1600,
    sha256::{State as Sha256State, sha256_compress},
};
use binius_core::{constraint_system::ValueVec, word::Word};
use binius_frontend::{Circuit, CircuitBuilder, Hint, Wire};
use num_bigint::BigUint as NativeBigUint;

use crate::{
    aes128, ecdsa, grumpkin, poseidon2,
    recursive::{BINIUS_ZK_PROOF_TYPE, FieldRef, RecursiveCallSpec, RecursiveMetadata},
};

pub const FIELD_LIMBS: usize = 4;

pub struct CompiledCircuit {
    pub circuit: Circuit,
    frames: Vec<FrameWires>,
    root_frame: usize,
    pub public_witnesses: Vec<Witness>,
    pub opcode_count: usize,
    pub(crate) recursive: RecursiveMetadata,
}

enum PendingFieldRef {
    Constant(FieldElement),
    Public(BigUint),
}

struct PendingRecursiveCall {
    active_word: Wire,
    proof_type: u32,
    verification_key: Vec<PendingFieldRef>,
    proof: Vec<PendingFieldRef>,
    public_inputs: Vec<PendingFieldRef>,
    key_hash: PendingFieldRef,
}

struct PublicIdentityHint;

impl Hint for PublicIdentityHint {
    const NAME: &'static str = "noir_binius::recursive_public_identity";

    fn shape(&self, _dimensions: &[usize]) -> (usize, usize) {
        (1, 1)
    }

    fn execute(&self, _dimensions: &[usize], inputs: &[Word], outputs: &mut [Word]) {
        outputs[0] = inputs[0];
    }
}

struct FrameWires {
    function_index: u32,
    witnesses: BTreeMap<Witness, BigUint>,
    children: Vec<ChildFrame>,
}

struct ChildFrame {
    frame_index: usize,
    predicate: Option<Expression<FieldElement>>,
}

struct WitnessFrame {
    index: u32,
    witness: WitnessMap<FieldElement>,
}

impl CompiledCircuit {
    pub fn populate(&self, witness_map: &WitnessMap<FieldElement>) -> Result<ValueVec> {
        ensure!(
            self.frames.len() == 1,
            "this compiled program requires a multi-frame Nargo witness stack"
        );
        let mut filler = self.circuit.new_witness_filler();
        fill_frame(&mut filler, &self.frames[0], witness_map)?;
        self.finish_population(filler)
    }

    pub fn populate_stack(
        &self,
        witness_stack: &mut WitnessStack<FieldElement>,
    ) -> Result<ValueVec> {
        let mut stack_items = Vec::with_capacity(witness_stack.length());
        while let Some(item) = witness_stack.pop() {
            stack_items.push(WitnessFrame {
                index: item.index,
                witness: item.witness,
            });
        }
        stack_items.reverse();
        let mut filler = self.circuit.new_witness_filler();
        let mut cursor = stack_items.len();
        self.fill_frame_tree(
            &mut filler,
            self.root_frame,
            true,
            &stack_items,
            &mut cursor,
        )?;
        ensure!(
            cursor == 0,
            "Nargo witness stack has {cursor} unexpected frames"
        );
        self.finish_population(filler)
    }

    fn fill_frame_tree(
        &self,
        filler: &mut binius_frontend::WitnessFiller<'_>,
        frame_index: usize,
        active: bool,
        stack_items: &[WitnessFrame],
        cursor: &mut usize,
    ) -> Result<()> {
        let frame = &self.frames[frame_index];
        if !active {
            fill_zero_frame(filler, frame);
            for child in frame.children.iter().rev() {
                self.fill_frame_tree(filler, child.frame_index, false, stack_items, cursor)?;
            }
            return Ok(());
        }
        ensure!(
            *cursor > 0,
            "Nargo witness stack is missing function {}",
            frame.function_index
        );
        *cursor -= 1;
        let item = &stack_items[*cursor];
        ensure!(
            item.index == frame.function_index,
            "witness frame is for ACIR function {}, expected function {}",
            item.index,
            frame.function_index
        );
        fill_frame(filler, frame, &item.witness)?;
        for child in frame.children.iter().rev() {
            let child_active = match &child.predicate {
                Some(predicate) => evaluate_expression(predicate, &item.witness)?.is_one(),
                None => true,
            };
            self.fill_frame_tree(filler, child.frame_index, child_active, stack_items, cursor)?;
        }
        Ok(())
    }

    fn finish_population(
        &self,
        mut filler: binius_frontend::WitnessFiller<'_>,
    ) -> Result<ValueVec> {
        self.circuit
            .populate_wire_witness(&mut filler)
            .context("Binius witness generation failed")?;
        let values = filler.into_value_vec();
        self.circuit
            .constraint_system()
            .verify(&values)
            .context("translated Binius constraint system is not satisfied")?;
        Ok(values)
    }

    pub fn public_words(&self, witness_map: &WitnessMap<FieldElement>) -> Result<Vec<u64>> {
        let mut words = Vec::with_capacity(self.public_witnesses.len() * FIELD_LIMBS);
        for witness in &self.public_witnesses {
            let value = witness_map.get(witness).with_context(|| {
                format!("public witness {witness} is missing from the witness file")
            })?;
            words.extend(field_to_limbs(*value));
        }
        Ok(words)
    }

    pub fn expected_public_word_count(&self) -> usize {
        self.circuit.inout().len()
    }

    pub(crate) fn verify_recursive_calls(&self, public_words: &[u64]) -> Result<()> {
        self.recursive.verify_calls(public_words)
    }
}

pub fn compile(acir: &AcirCircuit<FieldElement>) -> Result<CompiledCircuit> {
    compile_program(&Program {
        functions: vec![acir.clone()],
        unconstrained_functions: Vec::new(),
    })
}

pub fn compile_program(program: &Program<FieldElement>) -> Result<CompiledCircuit> {
    ensure!(
        !program.functions.is_empty(),
        "ACIR program has no entry point"
    );
    let root = &program.functions[0];
    let public: BTreeSet<_> = root
        .public_parameters
        .0
        .iter()
        .chain(&root.return_values.0)
        .copied()
        .collect();
    let builder = CircuitBuilder::new();
    let field = bn254_field(&builder);
    let mut frames = Vec::new();
    let mut opcode_count = 0;
    let mut call_stack = Vec::new();
    let mut pending_recursive = Vec::new();
    let (root_wires, root_frame) = compile_frame(
        program,
        0,
        true,
        &builder,
        &field,
        &mut frames,
        &mut opcode_count,
        &mut call_stack,
        &mut pending_recursive,
        builder.add_constant(Word::ALL_ONE),
    )?;
    let circuit = builder.build();
    let public_positions: HashMap<_, _> = circuit
        .inout()
        .iter()
        .enumerate()
        .map(|(index, &wire)| {
            Ok((
                wire,
                u32::try_from(index).context("too many Binius public words")?,
            ))
        })
        .collect::<Result<_>>()?;
    let public_witnesses: Vec<_> = public.into_iter().collect();
    let noir_public_inputs = public_witnesses
        .iter()
        .map(|witness| {
            let value = root_wires
                .get(witness)
                .with_context(|| format!("public witness {witness} was not compiled"))?;
            resolve_public_biguint(value, &public_positions)
        })
        .collect::<Result<_>>()?;
    let calls = pending_recursive
        .into_iter()
        .map(|call| resolve_recursive_call(call, &public_positions))
        .collect::<Result<_>>()?;
    Ok(CompiledCircuit {
        circuit,
        frames,
        root_frame,
        public_witnesses,
        opcode_count,
        recursive: RecursiveMetadata {
            noir_public_inputs,
            calls,
        },
    })
}

fn resolve_recursive_call(
    call: PendingRecursiveCall,
    public_positions: &HashMap<Wire, u32>,
) -> Result<RecursiveCallSpec> {
    Ok(RecursiveCallSpec {
        active_word: *public_positions
            .get(&call.active_word)
            .context("recursive activity flag was not promoted to a public word")?,
        proof_type: call.proof_type,
        verification_key: resolve_pending_fields(call.verification_key, public_positions)?,
        proof: resolve_pending_fields(call.proof, public_positions)?,
        public_inputs: resolve_pending_fields(call.public_inputs, public_positions)?,
        key_hash: resolve_pending_field(call.key_hash, public_positions)?,
    })
}

fn resolve_pending_fields(
    fields: Vec<PendingFieldRef>,
    public_positions: &HashMap<Wire, u32>,
) -> Result<Vec<FieldRef>> {
    fields
        .into_iter()
        .map(|field| resolve_pending_field(field, public_positions))
        .collect()
}

fn resolve_pending_field(
    field: PendingFieldRef,
    public_positions: &HashMap<Wire, u32>,
) -> Result<FieldRef> {
    match field {
        PendingFieldRef::Constant(value) => Ok(FieldRef::constant(field_to_limbs(value))),
        PendingFieldRef::Public(value) => resolve_public_biguint(&value, public_positions),
    }
}

fn resolve_public_biguint(
    value: &BigUint,
    public_positions: &HashMap<Wire, u32>,
) -> Result<FieldRef> {
    let offsets: [u32; FIELD_LIMBS] = value
        .limbs
        .iter()
        .map(|wire| {
            public_positions
                .get(wire)
                .copied()
                .context("recursive field limb was not promoted to a public word")
        })
        .collect::<Result<Vec<_>>>()?
        .try_into()
        .map_err(|_| anyhow::anyhow!("BN254 field does not have {FIELD_LIMBS} limbs"))?;
    Ok(FieldRef::public(offsets))
}

#[allow(clippy::too_many_arguments)]
fn compile_frame(
    program: &Program<FieldElement>,
    function_index: u32,
    is_root: bool,
    builder: &CircuitBuilder,
    field: &PseudoMersennePrimeField,
    frames: &mut Vec<FrameWires>,
    opcode_count: &mut usize,
    call_stack: &mut Vec<u32>,
    pending_recursive: &mut Vec<PendingRecursiveCall>,
    active: binius_frontend::Wire,
) -> Result<(BTreeMap<Witness, BigUint>, usize)> {
    ensure!(
        !call_stack.contains(&function_index),
        "recursive ACIR call cycle involving function {function_index} is unsupported"
    );
    let acir = program
        .functions
        .get(function_index as usize)
        .with_context(|| format!("ACIR call references missing function {function_index}"))?;
    call_stack.push(function_index);
    let public: BTreeSet<_> = if is_root {
        acir.public_parameters
            .0
            .iter()
            .chain(&acir.return_values.0)
            .copied()
            .collect()
    } else {
        BTreeSet::new()
    };
    let all_witnesses = collect_and_validate(acir)?;
    let mut witness_wires = BTreeMap::new();
    for witness in all_witnesses {
        let value = if public.contains(&witness) {
            BigUint::new_inout(builder, FIELD_LIMBS)
        } else {
            BigUint::new_witness(builder, FIELD_LIMBS)
        };
        let is_canonical = biguint_lt(builder, &value, field.modulus());
        builder.assert_true(
            format!("f{function_index}:{witness} is canonical BN254"),
            is_canonical,
        );
        witness_wires.insert(witness, value);
    }

    let mut memories = HashMap::<BlockId, Vec<BigUint>>::new();
    let mut children = Vec::new();
    for (index, opcode) in acir.opcodes.iter().enumerate() {
        match opcode {
            Opcode::AssertZero(expression) => {
                compile_assert_zero(builder, field, &witness_wires, expression, index, active)?;
            }
            Opcode::BlackBoxFuncCall(call) => {
                compile_black_box(
                    builder,
                    &witness_wires,
                    call,
                    index,
                    active,
                    pending_recursive,
                )?;
            }
            // Brillig is executed by Nargo while constructing the witness. It is a hint rather than a
            // relation; any constrained outputs are checked by subsequent ACIR opcodes.
            Opcode::BrilligCall { .. } => {}
            Opcode::MemoryInit { block_id, init, .. } => {
                ensure!(
                    !memories.contains_key(block_id),
                    "opcode {index}: memory block {block_id} is initialized more than once"
                );
                let values = init
                    .iter()
                    .map(|witness_index| witness(&witness_wires, *witness_index, index).cloned())
                    .collect::<Result<Vec<_>>>()?;
                memories.insert(*block_id, values);
            }
            Opcode::MemoryOp { block_id, op } => {
                let memory = memories.get_mut(block_id).with_context(|| {
                    format!("opcode {index}: memory block {block_id} was not initialized")
                })?;
                compile_memory_op(builder, field, &witness_wires, memory, op, index, active)?;
            }
            Opcode::Call {
                id,
                inputs,
                outputs,
                predicate,
            } => {
                let call_active = if let Some(predicate) = predicate {
                    let value =
                        compile_expression(builder, field, &witness_wires, predicate, index)?;
                    let zero = field_constant(builder, FieldElement::zero());
                    let one = field_constant(builder, FieldElement::one());
                    let is_zero = biguint_eq(builder, &value, &zero);
                    let is_one = biguint_eq(builder, &value, &one);
                    builder.assert_eq_cond(
                        format!(
                            "ACIR call f{function_index}->{}, predicate is boolean",
                            id.0
                        ),
                        builder.bor(is_zero, is_one),
                        builder.add_constant(Word::MSB_ONE),
                        active,
                    );
                    builder.band(active, is_one)
                } else {
                    active
                };
                let callee_index = id.0;
                let (callee_wires, child_frame) = compile_frame(
                    program,
                    callee_index,
                    false,
                    builder,
                    field,
                    frames,
                    opcode_count,
                    call_stack,
                    pending_recursive,
                    call_active,
                )?;
                children.push(ChildFrame {
                    frame_index: child_frame,
                    predicate: predicate.clone(),
                });
                let callee = &program.functions[callee_index as usize];
                ensure!(
                    inputs.len()
                        == callee.private_parameters.len() + callee.public_parameters.0.len(),
                    "function {function_index} opcode {index}: call input count does not match function {callee_index}"
                );
                for (parameter_index, input) in inputs.iter().enumerate() {
                    assert_biguint_eq_when(
                        builder,
                        format!(
                            "ACIR call f{function_index}->{callee_index} input {parameter_index}"
                        ),
                        witness(&witness_wires, *input, index)?,
                        witness(&callee_wires, Witness(parameter_index as u32), index)?,
                        call_active,
                    );
                }
                ensure!(
                    outputs.len() == callee.return_values.0.len(),
                    "function {function_index} opcode {index}: call output count does not match function {callee_index}"
                );
                for (output, return_witness) in outputs.iter().zip(&callee.return_values.0) {
                    let zero = field_constant(builder, FieldElement::zero());
                    let expected = select_biguint(
                        builder,
                        call_active,
                        witness(&callee_wires, *return_witness, index)?,
                        &zero,
                    );
                    assert_biguint_eq_when(
                        builder,
                        format!("ACIR call f{function_index}->{callee_index} output"),
                        witness(&witness_wires, *output, index)?,
                        &expected,
                        active,
                    );
                }
            }
        }
    }
    *opcode_count += acir.opcodes.len();
    call_stack.pop();
    let frame_index = frames.len();
    frames.push(FrameWires {
        function_index,
        witnesses: witness_wires.clone(),
        children,
    });
    Ok((witness_wires, frame_index))
}

fn fill_frame(
    filler: &mut binius_frontend::WitnessFiller<'_>,
    frame: &FrameWires,
    witness_map: &WitnessMap<FieldElement>,
) -> Result<()> {
    for (witness, wires) in &frame.witnesses {
        let value = witness_map.get(witness).with_context(|| {
            format!(
                "function {} witness {witness} is missing from the Nargo witness file",
                frame.function_index
            )
        })?;
        wires.populate_limbs(filler, &field_to_limbs(*value));
    }
    Ok(())
}

fn fill_zero_frame(filler: &mut binius_frontend::WitnessFiller<'_>, frame: &FrameWires) {
    for wires in frame.witnesses.values() {
        wires.populate_limbs(filler, &[0; FIELD_LIMBS]);
    }
}

fn evaluate_expression(
    expression: &Expression<FieldElement>,
    witness_map: &WitnessMap<FieldElement>,
) -> Result<FieldElement> {
    let mut value = expression.q_c;
    for (coefficient, lhs, rhs) in &expression.mul_terms {
        let lhs = witness_map
            .get(lhs)
            .with_context(|| format!("call predicate is missing witness {lhs}"))?;
        let rhs = witness_map
            .get(rhs)
            .with_context(|| format!("call predicate is missing witness {rhs}"))?;
        value += *coefficient * *lhs * *rhs;
    }
    for (coefficient, witness) in &expression.linear_combinations {
        let witness = witness_map
            .get(witness)
            .with_context(|| format!("call predicate is missing witness {witness}"))?;
        value += *coefficient * *witness;
    }
    Ok(value)
}

fn collect_and_validate(acir: &AcirCircuit<FieldElement>) -> Result<BTreeSet<Witness>> {
    let mut witnesses: BTreeSet<_> = acir
        .private_parameters
        .iter()
        .chain(&acir.public_parameters.0)
        .chain(&acir.return_values.0)
        .copied()
        .collect();

    for (index, opcode) in acir.opcodes.iter().enumerate() {
        match opcode {
            Opcode::AssertZero(expression) => collect_expression(expression, &mut witnesses),
            Opcode::BlackBoxFuncCall(call) => {
                for input in call.get_inputs_vec() {
                    collect_input(&input, &mut witnesses);
                }
                witnesses.extend(call.get_outputs_vec());
                match call {
                    BlackBoxFuncCall::AES128Encrypt {
                        inputs, outputs, ..
                    } => {
                        let expected_outputs = inputs.len() + 16 - inputs.len() % 16;
                        ensure!(
                            outputs.len() == expected_outputs,
                            "opcode {index}: AES-128-CBC has {} outputs, expected {expected_outputs}",
                            outputs.len()
                        );
                    }
                    BlackBoxFuncCall::RANGE { num_bits, .. } => {
                        ensure!(
                            *num_bits <= FieldElement::max_num_bits(),
                            "opcode {index}: RANGE width {num_bits} exceeds the ACIR field width"
                        );
                    }
                    BlackBoxFuncCall::AND { num_bits, .. }
                    | BlackBoxFuncCall::XOR { num_bits, .. } => {
                        ensure!(
                            *num_bits <= FieldElement::max_num_bits(),
                            "opcode {index}: bit width {num_bits} exceeds the ACIR field width"
                        );
                    }
                    BlackBoxFuncCall::Blake2s { .. }
                    | BlackBoxFuncCall::Blake3 { .. }
                    | BlackBoxFuncCall::EcdsaSecp256k1 { .. }
                    | BlackBoxFuncCall::EcdsaSecp256r1 { .. }
                    | BlackBoxFuncCall::EmbeddedCurveAdd { .. }
                    | BlackBoxFuncCall::Keccakf1600 { .. }
                    | BlackBoxFuncCall::MultiScalarMul { .. }
                    | BlackBoxFuncCall::Poseidon2Permutation { .. }
                    | BlackBoxFuncCall::Sha256Compression { .. } => {}
                    BlackBoxFuncCall::RecursiveAggregation { proof_type, .. } => ensure!(
                        *proof_type == BINIUS_ZK_PROOF_TYPE,
                        "opcode {index}: recursive proof type 0x{proof_type:08x} is unsupported; expected Binius ZK type 0x{BINIUS_ZK_PROOF_TYPE:08x}"
                    ),
                }
            }
            Opcode::BrilligCall { .. } => {}
            Opcode::MemoryOp { op, .. } => {
                collect_expression(&op.operation, &mut witnesses);
                collect_expression(&op.index, &mut witnesses);
                collect_expression(&op.value, &mut witnesses);
            }
            Opcode::MemoryInit { init, .. } => {
                witnesses.extend(init.iter().copied());
            }
            Opcode::Call {
                inputs,
                outputs,
                predicate,
                ..
            } => {
                witnesses.extend(inputs.iter().copied());
                witnesses.extend(outputs.iter().copied());
                if let Some(predicate) = predicate {
                    collect_expression(predicate, &mut witnesses);
                }
            }
        }
    }
    Ok(witnesses)
}

fn collect_expression(expression: &Expression<FieldElement>, witnesses: &mut BTreeSet<Witness>) {
    for (_, lhs, rhs) in &expression.mul_terms {
        witnesses.insert(*lhs);
        witnesses.insert(*rhs);
    }
    for (_, witness) in &expression.linear_combinations {
        witnesses.insert(*witness);
    }
}

fn collect_input(input: &FunctionInput<FieldElement>, witnesses: &mut BTreeSet<Witness>) {
    if let FunctionInput::Witness(witness) = input {
        witnesses.insert(*witness);
    }
}

fn compile_assert_zero(
    builder: &CircuitBuilder,
    field: &PseudoMersennePrimeField,
    witnesses: &BTreeMap<Witness, BigUint>,
    expression: &Expression<FieldElement>,
    opcode_index: usize,
    active: binius_frontend::Wire,
) -> Result<()> {
    let accumulator = compile_expression(builder, field, witnesses, expression, opcode_index)?;
    let zero = field_constant(builder, FieldElement::zero());
    assert_biguint_eq_when(
        builder,
        format!("ACIR AssertZero opcode {opcode_index}"),
        &accumulator,
        &zero,
        active,
    );
    Ok(())
}

fn compile_expression(
    builder: &CircuitBuilder,
    field: &PseudoMersennePrimeField,
    witnesses: &BTreeMap<Witness, BigUint>,
    expression: &Expression<FieldElement>,
    opcode_index: usize,
) -> Result<BigUint> {
    let mut accumulator = field_constant(builder, expression.q_c);

    for (coefficient, lhs, rhs) in &expression.mul_terms {
        let lhs = witness(witnesses, *lhs, opcode_index)?;
        let rhs = witness(witnesses, *rhs, opcode_index)?;
        let product = field.mul(builder, lhs, rhs);
        accumulator = accumulate_term(builder, field, accumulator, &product, *coefficient);
    }
    for (coefficient, input) in &expression.linear_combinations {
        let input = witness(witnesses, *input, opcode_index)?;
        accumulator = accumulate_term(builder, field, accumulator, input, *coefficient);
    }

    Ok(accumulator)
}

fn compile_memory_op(
    builder: &CircuitBuilder,
    field: &PseudoMersennePrimeField,
    witnesses: &BTreeMap<Witness, BigUint>,
    memory: &mut [BigUint],
    op: &MemOp<FieldElement>,
    opcode_index: usize,
    active: binius_frontend::Wire,
) -> Result<()> {
    let operation = compile_expression(builder, field, witnesses, &op.operation, opcode_index)?;
    constrain_range(builder, &operation, 1, opcode_index);
    let write_active = builder.band(active, builder.shl(operation.limbs[0], 63));
    let read_active = builder.band(active, builder.bnot(write_active));
    let index = compile_expression(builder, field, witnesses, &op.index, opcode_index)?;
    let length = field_constant(builder, FieldElement::from(memory.len() as u128));
    builder.assert_eq_cond(
        format!("ACIR memory opcode {opcode_index} index is in bounds"),
        biguint_lt(builder, &index, &length),
        builder.add_constant(Word::MSB_ONE),
        active,
    );

    let selectors: Vec<_> = (0..memory.len())
        .map(|memory_index| {
            let constant = field_constant(builder, FieldElement::from(memory_index as u128));
            biguint_eq(builder, &index, &constant)
        })
        .collect();
    let value = compile_expression(builder, field, witnesses, &op.value, opcode_index)?;

    let zero = field_constant(builder, FieldElement::zero());
    let selected = memory
        .iter()
        .zip(&selectors)
        .fold(zero, |selected, (cell, &selector)| {
            select_biguint(builder, selector, cell, &selected)
        });
    assert_biguint_eq_when(
        builder,
        format!("ACIR memory read opcode {opcode_index}"),
        &value,
        &selected,
        read_active,
    );
    for (cell, selector) in memory.iter_mut().zip(selectors) {
        let replace = builder.band(write_active, selector);
        *cell = select_biguint(builder, replace, &value, cell);
    }
    Ok(())
}

fn biguint_eq(builder: &CircuitBuilder, lhs: &BigUint, rhs: &BigUint) -> binius_frontend::Wire {
    assert_eq!(lhs.limbs.len(), rhs.limbs.len());
    lhs.limbs
        .iter()
        .zip(&rhs.limbs)
        .map(|(&lhs, &rhs)| builder.icmp_eq(lhs, rhs))
        .reduce(|equal, limb_equal| builder.band(equal, limb_equal))
        .expect("BN254 values always have limbs")
}

fn assert_biguint_eq_when(
    builder: &CircuitBuilder,
    name: impl Into<String>,
    lhs: &BigUint,
    rhs: &BigUint,
    condition: binius_frontend::Wire,
) {
    assert_eq!(lhs.limbs.len(), rhs.limbs.len());
    let name = name.into();
    for (index, (&lhs, &rhs)) in lhs.limbs.iter().zip(&rhs.limbs).enumerate() {
        builder.assert_eq_cond(format!("{name}[{index}]"), lhs, rhs, condition);
    }
}

fn accumulate_term(
    builder: &CircuitBuilder,
    field: &PseudoMersennePrimeField,
    accumulator: BigUint,
    term: &BigUint,
    coefficient: FieldElement,
) -> BigUint {
    if coefficient.is_zero() {
        accumulator
    } else if coefficient.is_one() {
        field.add(builder, &accumulator, term)
    } else if coefficient == -FieldElement::one() {
        field.sub(builder, &accumulator, term)
    } else {
        let scaled = field.mul(builder, term, &field_constant(builder, coefficient));
        field.add(builder, &accumulator, &scaled)
    }
}

fn compile_black_box(
    builder: &CircuitBuilder,
    witnesses: &BTreeMap<Witness, BigUint>,
    call: &BlackBoxFuncCall<FieldElement>,
    opcode_index: usize,
    active: binius_frontend::Wire,
    pending_recursive: &mut Vec<PendingRecursiveCall>,
) -> Result<()> {
    match call {
        BlackBoxFuncCall::RANGE { input, num_bits } => {
            let input = function_input(builder, witnesses, input, opcode_index)?;
            constrain_range(builder, &input, *num_bits, opcode_index);
        }
        BlackBoxFuncCall::AES128Encrypt {
            inputs,
            iv,
            key,
            outputs,
        } => {
            let inputs = input_words(builder, witnesses, inputs, 8, opcode_index)?;
            let iv: [binius_frontend::Wire; 16] =
                input_words(builder, witnesses, iv.as_slice(), 8, opcode_index)?
                    .try_into()
                    .expect("AES IV has exactly 16 bytes");
            let key: [binius_frontend::Wire; 16] =
                input_words(builder, witnesses, key.as_slice(), 8, opcode_index)?
                    .try_into()
                    .expect("AES key has exactly 16 bytes");
            let ciphertext = aes128::encrypt_cbc(builder, &inputs, iv, key);
            for (output, result) in outputs.iter().zip(ciphertext) {
                constrain_output_word(
                    builder,
                    witnesses,
                    *output,
                    result,
                    8,
                    opcode_index,
                    "AES-128-CBC",
                    active,
                )?;
            }
        }
        BlackBoxFuncCall::AND {
            lhs,
            rhs,
            num_bits,
            output,
        } => {
            let lhs = function_input(builder, witnesses, lhs, opcode_index)?;
            let rhs = function_input(builder, witnesses, rhs, opcode_index)?;
            constrain_range(builder, &lhs, *num_bits, opcode_index);
            constrain_range(builder, &rhs, *num_bits, opcode_index);
            let result = BigUint {
                limbs: lhs
                    .limbs
                    .iter()
                    .zip(&rhs.limbs)
                    .map(|(&left, &right)| builder.band(left, right))
                    .collect(),
            };
            let output = witness(witnesses, *output, opcode_index)?;
            constrain_range(builder, output, *num_bits, opcode_index);
            assert_biguint_eq_when(
                builder,
                format!("ACIR AND opcode {opcode_index}"),
                &result,
                output,
                active,
            );
        }
        BlackBoxFuncCall::XOR {
            lhs,
            rhs,
            num_bits,
            output,
        } => {
            let lhs = function_input(builder, witnesses, lhs, opcode_index)?;
            let rhs = function_input(builder, witnesses, rhs, opcode_index)?;
            constrain_range(builder, &lhs, *num_bits, opcode_index);
            constrain_range(builder, &rhs, *num_bits, opcode_index);
            let result = BigUint {
                limbs: lhs
                    .limbs
                    .iter()
                    .zip(&rhs.limbs)
                    .map(|(&left, &right)| builder.bxor(left, right))
                    .collect(),
            };
            let output = witness(witnesses, *output, opcode_index)?;
            constrain_range(builder, output, *num_bits, opcode_index);
            assert_biguint_eq_when(
                builder,
                format!("ACIR XOR opcode {opcode_index}"),
                &result,
                output,
                active,
            );
        }
        BlackBoxFuncCall::Blake2s { inputs, outputs } => {
            let input_bytes = input_words(builder, witnesses, inputs, 8, opcode_index)?;
            let digest = blake2s_hash(builder, &input_bytes);
            constrain_digest_bytes(
                builder,
                witnesses,
                outputs,
                &digest,
                opcode_index,
                "BLAKE2s",
                active,
            )?;
        }
        BlackBoxFuncCall::EcdsaSecp256k1 {
            public_key_x,
            public_key_y,
            signature,
            hashed_message,
            predicate,
            output,
        } => {
            let public_key_x: [binius_frontend::Wire; 32] =
                input_words(builder, witnesses, public_key_x.as_slice(), 8, opcode_index)?
                    .try_into()
                    .expect("secp256k1 public-key x coordinate has 32 bytes");
            let public_key_y: [binius_frontend::Wire; 32] =
                input_words(builder, witnesses, public_key_y.as_slice(), 8, opcode_index)?
                    .try_into()
                    .expect("secp256k1 public-key y coordinate has 32 bytes");
            let signature: [binius_frontend::Wire; 64] =
                input_words(builder, witnesses, signature.as_slice(), 8, opcode_index)?
                    .try_into()
                    .expect("secp256k1 signature has 64 bytes");
            let hashed_message: [binius_frontend::Wire; 32] = input_words(
                builder,
                witnesses,
                hashed_message.as_slice(),
                8,
                opcode_index,
            )?
            .try_into()
            .expect("secp256k1 message hash has 32 bytes");
            let predicate = function_input(builder, witnesses, predicate, opcode_index)?;
            let predicate = effective_predicate(builder, &predicate, active);
            let valid = ecdsa::verify_secp256k1(
                builder,
                &public_key_x,
                &public_key_y,
                &signature,
                &hashed_message,
                &predicate,
            );
            let output_word = builder.select(
                valid,
                builder.add_constant_64(1),
                builder.add_constant(Word::ZERO),
            );
            constrain_output_word(
                builder,
                witnesses,
                *output,
                output_word,
                1,
                opcode_index,
                "ECDSA secp256k1 verification",
                active,
            )?;
        }
        BlackBoxFuncCall::EcdsaSecp256r1 {
            public_key_x,
            public_key_y,
            signature,
            hashed_message,
            predicate,
            output,
        } => {
            let public_key_x: [binius_frontend::Wire; 32] =
                input_words(builder, witnesses, public_key_x.as_slice(), 8, opcode_index)?
                    .try_into()
                    .expect("secp256r1 public-key x coordinate has 32 bytes");
            let public_key_y: [binius_frontend::Wire; 32] =
                input_words(builder, witnesses, public_key_y.as_slice(), 8, opcode_index)?
                    .try_into()
                    .expect("secp256r1 public-key y coordinate has 32 bytes");
            let signature: [binius_frontend::Wire; 64] =
                input_words(builder, witnesses, signature.as_slice(), 8, opcode_index)?
                    .try_into()
                    .expect("secp256r1 signature has 64 bytes");
            let hashed_message: [binius_frontend::Wire; 32] = input_words(
                builder,
                witnesses,
                hashed_message.as_slice(),
                8,
                opcode_index,
            )?
            .try_into()
            .expect("secp256r1 message hash has 32 bytes");
            let predicate = function_input(builder, witnesses, predicate, opcode_index)?;
            let predicate = effective_predicate(builder, &predicate, active);
            let valid = ecdsa::verify_secp256r1(
                builder,
                &public_key_x,
                &public_key_y,
                &signature,
                &hashed_message,
                &predicate,
            );
            let output_word = builder.select(
                valid,
                builder.add_constant_64(1),
                builder.add_constant(Word::ZERO),
            );
            constrain_output_word(
                builder,
                witnesses,
                *output,
                output_word,
                1,
                opcode_index,
                "ECDSA secp256r1 verification",
                active,
            )?;
        }
        BlackBoxFuncCall::EmbeddedCurveAdd {
            input1,
            input2,
            predicate,
            outputs,
        } => {
            let input1 = grumpkin_input_point(builder, witnesses, input1, opcode_index)?;
            let input2 = grumpkin_input_point(builder, witnesses, input2, opcode_index)?;
            let predicate = function_input(builder, witnesses, predicate, opcode_index)?;
            constrain_range(builder, &predicate, 1, opcode_index);
            let predicate = builder.band(active, builder.shl(predicate.limbs[0], 63));
            let field = bn254_field(builder);
            grumpkin::assert_on_curve(builder, &field, &input1, predicate);
            grumpkin::assert_on_curve(builder, &field, &input2, predicate);
            let zero = builder.add_constant(Word::ZERO);
            builder.assert_eq_cond(
                format!("ACIR embedded curve add opcode {opcode_index}: first input is finite"),
                input1.infinity,
                zero,
                predicate,
            );
            builder.assert_eq_cond(
                format!("ACIR embedded curve add opcode {opcode_index}: second input is finite"),
                input2.infinity,
                zero,
                predicate,
            );
            let sum = grumpkin::add(builder, &field, &input1, &input2);
            let result = grumpkin::select(builder, predicate, &sum, &grumpkin::identity(builder));
            constrain_grumpkin_output(builder, witnesses, outputs, &result, opcode_index, active)?;
        }
        BlackBoxFuncCall::MultiScalarMul {
            points,
            scalars,
            predicate,
            outputs,
        } => {
            ensure!(
                points.len().is_multiple_of(3) && scalars.len() * 3 == points.len() * 2,
                "opcode {opcode_index}: malformed embedded-curve MSM input lengths"
            );
            let predicate = function_input(builder, witnesses, predicate, opcode_index)?;
            constrain_range(builder, &predicate, 1, opcode_index);
            let predicate = builder.band(active, builder.shl(predicate.limbs[0], 63));
            let field = bn254_field(builder);
            let points = points
                .chunks_exact(3)
                .map(|point| {
                    let inputs: &[FunctionInput<FieldElement>; 3] = point.try_into().unwrap();
                    let point = grumpkin_input_point(builder, witnesses, inputs, opcode_index)?;
                    grumpkin::assert_on_curve(builder, &field, &point, predicate);
                    Ok(point)
                })
                .collect::<Result<Vec<_>>>()?;
            let zero = field_constant(builder, FieldElement::zero());
            let scalar_modulus = BigUint::new_constant(
                builder,
                &NativeBigUint::parse_bytes(
                    b"30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47",
                    16,
                )
                .expect("valid Grumpkin scalar modulus"),
            );
            let scalars = scalars
                .chunks_exact(2)
                .map(|limbs| {
                    let low = function_input(builder, witnesses, &limbs[0], opcode_index)?;
                    let high = function_input(builder, witnesses, &limbs[1], opcode_index)?;
                    let low = select_biguint(builder, predicate, &low, &zero);
                    let high = select_biguint(builder, predicate, &high, &zero);
                    constrain_range(builder, &low, 128, opcode_index);
                    constrain_range(builder, &high, 128, opcode_index);
                    let scalar = BigUint {
                        limbs: vec![low.limbs[0], low.limbs[1], high.limbs[0], high.limbs[1]],
                    };
                    builder.assert_true(
                        format!("ACIR embedded-curve MSM opcode {opcode_index}: scalar in range"),
                        biguint_lt(builder, &scalar, &scalar_modulus),
                    );
                    Ok(scalar)
                })
                .collect::<Result<Vec<_>>>()?;
            let product = grumpkin::msm(builder, &field, &points, &scalars);
            let result =
                grumpkin::select(builder, predicate, &product, &grumpkin::identity(builder));
            constrain_grumpkin_output(builder, witnesses, outputs, &result, opcode_index, active)?;
        }
        BlackBoxFuncCall::Blake3 { inputs, outputs } => {
            let input_bytes = input_words(builder, witnesses, inputs, 8, opcode_index)?;
            let message_words = pack_bytes_le_u32(builder, &input_bytes);
            let digest = blake3_fixed(builder, &message_words, inputs.len());
            constrain_digest_bytes(
                builder,
                witnesses,
                outputs,
                &digest,
                opcode_index,
                "BLAKE3",
                active,
            )?;
        }
        BlackBoxFuncCall::Keccakf1600 { inputs, outputs } => {
            let input_words = input_words(builder, witnesses, inputs.as_slice(), 64, opcode_index)?;
            let mut state: [binius_frontend::Wire; 25] = input_words
                .try_into()
                .expect("ACIR Keccak-f1600 has exactly 25 inputs");
            keccak_f1600(builder, &mut state);
            for (output, result) in outputs.iter().zip(state) {
                constrain_output_word(
                    builder,
                    witnesses,
                    *output,
                    result,
                    64,
                    opcode_index,
                    "Keccak-f1600",
                    active,
                )?;
            }
        }
        BlackBoxFuncCall::Sha256Compression {
            inputs,
            hash_values,
            outputs,
        } => {
            let message: [binius_frontend::Wire; 16] =
                input_words(builder, witnesses, inputs.as_slice(), 32, opcode_index)?
                    .try_into()
                    .expect("ACIR SHA-256 compression has exactly 16 message words");
            let state: [binius_frontend::Wire; 8] =
                input_words(builder, witnesses, hash_values.as_slice(), 32, opcode_index)?
                    .try_into()
                    .expect("ACIR SHA-256 compression has exactly 8 state words");
            let digest = sha256_compress(builder, Sha256State::new(state), message).0;
            for (output, result) in outputs.iter().zip(digest) {
                constrain_output_word(
                    builder,
                    witnesses,
                    *output,
                    result,
                    32,
                    opcode_index,
                    "SHA-256 compression",
                    active,
                )?;
            }
        }
        BlackBoxFuncCall::Poseidon2Permutation { inputs, outputs } => {
            ensure!(
                inputs.len() == 4 && outputs.len() == 4,
                "opcode {opcode_index}: Poseidon2 requires exactly four inputs and four outputs"
            );
            let state = [
                function_input(builder, witnesses, &inputs[0], opcode_index)?,
                function_input(builder, witnesses, &inputs[1], opcode_index)?,
                function_input(builder, witnesses, &inputs[2], opcode_index)?,
                function_input(builder, witnesses, &inputs[3], opcode_index)?,
            ];
            let result = poseidon2::permutation(builder, &bn254_field(builder), state);
            for (output, result) in outputs.iter().zip(result) {
                assert_biguint_eq_when(
                    builder,
                    format!("ACIR Poseidon2 opcode {opcode_index}"),
                    witness(witnesses, *output, opcode_index)?,
                    &result,
                    active,
                );
            }
        }
        BlackBoxFuncCall::RecursiveAggregation {
            verification_key,
            proof,
            public_inputs,
            key_hash,
            proof_type,
            predicate,
        } => {
            let predicate_value = function_input(builder, witnesses, predicate, opcode_index)?;
            constrain_range(builder, &predicate_value, 1, opcode_index);
            let enabled = builder.band(active, builder.shl(predicate_value.limbs[0], 63));
            // Recursive proof verification is deliberately completed by the final verifier. The
            // activity flag and every supplied field are promoted into the outer proof's public
            // statement so a prover cannot substitute different native-verification inputs.
            let active_word = expose_public_word(builder, enabled);
            pending_recursive.push(PendingRecursiveCall {
                active_word,
                proof_type: *proof_type,
                verification_key: expose_inputs(
                    builder,
                    witnesses,
                    verification_key,
                    opcode_index,
                )?,
                proof: expose_inputs(builder, witnesses, proof, opcode_index)?,
                public_inputs: expose_inputs(builder, witnesses, public_inputs, opcode_index)?,
                key_hash: expose_input(builder, witnesses, key_hash, opcode_index)?,
            });
        }
    }
    Ok(())
}

fn expose_inputs(
    builder: &CircuitBuilder,
    witnesses: &BTreeMap<Witness, BigUint>,
    inputs: &[FunctionInput<FieldElement>],
    opcode_index: usize,
) -> Result<Vec<PendingFieldRef>> {
    inputs
        .iter()
        .map(|input| expose_input(builder, witnesses, input, opcode_index))
        .collect()
}

fn expose_input(
    builder: &CircuitBuilder,
    witnesses: &BTreeMap<Witness, BigUint>,
    input: &FunctionInput<FieldElement>,
    opcode_index: usize,
) -> Result<PendingFieldRef> {
    match input {
        FunctionInput::Constant(value) => Ok(PendingFieldRef::Constant(*value)),
        FunctionInput::Witness(index) => {
            let value = witness(witnesses, *index, opcode_index)?;
            let limbs = value
                .limbs
                .iter()
                .map(|&limb| expose_public_word(builder, limb))
                .collect();
            Ok(PendingFieldRef::Public(BigUint { limbs }))
        }
    }
}

fn expose_public_word(builder: &CircuitBuilder, value: Wire) -> Wire {
    let exposed = builder.call_hint(PublicIdentityHint, &[], &[value])[0];
    builder.assert_eq("recursive public input binding", exposed, value);
    builder.mark_inout(exposed);
    exposed
}

fn input_words(
    builder: &CircuitBuilder,
    witnesses: &BTreeMap<Witness, BigUint>,
    inputs: &[FunctionInput<FieldElement>],
    num_bits: u32,
    opcode_index: usize,
) -> Result<Vec<binius_frontend::Wire>> {
    inputs
        .iter()
        .map(|input| {
            let value = function_input(builder, witnesses, input, opcode_index)?;
            constrain_range(builder, &value, num_bits, opcode_index);
            Ok(value.limbs[0])
        })
        .collect()
}

fn grumpkin_input_point(
    builder: &CircuitBuilder,
    witnesses: &BTreeMap<Witness, BigUint>,
    inputs: &[FunctionInput<FieldElement>; 3],
    opcode_index: usize,
) -> Result<grumpkin::AffinePoint> {
    let x = function_input(builder, witnesses, &inputs[0], opcode_index)?;
    let y = function_input(builder, witnesses, &inputs[1], opcode_index)?;
    let infinity = function_input(builder, witnesses, &inputs[2], opcode_index)?;
    constrain_range(builder, &infinity, 1, opcode_index);
    Ok(grumpkin::AffinePoint {
        x,
        y,
        infinity: builder.shl(infinity.limbs[0], 63),
    })
}

fn constrain_grumpkin_output(
    builder: &CircuitBuilder,
    witnesses: &BTreeMap<Witness, BigUint>,
    outputs: &(Witness, Witness, Witness),
    result: &grumpkin::AffinePoint,
    opcode_index: usize,
    active: binius_frontend::Wire,
) -> Result<()> {
    assert_biguint_eq_when(
        builder,
        format!("ACIR embedded-curve opcode {opcode_index}: output x"),
        witness(witnesses, outputs.0, opcode_index)?,
        &result.x,
        active,
    );
    assert_biguint_eq_when(
        builder,
        format!("ACIR embedded-curve opcode {opcode_index}: output y"),
        witness(witnesses, outputs.1, opcode_index)?,
        &result.y,
        active,
    );
    let infinity = builder.select(
        result.infinity,
        builder.add_constant_64(1),
        builder.add_constant(Word::ZERO),
    );
    constrain_output_word(
        builder,
        witnesses,
        outputs.2,
        infinity,
        1,
        opcode_index,
        "embedded curve infinity flag",
        active,
    )
}

#[allow(clippy::too_many_arguments)]
fn constrain_output_word(
    builder: &CircuitBuilder,
    witnesses: &BTreeMap<Witness, BigUint>,
    output: Witness,
    result: binius_frontend::Wire,
    num_bits: u32,
    opcode_index: usize,
    operation: &str,
    active: binius_frontend::Wire,
) -> Result<()> {
    let output = witness(witnesses, output, opcode_index)?;
    constrain_range(builder, output, num_bits, opcode_index);
    builder.assert_eq_cond(
        format!("ACIR {operation} opcode {opcode_index}"),
        output.limbs[0],
        result,
        active,
    );
    Ok(())
}

fn pack_bytes_le_u32(
    builder: &CircuitBuilder,
    input_bytes: &[binius_frontend::Wire],
) -> Vec<binius_frontend::Wire> {
    let zero = builder.add_constant(Word::ZERO);
    input_bytes
        .chunks(4)
        .map(|chunk| {
            chunk
                .iter()
                .copied()
                .enumerate()
                .fold(zero, |packed, (index, byte)| {
                    builder.bxor(packed, builder.shl(byte, (index * 8) as u32))
                })
        })
        .collect()
}

fn constrain_digest_bytes(
    builder: &CircuitBuilder,
    witnesses: &BTreeMap<Witness, BigUint>,
    outputs: &[Witness; 32],
    digest: &[binius_frontend::Wire; 8],
    opcode_index: usize,
    operation: &str,
    active: binius_frontend::Wire,
) -> Result<()> {
    let byte_mask = builder.add_constant_64(0xff);
    for (index, output) in outputs.iter().enumerate() {
        let shifted = builder.shr(digest[index / 4], ((index % 4) * 8) as u32);
        let byte = builder.band(shifted, byte_mask);
        constrain_output_word(
            builder,
            witnesses,
            *output,
            byte,
            8,
            opcode_index,
            operation,
            active,
        )?;
    }
    Ok(())
}

fn blake2s_hash(
    builder: &CircuitBuilder,
    input_bytes: &[binius_frontend::Wire],
) -> [binius_frontend::Wire; 8] {
    const IV: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let mut state: [binius_frontend::Wire; 8] = std::array::from_fn(|index| {
        let value = if index == 0 {
            IV[index] ^ 0x0101_0020
        } else {
            IV[index]
        };
        builder.add_constant_64(value as u64)
    });
    let zero = builder.add_constant(Word::ZERO);
    let num_blocks = input_bytes.len().div_ceil(64).max(1);
    for block_index in 0..num_blocks {
        let block_start = block_index * 64;
        let message: [binius_frontend::Wire; 16] = std::array::from_fn(|word_index| {
            (0..4).fold(zero, |packed, byte_index| {
                let absolute_index = block_start + word_index * 4 + byte_index;
                match input_bytes.get(absolute_index) {
                    Some(&byte) => builder.bxor(packed, builder.shl(byte, (byte_index * 8) as u32)),
                    None => packed,
                }
            })
        });
        let consumed = ((block_index + 1) * 64).min(input_bytes.len());
        let counter = builder.add_constant_64(consumed as u64);
        let final_flag = builder.add_constant_64(if block_index + 1 == num_blocks {
            u32::MAX as u64
        } else {
            0
        });
        state = blake2s_compress(builder, state, message, counter, zero, final_flag);
    }
    state
}

fn constrain_range(builder: &CircuitBuilder, value: &BigUint, num_bits: u32, opcode_index: usize) {
    let full_limbs = (num_bits / 64) as usize;
    let partial_bits = num_bits % 64;
    for (index, &limb) in value.limbs.iter().enumerate() {
        if index < full_limbs {
            continue;
        }
        if index == full_limbs && partial_bits != 0 {
            builder.assert_zero(
                format!("ACIR range opcode {opcode_index}, limb {index}"),
                builder.shr(limb, partial_bits),
            );
        } else {
            builder.assert_zero(
                format!("ACIR range opcode {opcode_index}, limb {index}"),
                limb,
            );
        }
    }
}

fn function_input(
    builder: &CircuitBuilder,
    witnesses: &BTreeMap<Witness, BigUint>,
    input: &FunctionInput<FieldElement>,
    opcode_index: usize,
) -> Result<BigUint> {
    match input {
        FunctionInput::Constant(value) => Ok(field_constant(builder, *value)),
        FunctionInput::Witness(index) => Ok(witness(witnesses, *index, opcode_index)?.clone()),
    }
}

fn effective_predicate(
    builder: &CircuitBuilder,
    predicate: &BigUint,
    frame_active: binius_frontend::Wire,
) -> BigUint {
    let zero = field_constant(builder, FieldElement::zero());
    let one = field_constant(builder, FieldElement::one());
    let is_one = biguint_eq(builder, predicate, &one);
    select_biguint(builder, builder.band(frame_active, is_one), &one, &zero)
}

fn witness(
    witnesses: &BTreeMap<Witness, BigUint>,
    index: Witness,
    opcode_index: usize,
) -> Result<&BigUint> {
    witnesses
        .get(&index)
        .with_context(|| format!("opcode {opcode_index} references unknown witness {index}"))
}

fn bn254_field(builder: &CircuitBuilder) -> PseudoMersennePrimeField {
    let modulus = NativeBigUint::from_bytes_le(&FieldElement::modulus().to_bytes_le());
    let subtrahend = (NativeBigUint::from(1u8) << 256usize) - modulus;
    let limbs: Vec<u64> = subtrahend.iter_u64_digits().collect();
    PseudoMersennePrimeField::new(builder, 256, &limbs)
}

fn field_constant(builder: &CircuitBuilder, value: FieldElement) -> BigUint {
    BigUint::new_constant(builder, &NativeBigUint::from_bytes_le(&value.to_le_bytes()))
        .zero_extend(builder, FIELD_LIMBS)
}

pub fn field_to_limbs(value: FieldElement) -> [u64; FIELD_LIMBS] {
    let mut bytes = value.to_le_bytes();
    bytes.resize(FIELD_LIMBS * 8, 0);
    std::array::from_fn(|index| {
        u64::from_le_bytes(
            bytes[index * 8..(index + 1) * 8]
                .try_into()
                .expect("each limb is eight bytes"),
        )
    })
}

pub fn words_from_u64(values: &[u64]) -> Vec<Word> {
    values.iter().copied().map(Word::from_u64).collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use acir::{
        AcirField, FieldElement,
        circuit::{
            Circuit as AcirCircuit, Opcode, PublicInputs,
            opcodes::{BlackBoxFuncCall, FunctionInput},
        },
        native_types::{Expression, Witness, WitnessMap},
    };

    use crate::recursive::BINIUS_ZK_PROOF_TYPE;

    use super::compile;

    fn arithmetic_circuit() -> AcirCircuit<FieldElement> {
        let x = Witness(1);
        let expected = Witness(2);
        AcirCircuit {
            current_witness_index: 2,
            function_name: "main".to_owned(),
            opcodes: vec![Opcode::AssertZero(Expression {
                mul_terms: vec![(FieldElement::one(), x, x)],
                linear_combinations: vec![(-FieldElement::one(), expected)],
                q_c: FieldElement::from(5_u128),
            })],
            private_parameters: BTreeSet::from([x]),
            public_parameters: PublicInputs(BTreeSet::from([expected])),
            return_values: PublicInputs::default(),
            assert_messages: Vec::new(),
        }
    }

    fn arithmetic_witness(expected: u128) -> WitnessMap<FieldElement> {
        let mut witness = WitnessMap::new();
        witness.insert(Witness(1), FieldElement::from(3_u128));
        witness.insert(Witness(2), FieldElement::from(expected));
        witness
    }

    #[test]
    fn translated_arithmetic_accepts_a_valid_witness() {
        let compiled = compile(&arithmetic_circuit()).unwrap();
        compiled.populate(&arithmetic_witness(14)).unwrap();
    }

    #[test]
    fn translated_arithmetic_rejects_an_invalid_witness() {
        let compiled = compile(&arithmetic_circuit()).unwrap();
        assert!(compiled.populate(&arithmetic_witness(15)).is_err());
    }

    fn recursive_circuit(predicate: FieldElement) -> AcirCircuit<FieldElement> {
        AcirCircuit {
            current_witness_index: 0,
            function_name: "main".to_owned(),
            opcodes: vec![Opcode::BlackBoxFuncCall(
                BlackBoxFuncCall::RecursiveAggregation {
                    verification_key: vec![],
                    proof: vec![],
                    public_inputs: vec![],
                    key_hash: FunctionInput::Constant(FieldElement::zero()),
                    proof_type: BINIUS_ZK_PROOF_TYPE,
                    predicate: FunctionInput::Constant(predicate),
                },
            )],
            private_parameters: BTreeSet::new(),
            public_parameters: PublicInputs::default(),
            return_values: PublicInputs::default(),
            assert_messages: Vec::new(),
        }
    }

    #[test]
    fn disabled_recursive_aggregation_is_skipped_and_bound() {
        let compiled = compile(&recursive_circuit(FieldElement::zero())).unwrap();
        let values = compiled.populate(&WitnessMap::new()).unwrap();
        let public_words: Vec<_> = values.inout().iter().map(|word| word.as_u64()).collect();
        assert_eq!(public_words, vec![0]);
        compiled.verify_recursive_calls(&public_words).unwrap();
    }

    #[test]
    fn enabled_recursive_aggregation_is_checked_by_final_verifier() {
        let compiled = compile(&recursive_circuit(FieldElement::one())).unwrap();
        let values = compiled.populate(&WitnessMap::new()).unwrap();
        let public_words: Vec<_> = values.inout().iter().map(|word| word.as_u64()).collect();
        assert!(compiled.verify_recursive_calls(&public_words).is_err());
    }
}
