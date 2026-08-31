use std::collections::{BTreeMap, BTreeSet};

use acir::{
    AcirField, FieldElement,
    circuit::{
        Circuit as AcirCircuit, Opcode,
        opcodes::{BlackBoxFuncCall, FunctionInput},
    },
    native_types::{Expression, Witness, WitnessMap},
};
use anyhow::{Context, Result, bail, ensure};
use binius_circuits::bignum::{
    BigUint, PseudoMersennePrimeField, assert_eq as assert_biguint_eq, biguint_lt,
};
use binius_core::{constraint_system::ValueVec, word::Word};
use binius_frontend::{Circuit, CircuitBuilder};
use num_bigint::BigUint as NativeBigUint;

pub const FIELD_LIMBS: usize = 4;

pub struct CompiledCircuit {
    pub circuit: Circuit,
    witness_wires: BTreeMap<Witness, BigUint>,
    pub public_witnesses: Vec<Witness>,
    pub opcode_count: usize,
}

impl CompiledCircuit {
    pub fn populate(&self, witness_map: &WitnessMap<FieldElement>) -> Result<ValueVec> {
        let mut filler = self.circuit.new_witness_filler();
        for (witness, wires) in &self.witness_wires {
            let value = witness_map.get(witness).with_context(|| {
                format!("witness {witness} is missing from the Nargo witness file")
            })?;
            wires.populate_limbs(&mut filler, &field_to_limbs(*value));
        }
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
        self.public_witnesses.len() * FIELD_LIMBS
    }
}

pub fn compile(acir: &AcirCircuit<FieldElement>) -> Result<CompiledCircuit> {
    let public: BTreeSet<_> = acir
        .public_parameters
        .0
        .iter()
        .chain(&acir.return_values.0)
        .copied()
        .collect();
    let all_witnesses = collect_and_validate(acir)?;

    let builder = CircuitBuilder::new();
    let field = bn254_field(&builder);
    let mut witness_wires = BTreeMap::new();
    for witness in all_witnesses {
        let value = if public.contains(&witness) {
            BigUint::new_inout(&builder, FIELD_LIMBS)
        } else {
            BigUint::new_witness(&builder, FIELD_LIMBS)
        };
        let is_canonical = biguint_lt(&builder, &value, field.modulus());
        builder.assert_true(
            format!("{witness} is a canonical BN254 field element"),
            is_canonical,
        );
        witness_wires.insert(witness, value);
    }

    for (index, opcode) in acir.opcodes.iter().enumerate() {
        match opcode {
            Opcode::AssertZero(expression) => {
                compile_assert_zero(&builder, &field, &witness_wires, expression, index)?;
            }
            Opcode::BlackBoxFuncCall(call) => {
                compile_black_box(&builder, &witness_wires, call, index)?;
            }
            // Brillig is executed by Nargo while constructing the witness. It is a hint rather than a
            // relation; any constrained outputs are checked by subsequent ACIR opcodes.
            Opcode::BrilligCall { .. } => {}
            _ => unreachable!("collect_and_validate rejected unsupported opcode"),
        }
    }

    let public_witnesses = public.into_iter().collect();
    Ok(CompiledCircuit {
        circuit: builder.build(),
        witness_wires,
        public_witnesses,
        opcode_count: acir.opcodes.len(),
    })
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
            Opcode::BlackBoxFuncCall(call) => match call {
                BlackBoxFuncCall::RANGE { input, num_bits } => {
                    ensure!(
                        *num_bits <= FieldElement::max_num_bits(),
                        "opcode {index}: RANGE width {num_bits} exceeds the ACIR field width"
                    );
                    collect_input(input, &mut witnesses);
                }
                BlackBoxFuncCall::AND {
                    lhs,
                    rhs,
                    num_bits,
                    output,
                }
                | BlackBoxFuncCall::XOR {
                    lhs,
                    rhs,
                    num_bits,
                    output,
                } => {
                    ensure!(
                        *num_bits <= FieldElement::max_num_bits(),
                        "opcode {index}: bit width {num_bits} exceeds the ACIR field width"
                    );
                    collect_input(lhs, &mut witnesses);
                    collect_input(rhs, &mut witnesses);
                    witnesses.insert(*output);
                }
                other => bail!(
                    "opcode {index}: unsupported ACIR black-box function {}",
                    other.name()
                ),
            },
            Opcode::BrilligCall { .. } => {}
            Opcode::MemoryOp { .. } => {
                bail!("opcode {index}: ACIR memory operations are not yet supported")
            }
            Opcode::MemoryInit { .. } => {
                bail!("opcode {index}: ACIR memory blocks are not yet supported")
            }
            Opcode::Call { .. } => {
                bail!("opcode {index}: multi-function ACIR calls are not yet supported")
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
) -> Result<()> {
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

    let zero = field_constant(builder, FieldElement::zero());
    assert_biguint_eq(
        builder,
        format!("ACIR AssertZero opcode {opcode_index}"),
        &accumulator,
        &zero,
    );
    Ok(())
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
) -> Result<()> {
    match call {
        BlackBoxFuncCall::RANGE { input, num_bits } => {
            let input = function_input(builder, witnesses, input, opcode_index)?;
            constrain_range(builder, &input, *num_bits, opcode_index);
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
            assert_biguint_eq(
                builder,
                format!("ACIR AND opcode {opcode_index}"),
                &result,
                output,
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
            assert_biguint_eq(
                builder,
                format!("ACIR XOR opcode {opcode_index}"),
                &result,
                output,
            );
        }
        _ => unreachable!("collect_and_validate rejected unsupported black-box function"),
    }
    Ok(())
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
        circuit::{Circuit as AcirCircuit, Opcode, PublicInputs},
        native_types::{Expression, Witness, WitnessMap},
    };

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
}
