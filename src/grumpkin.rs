use acir::{AcirField, FieldElement};
use binius_circuits::bignum::{
    BigUint, PseudoMersennePrimeField, biguint_eq, select as select_biguint,
};
use binius_core::word::Word;
use binius_frontend::{CircuitBuilder, Wire};
use num_bigint::BigUint as NativeBigUint;

#[derive(Clone)]
pub(crate) struct AffinePoint {
    pub x: BigUint,
    pub y: BigUint,
    /// MSB-boolean.
    pub infinity: Wire,
}

#[derive(Clone)]
struct ProjectivePoint {
    x: BigUint,
    y: BigUint,
    z: BigUint,
}

pub(crate) fn assert_on_curve(
    builder: &CircuitBuilder,
    field: &PseudoMersennePrimeField,
    point: &AffinePoint,
    enabled: Wire,
) {
    let curve_a = constant(builder, FieldElement::zero());
    let curve_b = constant(builder, -FieldElement::from(17_u128));
    assert_on_curve_params(builder, field, point, &curve_a, &curve_b, enabled);
}

pub(crate) fn assert_on_curve_params(
    builder: &CircuitBuilder,
    field: &PseudoMersennePrimeField,
    point: &AffinePoint,
    curve_a: &BigUint,
    curve_b: &BigUint,
    enabled: Wire,
) {
    let check = builder.band(enabled, builder.bnot(point.infinity));
    let x_squared = field.square(builder, &point.x);
    let x_cubed = field.mul(builder, &x_squared, &point.x);
    let ax = field.mul(builder, curve_a, &point.x);
    let rhs = field.add(builder, &field.add(builder, &x_cubed, &ax), curve_b);
    let y_squared = field.square(builder, &point.y);
    assert_biguint_eq_cond(
        builder,
        "Grumpkin point is on curve",
        &y_squared,
        &rhs,
        check,
    );
}

pub(crate) fn add(
    builder: &CircuitBuilder,
    field: &PseudoMersennePrimeField,
    lhs: &AffinePoint,
    rhs: &AffinePoint,
) -> AffinePoint {
    let curve_a = constant(builder, FieldElement::zero());
    add_with_a(builder, field, lhs, rhs, &curve_a)
}

pub(crate) fn add_with_a(
    builder: &CircuitBuilder,
    field: &PseudoMersennePrimeField,
    lhs: &AffinePoint,
    rhs: &AffinePoint,
    curve_a: &BigUint,
) -> AffinePoint {
    let lhs = to_projective(builder, lhs);
    let rhs = to_projective(builder, rhs);
    to_affine(
        builder,
        field,
        &projective_add(builder, field, &lhs, &rhs, curve_a),
    )
}

pub(crate) fn msm(
    builder: &CircuitBuilder,
    field: &PseudoMersennePrimeField,
    points: &[AffinePoint],
    scalars: &[BigUint],
) -> AffinePoint {
    let curve_a = constant(builder, FieldElement::zero());
    msm_with_a(builder, field, points, scalars, &curve_a)
}

pub(crate) fn msm_with_a(
    builder: &CircuitBuilder,
    field: &PseudoMersennePrimeField,
    points: &[AffinePoint],
    scalars: &[BigUint],
    curve_a: &BigUint,
) -> AffinePoint {
    let mut accumulator = projective_identity(builder);
    for (point, scalar) in points.iter().zip(scalars) {
        let product = scalar_mul_windowed(
            builder,
            field,
            &to_projective(builder, point),
            scalar,
            curve_a,
        );
        accumulator = projective_add(builder, field, &accumulator, &product, curve_a);
    }
    to_affine(builder, field, &accumulator)
}

pub(crate) fn select(
    builder: &CircuitBuilder,
    condition: Wire,
    when_true: &AffinePoint,
    when_false: &AffinePoint,
) -> AffinePoint {
    AffinePoint {
        x: select_biguint(builder, condition, &when_true.x, &when_false.x),
        y: select_biguint(builder, condition, &when_true.y, &when_false.y),
        infinity: builder.select(condition, when_true.infinity, when_false.infinity),
    }
}

pub(crate) fn identity(builder: &CircuitBuilder) -> AffinePoint {
    let zero = constant(builder, FieldElement::zero());
    AffinePoint {
        x: zero.clone(),
        y: zero,
        infinity: builder.add_constant(Word::ALL_ONE),
    }
}

fn scalar_mul_windowed(
    builder: &CircuitBuilder,
    field: &PseudoMersennePrimeField,
    point: &ProjectivePoint,
    scalar: &BigUint,
    curve_a: &BigUint,
) -> ProjectivePoint {
    let mut table = Vec::with_capacity(16);
    table.push(projective_identity(builder));
    table.push(point.clone());
    for index in 2..16 {
        let next = projective_add(builder, field, &table[index - 1], point, curve_a);
        table.push(next);
    }

    let mask = builder.add_constant_64(0xf);
    let mut accumulator = projective_identity(builder);
    for window in (0..64).rev() {
        for _ in 0..4 {
            accumulator = projective_double(builder, field, &accumulator, curve_a);
        }
        let limb = scalar.limbs[window / 16];
        let nibble = builder.band(builder.shr(limb, ((window % 16) * 4) as u32), mask);
        let mut selected = table[0].clone();
        for value in 1..16_u64 {
            let equal = builder.icmp_eq(nibble, builder.add_constant_64(value));
            selected = select_projective(builder, equal, &table[value as usize], &selected);
        }
        accumulator = projective_add(builder, field, &accumulator, &selected, curve_a);
    }
    accumulator
}

fn projective_double(
    builder: &CircuitBuilder,
    field: &PseudoMersennePrimeField,
    point: &ProjectivePoint,
    curve_a: &BigUint,
) -> ProjectivePoint {
    // Standard Jacobian doubling formula for y^2 = x^3 + ax + b.
    let a = field.square(builder, &point.x);
    let b = field.square(builder, &point.y);
    let c = field.square(builder, &b);
    let x_plus_b = field.add(builder, &point.x, &b);
    let mut d = field.sub(
        builder,
        &field.sub(builder, &field.square(builder, &x_plus_b), &a),
        &c,
    );
    d = field.add(builder, &d, &d);
    let z_squared = field.square(builder, &point.z);
    let z_fourth = field.square(builder, &z_squared);
    let ax_z_fourth = field.mul(builder, curve_a, &z_fourth);
    let e = field.add(
        builder,
        &field.add(builder, &field.add(builder, &a, &a), &a),
        &ax_z_fourth,
    );
    let f = field.square(builder, &e);
    let x = field.sub(builder, &f, &field.add(builder, &d, &d));
    let eight_c = triple_double(builder, field, &c);
    let y = field.sub(
        builder,
        &field.mul(builder, &e, &field.sub(builder, &d, &x)),
        &eight_c,
    );
    let z = field.mul(builder, &field.add(builder, &point.y, &point.y), &point.z);
    ProjectivePoint { x, y, z }
}

fn projective_add(
    builder: &CircuitBuilder,
    field: &PseudoMersennePrimeField,
    lhs: &ProjectivePoint,
    rhs: &ProjectivePoint,
    curve_a: &BigUint,
) -> ProjectivePoint {
    // Formula add-2007-bl, with explicit selections for infinity and doubling.
    let z1z1 = field.square(builder, &lhs.z);
    let z2z2 = field.square(builder, &rhs.z);
    let u1 = field.mul(builder, &lhs.x, &z2z2);
    let u2 = field.mul(builder, &rhs.x, &z1z1);
    let s1 = field.mul(builder, &lhs.y, &field.mul(builder, &rhs.z, &z2z2));
    let s2 = field.mul(builder, &rhs.y, &field.mul(builder, &lhs.z, &z1z1));
    let h = field.sub(builder, &u2, &u1);
    let two_h = field.add(builder, &h, &h);
    let i = field.square(builder, &two_h);
    let j = field.mul(builder, &h, &i);
    let r = field.add(
        builder,
        &field.sub(builder, &s2, &s1),
        &field.sub(builder, &s2, &s1),
    );
    let v = field.mul(builder, &u1, &i);
    let x = field.sub(
        builder,
        &field.sub(builder, &field.square(builder, &r), &j),
        &field.add(builder, &v, &v),
    );
    let y = field.sub(
        builder,
        &field.mul(builder, &r, &field.sub(builder, &v, &x)),
        &field.add(
            builder,
            &field.mul(builder, &s1, &j),
            &field.mul(builder, &s1, &j),
        ),
    );
    let z_sum = field.add(builder, &lhs.z, &rhs.z);
    let z = field.mul(
        builder,
        &field.sub(
            builder,
            &field.sub(builder, &field.square(builder, &z_sum), &z1z1),
            &z2z2,
        ),
        &h,
    );
    let generic = ProjectivePoint { x, y, z };

    let same = builder.band(biguint_eq(builder, &u1, &u2), biguint_eq(builder, &s1, &s2));
    let doubled = projective_double(builder, field, lhs, curve_a);
    let result = select_projective(builder, same, &doubled, &generic);
    let lhs_infinity = lhs.z.is_zero(builder);
    let rhs_infinity = rhs.z.is_zero(builder);
    let result = select_projective(builder, lhs_infinity, rhs, &result);
    select_projective(builder, rhs_infinity, lhs, &result)
}

fn to_projective(builder: &CircuitBuilder, point: &AffinePoint) -> ProjectivePoint {
    let zero = constant(builder, FieldElement::zero());
    let one = constant(builder, FieldElement::one());
    ProjectivePoint {
        x: select_biguint(builder, point.infinity, &zero, &point.x),
        y: select_biguint(builder, point.infinity, &one, &point.y),
        z: select_biguint(builder, point.infinity, &zero, &one),
    }
}

fn to_affine(
    builder: &CircuitBuilder,
    field: &PseudoMersennePrimeField,
    point: &ProjectivePoint,
) -> AffinePoint {
    let infinity = point.z.is_zero(builder);
    let inverse = field.inverse(builder, &point.z, builder.bnot(infinity));
    let inverse_squared = field.square(builder, &inverse);
    let inverse_cubed = field.mul(builder, &inverse_squared, &inverse);
    let x = field.mul(builder, &point.x, &inverse_squared);
    let y = field.mul(builder, &point.y, &inverse_cubed);
    let zero = constant(builder, FieldElement::zero());
    AffinePoint {
        x: select_biguint(builder, infinity, &zero, &x),
        y: select_biguint(builder, infinity, &zero, &y),
        infinity,
    }
}

fn projective_identity(builder: &CircuitBuilder) -> ProjectivePoint {
    ProjectivePoint {
        x: constant(builder, FieldElement::zero()),
        y: constant(builder, FieldElement::one()),
        z: constant(builder, FieldElement::zero()),
    }
}

fn select_projective(
    builder: &CircuitBuilder,
    condition: Wire,
    when_true: &ProjectivePoint,
    when_false: &ProjectivePoint,
) -> ProjectivePoint {
    ProjectivePoint {
        x: select_biguint(builder, condition, &when_true.x, &when_false.x),
        y: select_biguint(builder, condition, &when_true.y, &when_false.y),
        z: select_biguint(builder, condition, &when_true.z, &when_false.z),
    }
}

fn triple_double(
    builder: &CircuitBuilder,
    field: &PseudoMersennePrimeField,
    value: &BigUint,
) -> BigUint {
    let twice = field.add(builder, value, value);
    let four = field.add(builder, &twice, &twice);
    field.add(builder, &four, &four)
}

fn constant(builder: &CircuitBuilder, value: FieldElement) -> BigUint {
    BigUint::new_constant(builder, &NativeBigUint::from_bytes_le(&value.to_le_bytes()))
        .zero_extend(builder, 4)
}

fn assert_biguint_eq_cond(
    builder: &CircuitBuilder,
    name: &str,
    lhs: &BigUint,
    rhs: &BigUint,
    condition: Wire,
) {
    assert_eq!(lhs.limbs.len(), rhs.limbs.len());
    for (index, (&lhs, &rhs)) in lhs.limbs.iter().zip(&rhs.limbs).enumerate() {
        builder.assert_eq_cond(format!("{name}[{index}]"), lhs, rhs, condition);
    }
}
