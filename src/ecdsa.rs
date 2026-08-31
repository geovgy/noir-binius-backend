use binius_circuits::{
    bignum::{BigUint, PseudoMersennePrimeField, biguint_eq, biguint_lt},
    ecdsa::bitcoin_verify,
    secp256k1::{Secp256k1, Secp256k1Affine, select as select_point},
};
use binius_core::word::Word;
use binius_frontend::{CircuitBuilder, Wire};
use num_bigint::BigUint as NativeBigUint;

use crate::grumpkin::{self, AffinePoint};

pub(crate) fn verify_secp256k1(
    builder: &CircuitBuilder,
    public_key_x: &[Wire; 32],
    public_key_y: &[Wire; 32],
    signature: &[Wire; 64],
    hashed_message: &[Wire; 32],
    predicate_value: &BigUint,
) -> Wire {
    let zero_word = builder.add_constant(Word::ZERO);
    let one = BigUint::new_constant(builder, &NativeBigUint::from(1_u8)).zero_extend(builder, 4);
    let predicate = biguint_eq(builder, predicate_value, &one);

    let public_key = Secp256k1Affine {
        x: pack_be_bytes(builder, public_key_x),
        y: pack_be_bytes(builder, public_key_y),
        is_point_at_infinity: zero_word,
    };
    // A disabled ACIR opcode returns true even if the supplied key is malformed. Substitute the
    // generator while disabled so the Binius gadget's on-curve assertion has the same semantics.
    let public_key = select_point(
        builder,
        predicate,
        &public_key,
        &Secp256k1Affine::generator(builder),
    );

    let r_original = pack_be_bytes(builder, signature[..32].try_into().unwrap());
    let s = pack_be_bytes(builder, signature[32..].try_into().unwrap());
    let z_original = pack_be_bytes(builder, hashed_message);
    let curve = Secp256k1::new(builder);
    let scalar_field = curve.f_scalar();
    // A 256-bit digest (and malformed r) can exceed the group order. Multiplication by one is
    // the cheapest available constrained reduction in the Binius pseudo-Mersenne field gadget.
    let z = scalar_field.mul(builder, &z_original, &one);
    let r = scalar_field.mul(builder, &r_original, &one);
    let signature_valid = bitcoin_verify(builder, public_key, &z, &r, &s);

    let r_in_range = biguint_lt(builder, &r_original, scalar_field.modulus());
    let half_order_plus_one = BigUint::new_constant(
        builder,
        &NativeBigUint::parse_bytes(
            b"7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1",
            16,
        )
        .expect("valid secp256k1 half-order constant"),
    );
    let normalized_s = biguint_lt(builder, &s, &half_order_plus_one);
    let valid = builder.band(signature_valid, builder.band(r_in_range, normalized_s));
    builder.select(predicate, valid, builder.add_constant(Word::ALL_ONE))
}

pub(crate) fn verify_secp256r1(
    builder: &CircuitBuilder,
    public_key_x: &[Wire; 32],
    public_key_y: &[Wire; 32],
    signature: &[Wire; 64],
    hashed_message: &[Wire; 32],
    predicate_value: &BigUint,
) -> Wire {
    let coordinate_field = PseudoMersennePrimeField::new(
        builder,
        256,
        &[
            0x0000_0000_0000_0001,
            0xffff_ffff_0000_0000,
            0xffff_ffff_ffff_ffff,
            0x0000_0000_ffff_fffe,
        ],
    );
    let scalar_field = PseudoMersennePrimeField::new(
        builder,
        256,
        &[
            0x0c46_353d_039c_daaf,
            0x4319_0552_58e8_617b,
            0,
            0x0000_0000_ffff_ffff,
        ],
    );
    let zero_word = builder.add_constant(Word::ZERO);
    let true_word = builder.add_constant(Word::ALL_ONE);
    let one = BigUint::new_constant(builder, &NativeBigUint::from(1_u8)).zero_extend(builder, 4);
    let predicate = biguint_eq(builder, predicate_value, &one);
    let curve_a = hex_constant(
        builder,
        "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
    );
    let curve_b = hex_constant(
        builder,
        "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
    );
    let generator = AffinePoint {
        x: hex_constant(
            builder,
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        ),
        y: hex_constant(
            builder,
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        ),
        infinity: zero_word,
    };
    let supplied_key = AffinePoint {
        x: pack_be_bytes(builder, public_key_x),
        y: pack_be_bytes(builder, public_key_y),
        infinity: zero_word,
    };
    let public_key = grumpkin::select(builder, predicate, &supplied_key, &generator);
    grumpkin::assert_on_curve_params(
        builder,
        &coordinate_field,
        &public_key,
        &curve_a,
        &curve_b,
        true_word,
    );

    let r_original = pack_be_bytes(builder, signature[..32].try_into().unwrap());
    let s = pack_be_bytes(builder, signature[32..].try_into().unwrap());
    let z_original = pack_be_bytes(builder, hashed_message);
    let z = scalar_field.mul(builder, &z_original, &one);
    let r = scalar_field.mul(builder, &r_original, &one);
    let valid_r = builder.band(
        builder.bnot(r_original.is_zero(builder)),
        biguint_lt(builder, &r_original, scalar_field.modulus()),
    );
    let valid_s = builder.band(
        builder.bnot(s.is_zero(builder)),
        biguint_lt(builder, &s, scalar_field.modulus()),
    );
    let u1 = scalar_field.div(builder, &z, &s, valid_s);
    let u2 = scalar_field.div(builder, &r, &s, valid_s);
    let nonce = grumpkin::msm_with_a(
        builder,
        &coordinate_field,
        &[generator, public_key],
        &[u1, u2],
        &curve_a,
    );
    let nonce_x = scalar_field.mul(builder, &nonce.x, &one);
    let x_matches_r = biguint_eq(builder, &nonce_x, &r);
    let half_order_plus_one = hex_constant(
        builder,
        "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a9",
    );
    let normalized_s = biguint_lt(builder, &s, &half_order_plus_one);
    let valid = [
        valid_r,
        valid_s,
        builder.bnot(nonce.infinity),
        x_matches_r,
        normalized_s,
    ]
    .into_iter()
    .reduce(|valid, condition| builder.band(valid, condition))
    .expect("ECDSA has validity conditions");
    builder.select(predicate, valid, true_word)
}

pub(crate) fn pack_be_bytes(builder: &CircuitBuilder, bytes: &[Wire; 32]) -> BigUint {
    let zero = builder.add_constant(Word::ZERO);
    let mut limbs = [zero; 4];
    for (index, byte) in bytes.iter().copied().enumerate() {
        let position = 31 - index;
        let limb = position / 8;
        let shift = (position % 8) * 8;
        limbs[limb] = builder.bxor(limbs[limb], builder.shl(byte, shift as u32));
    }
    BigUint {
        limbs: limbs.to_vec(),
    }
}

fn hex_constant(builder: &CircuitBuilder, value: &str) -> BigUint {
    BigUint::new_constant(
        builder,
        &NativeBigUint::parse_bytes(value.as_bytes(), 16).expect("valid curve constant"),
    )
}
