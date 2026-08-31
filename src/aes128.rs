use binius_core::word::Word;
use binius_frontend::{CircuitBuilder, Wire};

pub(crate) fn encrypt_cbc(
    builder: &CircuitBuilder,
    inputs: &[Wire],
    iv: [Wire; 16],
    key: [Wire; 16],
) -> Vec<Wire> {
    let round_keys = expand_key(builder, key);
    let padding = 16 - inputs.len() % 16;
    let mut plaintext = inputs.to_vec();
    plaintext.extend((0..padding).map(|_| builder.add_constant_64(padding as u64)));

    let mut previous = iv;
    let mut ciphertext = Vec::with_capacity(plaintext.len());
    for block in plaintext.chunks_exact(16) {
        let block: [Wire; 16] =
            std::array::from_fn(|index| builder.bxor(block[index], previous[index]));
        previous = encrypt_block(builder, block, &round_keys);
        ciphertext.extend(previous);
    }
    ciphertext
}

fn encrypt_block(
    builder: &CircuitBuilder,
    mut state: [Wire; 16],
    round_keys: &[[Wire; 16]; 11],
) -> [Wire; 16] {
    state = add_round_key(builder, state, &round_keys[0]);
    for round_key in &round_keys[1..10] {
        state = sub_bytes(builder, state);
        state = shift_rows(state);
        state = mix_columns(builder, state);
        state = add_round_key(builder, state, round_key);
    }
    state = sub_bytes(builder, state);
    state = shift_rows(state);
    add_round_key(builder, state, &round_keys[10])
}

fn expand_key(builder: &CircuitBuilder, key: [Wire; 16]) -> [[Wire; 16]; 11] {
    const RCON: [u8; 10] = [1, 2, 4, 8, 16, 32, 64, 128, 27, 54];

    let mut keys = Vec::with_capacity(11);
    keys.push(key);
    for round in 0..10 {
        let previous = keys[round];
        let mut temp = [
            aes_sbox(builder, previous[13]),
            aes_sbox(builder, previous[14]),
            aes_sbox(builder, previous[15]),
            aes_sbox(builder, previous[12]),
        ];
        temp[0] = builder.bxor(temp[0], builder.add_constant_64(RCON[round] as u64));
        let mut next = [builder.add_constant(Word::ZERO); 16];
        for index in 0..4 {
            next[index] = builder.bxor(previous[index], temp[index]);
        }
        for index in 4..16 {
            next[index] = builder.bxor(previous[index], next[index - 4]);
        }
        keys.push(next);
    }
    keys.try_into().expect("AES-128 has eleven round keys")
}

fn add_round_key(
    builder: &CircuitBuilder,
    state: [Wire; 16],
    round_key: &[Wire; 16],
) -> [Wire; 16] {
    std::array::from_fn(|index| builder.bxor(state[index], round_key[index]))
}

fn sub_bytes(builder: &CircuitBuilder, state: [Wire; 16]) -> [Wire; 16] {
    state.map(|byte| aes_sbox(builder, byte))
}

fn shift_rows(state: [Wire; 16]) -> [Wire; 16] {
    std::array::from_fn(|index| {
        let row = index % 4;
        let column = index / 4;
        state[row + 4 * ((column + row) % 4)]
    })
}

fn mix_columns(builder: &CircuitBuilder, state: [Wire; 16]) -> [Wire; 16] {
    let mut output = state;
    for column in 0..4 {
        let offset = column * 4;
        let a = &state[offset..offset + 4];
        let twice: [Wire; 4] = std::array::from_fn(|index| xtime(builder, a[index]));
        output[offset] = xor4(builder, twice[0], builder.bxor(twice[1], a[1]), a[2], a[3]);
        output[offset + 1] = xor4(builder, a[0], twice[1], builder.bxor(twice[2], a[2]), a[3]);
        output[offset + 2] = xor4(builder, a[0], a[1], twice[2], builder.bxor(twice[3], a[3]));
        output[offset + 3] = xor4(builder, builder.bxor(twice[0], a[0]), a[1], a[2], twice[3]);
    }
    output
}

fn xor4(builder: &CircuitBuilder, a: Wire, b: Wire, c: Wire, d: Wire) -> Wire {
    builder.bxor_multi(&[a, b, c, d])
}

fn aes_sbox(builder: &CircuitBuilder, byte: Wire) -> Wire {
    // In GF(2^8), x^-1 = x^254. Zero maps to zero under this fixed exponentiation.
    let x2 = gf_mul(builder, byte, byte);
    let x4 = gf_mul(builder, x2, x2);
    let x8 = gf_mul(builder, x4, x4);
    let x16 = gf_mul(builder, x8, x8);
    let x32 = gf_mul(builder, x16, x16);
    let x64 = gf_mul(builder, x32, x32);
    let x128 = gf_mul(builder, x64, x64);
    let mut inverse = gf_mul(builder, x2, x4);
    for power in [x8, x16, x32, x64, x128] {
        inverse = gf_mul(builder, inverse, power);
    }

    builder.bxor_multi(&[
        inverse,
        rotate_byte_left(builder, inverse, 1),
        rotate_byte_left(builder, inverse, 2),
        rotate_byte_left(builder, inverse, 3),
        rotate_byte_left(builder, inverse, 4),
        builder.add_constant_64(0x63),
    ])
}

fn gf_mul(builder: &CircuitBuilder, mut lhs: Wire, rhs: Wire) -> Wire {
    let zero = builder.add_constant(Word::ZERO);
    let one = builder.add_constant_64(1);
    let mut result = zero;
    for bit in 0..8 {
        let rhs_bit = builder.band(builder.shr(rhs, bit), one);
        let condition = builder.shl(rhs_bit, 63);
        result = builder.bxor(result, builder.select(condition, lhs, zero));
        lhs = xtime(builder, lhs);
    }
    result
}

fn xtime(builder: &CircuitBuilder, byte: Wire) -> Wire {
    let one = builder.add_constant_64(1);
    let mask = builder.add_constant_64(0xff);
    let high_bit = builder.band(builder.shr(byte, 7), one);
    let condition = builder.shl(high_bit, 63);
    let shifted = builder.band(builder.shl(byte, 1), mask);
    let reduction = builder.select(
        condition,
        builder.add_constant_64(0x1b),
        builder.add_constant(Word::ZERO),
    );
    builder.bxor(shifted, reduction)
}

fn rotate_byte_left(builder: &CircuitBuilder, byte: Wire, amount: u32) -> Wire {
    let mask = builder.add_constant_64(0xff);
    let left = builder.band(builder.shl(byte, amount), mask);
    builder.bxor(left, builder.shr(byte, 8 - amount))
}
