// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.28;
contract BiniusPrimitives {
    uint256 private constant REGISTER_COUNT = 1;
    // Primitive interpreter for the circuit-specialized verifier equations.
    // Field addition is XOR, multiplication is polynomial multiplication modulo
    // x^128+x^7+x^2+x+1. Proof field elements use little-endian canonical encoding.
    struct Machine {
        bytes observed;
        uint256 observedLength;
        bytes32 sample;
        uint256 sampleIndex;
        bool sampling;
        bytes scratch;
        bytes roundConstants;
        uint256[64] schedule;
        uint256[8] hashState;
        bytes32[4] batchDigests;
    }

    function _machine(uint256 capacity) private pure returns (Machine memory m) {
        m.observed = new bytes(capacity + 128);
        m.scratch = new bytes(capacity + 128);
        m.sample = hex"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        m.sampling = true;
        m.roundConstants =
            hex"428a2f9871374491b5c0fbcfe9b5dba53956c25b59f111f1923f82a4ab1c5ed5d807aa9812835b01243185be550c7dc372be5d7480deb1fe9bdc06a7c19bf174e49b69c1efbe47860fc19dc6240ca1cc2de92c6f4a7484aa5cb0a9dc76f988da983e5152a831c66db00327c8bf597fc7c6e00bf3d5a7914706ca63511429296727b70a852e1b21384d2c6dfc53380d13650a7354766a0abb81c2c92e92722c85a2bfe8a1a81a664bc24b8b70c76c51a3d192e819d6990624f40e3585106aa07019a4c1161e376c082748774c34b0bcb5391c0cb34ed8aa4a5b9cca4f682e6ff3748f82ee78a5636f84c878148cc7020890befffaa4506cebbef9a3f7c67178f2";
    }

    function _run(bytes memory program, bytes calldata proof) private pure returns (bool) {
        Machine memory m = _machine(proof.length);
        uint256[] memory registers = new uint256[](REGISTER_COUNT);
        uint256 cursor;
        unchecked {
            while (cursor < program.length) {
                uint256 opcode = uint8(program[cursor]);
                uint256 dest = _u32(program, cursor + 1);
                cursor += 5;
                uint256 a = _u32(program, cursor);
                uint256 b = _u32(program, cursor + 4);
                uint256 value;
                if (opcode == 0) {
                    assembly ("memory-safe") { value := shr(128, mload(add(add(program, 32), cursor))) }
                    cursor += 16;
                } else if (opcode == 1) {
                    value = registers[a] ^ registers[b];
                    cursor += 8;
                } else if (opcode == 2) {
                    value = a == b ? _square(registers[a]) : _mul(registers[a], registers[b]);
                    cursor += 8;
                } else if (opcode == 3) {
                    value = _inverse(registers[a]);
                    cursor += 4;
                } else if (opcode == 4) {
                    value = _readLE(proof, a, uint8(program[cursor + 4]));
                    cursor += 5;
                } else if (opcode == 5) {
                    assembly ("memory-safe") { value := calldataload(add(proof.offset, a)) }
                    cursor += 4;
                } else if (opcode == 6) {
                    value = _sample(m, 16);
                } else if (opcode == 7) {
                    value = _sample(m, 4) & ((1 << uint8(program[cursor])) - 1);
                    ++cursor;
                } else if (opcode == 8) {
                    _observe(m, proof, a, b);
                    cursor += 8;
                } else if (opcode == 9) {
                    if (registers[a] != 0) return false;
                    cursor += 4;
                } else if (opcode == 10) {
                    value = registers[a] >> uint8(program[cursor + 4]);
                    cursor += 5;
                } else if (opcode == 11) {
                    value = (registers[a] >> uint8(program[cursor + 4])) & 1;
                    cursor += 5;
                } else if (opcode == 12) {
                    value = registers[a] << uint8(program[cursor + 4]);
                    cursor += 5;
                } else if (opcode == 13) {
                    uint256[128] memory fields;
                    for (uint256 i; i < 128; ++i) {
                        fields[i] = _sample(m, 16);
                    }
                    assembly ("memory-safe") { value := fields }
                } else if (opcode == 14) {
                    if (!_layer(m, proof, bytes32(registers[a]), b, _u32(program, cursor + 8))) return false;
                    cursor += 12;
                } else if (opcode == 15) {
                    if (!_path(
                            m,
                            proof,
                            registers[a],
                            b,
                            _u32(program, cursor + 8),
                            _u32(program, cursor + 12),
                            _u32(program, cursor + 16)
                        )) return false;
                    cursor += 20;
                } else if (opcode == 16) {
                    if (!_vector(
                            m, proof, bytes32(registers[a]), b, _u32(program, cursor + 8), _u32(program, cursor + 12)
                        )) return false;
                    cursor += 16;
                } else if (opcode == 17) {
                    uint256[128] memory rows;
                    for (uint256 i; i < 128; ++i) {
                        rows[i] = registers[_u32(program, cursor + 4 * i)];
                    }
                    _transpose(rows);
                    assembly ("memory-safe") { value := rows }
                    cursor += 512;
                } else if (opcode == 18) {
                    uint256 pointer = registers[a];
                    uint256 row = uint8(program[cursor + 4]);
                    assembly ("memory-safe") { value := mload(add(pointer, mul(row, 32))) }
                    cursor += 5;
                } else if (opcode == 19) {
                    uint256[] memory array = new uint256[](a);
                    for (uint256 i; i < a; ++i) {
                        array[i] = registers[_u32(program, cursor + 4 + 4 * i)];
                    }
                    assembly ("memory-safe") { value := add(array, 32) }
                    cursor += 4 + 4 * a;
                } else if (opcode == 20) {
                    uint256 pointer = registers[b];
                    uint256 index = registers[a] & (_u32(program, cursor + 8) - 1);
                    assembly ("memory-safe") { value := mload(add(pointer, mul(index, 32))) }
                    cursor += 12;
                } else if (opcode == 21) {
                    assembly ("memory-safe") { value := add(add(program, 36), cursor) }
                    cursor += 4 + a;
                } else if (opcode == 22) {
                    value = registers[a] & ((uint256(1) << uint8(program[cursor + 4])) - 1);
                    cursor += 5;
                } else if (opcode == 23) {
                    value = _publicWiring(program, cursor + 4, registers);
                    cursor += 4 + a;
                } else if (opcode == 24) {
                    value = _wiring(
                        registers[a],
                        registers[b],
                        registers[_u32(program, cursor + 8)],
                        registers[_u32(program, cursor + 12)],
                        uint8(program[cursor + 16])
                    );
                    cursor += 17;
                } else if (opcode == 25) {
                    bool success;
                    (success, value) = _fri(m, program, cursor + 4, registers, proof);
                    if (!success) return false;
                    cursor += 4 + a;
                } else if (opcode == 26) {
                    value = _vectorBinary(
                        registers[a], registers[b], uint8(program[cursor + 8]), uint8(program[cursor + 9])
                    );
                    cursor += 10;
                } else if (opcode == 27) {
                    uint256[128] memory fields;
                    for (uint256 i; i < 128; ++i) {
                        fields[i] = _readLE(proof, a + 16 * i, 16);
                    }
                    assembly ("memory-safe") { value := fields }
                    cursor += 4;
                } else if (opcode == 28) {
                    uint256[128] memory powers;
                    powers[0] = registers[a];
                    for (uint256 i = 1; i < 128; ++i) {
                        powers[i] = _square(powers[i - 1]);
                    }
                    assembly ("memory-safe") { value := powers }
                    cursor += 4;
                } else if (opcode == 29) {
                    uint256 n = uint8(program[cursor]);
                    uint256[128] memory values;
                    values[0] = 1;
                    for (uint256 bit; bit < n; ++bit) {
                        uint256 r = registers[_u32(program, cursor + 1 + 4 * bit)];
                        uint256 size = uint256(1) << bit;
                        for (uint256 i; i < size; ++i) {
                            uint256 high = _mul(values[i], r);
                            values[i] ^= high;
                            values[i + size] = high;
                        }
                    }
                    assembly ("memory-safe") { value := values }
                    cursor += 1 + 4 * n;
                } else if (opcode == 30) {
                    value = _innerWiring(program, cursor + 4, registers);
                    cursor += 4 + a;
                } else if (opcode == 31) {
                    uint256[128] memory rows;
                    uint256 pointer = registers[a];
                    assembly ("memory-safe") { mcopy(rows, pointer, 4096) }
                    _transpose(rows);
                    assembly ("memory-safe") { value := rows }
                    cursor += 4;
                } else {
                    return false;
                }
                registers[dest] = value;
            }
        }
        return cursor == program.length;
    }

    function _axis(uint256[] memory point, uint256 start, uint256 count, uint256 index)
        private
        pure
        returns (uint256 value)
    {
        value = 1;
        for (uint256 i; i < count; ++i) {
            value = _mul(value, point[start + i] ^ (((index >> i) & 1) ^ 1));
        }
    }

    // The inner wiring tensor's axes are operation, constraint, operand,
    // inner shift, outer shift, and value address. Contract the two address
    // axes with the same exact sparse evaluator used by outer Spartan.
    struct InnerWiringState {
        uint256[4] dimensions;
        uint256[4] cachedX;
        uint256[] point;
        uint256 shiftStart;
        uint256 cachedY;
        uint256 yPointer;
    }

    function _innerWiring(bytes memory data, uint256 cursor, uint256[] memory registers)
        private
        pure
        returns (uint256 result)
    {
        InnerWiringState memory state;
        state.shiftStart = 5;
        for (uint256 i; i < 4; ++i) {
            state.dimensions[i] = uint8(data[cursor + i]);
            state.shiftStart += state.dimensions[i];
        }
        uint256 count = _u32(data, cursor + 5) >> 16;
        uint256 groups = _u32(data, cursor + 7) >> 16;
        cursor += 9;
        state.point = new uint256[](count);
        for (uint256 i; i < count; ++i) {
            state.point[i] = registers[_u32(data, cursor)];
            cursor += 4;
        }
        uint256[] memory point = state.point;
        uint256 shiftStart = state.shiftStart;
        uint256 yPointer;
        assembly ("memory-safe") { yPointer := add(add(point, 32), shl(5, add(shiftStart, 18))) }
        state.yPointer = yPointer;
        for (uint256 g; g < groups; ++g) {
            uint256 operation = uint8(data[cursor]);
            uint256 length = _u32(data, cursor + 5);
            uint256 matrix;
            assembly ("memory-safe") { matrix := add(add(data, 41), cursor) }
            if (state.cachedY == 0) state.cachedY = _wiring(matrix, 0, state.yPointer, 0, 3);
            if (state.cachedX[operation] == 0) {
                uint256 start = 5;
                for (uint256 i; i < operation; ++i) {
                    start += state.dimensions[i];
                }
                uint256 xPointer;
                assembly ("memory-safe") { xPointer := add(add(point, 32), shl(5, start)) }
                state.cachedX[operation] = _wiring(matrix, xPointer, 0, 0, 0);
            }
            result ^= _innerGroup(state, data, cursor, matrix, operation);
            cursor += 9 + length;
        }
    }

    function _innerGroup(
        InnerWiringState memory state,
        bytes memory data,
        uint256 cursor,
        uint256 matrix,
        uint256 operation
    ) private pure returns (uint256) {
        uint256 inner = _u32(data, cursor + 1) >> 16;
        uint256 outer = _u32(data, cursor + 3) >> 16;
        uint256 scalar = _mul(_axis(state.point, 0, 2, operation), _axis(state.point, 2, 3, inner & 7));
        scalar = _mul(scalar, _axis(state.point, state.shiftStart, 9, inner >> 3));
        scalar = _mul(scalar, _axis(state.point, state.shiftStart + 9, 9, outer));
        return _mul(scalar, _wiring(matrix, state.cachedX[operation], state.cachedY, 0, 2));
    }

    function _vectorBinary(uint256 left, uint256 right, uint256 kind, uint256 shift)
        private
        pure
        returns (uint256 pointer)
    {
        uint256[128] memory values;
        for (uint256 i; i < 128; ++i) {
            uint256 a;
            uint256 b = right;
            assembly ("memory-safe") { a := mload(add(left, shl(5, i))) }
            if (kind & 2 == 0) assembly ("memory-safe") { b := mload(add(right, shl(5, and(add(i, shift), 127)))) }
            values[i] = kind & 1 == 0 ? a ^ b : _mul(a, b);
        }
        assembly ("memory-safe") { pointer := values }
    }

    function _varint(bytes memory data, uint256 cursor) private pure returns (uint256 value, uint256 next) {
        uint256 shift;
        do {
            uint256 b = uint8(data[cursor++]);
            value |= (b & 127) << shift;
            if (b & 128 == 0) return (value, cursor);
            shift += 7;
        } while (true);
    }

    // Multi-terminal decision DAG of the exact public matrix columns.
    // Identical subtrees share one interpolation; leaves remain runtime values.
    function _publicWiring(bytes memory data, uint256 cursor, uint256[] memory registers)
        private
        pure
        returns (uint256)
    {
        uint256 leaves = _u32(data, cursor);
        uint256 count = _u32(data, cursor + 4);
        uint256 dimensions = uint8(data[cursor + 8]);
        uint256[3] memory roots = [_u32(data, cursor + 9), _u32(data, cursor + 13), _u32(data, cursor + 17)];
        uint256 lambda = registers[_u32(data, cursor + 21)];
        cursor += 25;
        uint256[] memory point = new uint256[](dimensions);
        for (uint256 i; i < dimensions; ++i) {
            point[i] = registers[_u32(data, cursor)];
            cursor += 4;
        }
        uint256[] memory values = new uint256[](leaves + count);
        uint256[2] memory previousLeaf;
        uint256[4] memory previousChild;
        unchecked {
            for (uint256 i; i < leaves; ++i) {
                uint256 code;
                (code, cursor) = _varint(data, cursor);
                uint256 kind = code & 1;
                uint256 delta = code >> 1;
                previousLeaf[kind] += delta & 1 == 0 ? delta >> 1 : ~(delta >> 1);
                uint256 value = registers[previousLeaf[kind]];
                if (kind != 0) {
                    uint256 row = uint8(data[cursor++]);
                    assembly ("memory-safe") { value := mload(add(value, shl(5, row))) }
                }
                values[i] = value;
            }
            for (uint256 i = leaves; i < values.length; ++i) {
                uint256 code = uint8(data[cursor++]);
                uint256 lane = code & 1;
                uint256 delta;
                (delta, cursor) = _varint(data, cursor);
                previousChild[lane] += delta & 1 == 0 ? delta >> 1 : ~(delta >> 1);
                uint256 a = values[previousChild[lane]];
                lane = 2 + ((code >> 1) & 1);
                (delta, cursor) = _varint(data, cursor);
                previousChild[lane] += delta & 1 == 0 ? delta >> 1 : ~(delta >> 1);
                uint256 b = values[previousChild[lane]];
                values[i] = a ^ _mul(point[code >> 2], a ^ b);
            }
        }
        return values[roots[0]] ^ _mul(lambda, values[roots[1]] ^ _mul(lambda, values[roots[2]]));
    }

    function _wiring(uint256 data, uint256 pointX, uint256 pointY, uint256 lambda, uint256 mode)
        private
        pure
        returns (uint256 result)
    {
        assembly ("memory-safe") {
            function fm(a, b) -> r {
                // Five interleaved coefficient lanes, with five bits per digit.
                // Each integer-product digit sums at most 26 one-bit products,
                // so it cannot carry into the next digit. Masking extracts parity.
                let a0 := and(a, 0x8421084210842108421084210842108421084210842108421084210842108421)
                let b0 := and(b, 0x8421084210842108421084210842108421084210842108421084210842108421)
                let a1 := and(a, 0x0842108421084210842108421084210842108421084210842108421084210842)
                let b1 := and(b, 0x0842108421084210842108421084210842108421084210842108421084210842)
                let a2 := and(a, 0x1084210842108421084210842108421084210842108421084210842108421084)
                let b2 := and(b, 0x1084210842108421084210842108421084210842108421084210842108421084)
                let a3 := and(a, 0x2108421084210842108421084210842108421084210842108421084210842108)
                let b3 := and(b, 0x2108421084210842108421084210842108421084210842108421084210842108)
                let a4 := and(a, 0x4210842108421084210842108421084210842108421084210842108421084210)
                let b4 := and(b, 0x4210842108421084210842108421084210842108421084210842108421084210)
                r := xor(
                    r,
                    and(
                        xor(xor(xor(xor(mul(a0, b0), mul(a1, b4)), mul(a2, b3)), mul(a3, b2)), mul(a4, b1)),
                        0x8421084210842108421084210842108421084210842108421084210842108421
                    )
                )
                r := xor(
                    r,
                    and(
                        xor(xor(xor(xor(mul(a0, b1), mul(a1, b0)), mul(a2, b4)), mul(a3, b3)), mul(a4, b2)),
                        0x0842108421084210842108421084210842108421084210842108421084210842
                    )
                )
                r := xor(
                    r,
                    and(
                        xor(xor(xor(xor(mul(a0, b2), mul(a1, b1)), mul(a2, b0)), mul(a3, b4)), mul(a4, b3)),
                        0x1084210842108421084210842108421084210842108421084210842108421084
                    )
                )
                r := xor(
                    r,
                    and(
                        xor(xor(xor(xor(mul(a0, b3), mul(a1, b2)), mul(a2, b1)), mul(a3, b0)), mul(a4, b4)),
                        0x2108421084210842108421084210842108421084210842108421084210842108
                    )
                )
                r := xor(
                    r,
                    and(
                        xor(xor(xor(xor(mul(a0, b4), mul(a1, b3)), mul(a2, b2)), mul(a3, b1)), mul(a4, b0)),
                        0x4210842108421084210842108421084210842108421084210842108421084210
                    )
                )
                let h := shr(128, r)
                let t := xor(xor(h, shl(1, h)), xor(shl(2, h), shl(7, h)))
                let o := shr(128, t)
                r := and(
                    xor(xor(r, t), xor(xor(o, shl(1, o)), xor(shl(2, o), shl(7, o)))),
                    0xffffffffffffffffffffffffffffffff
                )
            }
            function times(a, b) -> r {
                if and(iszero(iszero(a)), iszero(iszero(b))) {
                    switch a
                    case 1 { r := b }
                    default { switch b
                    case 1 { r := a }
                    default { r := fm(a, b) } }
                }
            }
            function uv(p) -> v, q {
                let b := byte(0, mload(p))
                v := and(b, 127)
                q := add(p, 1)
                for { let shift := 7 } and(b, 128) { shift := add(shift, 7) } {
                    b := byte(0, mload(q))
                    v := or(v, shl(shift, and(b, 127)))
                    q := add(q, 1)
                }
            }
            // Cache every contiguous interval of at most eight coordinates.
            // A full 18-bit equality product now needs three table products.
            // Each starting position stores a binary tree of partial products;
            // all eight trees fit in 1024 words per chunk.
            function prepare(point, n) -> descriptor {
                descriptor := mload(0x40)
                let table := add(descriptor, 64)
                let chunks := shr(3, add(n, 7))
                mstore(0x40, add(table, mul(chunks, 32768)))
                mstore(descriptor, point)
                mstore(add(descriptor, 32), table)
                for { let chunk := 0 } lt(chunk, chunks) { chunk := add(chunk, 1) } {
                    let base := add(table, mul(chunk, 32768))
                    for { let lo := 0 } lt(lo, 8) { lo := add(lo, 1) } {
                        let start := add(base, shl(5, sub(1024, shl(sub(10, lo), 1))))
                        mstore(add(start, 32), 1)
                        for { let width := 0 } lt(width, sub(8, lo)) { width := add(width, 1) } {
                            let bit := add(mul(chunk, 8), add(lo, width))
                            let r := 0
                            if lt(bit, n) { r := mload(add(point, shl(5, bit))) }
                            let size := shl(width, 1)
                            for { let i := 0 } lt(i, size) { i := add(i, 1) } {
                                let old := mload(add(start, shl(5, add(size, i))))
                                let high := times(old, r)
                                mstore(add(start, shl(5, add(mul(size, 2), i))), xor(old, high))
                                mstore(add(start, shl(5, add(mul(size, 3), i))), high)
                            }
                        }
                    }
                }
            }
            function part(point, index, lo, hi) -> value {
                value := 1
                let table := mload(add(point, 32))
                for {} lt(lo, hi) {} {
                    let chunk := shr(3, lo)
                    let end := mul(add(chunk, 1), 8)
                    if gt(end, hi) { end := hi }
                    let size := shl(sub(end, lo), 1)
                    let base := sub(1024, shl(sub(10, and(lo, 7)), 1))
                    let entry := add(add(base, size), and(shr(lo, index), sub(size, 1)))
                    value := times(value, mload(add(add(table, mul(chunk, 32768)), shl(5, entry))))
                    lo := end
                }
            }
            function power(n) -> yes { yes := and(gt(n, 0), iszero(and(n, sub(n, 1)))) }
            function log(n) -> k { for {} gt(n, 1) { n := shr(1, n) } { k := add(k, 1) } }
            // Largest aligned dyadic block contained in the remaining interval.
            function block(start, remaining) -> k, n {
                n := 1
                for {} and(iszero(and(start, n)), iszero(gt(shl(1, n), remaining))) {} {
                    n := shl(1, n)
                    k := add(k, 1)
                }
            }
            function interval(point, n, start, stride, count) -> value {
                let shift := log(stride)
                let low := part(point, start, 0, shift)
                for {} count {} {
                    let k, size := block(shr(shift, start), count)
                    value := xor(value, part(point, start, add(shift, k), n))
                    start := add(start, mul(size, stride))
                    count := sub(count, size)
                }
                value := times(value, low)
            }
            // Sum eq(x,row+t*2^a)*eq(y,column+t*2^b). Align x's
            // free bits dyadically; addition to y's offset has two carry states.
            // With A=1+x+y, B=(1+x)y, C=x(1+y), an offset bit 0 maps
            // (s0,s1) to (s0*A+s1*B,s1*C); bit 1 to (s0*B,s0*C+s1*A).
            function progression(x, nx, y, ny, row, column, a, b, count) -> value {
                let fixedLow := times(part(x, row, 0, a), part(y, column, 0, b))
                for {} count {} {
                    let k, size := block(shr(a, row), count)
                    let s0 := 1
                    let s1 := 0
                    for { let bit := 0 } lt(bit, k) { bit := add(bit, 1) } {
                        let xx := mload(add(mload(x), shl(5, add(a, bit))))
                        let yy := mload(add(mload(y), shl(5, add(b, bit))))
                        let xy := times(xx, yy)
                        let diagonal := xor(1, xor(xx, yy))
                        let off01 := xor(yy, xy)
                        let off10 := xor(xx, xy)
                        switch and(shr(add(b, bit), column), 1)
                        case 0 {
                            s0 := xor(times(s0, diagonal), times(s1, off01))
                            s1 := times(s1, off10)
                        }
                        default {
                            let next1 := xor(times(s0, off10), times(s1, diagonal))
                            s0 := times(s0, off01)
                            s1 := next1
                        }
                    }
                    let high := times(s0, part(y, column, add(b, k), ny))
                    if s1 {
                        let carried := add(column, shl(add(b, k), 1))
                        if lt(carried, shl(ny, 1)) { high := xor(high, times(s1, part(y, carried, add(b, k), ny))) }
                    }
                    value := xor(value, times(part(x, row, add(a, k), nx), high))
                    row := add(row, shl(a, size))
                    column := add(column, shl(b, size))
                    count := sub(count, size)
                }
                value := times(value, fixedLow)
            }
            function affine(x, nx, y, ny, run) -> value {
                let count := mload(add(run, 32))
                let row := mload(add(run, 64))
                let column := mload(add(run, 96))
                let dr := mload(add(run, 128))
                let dc := mload(add(run, 160))
                switch and(iszero(dr), power(dc))
                case 1 { value := times(part(x, row, 0, nx), interval(y, ny, column, dc, count)) }
                default {
                    switch and(iszero(dc), power(dr))
                    case 1 { value := times(interval(x, nx, row, dr, count), part(y, column, 0, ny)) }
                    default {
                        switch and(and(power(dr), power(dc)), gt(count, 3))
                        case 1 { value := progression(x, nx, y, ny, row, column, log(dr), log(dc), count) }
                        default {
                            for { let i := 0 } lt(i, count) { i := add(i, 1) } {
                                value := xor(value, times(part(x, row, 0, nx), part(y, column, 0, ny)))
                                row := add(row, dr)
                                column := add(column, dc)
                            }
                        }
                    }
                }
            }
            let nx, ny, count
            nx, data := uv(data)
            ny, data := uv(data)
            count, data := uv(data)
            switch mode
            case 0 { result := prepare(pointX, nx) }
            case 3 { result := prepare(pointY, ny) }
            default {
                let cachedX := pointX
                let cachedY := pointY
                if eq(mode, 1) {
                    cachedX := prepare(pointX, nx)
                    cachedY := prepare(pointY, ny)
                }
                let run := mload(0x40)
                // Keep the three matrix sums after the six run operands.
                // This avoids a Yul stack-allocation failure when a circuit's
                // smaller instruction set causes more aggressive inlining.
                mstore(0x40, add(run, 288))
                for { let p := run } lt(p, add(run, 288)) { p := add(p, 32) } { mstore(p, 0) }
                for { let i := 0 } lt(i, count) { i := add(i, 1) } {
                    for { let p := run } lt(p, add(run, 192)) { p := add(p, 32) } {
                        let delta
                        delta, data := uv(data)
                        mstore(p, add(mload(p), xor(shr(1, delta), sub(0, and(delta, 1)))))
                    }
                    let sum := affine(cachedX, nx, cachedY, ny, run)
                    let mask := mload(run)
                    if and(mask, 1) { mstore(add(run, 192), xor(mload(add(run, 192)), sum)) }
                    if and(mask, 2) { mstore(add(run, 224), xor(mload(add(run, 224)), sum)) }
                    if and(mask, 4) { mstore(add(run, 256), xor(mload(add(run, 256)), sum)) }
                }
                result := xor(mload(add(run, 192)), times(lambda, xor(mload(add(run, 224)), times(lambda, mload(add(run, 256))))))
            }
        }
    }

    function _u32(bytes memory b, uint256 o) private pure returns (uint256 v) {
        assembly ("memory-safe") { v := shr(224, mload(add(add(b, 32), o))) }
    }

    function _reverse(uint256 x) private pure returns (uint256) {
        unchecked {
            x = ((x & 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff) << 8)
                | ((x >> 8) & 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff);
            x = ((x & 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff) << 16)
                | ((x >> 16) & 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff);
            x = ((x & 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff) << 32)
                | ((x >> 32) & 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff);
            x = ((x & 0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff) << 64)
                | ((x >> 64) & 0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff);
            return (x << 128) | (x >> 128);
        }
    }

    function _readLE(bytes calldata b, uint256 offset, uint256 n) private pure returns (uint256 v) {
        assembly ("memory-safe") { v := calldataload(add(b.offset, offset)) }
        return _reverse(v) & ((1 << (n * 8)) - 1);
    }

    function _observe(Machine memory m, bytes calldata proof, uint256 offset, uint256 length) private pure {
        bytes memory buffer = m.observed;
        if (m.sampling) {
            bytes32 digest = m.sample;
            uint256 cursor = m.sampleIndex;
            assembly ("memory-safe") { mstore(add(buffer, 32), digest) }
            for (uint256 i; i < 8; ++i) {
                buffer[32 + i] = bytes1(uint8(cursor >> (8 * i)));
            }
            m.observedLength = 40;
            m.sampling = false;
        }
        uint256 position = m.observedLength;
        assembly ("memory-safe") { calldatacopy(add(add(buffer, 32), position), add(proof.offset, offset), length) }
        m.observedLength = position + length;
    }

    function _sample(Machine memory m, uint256 n) private pure returns (uint256 value) {
        if (!m.sampling) {
            m.sample = _shaMemory(m, m.observed, 0, m.observedLength);
            m.sampleIndex = 0;
            m.sampling = true;
        }
        uint256 consumed;
        while (consumed < n) {
            if (m.sampleIndex == 32) {
                bytes memory buffer = m.observed;
                bytes32 digest = m.sample;
                assembly ("memory-safe") { mstore(add(buffer, 32), digest) }
                m.sample = _shaMemory(m, buffer, 0, 32);
                m.sampleIndex = 0;
            }
            uint256 count = 32 - m.sampleIndex;
            if (count > n - consumed) count = n - consumed;
            uint256 word = _reverse(uint256(m.sample) << (m.sampleIndex * 8));
            value |= (word & ((1 << (8 * count)) - 1)) << (8 * consumed);
            m.sampleIndex += count;
            consumed += count;
        }
    }

    function _mul(uint256 a, uint256 b) private pure returns (uint256 r) {
        assembly ("memory-safe") {
            // Five interleaved coefficient lanes, with five bits per digit.
            // Each integer-product digit sums at most 26 one-bit products,
            // so it cannot carry into the next digit. Masking extracts parity.
            let a0 := and(a, 0x8421084210842108421084210842108421084210842108421084210842108421)
            let b0 := and(b, 0x8421084210842108421084210842108421084210842108421084210842108421)
            let a1 := and(a, 0x0842108421084210842108421084210842108421084210842108421084210842)
            let b1 := and(b, 0x0842108421084210842108421084210842108421084210842108421084210842)
            let a2 := and(a, 0x1084210842108421084210842108421084210842108421084210842108421084)
            let b2 := and(b, 0x1084210842108421084210842108421084210842108421084210842108421084)
            let a3 := and(a, 0x2108421084210842108421084210842108421084210842108421084210842108)
            let b3 := and(b, 0x2108421084210842108421084210842108421084210842108421084210842108)
            let a4 := and(a, 0x4210842108421084210842108421084210842108421084210842108421084210)
            let b4 := and(b, 0x4210842108421084210842108421084210842108421084210842108421084210)
            r := xor(
                r,
                and(
                    xor(xor(xor(xor(mul(a0, b0), mul(a1, b4)), mul(a2, b3)), mul(a3, b2)), mul(a4, b1)),
                    0x8421084210842108421084210842108421084210842108421084210842108421
                )
            )
            r := xor(
                r,
                and(
                    xor(xor(xor(xor(mul(a0, b1), mul(a1, b0)), mul(a2, b4)), mul(a3, b3)), mul(a4, b2)),
                    0x0842108421084210842108421084210842108421084210842108421084210842
                )
            )
            r := xor(
                r,
                and(
                    xor(xor(xor(xor(mul(a0, b2), mul(a1, b1)), mul(a2, b0)), mul(a3, b4)), mul(a4, b3)),
                    0x1084210842108421084210842108421084210842108421084210842108421084
                )
            )
            r := xor(
                r,
                and(
                    xor(xor(xor(xor(mul(a0, b3), mul(a1, b2)), mul(a2, b1)), mul(a3, b0)), mul(a4, b4)),
                    0x2108421084210842108421084210842108421084210842108421084210842108
                )
            )
            r := xor(
                r,
                and(
                    xor(xor(xor(xor(mul(a0, b4), mul(a1, b3)), mul(a2, b2)), mul(a3, b1)), mul(a4, b0)),
                    0x4210842108421084210842108421084210842108421084210842108421084210
                )
            )
            let h := shr(128, r)
            let t := xor(xor(h, shl(1, h)), xor(shl(2, h), shl(7, h)))
            let o := shr(128, t)
            r := and(
                xor(xor(r, t), xor(xor(o, shl(1, o)), xor(shl(2, o), shl(7, o)))),
                0xffffffffffffffffffffffffffffffff
            )
        }
    }

    function _transpose(uint256[128] memory rows) private pure {
        assembly ("memory-safe") {
            let mask := 0xffffffffffffffff
            for { let shift := 64 } gt(shift, 0) {
                shift := shr(1, shift)
                mask := xor(mask, shl(shift, mask))
            } {
                for { let i := 0 } lt(i, 128) { i := add(i, 1) } {
                    if iszero(and(i, shift)) {
                        let a := add(rows, shl(5, i))
                        let b := add(rows, shl(5, add(i, shift)))
                        let t := and(xor(shr(shift, mload(a)), mload(b)), mask)
                        mstore(a, xor(mload(a), shl(shift, t)))
                        mstore(b, xor(mload(b), t))
                    }
                }
            }
        }
    }

    function _square(uint256 a) private pure returns (uint256 r) {
        assembly ("memory-safe") {
            function spread(x) -> y {
                x := and(or(x, shl(32, x)), 0x00000000ffffffff00000000ffffffff)
                x := and(or(x, shl(16, x)), 0x0000ffff0000ffff0000ffff0000ffff)
                x := and(or(x, shl(8, x)), 0x00ff00ff00ff00ff00ff00ff00ff00ff)
                x := and(or(x, shl(4, x)), 0x0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f)
                x := and(or(x, shl(2, x)), 0x33333333333333333333333333333333)
                y := and(or(x, shl(1, x)), 0x55555555555555555555555555555555)
            }
            r := or(spread(and(a, 0xffffffffffffffff)), shl(128, spread(shr(64, a))))
            let h := shr(128, r)
            let t := xor(xor(h, shl(1, h)), xor(shl(2, h), shl(7, h)))
            let o := shr(128, t)
            r := and(
                xor(xor(r, t), xor(xor(o, shl(1, o)), xor(shl(2, o), shl(7, o)))),
                0xffffffffffffffffffffffffffffffff
            )
        }
    }

    function _inverse(uint256 a) private pure returns (uint256 r) {
        // Addition chain for a^(2^128-2); zero maps to zero as in the backend.
        r = a;
        uint256 exponent = 1;
        for (uint256 i; i < 6; ++i) {
            uint256 power = r;
            for (uint256 j; j < exponent; ++j) {
                r = _square(r);
            }
            r = _mul(r, power);
            exponent *= 2;
            r = _mul(_square(r), a);
            ++exponent;
        }
        return _square(r);
    }

    function _shaMemory(Machine memory m, bytes memory input, uint256 offset, uint256 length)
        private
        pure
        returns (bytes32)
    {
        bytes memory scratch = m.scratch;
        assembly ("memory-safe") { mcopy(add(scratch, 32), add(add(input, 32), offset), length) }
        return _shaFinish(m, length);
    }

    function _shaCalldata(Machine memory m, bytes calldata input, uint256 offset, uint256 length)
        private
        pure
        returns (bytes32)
    {
        bytes memory scratch = m.scratch;
        assembly ("memory-safe") { calldatacopy(add(scratch, 32), add(input.offset, offset), length) }
        return _shaFinish(m, length);
    }

    function _shaFinish(Machine memory m, uint256 length) private pure returns (bytes32) {
        uint256 padded = (length + 72) & ~uint256(63);
        bytes memory s = m.scratch;
        // Clear only the suffix, preserving all message bytes at block edges.
        assembly ("memory-safe") {
            let start := add(s, 32)
            for { let p := add(start, length) } lt(p, add(start, padded)) { p := add(p, 32) } { mstore(p, 0) }
            mstore8(add(start, length), 0x80)
            mstore(add(start, sub(padded, 8)), shl(192, mul(length, 8)))
        }
        _hashInit(m, false);
        for (uint256 i; i < padded; i += 64) {
            _compress(m, s, i);
        }
        return _digest(m, false);
    }

    function _node(Machine memory m, bytes32 left, bytes32 right) private pure returns (bytes32) {
        // Native Binius Sha256Compression: domain IV in little-endian word order,
        // one unpadded compression block, and little-endian output state words.
        _hashInit(m, true);
        bytes memory s = m.scratch;
        assembly ("memory-safe") {
            mstore(add(s, 32), left)
            mstore(add(s, 64), right)
        }
        _compress(m, s, 0);
        return _digest(m, true);
    }

    function _digest(Machine memory m, bool little) private pure returns (bytes32 result) {
        _digest4(m, little);
        return m.batchDigests[0];
    }

    function _compress(Machine memory m, bytes memory data, uint256 offset) private pure {
        uint256[64] memory w = m.schedule;
        assembly ("memory-safe") {
            let p := add(add(data, 32), offset)
            for { let i := 0 } lt(i, 16) { i := add(i, 1) } {
                mstore(add(w, shl(5, i)), shr(224, mload(add(p, shl(2, i)))))
            }
        }
        _shaRounds(m);
    }

    function _shaRounds(Machine memory m) private pure {
        uint256[64] memory w = m.schedule;
        uint256[8] memory state = m.hashState;
        bytes memory constants = m.roundConstants;
        assembly ("memory-safe") {
            // Four independent 32-bit words, separated by 32 zero guard bits.
            // Rotations cannot reach another lane. Mask each sigma before adding:
            // the sum has at most five 32-bit terms and cannot cross a guard.
            function rr(x, n) -> z { z := or(shr(n, x), shl(sub(32, n), x)) }
            let mask := 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff
            let repeat := 0x0000000000000001000000000000000100000000000000010000000000000001
            for { let i := 16 } lt(i, 64) { i := add(i, 1) } {
                let x := mload(add(w, shl(5, sub(i, 15))))
                let y := mload(add(w, shl(5, sub(i, 2))))
                let s0 := and(xor(xor(rr(x, 7), rr(x, 18)), shr(3, x)), mask)
                let s1 := and(xor(xor(rr(y, 17), rr(y, 19)), shr(10, y)), mask)
                mstore(
                    add(w, shl(5, i)),
                    and(
                        add(add(s0, s1), add(mload(add(w, shl(5, sub(i, 16)))), mload(add(w, shl(5, sub(i, 7)))))),
                        mask
                    )
                )
            }
            let a := mload(state)
            let b := mload(add(state, 32))
            let c := mload(add(state, 64))
            let d := mload(add(state, 96))
            let e := mload(add(state, 128))
            let f := mload(add(state, 160))
            let g := mload(add(state, 192))
            let h := mload(add(state, 224))
            for { let i := 0 } lt(i, 64) { i := add(i, 1) } {
                let s1 := and(xor(xor(rr(e, 6), rr(e, 11)), rr(e, 25)), mask)
                let ch := xor(g, and(e, xor(f, g)))
                let k := mul(repeat, shr(224, mload(add(add(constants, 32), shl(2, i)))))
                let t1 := and(add(add(add(h, s1), ch), add(k, mload(add(w, shl(5, i))))), mask)
                let s0 := and(xor(xor(rr(a, 2), rr(a, 13)), rr(a, 22)), mask)
                let maj := xor(and(a, b), and(c, xor(a, b)))
                h := g
                g := f
                f := e
                e := and(add(d, t1), mask)
                d := c
                c := b
                b := a
                a := and(add(t1, add(s0, maj)), mask)
            }
            mstore(state, and(add(mload(state), a), mask))
            mstore(add(state, 32), and(add(mload(add(state, 32)), b), mask))
            mstore(add(state, 64), and(add(mload(add(state, 64)), c), mask))
            mstore(add(state, 96), and(add(mload(add(state, 96)), d), mask))
            mstore(add(state, 128), and(add(mload(add(state, 128)), e), mask))
            mstore(add(state, 160), and(add(mload(add(state, 160)), f), mask))
            mstore(add(state, 192), and(add(mload(add(state, 192)), g), mask))
            mstore(add(state, 224), and(add(mload(add(state, 224)), h), mask))
        }
    }

    function _hashInit(Machine memory m, bool merkle) private pure {
        uint256[8] memory state = m.hashState;
        assembly ("memory-safe") {
            let repeat := 0x0000000000000001000000000000000100000000000000010000000000000001
            let iv := 0x6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19
            if merkle { iv := 0x16684ff553a717d21d4154c8574f1b56a37e524ef12dfd416303f9323754018c }
            for { let i := 0 } lt(i, 8) { i := add(i, 1) } {
                mstore(add(state, shl(5, i)), mul(and(shr(sub(224, shl(5, i)), iv), 0xffffffff), repeat))
            }
        }
    }

    function _compress4(Machine memory m, uint256 data, uint256 stride) private pure {
        uint256[64] memory w = m.schedule;
        assembly ("memory-safe") {
            for { let i := 0 } lt(i, 16) { i := add(i, 1) } {
                let p := add(data, shl(2, i))
                let value := shr(224, mload(p))
                value := or(value, shl(64, shr(224, mload(add(p, stride)))))
                value := or(value, shl(128, shr(224, mload(add(p, mul(stride, 2))))))
                value := or(value, shl(192, shr(224, mload(add(p, mul(stride, 3))))))
                mstore(add(w, shl(5, i)), value)
            }
        }
        _shaRounds(m);
    }

    function _digest4(Machine memory m, bool little) private pure {
        uint256[8] memory state = m.hashState;
        bytes32[4] memory output = m.batchDigests;
        assembly ("memory-safe") {
            for { let lane := 0 } lt(lane, 4) { lane := add(lane, 1) } {
                let result := 0
                for { let i := 0 } lt(i, 8) { i := add(i, 1) } {
                    let word := and(shr(shl(6, lane), mload(add(state, shl(5, i)))), 0xffffffff)
                    if little {
                        word := or(shl(8, and(word, 0x00ff00ff)), and(shr(8, word), 0x00ff00ff))
                        word := or(shl(16, and(word, 0xffff)), shr(16, word))
                    }
                    result := or(shl(32, result), word)
                }
                mstore(add(output, shl(5, lane)), result)
            }
        }
    }

    function _leaves4(
        Machine memory m, bytes calldata proof, uint256 offset, uint256 stride,
        uint256 length, uint256 count
    ) private pure {
        uint256 padded = (length + 72) & ~uint256(63);
        if (m.scratch.length < 4 * padded + 32) m.scratch = new bytes(4 * padded + 32);
        bytes memory scratch = m.scratch;
        uint256 data;
        assembly ("memory-safe") {
            data := add(scratch, 32)
            for { let lane := 0 } lt(lane, count) { lane := add(lane, 1) } {
                let p := add(data, mul(lane, padded))
                calldatacopy(p, add(add(proof.offset, offset), mul(lane, stride)), length)
                for { let end := add(p, length) } lt(end, add(p, padded)) { end := add(end, 32) } {
                    mstore(end, 0)
                }
                mstore8(add(p, length), 0x80)
                mstore(add(p, sub(padded, 8)), shl(192, mul(length, 8)))
            }
        }
        _hashInit(m, false);
        for (uint256 blockOffset; blockOffset < padded; blockOffset += 64) {
            _compress4(m, data + blockOffset, padded);
        }
        _digest4(m, false);
    }

    function _paths(
        Machine memory m, bytes calldata proof, uint256[] memory indices, uint256 shift,
        uint256 layer, uint256 offset, uint256 leafSize, uint256 depth
    ) private pure returns (bool) {
        uint256 stride = leafSize * 16 + depth * 32;
        for (uint256 q; q < indices.length; q += 4) {
            uint256 count = indices.length - q;
            if (count > 4) count = 4;
            _leaves4(m, proof, offset + q * stride, stride, leafSize * 16, count);
            bytes memory scratch = m.scratch;
            uint256 data;
            assembly ("memory-safe") { data := add(scratch, 32) }
            for (uint256 level; level < depth; ++level) {
                for (uint256 lane; lane < count; ++lane) {
                    uint256 siblingOffset = offset + (q + lane) * stride + leafSize * 16 + level * 32;
                    bytes32 h = m.batchDigests[lane];
                    uint256 bit = (indices[q + lane] >> (shift + level)) & 1;
                    assembly ("memory-safe") {
                        let p := add(data, shl(6, lane))
                        mstore(add(p, shl(5, bit)), h)
                        mstore(add(p, shl(5, xor(bit, 1))), calldataload(add(proof.offset, siblingOffset)))
                    }
                }
                _hashInit(m, true);
                _compress4(m, data, 64);
                _digest4(m, true);
            }
            for (uint256 lane; lane < count; ++lane) {
                uint256 position = layer + (indices[q + lane] >> (shift + depth)) * 32;
                if (m.batchDigests[lane] != bytes32(proof[position:position + 32])) return false;
            }
        }
        return true;
    }

    function _layer(Machine memory m, bytes calldata proof, bytes32 root, uint256 offset, uint256 depth)
        private
        pure
        returns (bool)
    {
        uint256 count = 1 << depth;
        bytes32[] memory hashes = new bytes32[](count);
        for (uint256 i; i < count; ++i) {
            hashes[i] = bytes32(proof[offset + i * 32:offset + (i + 1) * 32]);
        }
        return _fold(m, hashes) == root;
    }

    function _fold(Machine memory m, bytes32[] memory hashes) private pure returns (bytes32) {
        if (m.scratch.length < 288) m.scratch = new bytes(288);
        for (uint256 n = hashes.length; n > 1; n >>= 1) {
            for (uint256 i; i < n / 2; i += 4) {
                uint256 count = n / 2 - i;
                if (count > 4) count = 4;
                bytes memory scratch = m.scratch;
                uint256 data;
                assembly ("memory-safe") {
                    data := add(scratch, 32)
                    mcopy(data, add(add(hashes, 32), shl(6, i)), shl(6, count))
                }
                _hashInit(m, true);
                _compress4(m, data, 64);
                _digest4(m, true);
                for (uint256 lane; lane < count; ++lane) {
                    hashes[i + lane] = m.batchDigests[lane];
                }
            }
        }
        return hashes[0];
    }

    function _path(
        Machine memory m,
        bytes calldata proof,
        uint256 index,
        uint256 layer,
        uint256 offset,
        uint256 leafSize,
        uint256 depth
    ) private pure returns (bool) {
        bytes32 h = _shaCalldata(m, proof, offset, leafSize * 16);
        offset += leafSize * 16;
        for (uint256 i; i < depth; ++i) {
            bytes32 sibling = bytes32(proof[offset:offset + 32]);
            h = index & 1 == 0 ? _node(m, h, sibling) : _node(m, sibling, h);
            index >>= 1;
            offset += 32;
        }
        return h == bytes32(proof[layer + index * 32:layer + (index + 1) * 32]);
    }

    function _vector(
        Machine memory m,
        bytes calldata proof,
        bytes32 root,
        uint256 offset,
        uint256 leafSize,
        uint256 depth
    ) private pure returns (bool) {
        bytes32[] memory hashes = new bytes32[](1 << depth);
        for (uint256 i; i < hashes.length; i += 4) {
            uint256 count = hashes.length - i;
            if (count > 4) count = 4;
            _leaves4(m, proof, offset + i * leafSize * 16, leafSize * 16, leafSize * 16, count);
            for (uint256 lane; lane < count; ++lane) {
                hashes[i + lane] = m.batchDigests[lane];
            }
        }
        return _fold(m, hashes) == root;
    }
    struct FriOracle {
        bytes32 root;
        uint256 leafLog;
        uint256 depth;
        uint256 early;
        uint256 later;
        uint256 lift;
    }

    struct FriState {
        uint256 offset;
        uint256 end;
        uint256 bits;
        uint256 rate;
        uint256 finalCount;
        uint256 inputCount;
        uint256 roundCount;
        uint256 early;
        uint256 later;
        uint256 outerBits;
        uint256 queryLog;
        uint256[] indices;
        uint256[] claims;
        uint256[] challenges;
        uint256[] basis;
        uint256[] work;
        FriOracle[] oracles;
    }

    function _friConfig(bytes memory program, uint256 cursor, uint256[] memory registers)
        private
        pure
        returns (FriState memory s)
    {
        s.offset = _u32(program, cursor);
        s.end = _u32(program, cursor + 4);
        uint256 queries = _u32(program, cursor + 8) >> 16;
        s.bits = uint8(program[cursor + 10]);
        s.rate = uint8(program[cursor + 11]);
        s.finalCount = uint8(program[cursor + 12]);
        s.inputCount = uint8(program[cursor + 13]);
        s.roundCount = uint8(program[cursor + 14]);
        uint256 n = uint8(program[cursor + 15]);
        cursor += 16;
        s.challenges = new uint256[](n);
        for (uint256 i; i < n; ++i) {
            s.challenges[i] = registers[_u32(program, cursor)];
            cursor += 4;
        }
        s.basis = new uint256[](s.bits);
        for (uint256 i; i < s.bits; ++i) {
            uint256 value;
            assembly ("memory-safe") { value := shr(128, mload(add(add(program, 32), cursor))) }
            s.basis[i] = value;
            cursor += 16;
        }
        s.oracles = new FriOracle[](s.inputCount + s.roundCount);
        uint256 maximum = s.finalCount;
        for (uint256 i; i < s.oracles.length; ++i) {
            FriOracle memory o = s.oracles[i];
            o.root = bytes32(registers[_u32(program, cursor)]);
            o.leafLog = uint8(program[cursor + 4]);
            o.depth = uint8(program[cursor + 5]);
            cursor += 6;
            if (i < s.inputCount) {
                o.early = uint8(program[cursor]);
                o.later = uint8(program[cursor + 1]);
                o.lift = uint8(program[cursor + 2]);
                cursor += 3;
                if (o.early > s.early) s.early = o.early;
                if (o.later > s.later) s.later = o.later;
            }
            if (o.leafLog > maximum) maximum = o.leafLog;
        }
        s.work = new uint256[](uint256(1) << maximum);
        s.indices = new uint256[](queries);
        s.claims = new uint256[](queries);
        for (uint256 size = 1; size < queries; size <<= 1) {
            ++s.queryLog;
        }
        for (uint256 size = 1; size < s.inputCount; size <<= 1) {
            ++s.outerBits;
        }
    }

    function _friRead(FriState memory s, bytes calldata proof, uint256 count) private pure {
        for (uint256 i; i < count; ++i) {
            s.work[i] = _readLE(proof, s.offset + 16 * i, 16);
        }
    }

    function _friCoset(
        uint256[] memory values,
        uint256 count,
        uint256 index,
        uint256[] memory challenges,
        uint256 challengeOffset,
        uint256[] memory basis
    ) private pure returns (uint256) {
        for (uint256 round; round < count; ++round) {
            uint256 shift = count - round - 1;
            uint256 challenge = challenges[challengeOffset + round];
            for (uint256 j; j < (uint256(1) << shift); ++j) {
                uint256 blockIndex = (index << shift) | j;
                uint256 twiddle;
                for (uint256 bit = 1; blockIndex != 0; ++bit) {
                    if (blockIndex & 1 != 0) twiddle ^= basis[bit];
                    blockIndex >>= 1;
                }
                uint256 u = values[2 * j];
                uint256 v = values[2 * j + 1] ^ u;
                u ^= _mul(v, twiddle);
                values[j] = u ^ _mul(v ^ u, challenge);
            }
        }
        return values[0];
    }

    function _fri(
        Machine memory m,
        bytes memory program,
        uint256 cursor,
        uint256[] memory registers,
        bytes calldata proof
    ) private pure returns (bool, uint256) {
        FriState memory s = _friConfig(program, cursor, registers);
        for (uint256 q; q < s.indices.length; ++q) {
            s.indices[q] = _sample(m, 4) & ((uint256(1) << s.bits) - 1);
        }
        // Open each input oracle, fold its early/later interleaving, then batch
        // with the oracle-index equality indicator at the outer challenges.
        for (uint256 i; i < s.inputCount; ++i) {
            FriOracle memory o = s.oracles[i];
            uint256 layerDepth = s.queryLog < o.depth ? s.queryLog : o.depth;
            uint256 layer = s.offset;
            if (!_layer(m, proof, o.root, layer, layerDepth)) return (false, 0);
            s.offset += 32 << layerDepth;
            uint256 leaf = uint256(1) << o.leafLog;
            uint256 pathDepth = o.depth - layerDepth;
            uint256 scalar = 1;
            for (uint256 bit; bit < s.outerBits; ++bit) {
                uint256 challenge = s.challenges[s.early + bit];
                scalar = _mul(scalar, ((i >> bit) & 1) == 0 ? challenge ^ 1 : challenge);
            }
            if (!_paths(m, proof, s.indices, o.lift, layer, s.offset, leaf, pathDepth)) return (false, 0);
            for (uint256 q; q < s.indices.length; ++q) {
                _friRead(s, proof, leaf);
                for (uint256 bit = o.early + o.later; bit > 0; --bit) {
                    uint256 k = bit - 1;
                    uint256 challengeIndex = k < o.early
                        ? s.early - o.early + k
                        : s.early + s.outerBits + s.later - o.later + k - o.early;
                    uint256 challenge = s.challenges[challengeIndex];
                    uint256 half = uint256(1) << k;
                    for (uint256 j; j < half; ++j) {
                        s.work[j] ^= _mul(challenge, s.work[j + half] ^ s.work[j]);
                    }
                }
                s.claims[q] ^= _mul(s.work[0], scalar);
                s.offset += 16 * leaf + 32 * pathDepth;
            }
        }
        uint256 challengeOffset = s.early + s.outerBits + s.later;
        // Every intermediate queried leaf is authenticated, linked to the prior
        // claim, and reduced with the additive Gao-Mateer butterflies.
        for (uint256 i = s.inputCount; i + 1 < s.oracles.length; ++i) {
            FriOracle memory o = s.oracles[i];
            uint256 layerDepth = s.queryLog < o.depth ? s.queryLog : o.depth;
            uint256 layer = s.offset;
            if (!_layer(m, proof, o.root, layer, layerDepth)) return (false, 0);
            s.offset += 32 << layerDepth;
            uint256 leaf = uint256(1) << o.leafLog;
            uint256 pathDepth = o.depth - layerDepth;
            if (!_paths(m, proof, s.indices, o.leafLog, layer, s.offset, leaf, pathDepth)) return (false, 0);
            for (uint256 q; q < s.indices.length; ++q) {
                uint256 index = s.indices[q] >> o.leafLog;
                _friRead(s, proof, leaf);
                if (s.work[s.indices[q] & (leaf - 1)] != s.claims[q]) return (false, 0);
                s.claims[q] = _friCoset(s.work, o.leafLog, index, s.challenges, challengeOffset, s.basis);
                s.indices[q] = index;
                s.offset += 16 * leaf + 32 * pathDepth;
            }
            challengeOffset += o.leafLog;
        }
        FriOracle memory terminal = s.oracles[s.oracles.length - 1];
        uint256 terminalLeaf = uint256(1) << terminal.leafLog;
        if (!_vector(m, proof, terminal.root, s.offset, terminalLeaf, terminal.depth)) return (false, 0);
        for (uint256 q; q < s.indices.length; ++q) {
            if (_readLE(proof, s.offset + 16 * s.indices[q], 16) != s.claims[q]) return (false, 0);
        }
        uint256 finalValue;
        for (uint256 i; i < (uint256(1) << terminal.depth); ++i) {
            _friRead(s, proof, terminalLeaf);
            uint256 value = _friCoset(s.work, s.finalCount, i, s.challenges, challengeOffset, s.basis);
            if (i == 0) finalValue = value;
            else if (value != finalValue) return (false, 0);
            s.offset += 16 * terminalLeaf;
        }
        return (s.offset == s.end, finalValue);
    }
    // Raw LZMA1, fixed lc=1/lp=0/pb=2. The fixed constructor
    // literal supplies the compressed stream; proof bytes never enter it.
    function _unlzma(bytes memory compressed, uint256 size) private pure returns (bytes memory decoded) {
        decoded = new bytes(size + 32);
        uint256[3382] memory probabilities;
        uint256[9] memory state;
        assembly ("memory-safe") {
            // State: range, code, input pointer, probability pointer, rep[0..3], LZ state.
            function normalize(c) {
                let range := mload(c)
                if lt(range, 0x1000000) {
                    let p := mload(add(c, 64))
                    mstore(c, shl(8, range))
                    mstore(add(c, 32), and(or(shl(8, mload(add(c, 32))), byte(0, mload(p))), 0xffffffff))
                    mstore(add(c, 64), add(p, 1))
                }
            }
            function bit(c, index) -> value {
                let p := add(mload(add(c, 96)), shl(5, index))
                let prob := mload(p)
                let bound := mul(shr(11, mload(c)), prob)
                switch lt(mload(add(c, 32)), bound)
                case 1 {
                    mstore(c, bound)
                    mstore(p, add(prob, shr(5, sub(2048, prob))))
                }
                default {
                    value := 1
                    mstore(c, sub(mload(c), bound))
                    mstore(add(c, 32), sub(mload(add(c, 32)), bound))
                    mstore(p, sub(prob, shr(5, prob)))
                }
                normalize(c)
            }
            function tree(c, base, n) -> value {
                value := 1
                for { let i := 0 } lt(i, n) { i := add(i, 1) } { value := add(shl(1, value), bit(c, add(base, value))) }
                value := sub(value, shl(n, 1))
            }
            function reverseTree(c, base, n) -> value {
                let node := 1
                for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                    let b := bit(c, add(base, node))
                    node := add(shl(1, node), b)
                    value := or(value, shl(i, b))
                }
            }
            function direct(c, n) -> value {
                for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                    let range := shr(1, mload(c))
                    mstore(c, range)
                    let b := iszero(lt(mload(add(c, 32)), range))
                    if b { mstore(add(c, 32), sub(mload(add(c, 32)), range)) }
                    value := or(shl(1, value), b)
                    normalize(c)
                }
            }
            function length(c, base, pos) -> value {
                switch bit(c, base)
                case 0 { value := tree(c, add(add(base, 2), shl(3, pos)), 3) }
                default {
                    switch bit(c, add(base, 1))
                    case 0 { value := add(8, tree(c, add(add(base, 130), shl(3, pos)), 3)) }
                    default { value := add(16, tree(c, add(base, 258), 8)) }
                }
                value := add(value, 2)
            }
            function literal(c, base, matched, prediction) -> value {
                value := 1
                if matched {
                    for {} lt(value, 256) {} {
                        let expected := and(shr(7, prediction), 1)
                        prediction := shl(1, prediction)
                        let b := bit(c, add(add(base, shl(8, add(1, expected))), value))
                        value := add(shl(1, value), b)
                        if iszero(eq(expected, b)) { break }
                    }
                }
                for {} lt(value, 256) {} { value := add(shl(1, value), bit(c, add(base, value))) }
            }
            let start := add(decoded, 32)
            let out := start
            let end := add(start, size)
            let input := add(compressed, 32)
            if byte(0, mload(input)) { revert(0, 0) }
            mstore(state, 0xffffffff)
            mstore(add(state, 32), shr(224, mload(add(input, 1))))
            mstore(add(state, 64), add(input, 5))
            mstore(add(state, 96), probabilities)
            for { let p := probabilities } lt(p, add(probabilities, 108224)) { p := add(p, 32) } { mstore(p, 1024) }
            for {} lt(out, end) {} {
                let pos := and(sub(out, start), 3)
                let machine := mload(add(state, 256))
                switch bit(state, add(shl(4, machine), pos))
                case 0 {
                    let previous := 0
                    if gt(out, start) { previous := byte(0, mload(sub(out, 1))) }
                    let prediction := 0
                    if gt(machine, 6) { prediction := byte(0, mload(sub(sub(out, 1), mload(add(state, 128))))) }
                    mstore8(out, literal(state, add(1846, mul(shr(7, previous), 768)), gt(machine, 6), prediction))
                    out := add(out, 1)
                    switch lt(machine, 4)
                    case 1 { machine := 0 }
                    default { switch lt(machine, 10)
                    case 1 { machine := sub(machine, 3) }
                    default { machine := sub(machine, 6) } }
                }
                default {
                    let n := 0
                    switch bit(state, add(192, machine))
                    case 1 {
                        switch bit(state, add(204, machine))
                        case 0 {
                            if iszero(bit(state, add(240, add(shl(4, machine), pos)))) {
                                n := 1
                                switch lt(machine, 7)
                                case 1 { machine := 9 }
                                default { machine := 11 }
                            }
                        }
                        default {
                            let distance
                            switch bit(state, add(216, machine))
                            case 0 { distance := mload(add(state, 160)) }
                            default {
                                switch bit(state, add(228, machine))
                                case 0 { distance := mload(add(state, 192)) }
                                default {
                                    distance := mload(add(state, 224))
                                    mstore(add(state, 224), mload(add(state, 192)))
                                }
                                mstore(add(state, 192), mload(add(state, 160)))
                            }
                            mstore(add(state, 160), mload(add(state, 128)))
                            mstore(add(state, 128), distance)
                        }
                        if iszero(n) {
                            n := length(state, 1332, pos)
                            switch lt(machine, 7)
                            case 1 { machine := 8 }
                            default { machine := 11 }
                        }
                    }
                    default {
                        mstore(add(state, 224), mload(add(state, 192)))
                        mstore(add(state, 192), mload(add(state, 160)))
                        mstore(add(state, 160), mload(add(state, 128)))
                        n := length(state, 818, pos)
                        switch lt(machine, 7)
                        case 1 { machine := 7 }
                        default { machine := 10 }
                        let lenState := sub(n, 2)
                        if gt(lenState, 3) { lenState := 3 }
                        let slot := tree(state, add(432, shl(6, lenState)), 6)
                        let distance := slot
                        if gt(slot, 3) {
                            let bits := sub(shr(1, slot), 1)
                            distance := shl(bits, or(2, and(slot, 1)))
                            switch lt(slot, 14)
                            case 1 {
                                distance := add(
                                    distance,
                                    reverseTree(state, sub(add(688, distance), add(slot, 1)), bits)
                                )
                            }
                            default {
                                distance := add(distance, shl(4, direct(state, sub(bits, 4))))
                                distance := add(distance, reverseTree(state, 802, 4))
                            }
                        }
                        mstore(add(state, 128), distance)
                    }
                    let distance := add(mload(add(state, 128)), 1)
                    if or(gt(distance, sub(out, start)), gt(n, sub(end, out))) { revert(0, 0) }
                    let source := sub(out, distance)
                    for { let copied := 0 } lt(copied, n) {} {
                        let count := add(distance, copied)
                        if gt(count, sub(n, copied)) { count := sub(n, copied) }
                        mcopy(add(out, copied), source, count)
                        copied := add(copied, count)
                    }
                    out := add(out, n)
                }
                mstore(add(state, 256), machine)
                if gt(mload(add(state, 64)), add(input, mload(compressed))) { revert(0, 0) }
            }
            mstore(decoded, size)
        }
    }

    function _expandProgram(bytes memory encoded, uint256 size) private pure returns (bytes memory program) {
        program = new bytes(size + 32);
        uint256[256] memory previous;
        assembly ("memory-safe") {
            function operand(p, out, base, lane) -> q, next, value {
                let n := 0
                let shift := 0
                q := p
                for {} 1 {} {
                    let b := byte(0, mload(q))
                    q := add(q, 1)
                    n := or(n, shl(shift, and(b, 127)))
                    if iszero(and(b, 128)) { break }
                    shift := add(shift, 7)
                }
                let slot := add(base, shl(5, lane))
                value := add(mload(slot), xor(shr(1, n), sub(0, and(n, 1))))
                mstore(slot, value)
                mstore(out, shl(224, value))
                next := add(out, 4)
            }
            let p := add(encoded, 32)
            let end := add(p, mload(encoded))
            let out := add(program, 32)
            for {} lt(p, end) {} {
                let op := byte(0, mload(p))
                p := add(p, 1)
                mstore8(out, op)
                out := add(out, 1)
                let base := add(previous, shl(8, op))
                let n
                p, out, n := operand(p, out, base, 0)
                let fixed := 0
                let copied := 0
                switch op
                case 0 { copied := 16 }
                case 1 { fixed := 2 }
                case 2 { fixed := 2 }
                case 3 { fixed := 1 }
                case 4 {
                    fixed := 1
                    copied := 1
                }
                case 5 { fixed := 1 }
                case 6 {}
                case 13 {}
                case 7 { copied := 1 }
                case 8 { fixed := 2 }
                case 9 { fixed := 1 }
                case 10 {
                    fixed := 1
                    copied := 1
                }
                case 11 {
                    fixed := 1
                    copied := 1
                }
                case 12 {
                    fixed := 1
                    copied := 1
                }
                case 14 { fixed := 3 }
                case 15 { fixed := 5 }
                case 16 { fixed := 4 }
                case 17 { for { let i := 0 } lt(i, 128) { i := add(i, 1) } { p, out, n := operand(p, out, base, 1) } }
                case 18 {
                    fixed := 1
                    copied := 1
                }
                case 19 {
                    p, out, n := operand(p, out, base, 1)
                    for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                        let ignored
                        p, out, ignored := operand(p, out, base, 2)
                    }
                }
                case 20 { fixed := 3 }
                case 21 { p, out, copied := operand(p, out, base, 1) }
                case 22 {
                    fixed := 1
                    copied := 1
                }
                case 23 { p, out, copied := operand(p, out, base, 1) }
                case 24 {
                    fixed := 4
                    copied := 1
                }
                case 25 { p, out, copied := operand(p, out, base, 1) }
                case 26 {
                    fixed := 2
                    copied := 2
                }
                case 27 { fixed := 1 }
                case 28 { fixed := 1 }
                case 29 {
                    n := byte(0, mload(p))
                    mstore8(out, n)
                    p := add(p, 1)
                    out := add(out, 1)
                    for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                        let ignored
                        p, out, ignored := operand(p, out, base, 1)
                    }
                }
                case 30 { p, out, copied := operand(p, out, base, 1) }
                case 31 { fixed := 1 }
                default { revert(0, 0) }
                for { let i := 1 } iszero(gt(i, fixed)) { i := add(i, 1) } { p, out, n := operand(p, out, base, i) }
                mcopy(out, p, copied)
                out := add(out, copied)
                p := add(p, copied)
            }
            if or(iszero(eq(p, end)), iszero(eq(out, add(add(program, 32), size)))) { revert(0, 0) }
            mstore(program, size)
        }
    }

    function wiringTest(bytes memory data,uint256[] memory x,uint256[] memory y,uint256 lambda) external pure returns(uint256 value) {
        uint256 d;uint256 xp;uint256 yp;
        assembly ("memory-safe") { d:=add(data,32) xp:=add(x,32) yp:=add(y,32) }
        return _wiring(d,xp,yp,lambda,1);
    }
    function decompressTest(bytes memory b,uint256 n) external pure returns(bytes memory){return _unlzma(b,n);}
    function expandTest(bytes memory b,uint256 n) external pure returns(bytes memory){return _expandProgram(b,n);}
    function mulTest(uint a,uint b) external pure returns(uint){return _mul(a,b);}
    function squareTest(uint a) external pure returns(uint){return _square(a);}
    function inverseTest(uint a) external pure returns(uint){return _inverse(a);}
    function shaTest(bytes calldata b) external pure returns(bytes32){Machine memory m=_machine(b.length);return _shaCalldata(m,b,0,b.length);}
    function nodeTest(bytes32 a,bytes32 b) external pure returns(bytes32){Machine memory m=_machine(64);return _node(m,a,b);}
    function readTest(bytes calldata b) external pure returns(uint){return _readLE(b,0,16);}
    function hashesTest(bytes calldata data,uint256 length,uint256 count) external pure returns(bytes32[4] memory) {
        require(data.length == count * length && count > 0 && count <= 4);
        Machine memory m = _machine(data.length);
        _leaves4(m,data,0,length,length,count);
        return m.batchDigests;
    }
    function nodesTest(bytes32[8] calldata data) external pure returns(bytes32[4] memory) {
        Machine memory m = _machine(288);
        bytes memory scratch=m.scratch;
        uint256 p;
        assembly ("memory-safe") {p:=add(scratch,32) calldatacopy(p,data,256)}
        _hashInit(m,true);_compress4(m,p,64);_digest4(m,true);
        return m.batchDigests;
    }
}
