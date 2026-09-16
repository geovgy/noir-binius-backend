    // Primitive interpreter for the circuit-specialized verifier equations.
    // Field addition is XOR, multiplication is polynomial multiplication modulo
    // x^128+x^7+x^2+x+1. Proof field elements use little-endian canonical encoding.
    uint256 private constant SHA_WORD_MASK = 0x3fffffffc1fffffffe0ffffffff07fffffff83fffffffc1fffffffe0ffffffff;
    uint256 private constant SHA_WORD_REPEAT = 0x0000000040000000020000000010000000008000000004000000002000000001;

    struct Machine {
        bytes observed;
        uint256 observedLength;
        bytes32 sample;
        uint256 sampleIndex;
        bool sampling;
        bytes scratch;
        // 64 SHA round constants, then the standard and Merkle initial states.
        uint256[80] hashConstants;
        uint256[64] schedule;
        uint256[8] hashState;
        bytes32[7] batchDigests;
        uint256 hashMask;
        uint256 hashRepeat;
        uint256[8] hashWork;
        // Lazily allocated, call-local cache of complete Merkle input pairs.
        uint256 nodeCache;
        // Absolute calldata cursors; zero hintAt selects ordinary SHA execution.
        uint256 hintAt;
        uint256 hintEnd;
        // List of copied native SHA messages and their untrusted digest hints.
        uint256 hintQueue;
    }

    function _machine(uint256 capacity) private pure returns (Machine memory m) {
        m.hashMask = SHA_WORD_MASK;
        m.hashRepeat = SHA_WORD_REPEAT;
        m.observed = new bytes(capacity + 128);
        m.scratch = new bytes(capacity + 128);
        m.sample = hex"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        m.sampling = true;
        bytes memory rawConstants =
            hex"428a2f9871374491b5c0fbcfe9b5dba53956c25b59f111f1923f82a4ab1c5ed5d807aa9812835b01243185be550c7dc372be5d7480deb1fe9bdc06a7c19bf174e49b69c1efbe47860fc19dc6240ca1cc2de92c6f4a7484aa5cb0a9dc76f988da983e5152a831c66db00327c8bf597fc7c6e00bf3d5a7914706ca63511429296727b70a852e1b21384d2c6dfc53380d13650a7354766a0abb81c2c92e92722c85a2bfe8a1a81a664bc24b8b70c76c51a3d192e819d6990624f40e3585106aa07019a4c1161e376c082748774c34b0bcb5391c0cb34ed8aa4a5b9cca4f682e6ff3748f82ee78a5636f84c878148cc7020890befffaa4506cebbef9a3f7c67178f26a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd1916684ff553a717d21d4154c8574f1b56a37e524ef12dfd416303f9323754018c";
        uint256[80] memory constants = m.hashConstants;
        uint256 repeat = m.hashRepeat;
        assembly ("memory-safe") {
            // Broadcast the round constants and both IVs once per call.
            // Packed SHA uses seven lanes; scalar SHA uses the low 32 bits.
            for { let i := 0 } lt(i, 80) { i := add(i, 1) } {
                mstore(add(constants, shl(5, i)), mul(repeat, shr(224, mload(add(add(rawConstants, 32), shl(2, i))))))
            }
        }
    }

    // Register addresses come only from the circuit's checked fixed program.
    // Runtime proof values never select a register, and the constructor is the
    // only writer of that program. Each encoded slot is below REGISTER_COUNT.
    function _register(uint256[] memory registers, uint256 index) private pure returns (uint256 value) {
        assembly ("memory-safe") { value := mload(add(add(registers, 32), shl(5, index))) }
    }

    function _run(bytes memory program, bytes calldata proof, bytes calldata hints) private pure returns (bool) {
        Machine memory m = _machine(HASH_CAPACITY);
        if (hints.length != 0) {
            uint256 start;
            assembly ("memory-safe") { start := hints.offset }
            m.hintAt = start;
            m.hintEnd = start + hints.length;
        }
        uint256[] memory registers = new uint256[](REGISTER_COUNT);
        uint256 cursor;
        unchecked {
            while (cursor < program.length) {
                uint256 opcode = _programByte(program, cursor);
                uint256 dest = _programWord(program, cursor + 1);
                cursor += PROGRAM_WORD_BYTES + 1;
                uint256 a = _programWord(program, cursor);
                uint256 b = _programWord(program, cursor + PROGRAM_WORD_BYTES);
                uint256 value;
                if (opcode == 0) {
                    assembly ("memory-safe") { value := shr(128, mload(add(add(program, 32), cursor))) }
                    cursor += 16;
                } else if (opcode == 1) {
                    value = _register(registers, a) ^ _register(registers, b);
                    cursor += 2 * PROGRAM_WORD_BYTES;
                } else if (opcode == 2) {
                    value = a == b ? _square(_register(registers, a)) : _mul(_register(registers, a), _register(registers, b));
                    cursor += 2 * PROGRAM_WORD_BYTES;
                } else if (opcode == 3) {
                    value = _inverse(_register(registers, a));
                    cursor += PROGRAM_WORD_BYTES;
                } else if (opcode == 4) {
                    value = _readLE(proof, a, _programByte(program, cursor + PROGRAM_WORD_BYTES));
                    cursor += PROGRAM_WORD_BYTES + 1;
                } else if (opcode == 5) {
                    assembly ("memory-safe") { value := calldataload(add(proof.offset, a)) }
                    cursor += PROGRAM_WORD_BYTES;
                } else if (opcode == 6) {
                    value = _sample(m, 16);
                } else if (opcode == 7) {
                    value = _sample(m, 4) & ((1 << _programByte(program, cursor)) - 1);
                    ++cursor;
                } else if (opcode == 8) {
                    _observe(m, proof, a, b);
                    cursor += 2 * PROGRAM_WORD_BYTES;
                } else if (opcode == 9) {
                    if (_register(registers, a) != 0) return false;
                    cursor += PROGRAM_WORD_BYTES;
                } else if (opcode == 10) {
                    value = _register(registers, a) >> _programByte(program, cursor + PROGRAM_WORD_BYTES);
                    cursor += PROGRAM_WORD_BYTES + 1;
                } else if (opcode == 11) {
                    value = (_register(registers, a) >> _programByte(program, cursor + PROGRAM_WORD_BYTES)) & 1;
                    cursor += PROGRAM_WORD_BYTES + 1;
                } else if (opcode == 12) {
                    value = _register(registers, a) << _programByte(program, cursor + PROGRAM_WORD_BYTES);
                    cursor += PROGRAM_WORD_BYTES + 1;
                } else if (opcode == 13) {
                    uint256[128] memory fields;
                    for (uint256 i; i < 128; ++i) {
                        fields[i] = _sample(m, 16);
                    }
                    assembly ("memory-safe") { value := fields }
                } else if (opcode == 14) {
                    if (!_layer(m, proof, bytes32(_register(registers, a)), b, _programWord(program, cursor + 2 * PROGRAM_WORD_BYTES))) return false;
                    cursor += 3 * PROGRAM_WORD_BYTES;
                } else if (opcode == 15) {
                    if (!_path(
                            m,
                            proof,
                            _register(registers, a),
                            b,
                            _programWord(program, cursor + 2 * PROGRAM_WORD_BYTES),
                            _programWord(program, cursor + 3 * PROGRAM_WORD_BYTES),
                            _programWord(program, cursor + 4 * PROGRAM_WORD_BYTES)
                        )) return false;
                    cursor += 5 * PROGRAM_WORD_BYTES;
                } else if (opcode == 16) {
                    if (!_vector(
                            m, proof, bytes32(_register(registers, a)), b, _programWord(program, cursor + 2 * PROGRAM_WORD_BYTES), _programWord(program, cursor + 3 * PROGRAM_WORD_BYTES)
                        )) return false;
                    cursor += 4 * PROGRAM_WORD_BYTES;
                } else if (opcode == 17) {
                    uint256[128] memory rows;
                    for (uint256 i; i < 128; ++i) {
                        rows[i] = _register(registers, _programWord(program, cursor + PROGRAM_WORD_BYTES * i));
                    }
                    _transpose(rows);
                    assembly ("memory-safe") { value := rows }
                    cursor += 128 * PROGRAM_WORD_BYTES;
                } else if (opcode == 18) {
                    uint256 pointer = _register(registers, a);
                    uint256 row = _programByte(program, cursor + PROGRAM_WORD_BYTES);
                    assembly ("memory-safe") { value := mload(add(pointer, mul(row, 32))) }
                    cursor += PROGRAM_WORD_BYTES + 1;
                } else if (opcode == 19) {
                    uint256[] memory array = new uint256[](a);
                    for (uint256 i; i < a; ++i) {
                        array[i] = _register(registers, _programWord(program, cursor + PROGRAM_WORD_BYTES + PROGRAM_WORD_BYTES * i));
                    }
                    assembly ("memory-safe") { value := add(array, 32) }
                    cursor += PROGRAM_WORD_BYTES + PROGRAM_WORD_BYTES * a;
                } else if (opcode == 20) {
                    uint256 pointer = _register(registers, b);
                    uint256 index = _register(registers, a) & (_programWord(program, cursor + 2 * PROGRAM_WORD_BYTES) - 1);
                    assembly ("memory-safe") { value := mload(add(pointer, mul(index, 32))) }
                    cursor += 3 * PROGRAM_WORD_BYTES;
                } else if (opcode == 21) {
                    assembly ("memory-safe") { value := add(add(program, add(32, PROGRAM_WORD_BYTES)), cursor) }
                    cursor += PROGRAM_WORD_BYTES + a;
                } else if (opcode == 22) {
                    value = _register(registers, a) & ((uint256(1) << _programByte(program, cursor + PROGRAM_WORD_BYTES)) - 1);
                    cursor += PROGRAM_WORD_BYTES + 1;
                } else if (opcode == 23) {
                    value = _publicWiring(program, cursor + PROGRAM_WORD_BYTES, registers);
                    cursor += PROGRAM_WORD_BYTES + a;
                } else if (opcode == 24) {
                    value = _wiring(
                        _register(registers, a),
                        _register(registers, b),
                        _register(registers, _programWord(program, cursor + 2 * PROGRAM_WORD_BYTES)),
                        _register(registers, _programWord(program, cursor + 3 * PROGRAM_WORD_BYTES)),
                        _programByte(program, cursor + 4 * PROGRAM_WORD_BYTES)
                    );
                    cursor += 4 * PROGRAM_WORD_BYTES + 1;
                } else if (opcode == 25) {
                    bool success;
                    (success, value) = _fri(m, program, cursor + PROGRAM_WORD_BYTES, registers, proof);
                    if (!success) return false;
                    cursor += PROGRAM_WORD_BYTES + a;
                } else if (opcode == 26) {
                    value = _vectorBinary(
                        _register(registers, a), _register(registers, b), _programByte(program, cursor + 2 * PROGRAM_WORD_BYTES), _programByte(program, cursor + 2 * PROGRAM_WORD_BYTES + 1)
                    );
                    cursor += 2 * PROGRAM_WORD_BYTES + 2;
                } else if (opcode == 27) {
                    uint256[128] memory fields;
                    assembly ("memory-safe") { value := fields }
                    _readFields(value, proof, a, 128);
                    cursor += PROGRAM_WORD_BYTES;
                } else if (opcode == 28) {
                    uint256[128] memory powers;
                    powers[0] = _register(registers, a);
                    for (uint256 i = 1; i < 128; ++i) {
                        powers[i] = _square(powers[i - 1]);
                    }
                    assembly ("memory-safe") { value := powers }
                    cursor += PROGRAM_WORD_BYTES;
                } else if (opcode == 29) {
                    uint256 n = _programByte(program, cursor);
                    uint256[128] memory values;
                    values[0] = 1;
                    for (uint256 bit; bit < n; ++bit) {
                        uint256 r = _register(registers, _programWord(program, cursor + 1 + PROGRAM_WORD_BYTES * bit));
                        uint256 size = uint256(1) << bit;
                        for (uint256 i; i < size; ++i) {
                            uint256 high = _mul(values[i], r);
                            values[i] ^= high;
                            values[i + size] = high;
                        }
                    }
                    assembly ("memory-safe") { value := values }
                    cursor += 1 + PROGRAM_WORD_BYTES * n;
                } else if (opcode == 30) {
                    value = _innerWiring(program, cursor + PROGRAM_WORD_BYTES, registers);
                    cursor += PROGRAM_WORD_BYTES + a;
                } else if (opcode == 31) {
                    uint256[128] memory rows;
                    uint256 pointer = _register(registers, a);
                    assembly ("memory-safe") { mcopy(rows, pointer, 4096) }
                    _transpose(rows);
                    assembly ("memory-safe") { value := rows }
                    cursor += PROGRAM_WORD_BYTES;
                } else {
                    return false;
                }
                assembly ("memory-safe") { mstore(add(add(registers, 32), shl(5, dest)), value) }
            }
        }
        // A true result requires every supplied digest to equal the SHA result
        // recomputed here. No successful path can bypass these deferred checks.
        return cursor == program.length && _checkShaHints(m);
    }

    function _axis(uint256[] memory point, uint256 start, uint256 count, uint256 index)
        private
        pure
        returns (uint256 value)
    {
        // The checked inner-wiring program fixes this coordinate range.
        value = 1;
        unchecked {
            for (uint256 i; i < count; ++i) {
                uint256 coordinate;
                assembly ("memory-safe") { coordinate := mload(add(add(point, 32), shl(5, add(start, i)))) }
                value = _mul(value, coordinate ^ (((index >> i) & 1) ^ 1));
            }
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
        // All dimensions and cursors come from the fixed, checked program.
        unchecked {
            uint256 scratchStart;
            assembly ("memory-safe") { scratchStart := mload(0x40) }
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
            // All points and prepared descriptors are local; only a scalar escapes.
            assembly ("memory-safe") { mstore(0x40, scratchStart) }
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
        // This is a polynomial term, with no transcript interaction or proof
        // assertion inside _wiring. A zero coefficient makes its exact value zero.
        if (scalar == 0) return 0;
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
            uint256 value;
            if (kind & 1 == 0) value = a ^ b;
            // These identities hold for every field element, including values
            // read from an invalid proof. No nonzero assumption is introduced.
            else {
                assembly ("memory-safe") { value := and(gt(a, 1), gt(b, 1)) }
                if (value != 0) value = _mul(a, b);
                else assembly ("memory-safe") { value := mul(a, b) }
            }
            // The loop bounds this store to the allocated 128-word vector.
            assembly ("memory-safe") { mstore(add(values, shl(5, i)), value) }
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
        private pure returns (uint256 result)
    {
        uint256 values;
        uint256 point;
        uint256 previous;
        uint256 p;
        uint256 leaves;
        uint256 end;
        uint256 scratchStart;
        // Every address below is part of the circuit's immutable program.
        // Leaves and nodes are filled in order; no proof-supplied address is used.
        assembly ("memory-safe") {
            function uv(q) -> v, next {
                let b := byte(0, mload(q))
                v := and(b, 127)
                next := add(q, 1)
                for { let shift := 7 } and(b, 128) { shift := add(shift, 7) } {
                    b := byte(0, mload(next))
                    v := or(v, shl(shift, and(b, 127)))
                    next := add(next, 1)
                }
            }
            let header := add(add(data, 32), cursor)
            leaves := shr(224, mload(header))
            end := add(leaves, shr(224, mload(add(header, 4))))
            let dimensions := byte(0, mload(add(header, 8)))
            scratchStart := mload(0x40)
            previous := scratchStart
            values := add(previous, 192)
            point := add(values, shl(5, end))
            mstore(0x40, add(point, shl(5, dimensions)))
            for { let i := 0 } lt(i, 192) { i := add(i, 32) } { mstore(add(previous, i), 0) }
            p := add(header, 25)
            for { let i := 0 } lt(i, dimensions) { i := add(i, 1) } {
                mstore(add(point, shl(5, i)), mload(add(add(registers, 32), shl(5, shr(224, mload(p))))))
                p := add(p, 4)
            }
            for { let i := 0 } lt(i, leaves) { i := add(i, 1) } {
                let code
                code, p := uv(p)
                let kind := and(code, 1)
                let delta := shr(1, code)
                let slot := add(previous, shl(5, kind))
                let index := add(mload(slot), xor(shr(1, delta), sub(0, and(delta, 1))))
                mstore(slot, index)
                let value := mload(add(add(registers, 32), shl(5, index)))
                if kind {
                    value := mload(add(value, shl(5, byte(0, mload(p)))))
                    p := add(p, 1)
                }
                mstore(add(values, shl(5, i)), value)
            }
            previous := add(previous, 64)
        }
        for (uint256 i = leaves; i < end; ++i) {
            uint256 a;
            uint256 b;
            uint256 r;
            assembly ("memory-safe") {
                function child(q, slot) -> value, next {
                    let octet := byte(0, mload(q))
                    let delta := and(octet, 127)
                    next := add(q, 1)
                    for { let shift := 7 } and(octet, 128) { shift := add(shift, 7) } {
                        octet := byte(0, mload(next))
                        delta := or(delta, shl(shift, and(octet, 127)))
                        next := add(next, 1)
                    }
                    value := add(mload(slot), xor(shr(1, delta), sub(0, and(delta, 1))))
                    mstore(slot, value)
                }
                let code := byte(0, mload(p))
                let index
                index, p := child(add(p, 1), add(previous, shl(5, and(code, 1))))
                a := mload(add(values, shl(5, index)))
                index, p := child(p, add(previous, shl(5, add(2, and(shr(1, code), 1)))))
                b := mload(add(values, shl(5, index)))
                r := mload(add(point, shl(5, shr(2, code))))
            }
            uint256 value = a ^ _mul(r, a ^ b);
            assembly ("memory-safe") { mstore(add(values, shl(5, i)), value) }
        }
        uint256 sumA;
        uint256 sumB;
        uint256 sumC;
        uint256 lambda;
        assembly ("memory-safe") {
            let header := add(add(data, 32), cursor)
            sumA := mload(add(values, shl(5, shr(224, mload(add(header, 9))))))
            sumB := mload(add(values, shl(5, shr(224, mload(add(header, 13))))))
            sumC := mload(add(values, shl(5, shr(224, mload(add(header, 17))))))
            lambda := mload(add(add(registers, 32), shl(5, shr(224, mload(add(header, 21))))))
        }
        result = sumA ^ _mul(lambda, sumB ^ _mul(lambda, sumC));
        assembly ("memory-safe") { mstore(0x40, scratchStart) }
    }

    // The instruction stream and all backward offsets are fixed by the key.
    // Parallel operand streams keep repeated operations compact in initcode.
    function _factoredWiring(uint256 data, uint256 pointX, uint256 pointY, uint256 lambda)
        private pure returns (uint256 result)
    {
        uint256 values;
        uint256 start;
        uint256 finish;
        uint256 root;
        uint256 streamA;
        uint256 streamB;
        uint256 scratchStart;
        uint256 square = _square(lambda);
        assembly ("memory-safe") {
            function uv(p) -> value, next {
                let b := byte(0, mload(p))
                value := and(b, 127)
                next := add(p, 1)
                for { let shift := 7 } and(b, 128) { shift := add(shift, 7) } {
                    b := byte(0, mload(next))
                    value := or(value, shl(shift, and(b, 127)))
                    next := add(next, 1)
                }
            }
            let nx := byte(0, mload(data))
            let ny := byte(0, mload(add(data, 1)))
            let n := add(nx, ny)
            let count
            count, data := uv(add(data, 2))
            root, data := uv(data)
            let aBytes
            aBytes, data := uv(data)
            streamA := add(data, count)
            streamB := add(streamA, aBytes)
            scratchStart := mload(0x40)
            values := scratchStart
            start := add(values, shl(5, add(8, shl(1, n))))
            finish := add(start, shl(5, count))
            mstore(0x40, finish)
            mstore(values, 0)
            mstore(add(values, 32), 1)
            mstore(add(values, 64), lambda)
            mstore(add(values, 96), xor(lambda, 1))
            mstore(add(values, 128), square)
            mstore(add(values, 160), xor(square, 1))
            mstore(add(values, 192), xor(square, lambda))
            mstore(add(values, 224), xor(xor(square, lambda), 1))
            let points := add(values, 256)
            mcopy(points, pointX, shl(5, nx))
            mcopy(add(points, shl(5, nx)), pointY, shl(5, ny))
            for { let i := 0 } lt(i, shl(5, n)) { i := add(i, 32) } {
                mstore(add(add(points, shl(5, n)), i), xor(mload(add(points, i)), 1))
            }
        }
        for (uint256 dest = start; dest < finish;) {
            uint256 code;
            uint256 a;
            uint256 b;
            uint256 r;
            assembly ("memory-safe") {
                function uv(p) -> value, next {
                    let octet := byte(0, mload(p))
                    value := and(octet, 127)
                    next := add(p, 1)
                    for { let shift := 7 } and(octet, 128) { shift := add(shift, 7) } {
                        octet := byte(0, mload(next))
                        value := or(value, shl(shift, and(octet, 127)))
                        next := add(next, 1)
                    }
                }
                code := byte(0, mload(data))
                data := add(data, 1)
                let delta
                delta, streamA := uv(streamA)
                a := mload(sub(dest, shl(5, delta)))
                delta, streamB := uv(streamB)
                b := mload(sub(dest, shl(5, delta)))
                r := mload(add(values, shl(5, add(code, 7))))
            }
            uint256 value = code == 0 ? _mul(a, b) : a ^ _mul(r, a ^ b);
            assembly ("memory-safe") { mstore(dest, value) dest := add(dest, 32) }
        }
        assembly ("memory-safe") {
            result := mload(add(values, shl(5, root)))
            mstore(0x40, scratchStart)
        }
    }

    function _wiring(uint256 data, uint256 pointX, uint256 pointY, uint256 lambda, uint256 mode)
        private
        pure
        returns (uint256 result)
    {
        uint256 factored;
        if (true /* factored wiring */) {
            assembly ("memory-safe") {
                factored := eq(byte(0, mload(data)), 255)
                data := add(data, factored)
            }
            if (factored != 0 && mode != 0 && mode != 3) {
                assembly ("memory-safe") {
                    if iszero(eq(mode, 1)) { pointX := mload(pointX) }
                    if eq(mode, 2) { pointY := mload(pointY) }
                }
                return _factoredWiring(data, pointX, pointY, lambda);
            }
        }
        assembly ("memory-safe") {
            function fm(a, b) -> r {
                // Five interleaved coefficient lanes, with five bits per digit.
                // Each integer-product digit sums at most 26 one-bit products,
                // so it cannot carry into the next digit. Masking extracts parity.
                // Inputs are canonical 128-bit field elements. Product masks
                // below retain the full 255 possible polynomial coefficients.
                let a0 := and(a, 0x21084210842108421084210842108421)
                let b0 := and(b, 0x21084210842108421084210842108421)
                let a1 := and(a, 0x42108421084210842108421084210842)
                let b1 := and(b, 0x42108421084210842108421084210842)
                let a2 := and(a, 0x84210842108421084210842108421084)
                let b2 := and(b, 0x84210842108421084210842108421084)
                let a3 := and(a, 0x08421084210842108421084210842108)
                let b3 := and(b, 0x08421084210842108421084210842108)
                let a4 := and(a, 0x10842108421084210842108421084210)
                let b4 := and(b, 0x10842108421084210842108421084210)
                // Balance the XOR tree to limit simultaneous intermediates on
                // the EVM stack. All 25 products and five parity masks remain.
                r := xor(
                    xor(
                        and(xor(xor(mul(a0, b0), mul(a1, b4)), xor(mul(a2, b3), xor(mul(a3, b2), mul(a4, b1)))), 0x8421084210842108421084210842108421084210842108421084210842108421),
                        and(xor(xor(mul(a0, b1), mul(a1, b0)), xor(mul(a2, b4), xor(mul(a3, b3), mul(a4, b2)))), 0x0842108421084210842108421084210842108421084210842108421084210842)
                    ),
                    xor(
                        and(xor(xor(mul(a0, b2), mul(a1, b1)), xor(mul(a2, b0), xor(mul(a3, b4), mul(a4, b3)))), 0x1084210842108421084210842108421084210842108421084210842108421084),
                        xor(
                            and(xor(xor(mul(a0, b3), mul(a1, b2)), xor(mul(a2, b1), xor(mul(a3, b0), mul(a4, b4)))), 0x2108421084210842108421084210842108421084210842108421084210842108),
                            and(xor(xor(mul(a0, b4), mul(a1, b3)), xor(mul(a2, b2), xor(mul(a3, b1), mul(a4, b0)))), 0x4210842108421084210842108421084210842108421084210842108421084210)
                        )
                    )
                )
                // Fuse the two reductions as in _mul. A product of two
                // 128-bit polynomials has no coefficient at degree 255.
                let h := shr(128, r)
                h := xor(h, xor(shr(126, h), shr(121, h)))
                r := and(xor(xor(r, h), xor(shl(1, h), xor(shl(2, h), shl(7, h)))), 0xffffffffffffffffffffffffffffffff)
            }
            function times(a, b) -> r {
                // Integer and binary-field multiplication agree when either
                // operand is zero or one. Every other product uses the full
                // polynomial multiplication and reduction in fm.
                switch and(gt(a, 1), gt(b, 1))
                case 0 { r := mul(a, b) }
                default { r := fm(a, b) }
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
            // Store suffix equality tensors as cumulative sums in chunks of
            // at most nine coordinates. For each starting coordinate lo, the
            // row begins at lo + 1024 - 2^(10-lo) and includes both endpoints.
            // F_lo(2i)=F_{lo+1}(i); F_lo(2i+1)=F_{lo+1}(i+1)+r*eq_{lo+1}(i).
            // Adjacent differences recover eq. Only actual coordinates of the
            // final chunk are initialized or queried. The separate 4096-entry
            // memo retains repeated complete suffix evaluations.
            function prepare(point, n) -> descriptor {
                descriptor := mload(0x40)
                let memo := add(descriptor, 128)
                let table := add(memo, 131072)
                calldatacopy(memo, calldatasize(), 131072)
                let chunks := div(add(n, 8), 9)
                mstore(0x40, add(table, mul(chunks, 33056)))
                mstore(descriptor, point)
                mstore(add(descriptor, 32), table)
                mstore(add(descriptor, 64), 0)
                mstore(add(descriptor, 96), n)
                for { let chunk := 0 } lt(chunk, chunks) { chunk := add(chunk, 1) } {
                    let base := add(table, mul(chunk, 33056))
                    let bits := sub(n, mul(chunk, 9))
                    if gt(bits, 9) { bits := 9 }
                    let empty := add(base, shl(5, add(bits, sub(1024, shl(sub(10, bits), 1)))))
                    mstore(empty, 0)
                    mstore(add(empty, 32), 1)
                    for { let lo := bits } lo {} {
                        lo := sub(lo, 1)
                        let bit := add(mul(chunk, 9), lo)
                        let r := mload(add(point, shl(5, bit)))
                        let start := add(base, shl(5, add(lo, sub(1024, shl(sub(10, lo), 1)))))
                        let previous := add(base, shl(5, add(add(lo, 1), sub(1024, shl(sub(9, lo), 1)))))
                        let size := shl(sub(sub(bits, 1), lo), 1)
                        let before := 0
                        for { let i := 0 } lt(i, size) { i := add(i, 1) } {
                            let after := mload(add(previous, shl(5, add(i, 1))))
                            let high := times(xor(before, after), r)
                            mstore(add(start, shl(6, i)), before)
                            mstore(add(add(start, shl(6, i)), 32), xor(after, high))
                            before := after
                        }
                        mstore(add(start, shl(6, size)), 1)
                    }
                }
            }
            function prefix(point, index, n) -> value {
                // Marginalize the first chunk when at most three high bits
                // remain: their complete equality tensor sums to one.
                if and(gt(n, 5), lt(n, 10)) {
                    let bits := mload(add(point, 96))
                    if gt(bits, 9) { bits := 9 }
                    let stride := shl(n, 1)
                    let table := mload(add(point, 32))
                    let end := add(table, shl(add(bits, 5), 1))
                    let p := add(table, shl(5, and(index, sub(stride, 1))))
                    for {} lt(p, end) { p := add(p, shl(5, stride)) } {
                        value := xor(value, xor(mload(p), mload(add(p, 32))))
                    }
                    leave
                }
                value := 1
                let coordinates := mload(point)
                for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                    value := times(value, xor(mload(add(coordinates, shl(5, i))), xor(and(shr(i, index), 1), 1)))
                }
            }
            function part(point, index, lo) -> value {
                // With u32 matrix indices and lo <= 32, the complete key
                // fits in 39 bits. Store it alongside the 128-bit field value.
                // The point itself is implicit in this descriptor-owned cache.
                // Share products of remaining chunks, checking the complete
                // key before reuse. A final whole chunk is already tabulated
                // and does not need a second memo lookup. At most four chunks
                // cover a u32 index, including a partial final chunk.
                let key := or(shl(6, add(shr(lo, index), 1)), lo)
                let slot := add(add(point, 128), shl(5, and(shr(52, mul(key, 0x9e3779b97f4a7c15)), 4095)))
                let cached := mload(slot)
                if eq(and(cached, 0xffffffffffffffff), key) {
                    value := shr(64, cached)
                    leave
                }
                let n := mload(add(point, 96))
                value := 1
                if lt(lo, n) {
                    let table := add(mload(add(point, 32)), mul(div(lo, 9), 33056))
                    let boundary := mul(add(div(lo, 9), 1), 9)
                    let size := shl(sub(boundary, lo), 1)
                    let base := add(mod(lo, 9), sub(1024, shl(sub(10, mod(lo, 9)), 1)))
                    let entry := add(base, and(shr(lo, index), sub(size, 1)))
                    let p := add(table, shl(5, entry))
                    value := xor(mload(p), mload(add(p, 32)))
                    if lt(boundary, n) {
                        let high
                        switch lt(add(boundary, 9), n)
                        case 1 { high := part(point, index, boundary) }
                        default {
                            // A final whole chunk is already materialized. Read
                            // it directly without displacing a product memo entry.
                            let q := add(add(table, 33056), shl(5, and(shr(boundary, index), 511)))
                            high := xor(mload(q), mload(add(q, 32)))
                        }
                        value := fm(value, high)
                    }
                }
                mstore(slot, or(shl(64, value), key))
            }
            function power(n) -> yes { yes := and(gt(n, 0), iszero(and(n, sub(n, 1)))) }
            // All callers pass a positive stride or count.
            function log(n) -> k { k := sub(255, clz(n)) }
            // Largest aligned dyadic block contained in the remaining interval.
            function block(start, remaining) -> k, n {
                // remaining > 0 at every call. For start == 0, aligned is
                // 2^256-1, so the remaining-length bound is selected.
                k := sub(255, clz(remaining))
                let aligned := sub(255, clz(and(start, sub(0, start))))
                if lt(aligned, k) { k := aligned }
                n := shl(k, 1)
            }
            // Sum eq(point[lo..], j) for j below index>>lo. Combining a
            // higher chunk H and lower chunk L gives F_H + eq_H * F_L.
            function prefixMass(point, index, lo) -> value {
                let n := mload(add(point, 96))
                if iszero(shr(lo, index)) { leave }
                if shr(n, index) { value := 1 leave }
                let table := mload(add(point, 32))
                for {} lt(lo, n) {} {
                    let chunk := div(lo, 9)
                    let boundary := mul(add(chunk, 1), 9)
                    let size := shl(sub(boundary, lo), 1)
                    let base := add(mod(lo, 9), sub(1024, shl(sub(10, mod(lo, 9)), 1)))
                    let entry := add(base, and(shr(lo, index), sub(size, 1)))
                    let p := add(add(table, mul(chunk, 33056)), shl(5, entry))
                    let before := mload(p)
                    value := xor(before, times(xor(before, mload(add(p, 32))), value))
                    lo := boundary
                }
            }
            function interval(point, start, stride, count) -> value {
                let shift := log(stride)
                let low := prefix(point, start, shift)
                value := times(low, xor(prefixMass(point, start, shift), prefixMass(point, add(start, mul(count, stride)), shift)))
            }
            // Four states track carries into the row and column separately.
            // Matrix indices are u32; both low-bit prefixes fit in this key.
            // A complete key match is required. Collisions evict entries and
            // cause recomputation. Each point pair gets a fresh cache.
            // The nonzero key fits below bit 88. Four canonical 128-bit states
            // and that key fit in three words: key|s0<<128, s1|s2<<128, s3.
            function carryKey(a, b, k, row, column) -> key {
                let mask := sub(shl(k, 1), 1)
                key := or(shl(80, add(a, 1)), or(shl(72, b), or(shl(64, k), or(shl(32, and(row, mask)), and(column, mask)))))
            }
            function cacheSlot(cache, key) -> slot {
                let hash := mul(xor(key, shr(41, key)), 0x9e3779b97f4a7c15)
                hash := xor(hash, shr(37, hash))
                slot := add(add(cache, 288), mul(and(hash, mload(cache)), 96))
            }
            function carryStep(out, state, xx, yy, bits, product) {
                // With row carry zero and row-offset bit zero, only the
                // two column-carry states can be nonzero. Their total has the
                // same recurrence, and one output is a single product.
                if iszero(or(shr(1, bits), or(mload(add(state, 64)), mload(add(state, 96))))) {
                    let s0 := mload(state)
                    let s1 := mload(add(state, 32))
                    let total := times(xor(xx, yy), xor(s0, s1))
                    switch bits
                    case 0 {
                        let t1 := times(xor(xx, product), s1)
                        mstore(out, xor(xor(total, s0), t1))
                        mstore(add(out, 32), t1)
                    }
                    case 1 {
                        let t0 := times(xor(yy, product), s0)
                        mstore(out, t0)
                        mstore(add(out, 32), xor(xor(total, s1), t0))
                    }
                    mstore(add(out, 64), 0)
                    mstore(add(out, 96), 0)
                    leave
                }
                // Complement both point coordinates and permute carries by
                // XOR 3 when the row-offset bit is one. The free summation
                // bit is complemented too, leaving offset cases 00 and 01.
                let bit := shr(1, bits)
                let flip := mul(bit, 96)
                xx := xor(xx, bit)
                yy := xor(yy, bit)
                // The original x*y product is cached per coordinate pair.
                // Complementing both inputs gives x*y+x+y+1; x+y itself
                // is unchanged by that complement in characteristic two.
                let d := xor(product, and(sub(0, bit), xor(1, xor(xx, yy))))
                let b := xor(yy, d)
                let c := xor(xx, d)
                let a := xor(1, xor(xor(xx, yy), d))
                // The sum of all four outgoing states is a single
                // multiplication by x+y, plus one incoming parity class.
                // In normalized coordinates, T=sum(s_i) gives:
                //   case 00: T'=(x+y)*T+s_0+s_3
                //   case 01: T'=(x+y)*T+s_1+s_2.
                // Recover one state from that sum instead of expanding it.
                let total := times(xor(xx, yy), xor(xor(mload(state), mload(add(state, 32))), xor(mload(add(state, 64)), mload(add(state, 96)))))
                switch and(xor(bits, shr(1, bits)), 1)
                case 0 {
                    total := xor(total, xor(mload(add(state, flip)), mload(add(state, xor(96, flip)))))
                    mstore(add(out, xor(32, flip)), times(c, mload(add(state, xor(32, flip)))))
                    mstore(add(out, xor(64, flip)), times(b, mload(add(state, xor(64, flip)))))
                    mstore(add(out, xor(96, flip)), times(a, mload(add(state, xor(96, flip)))))
                    mstore(add(out, flip), xor(total, xor(mload(add(out, xor(32, flip))), xor(mload(add(out, xor(64, flip))), mload(add(out, xor(96, flip)))))))
                }
                case 1 {
                    total := xor(total, xor(mload(add(state, xor(32, flip))), mload(add(state, xor(64, flip)))))
                    mstore(add(out, flip), xor(times(b, mload(add(state, flip))), times(d, mload(add(state, xor(64, flip))))))
                    mstore(add(out, xor(64, flip)), 0)
                    mstore(add(out, xor(96, flip)), xor(times(a, mload(add(state, xor(64, flip)))), times(b, mload(add(state, xor(96, flip))))))
                    mstore(add(out, xor(32, flip)), xor(total, xor(mload(add(out, flip)), mload(add(out, xor(96, flip))))))
                }
            }
            function carry(x, y, a, b, k, row, column) -> state {
                let cache := mload(add(x, 64))
                let level := k
                state := add(cache, 32)
                mstore(state, 1)
                mstore(add(state, 32), 0)
                mstore(add(state, 64), 0)
                mstore(add(state, 96), 0)
                for {} level { level := sub(level, 1) } {
                    let key := carryKey(a, b, level, row, column)
                    let slot := cacheSlot(cache, key)
                    let head := mload(slot)
                    if eq(and(head, 0xffffffffffffffffffffffffffffffff), key) {
                        // Unpack into the first scratch state. Computation then
                        // alternates the two scratch buffers without aliasing
                        // a packed record that a later cache write can evict.
                        mstore(state, shr(128, head))
                        let pair := mload(add(slot, 32))
                        mstore(add(state, 32), and(pair, 0xffffffffffffffffffffffffffffffff))
                        mstore(add(state, 64), shr(128, pair))
                        mstore(add(state, 96), mload(add(slot, 64)))
                        break
                    }
                }
                for {} lt(level, k) { level := add(level, 1) } {
                    let out := add(cache, 32)
                    if eq(state, out) { out := add(out, 128) }
                    let bits := or(shl(1, and(shr(level, row), 1)), and(shr(level, column), 1))
                    let ix := add(a, level)
                    let iy := add(b, level)
                    let xx := mload(add(mload(x), shl(5, ix)))
                    let yy := mload(add(mload(y), shl(5, iy)))
                    let coefficients := add(add(cache, 288), mul(add(mload(cache), 1), 96))
                    let slotXY := add(coefficients, shl(5, add(mul(ix, mload(add(y, 96))), iy)))
                    let product := mload(slotXY)
                    if iszero(product) {
                        // Zero is a cache miss, including an actual zero
                        // product. Recomputing it preserves every field value.
                        product := times(xx, yy)
                        mstore(slotXY, product)
                    }
                    carryStep(out, state, xx, yy, bits, product)
                    let key := carryKey(a, b, add(level, 1), row, column)
                    let slot := cacheSlot(cache, key)
                    mstore(slot, or(key, shl(128, mload(out))))
                    mstore(add(slot, 32), or(mload(add(out, 32)), shl(128, mload(add(out, 64)))))
                    mstore(add(slot, 64), mload(add(out, 96)))
                    state := out
                }
            }
            function rounded(x, y, row, column, a, b, k) -> value {
                let state := carry(x, y, a, b, k, shr(a, row), shr(b, column))
                let x0 := part(x, row, add(a, k))
                let y0 := part(y, column, add(b, k))
                let x1 := 0
                let y1 := 0
                if or(mload(add(state, 64)), mload(add(state, 96))) {
                    x1 := part(x, add(row, shl(add(a, k), 1)), add(a, k))
                }
                if or(mload(add(state, 32)), mload(add(state, 96))) {
                    y1 := part(y, add(column, shl(add(b, k), 1)), add(b, k))
                }
                value := xor(times(x0, xor(times(mload(state), y0), times(mload(add(state, 32)), y1))), times(x1, xor(times(mload(add(state, 64)), y0), times(mload(add(state, 96)), y1))))
            }
            // Sum eq(x,row+t*2^a)*eq(y,column+t*2^b). For an aligned row
            // block, the row carry is zero and only states 00/01 contribute.
            // Nearly complete runs also use blocks with two unaligned offsets.
            function progression(x, nx, y, row, column, a, b, count) -> value {
                let fixedLow := times(prefix(x, row, a), prefix(y, column, b))
                // Complete a nearly full interval in the run parameter,
                // then cancel the extra points in characteristic two.
                {
                let k := add(log(sub(count, 1)), 1)
                let size := shl(k, 1)
                if and(and(gt(count, 8), lt(sub(size, count), 4)), and(lt(add(row, shl(a, sub(size, 1))), shl(nx, 1)), lt(add(column, shl(b, sub(size, 1))), shl(mload(add(y, 96)), 1)))) {
                    value := times(fixedLow, rounded(x, y, row, column, a, b, k))
                    for { let i := count } lt(i, size) { i := add(i, 1) } {
                        value := xor(value, times(part(x, add(row, shl(a, i)), 0), part(y, add(column, shl(b, i)), 0)))
                    }
                    leave
                }
                }
                for {} count {} {
                    let k, size := block(shr(a, row), count)
                    let state := carry(x, y, a, b, k, 0, shr(b, column))
                    let s0 := mload(state)
                    let s1 := mload(add(state, 32))
                    let high := times(s0, part(y, column, add(b, k)))
                    if s1 {
                        let carried := add(column, shl(add(b, k), 1))
                        if lt(carried, shl(mload(add(y, 96)), 1)) { high := xor(high, times(s1, part(y, carried, add(b, k)))) }
                    }
                    value := xor(value, times(part(x, row, add(a, k)), high))
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
                case 1 { value := times(part(x, row, 0), interval(y, column, dc, count)) }
                default {
                    switch and(iszero(dc), power(dr))
                    case 1 { value := times(interval(x, row, dr, count), part(y, column, 0)) }
                    default {
                        switch and(and(power(dr), power(dc)), gt(count, 3))
                        case 1 { value := progression(x, nx, y, row, column, log(dr), log(dc), count) }
                        default {
                            for { let i := 0 } lt(i, count) { i := add(i, 1) } {
                                value := xor(value, times(part(x, row, 0), part(y, column, 0)))
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
                let scratchStart := mload(0x40)
                let cachedX := pointX
                let cachedY := pointY
                if eq(mode, 1) {
                    cachedX := prepare(pointX, nx)
                    cachedY := prepare(pointY, ny)
                }
                // Mode 4 keeps the shared row descriptor and prepares only
                // this matrix's column point within the reclaimed scratch.
                if eq(mode, 4) { cachedY := prepare(pointY, ny) }
                let capacity := 16
                for {} and(lt(capacity, count), lt(capacity, 2048)) {} { capacity := shl(1, capacity) }
                let cache := mload(0x40)
                // Carry entries followed by a directly indexed x_i*y_j table.
                // Clear both, including when evaluation reuses old scratch.
                let bytesNeeded := add(mul(capacity, 96), shl(5, mul(nx, ny)))
                mstore(0x40, add(add(cache, 288), bytesNeeded))
                mstore(cache, sub(capacity, 1))
                calldatacopy(add(cache, 288), calldatasize(), bytesNeeded)
                mstore(add(cachedX, 64), cache)
                let run := mload(0x40)
                // Keep the three matrix sums after the six run operands.
                // This avoids a Yul stack-allocation failure when a circuit's
                // smaller instruction set causes more aggressive inlining.
                mstore(0x40, add(run, 288))
                for { let p := run } lt(p, add(run, 288)) { p := add(p, 32) } { mstore(p, 0) }
                for { let i := 0 } lt(i, count) { i := add(i, 1) } {
                    // Undo the compiler's next-coordinate prediction before
                    // applying signed deltas to the six exact run operands.
                    mstore(add(run, 64), add(mload(add(run, 64)), mul(mload(add(run, 32)), mload(add(run, 128)))))
                    mstore(add(run, 96), add(mload(add(run, 96)), mul(mload(add(run, 32)), mload(add(run, 160)))))
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
                result := xor(mload(add(run, 192)), fm(lambda, xor(mload(add(run, 224)), fm(lambda, mload(add(run, 256))))))
                // Only a scalar leaves evaluation modes 1/2/4. Descriptors from
                // prepare modes 0/3 remain live and are not reclaimed here.
                mstore(add(cachedX, 64), 0)
                mstore(0x40, scratchStart)
            }
        }
    }

    // Opcode/metadata offsets are fixed by the checked generated program.
    function _programByte(bytes memory data, uint256 offset) private pure returns (uint8 value) {
        assembly ("memory-safe") { value := byte(0, mload(add(add(data, 32), offset))) }
    }

    function _programWord(bytes memory data, uint256 offset) private pure returns (uint256 value) {
        assembly ("memory-safe") {
            value := shr(sub(256, mul(8, PROGRAM_WORD_BYTES)), mload(add(add(data, 32), offset)))
        }
    }

    function _u32(bytes memory b, uint256 o) private pure returns (uint256 v) {
        assembly ("memory-safe") { v := shr(224, mload(add(add(b, 32), o))) }
    }

    // Share the byte swaps within each 32-bit word with Merkle serialization.
    function _reverse(uint256 x) private pure returns (uint256 r) {
        assembly ("memory-safe") {
            // delta selects differing bit pairs; XORing it into both halves
            // swaps those halves without losing any of the full 256-bit input.
            function reverseWords(wordIn) -> wordOut {
                let delta := and(xor(wordIn, shr(8, wordIn)), 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff)
                wordOut := xor(xor(wordIn, delta), shl(8, delta))
                delta := and(xor(wordOut, shr(16, wordOut)), 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff)
                wordOut := xor(xor(wordOut, delta), shl(16, delta))
            }
            x := reverseWords(x)
            let delta := and(xor(x, shr(32, x)), 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff)
            x := xor(xor(x, delta), shl(32, delta))
            delta := and(xor(x, shr(64, x)), 0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff)
            x := xor(xor(x, delta), shl(64, delta))
            r := or(shl(128, x), shr(128, x))
        }
    }



    function _readLE(bytes calldata b, uint256 offset, uint256 n) private pure returns (uint256 v) {
        assembly ("memory-safe") { v := calldataload(add(b.offset, offset)) }
        return _reverse(v) & ((1 << (n * 8)) - 1);
    }

    // Decode two consecutive 128-bit field elements per calldata word.
    // The immutable verifier schedule bounds the destination and proof slice.
    function _readFields(uint256 dest, bytes calldata proof, uint256 offset, uint256 count) private pure {
        unchecked {
            for (; count > 1; count -= 2) {
                uint256 word;
                assembly ("memory-safe") { word := calldataload(add(proof.offset, offset)) }
                word = _reverse(word);
                assembly ("memory-safe") {
                    mstore(dest, and(word, 0xffffffffffffffffffffffffffffffff))
                    mstore(add(dest, 32), shr(128, word))
                }
                dest += 64;
                offset += 32;
            }
            if (count != 0) {
                uint256 word = _readLE(proof, offset, 16);
                assembly ("memory-safe") { mstore(dest, word) }
            }
        }
    }

    function _observe(Machine memory m, bytes calldata proof, uint256 offset, uint256 length) private pure {
        // The fixed observation schedule bounds every offset and its total length.
        unchecked {
            bytes memory buffer = m.observed;
            if (m.sampling) {
                bytes32 digest = m.sample;
                uint256 cursor = m.sampleIndex;
                // The consumed sample index is in 0..32. Its native u64 LE
                // encoding is one byte and seven zeros. Observation bytes are
                // copied over the remaining zero padding immediately below.
                assembly ("memory-safe") {
                    mstore(add(buffer, 32), digest)
                    mstore(add(buffer, 64), shl(248, cursor))
                }
                m.observedLength = 40;
                m.sampling = false;
            }
            uint256 position = m.observedLength;
            assembly ("memory-safe") { calldatacopy(add(add(buffer, 32), position), add(proof.offset, offset), length) }
            m.observedLength = position + length;
        }
    }

    function _sample(Machine memory m, uint256 n) private pure returns (uint256 value) {
        // Requests consume 4 or 16 bytes; the sample cursor stays within 0..32.
        unchecked {
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
    }

    function _mul(uint256 a, uint256 b) private pure returns (uint256 r) {
        assembly ("memory-safe") {
            // Five interleaved coefficient lanes, with five bits per digit.
            // Each integer-product digit sums at most 26 one-bit products,
            // so it cannot carry into the next digit. Masking extracts parity.
            // Field inputs are canonical 128-bit values, including proof reads.
            let a0 := and(a, 0x21084210842108421084210842108421)
            let b0 := and(b, 0x21084210842108421084210842108421)
            let a1 := and(a, 0x42108421084210842108421084210842)
            let b1 := and(b, 0x42108421084210842108421084210842)
            let a2 := and(a, 0x84210842108421084210842108421084)
            let b2 := and(b, 0x84210842108421084210842108421084)
            let a3 := and(a, 0x08421084210842108421084210842108)
            let b3 := and(b, 0x08421084210842108421084210842108)
            let a4 := and(a, 0x10842108421084210842108421084210)
            let b4 := and(b, 0x10842108421084210842108421084210)
            // Balance the XOR tree to limit simultaneous intermediates on
            // the EVM stack. All 25 products and five parity masks remain.
            r := xor(
                xor(
                    and(xor(xor(mul(a0, b0), mul(a1, b4)), xor(mul(a2, b3), xor(mul(a3, b2), mul(a4, b1)))), 0x8421084210842108421084210842108421084210842108421084210842108421),
                    and(xor(xor(mul(a0, b1), mul(a1, b0)), xor(mul(a2, b4), xor(mul(a3, b3), mul(a4, b2)))), 0x0842108421084210842108421084210842108421084210842108421084210842)
                ),
                xor(
                    and(xor(xor(mul(a0, b2), mul(a1, b1)), xor(mul(a2, b0), xor(mul(a3, b4), mul(a4, b3)))), 0x1084210842108421084210842108421084210842108421084210842108421084),
                    xor(
                        and(xor(xor(mul(a0, b3), mul(a1, b2)), xor(mul(a2, b1), xor(mul(a3, b0), mul(a4, b4)))), 0x2108421084210842108421084210842108421084210842108421084210842108),
                        and(xor(xor(mul(a0, b4), mul(a1, b3)), xor(mul(a2, b2), xor(mul(a3, b1), mul(a4, b0)))), 0x4210842108421084210842108421084210842108421084210842108421084210)
                    )
                )
            )
            // Write the product as L + X^128*H and q=1+X+X^2+X^7.
            // Its degree is at most 254, so H has no bit 127. The overflow
            // E of q*H is (H>>126) XOR (H>>121). Since q*E has degree <128,
            // reduction is the low 128 bits of L + q*(H+E).
            let h := shr(128, r)
            h := xor(h, xor(shr(126, h), shr(121, h)))
            r := and(xor(xor(r, h), xor(shl(1, h), xor(shl(2, h), shl(7, h)))), 0xffffffffffffffffffffffffffffffff)
        }
    }

    // Every row is a canonical 128-bit field element. The interpreter creates
    // fresh row arrays, or copies an existing vector before this in-place call.
    function _transpose(uint256[128] memory rows) private pure {
        assembly ("memory-safe") {
            // Pair row i with row i+64 and perform the first butterfly while
            // packing their four 64-bit quarters into one EVM word.
            for { let i := 0 } lt(i, 2048) { i := add(i, 32) } {
                let a := mload(add(rows, i))
                let b := mload(add(add(rows, 2048), i))
                a := and(or(a, shl(64, a)), 0xffffffffffffffff0000000000000000ffffffffffffffff)
                b := and(or(b, shl(64, b)), 0xffffffffffffffff0000000000000000ffffffffffffffff)
                mstore(add(rows, i), or(a, shl(64, b)))
            }
            let mask := 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff
            for { let shift := 32 } shift {
                shift := shr(1, shift)
                mask := xor(mask, shl(shift, mask))
            } {
                for { let i := 0 } lt(i, 64) { i := and(add(i, add(shift, 1)), not(shift)) } {
                    let a := add(rows, shl(5, i))
                    let b := add(rows, shl(5, add(i, shift)))
                    let t := and(xor(shr(shift, mload(a)), mload(b)), mask)
                    mstore(a, xor(mload(a), shl(shift, t)))
                    mstore(b, xor(mload(b), t))
                }
            }
            // Only the first half holds packed words. Each forward store
            // replaces the word just read or writes to the separate second half.
            for { let i := 0 } lt(i, 2048) { i := add(i, 32) } {
                let a := add(rows, i)
                let word := mload(a)
                mstore(a, and(word, 0xffffffffffffffffffffffffffffffff))
                mstore(add(a, 2048), shr(128, word))
            }
        }
    }

    function _square(uint256 a) private pure returns (uint256 r) {
        assembly ("memory-safe") {
            // Canonical a has 128 bits. These seven non-overlapping spreads
            // place its coefficient i at bit 2*i in the complete EVM word.
            // Canonical field inputs have zero upper 128 bits. Reuse that
            // proven zero to form all ones; no external state is read.
            let ones := not(shr(128, a))
            r := a
            r := and(or(r, shl(64, r)), div(ones, 0x10000000000000001))
            r := and(or(r, shl(32, r)), div(ones, 0x100000001))
            r := and(or(r, shl(16, r)), div(ones, 0x10001))
            r := and(or(r, shl(8, r)), div(ones, 0x101))
            r := and(or(r, shl(4, r)), div(ones, 0x11))
            r := and(or(r, shl(2, r)), div(ones, 0x5))
            r := and(or(r, shl(1, r)), div(ones, 0x3))
            let h := shr(128, r)
            h := xor(h, xor(shr(126, h), shr(121, h)))
            r := and(xor(xor(r, h), xor(shl(1, h), xor(shl(2, h), shl(7, h)))), 0xffffffffffffffffffffffffffffffff)
        }
    }

    function _inverse(uint256 a) private pure returns (uint256 r) {
        // Polynomial extended Euclid over GF(2), modulo X^128+X^7+X^2+X+1.
        // Inputs are canonical field elements; zero maps to zero.
        // r*a = u and t*a = v modulo P. Each cancellation lowers the sum of
        // remainder degrees, so at most 255 iterations reach u=1. Coefficients
        // stay below degree 128; shifts and XORs cannot truncate a field bit.
        assembly ("memory-safe") {
            if a {
                let u := a
                let v := 0x100000000000000000000000000000087
                let t := 0
                r := 1
                for { } gt(u, 1) { } {
                    // Integer ordering also orders polynomial degrees.
                    if lt(u, v) {
                        let z := u u := v v := z
                        z := r r := t t := z
                    }
                    let shift := sub(clz(v), clz(u))
                    u := xor(u, shl(shift, v))
                    r := xor(r, shl(shift, t))
                }
            }
        }
    }

    function _shaMemory(Machine memory m, bytes memory input, uint256 offset, uint256 length)
        private
        pure
        returns (bytes32)
    {
        if (m.hintAt != 0) return _recordSha(m, input, offset, length);
        bytes memory scratch = m.scratch;
        assembly ("memory-safe") { mcopy(add(scratch, 32), add(add(input, 32), offset), length) }
        return _shaFinish(m, length);
    }

    // Hints supply temporary digest values, never trusted hash results. Copy the
    // exact message before its transcript buffer is reused. A record holds
    // [next, expectedDigest, paddedLength, paddedMessage, 32-byte guard]. The
    // final 64 bytes are cleared before copying the message, and
    // the wide 0x80/bit-length stores stay inside the allocation. Message
    // lengths are bounded by the key's fixed HASH_CAPACITY schedule.
    function _recordSha(Machine memory m, bytes memory input, uint256 offset, uint256 length)
        private pure returns (bytes32 expected)
    {
        unchecked {
            if (m.hintAt + 32 > m.hintEnd) {
                m.hintEnd = 0;
                return bytes32(0);
            }
            uint256 hintAt = m.hintAt;
            assembly ("memory-safe") { expected := calldataload(hintAt) }
            m.hintAt = hintAt + 32;
            uint256 padded = (length + 72) & ~uint256(63);
            uint256 head = m.hintQueue;
            uint256 record;
            assembly ("memory-safe") {
                record := mload(0x40)
                mstore(0x40, add(add(record, 128), padded))
                mstore(record, head)
                mstore(add(record, 32), expected)
                mstore(add(record, 64), padded)
                let data := add(record, 96)
                mstore(add(data, sub(padded, 64)), 0)
                mstore(add(data, sub(padded, 32)), 0)
                mcopy(data, add(add(input, 32), offset), length)
                mstore(add(data, length), shl(248, 0x80))
                mstore(add(data, sub(padded, 8)), shl(192, mul(length, 8)))
            }
            m.hintQueue = record;
        }
    }

    // Starting from the fixed SHA256(empty), equality of every complete digest
    // forces the hinted challenger to be the native challenger, by induction.
    // Keep all seven compression lanes occupied by refilling each finished
    // lane from the message list, regardless of message length. Reset only
    // that lane's eight IV words; unfinished lanes retain their exact state.
    // A record's next/length words become its current/end cursors only after
    // its successor is saved. Every complete digest must match before true
    // can leave this function. Queue order does not change the hash messages.
    function _checkShaHints(Machine memory m) private pure returns (bool) {
        unchecked {
            if (m.hintAt == 0) return true;
            if (m.hintAt != m.hintEnd) return false;
            uint256 head = m.hintQueue;
            // The record retains its cursors; each lane stores its record pointer.
            uint256[7] memory lanes;
            if (m.scratch.length < 480) m.scratch = new bytes(480);
            uint256 data;
            bytes memory scratch = m.scratch;
            assembly ("memory-safe") { data := add(scratch, 32) }
            while (true) {
                uint256 active;
                uint256 finished;
                uint256[8] memory state = m.hashState;
                uint256[80] memory constants = m.hashConstants;
                assembly ("memory-safe") {
                    for { let lane := 0 } lt(lane, 7) { lane := add(lane, 1) } {
                        let slot := add(lanes, shl(5, lane))
                        let record := mload(slot)
                        if and(iszero(record), iszero(iszero(head))) {
                            record := head
                            head := mload(record)
                            let start := add(record, 96)
                            mstore(slot, record)
                            mstore(record, start)
                            mstore(add(record, 64), add(start, mload(add(record, 64))))
                            let mask := shl(mul(lane, 37), 0xffffffff)
                            for { let j := 0 } lt(j, 256) { j := add(j, 32) } {
                                let p := add(state, j)
                                let value := mload(p)
                                mstore(p, xor(value, and(xor(value, mload(add(add(constants, 2048), j))), mask)))
                            }
                        }
                        if record {
                            active := add(active, 1)
                            let p := mload(record)
                            mcopy(add(data, shl(6, lane)), p, 64)
                            p := add(p, 64)
                            mstore(record, p)
                            if eq(p, mload(add(record, 64))) { finished := or(finished, shl(lane, 1)) }
                        }
                    }
                }
                if (active == 0) break;
                _compressBatch(m, data, 64);
                if (finished != 0) {
                    _digestBatch(m, false, 7);
                    bytes32[7] memory actual = m.batchDigests;
                    uint256 bad;
                    assembly ("memory-safe") {
                        for { let lane := 0 } lt(lane, 7) { lane := add(lane, 1) } {
                            if and(finished, shl(lane, 1)) {
                                let slot := add(lanes, shl(5, lane))
                                if xor(mload(add(actual, shl(5, lane))), mload(add(mload(slot), 32))) {
                                    bad := 1
                                }
                                mstore(slot, 0)
                            }
                        }
                    }
                    if (bad != 0) return false;
                }
            }
            return true;
        }
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
        // The fixed transcript/leaf size bounds padding well below uint256 overflow.
        unchecked {
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
        _digestBatch(m, little, 1);
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
        _shaRounds(m, false);
    }

    // Keep the feed-forward values in a separate array. The round function
    // can update eight working words without retaining eight original words
    // on the EVM stack throughout all 64 rounds.
    function _shaRounds(Machine memory m, bool packed) private pure {
        uint256[8] memory state = m.hashState;
        uint256[8] memory work = m.hashWork;
        uint256 mask = m.hashMask;
        assembly ("memory-safe") { mcopy(work, state, 256) }
        if (packed) _shaMix(m);
        else _shaMixScalar(m);
        assembly ("memory-safe") {
            for { let i := 0 } lt(i, 256) { i := add(i, 32) } {
                mstore(add(state, i), and(add(mload(add(state, i)), mload(add(work, i))), mask))
            }
        }
    }

    // Pure operands are ordered and associative expressions grouped to reduce
    // EVM stack traffic. Addition retains its modulo-2^256 semantics; the
    // existing lane masks still enforce each SHA word's modulo-2^32 result.
    function _shaMix(Machine memory m) private pure {
        uint256[64] memory w = m.schedule;
        uint256[8] memory state = m.hashWork;
        uint256[80] memory constants = m.hashConstants;
        uint256 mask = SHA_WORD_MASK;
        uint256 repeat = SHA_WORD_REPEAT;
        assembly ("memory-safe") {
            // Seven 32-bit words, with five guard bits between adjacent words.
            // General rotations clear the bits that would cross a lane.
            // The two exceptions below retain only high guard bits whose
            // addition cannot overflow into the next lane.
            function rr(x, n, rep) -> z {
                let low := and(x, mul(rep, sub(shl(n, 1), 1)))
                z := or(shr(n, xor(x, low)), shl(sub(32, n), low))
            }
            function ls(x, n, rep) -> z {
                z := and(shr(n, x), mul(rep, shr(n, 0xffffffff)))
            }
            // For canonical lanes, W_n = (x & (rep*(2^n-1))) << (32-n)
            // is the high part of ROTR_n. The unwanted cross-lane bits in
            // x >> n are exactly W_n >> 32. XOR the W_n terms first, then
            // correct their combined spill with one shift. This computes
            // the same XOR of rotations, with every result lane canonical.
            // SHR3 below still uses its separately bounded guard bits.
            // p addresses W[i]. The fixed byte displacements read exactly
            // W[i-15], W[i-2], W[i-16] and W[i-7], for i = 16..63.
            for { let p := add(w, 512) } lt(p, add(w, 2048)) { p := add(p, 32) } {
                let x := mload(sub(p, 480))
                let y := mload(sub(p, 64))
                // SHR3 leaves the next lane's low three bits at positions
                // 34..36. The four 32-bit summands use only bits 0..33:
                // 7*2^34 + 4*(2^32-1) = 2^37-4, so no lane carries.
                let wrap_s0 := xor(shl(25, and(x, mul(repeat, 127))), shl(14, and(x, mul(repeat, 262143))))
                let s0 := xor(xor(xor(shr(7, x), shr(18, x)), xor(wrap_s0, shr(32, wrap_s0))), shr(3, x))
                let wrap_s1 := xor(shl(15, and(y, mul(repeat, 131071))), shl(13, and(y, mul(repeat, 524287))))
                let s1 := xor(xor(xor(shr(17, y), shr(19, y)), xor(wrap_s1, shr(32, wrap_s1))), ls(y, 10, repeat))
                mstore(
                    p,
                    and(add(s0, add(s1, add(mload(sub(p, 512)), mload(sub(p, 224))))), mask)
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
                // Shifting a canonical lane by five stays inside its guard
                // bits. The low eleven bits of (e << 5) XOR e therefore
                // combine both ROTR6/ROTR11 wraps with one shared mask.
                let wrap_S1 := xor(shl(21, and(xor(shl(5, e), e), mul(repeat, 2047))), shl(7, and(e, mul(repeat, 33554431))))
                let s1 := xor(xor(shr(6, e), xor(shr(11, e), shr(25, e))), xor(wrap_S1, shr(32, wrap_S1)))
                let ch := xor(g, and(e, xor(f, g)))
                let k := mload(add(constants, shl(5, i)))
                // T1 has five terms; adding sigma0 and majority makes seven.
                // This fits below the next 37-bit lane. Mask only the final
                // A/E values, which are the next round's 32-bit inputs.
                // T1 = H + Sigma1(E) + Ch(E,F,G) + K[i] + W[i].
                let t1 := add(s1, add(ch, add(h, add(mload(add(w, shl(5, i))), k))))
                // ROTR2 can likewise retain the next lane's low two bits
                // at positions 35..36. Seven 32-bit summands stay below
                // 3*2^35 + 7*2^32 < 2^37. The final A mask clears them.
                let s0 := xor(or(shr(2, a), shl(30, and(a, mul(repeat, 3)))), xor(rr(a, 13, repeat), rr(a, 22, repeat)))
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
            mstore(state, a)
            mstore(add(state, 32), b)
            mstore(add(state, 64), c)
            mstore(add(state, 96), d)
            mstore(add(state, 128), e)
            mstore(add(state, 160), f)
            mstore(add(state, 192), g)
            mstore(add(state, 224), h)
        }
    }

    function _shaMixScalar(Machine memory m) private pure {
        uint256[64] memory w = m.schedule;
        uint256[8] memory state = m.hashWork;
        uint256[80] memory constants = m.hashConstants;
        uint256 mask = 0xffffffff;
        assembly ("memory-safe") {
            // For a 32-bit word x, x*(2^32+1) repeats x twice. Shifting that
            // 64-bit value by n has ROTR32(x,n) in its low 32 bits. Sigma high
            // bits cannot affect additions modulo 2^32 and are masked away.
            // Schedule words remain 32-bit; working state words keep both copies.
            // The pre-broadcast constants also have the original scalar value
            // in their low 32 bits; higher lanes cannot carry downward.
            for { let p := add(w, 512) } lt(p, add(w, 2048)) { p := add(p, 32) } {
                let x := mload(sub(p, 480))
                let y := mload(sub(p, 64))
                let xx := mul(x, 0x100000001)
                let yy := mul(y, 0x100000001)
                let s0 := xor(shr(7, xx), xor(shr(18, xx), shr(3, x)))
                let s1 := xor(shr(17, yy), xor(shr(19, yy), shr(10, y)))
                mstore(
                    p,
                    and(add(s0, add(s1, add(mload(sub(p, 512)), mload(sub(p, 224))))), mask)
                )
            }
            // The shared initializer broadcasts the IV to seven hash lanes.
            // Extract the scalar word before making its two identical copies.
            let a := mul(and(mload(state), mask), 0x100000001)
            let b := mul(and(mload(add(state, 32)), mask), 0x100000001)
            let c := mul(and(mload(add(state, 64)), mask), 0x100000001)
            let d := mul(and(mload(add(state, 96)), mask), 0x100000001)
            let e := mul(and(mload(add(state, 128)), mask), 0x100000001)
            let f := mul(and(mload(add(state, 160)), mask), 0x100000001)
            let g := mul(and(mload(add(state, 192)), mask), 0x100000001)
            let h := mul(and(mload(add(state, 224)), mask), 0x100000001)
            // Execute every SHA round in groups of 4.
            for { let i := 0 } lt(i, 64) { i := add(i, 4) } {
                {
                    let s1 := xor(shr(6, e), xor(shr(11, e), shr(25, e)))
                    let ch := xor(g, and(e, xor(f, g)))
                    let k := mload(add(constants, shl(5, i)))
                    let t1 := add(s1, add(ch, add(h, add(mload(add(w, shl(5, i))), k))))
                    let s0 := xor(shr(2, a), xor(shr(13, a), shr(22, a)))
                    let maj := xor(and(a, b), and(c, xor(a, b)))
                    d := mul(and(add(d, t1), mask), 0x100000001)
                    h := mul(and(add(t1, add(s0, maj)), mask), 0x100000001)
                }
                {
                    let s1 := xor(shr(6, d), xor(shr(11, d), shr(25, d)))
                    let ch := xor(f, and(d, xor(e, f)))
                    let k := mload(add(constants, shl(5, add(i, 1))))
                    let t1 := add(s1, add(ch, add(g, add(mload(add(w, shl(5, add(i, 1)))), k))))
                    let s0 := xor(shr(2, h), xor(shr(13, h), shr(22, h)))
                    let maj := xor(and(h, a), and(b, xor(h, a)))
                    c := mul(and(add(c, t1), mask), 0x100000001)
                    g := mul(and(add(t1, add(s0, maj)), mask), 0x100000001)
                }
                {
                    let s1 := xor(shr(6, c), xor(shr(11, c), shr(25, c)))
                    let ch := xor(e, and(c, xor(d, e)))
                    let k := mload(add(constants, shl(5, add(i, 2))))
                    let t1 := add(s1, add(ch, add(f, add(mload(add(w, shl(5, add(i, 2)))), k))))
                    let s0 := xor(shr(2, g), xor(shr(13, g), shr(22, g)))
                    let maj := xor(and(g, h), and(a, xor(g, h)))
                    b := mul(and(add(b, t1), mask), 0x100000001)
                    f := mul(and(add(t1, add(s0, maj)), mask), 0x100000001)
                }
                {
                    let s1 := xor(shr(6, b), xor(shr(11, b), shr(25, b)))
                    let ch := xor(d, and(b, xor(c, d)))
                    let k := mload(add(constants, shl(5, add(i, 3))))
                    let t1 := add(s1, add(ch, add(e, add(mload(add(w, shl(5, add(i, 3)))), k))))
                    let s0 := xor(shr(2, f), xor(shr(13, f), shr(22, f)))
                    let maj := xor(and(f, g), and(h, xor(f, g)))
                    a := mul(and(add(a, t1), mask), 0x100000001)
                    e := mul(and(add(t1, add(s0, maj)), mask), 0x100000001)
                }
                let nexta := e
                let nextb := f
                let nextc := g
                let nextd := h
                let nexte := a
                let nextf := b
                let nextg := c
                let nexth := d
                a := nexta
                b := nextb
                c := nextc
                d := nextd
                e := nexte
                f := nextf
                g := nextg
                h := nexth
            }
            // Scalar callers consume only each state's low 32 bits. The next
            // scalar block extracts those bits again; a new packed hash resets
            // all seven lanes through _hashInit before processing any block.
            mstore(state, a)
            mstore(add(state, 32), b)
            mstore(add(state, 64), c)
            mstore(add(state, 96), d)
            mstore(add(state, 128), e)
            mstore(add(state, 160), f)
            mstore(add(state, 192), g)
            mstore(add(state, 224), h)
        }
    }    function _hashInit(Machine memory m, bool merkle) private pure {
        uint256[8] memory state = m.hashState;
        uint256[80] memory constants = m.hashConstants;
        assembly ("memory-safe") {
            // Words 64..71 are the SHA IV; 72..79 are the Binius domain IV.
            mcopy(state, add(add(constants, 2048), mul(merkle, 256)), 256)
        }
    }

    function _compressBatch(Machine memory m, uint256 data, uint256 stride) private pure {
        uint256[64] memory w = m.schedule;
        assembly ("memory-safe") {
            // Advance by one input u32 and one schedule word per iteration.
            for { let dest := w } lt(dest, add(w, 512)) {
                dest := add(dest, 32)
                data := add(data, 4)
            } {
                let p := data
                let value := shr(224, mload(p))
                value := or(value, shl(37, shr(224, mload(add(p, mul(stride, 1))))))
                value := or(value, shl(74, shr(224, mload(add(p, mul(stride, 2))))))
                value := or(value, shl(111, shr(224, mload(add(p, mul(stride, 3))))))
                value := or(value, shl(148, shr(224, mload(add(p, mul(stride, 4))))))
                value := or(value, shl(185, shr(224, mload(add(p, mul(stride, 5))))))
                value := or(value, shl(222, shr(224, mload(add(p, mul(stride, 6))))))
                mstore(dest, value)
            }
        }
        _shaRounds(m, true);
    }

    function _digestBatch(Machine memory m, bool little, uint256 count) private pure {
        uint256[8] memory state = m.hashState;
        bytes32[7] memory output = m.batchDigests;
        assembly ("memory-safe") {
            // delta selects differing bit pairs; XORing it into both halves
            // swaps those halves without losing any of the full 256-bit input.
            function reverseWords(wordIn) -> wordOut {
                let delta := and(xor(wordIn, shr(8, wordIn)), 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff)
                wordOut := xor(xor(wordIn, delta), shl(8, delta))
                delta := and(xor(wordOut, shr(16, wordOut)), 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff)
                wordOut := xor(xor(wordOut, delta), shl(16, delta))
            }
            for { let lane := 0 } lt(lane, count) { lane := add(lane, 1) } {
                // Gather this lane's eight u32 words in native digest order.
                // The seven shifts discard the first word's upper bits.
                let shift := mul(37, lane)
                let result := shr(shift, mload(state))
                result := or(shl(32, result), and(shr(shift, mload(add(state, 32))), 0xffffffff))
                result := or(shl(32, result), and(shr(shift, mload(add(state, 64))), 0xffffffff))
                result := or(shl(32, result), and(shr(shift, mload(add(state, 96))), 0xffffffff))
                result := or(shl(32, result), and(shr(shift, mload(add(state, 128))), 0xffffffff))
                result := or(shl(32, result), and(shr(shift, mload(add(state, 160))), 0xffffffff))
                result := or(shl(32, result), and(shr(shift, mload(add(state, 192))), 0xffffffff))
                result := or(shl(32, result), and(shr(shift, mload(add(state, 224))), 0xffffffff))
                if little { result := reverseWords(result) }
                mstore(add(output, shl(5, lane)), result)
            }
        }
    }

    function _leavesBatch(
        Machine memory m, bytes calldata proof, uint256 offset, uint256 stride,
        uint256 length, uint256 count
    ) private pure {
        // The fixed verifier program bounds these sizes and offsets.
        unchecked {
            uint256 padded = (length + 72) & ~uint256(63);
            if (count == 1) {
                // A singleton uses the same padded SHA message with scalar
                // rounds. It may be the first leaf, so size scratch explicitly;
                // the wide suffix stores also need up to 31 padding bytes.
                if (m.scratch.length < padded + 32) m.scratch = new bytes(padded + 32);
                m.batchDigests[0] = _shaCalldata(m, proof, offset, length);
                return;
            }
            if (m.scratch.length < 7 * padded + 32) m.scratch = new bytes(7 * padded + 32);
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
                _compressBatch(m, data + blockOffset, padded);
            }
            _digestBatch(m, false, count);
        }
    }

    // Callers put 1..7 complete child pairs at the start of scratch. A single
    // pair uses scalar rounds; both paths use the same Merkle IV, one unpadded
    // block, and little-endian state serialization. Compression only reads
    // scratch, so the original children remain available for cache insertion.
    function _nodesBatch(Machine memory m, uint256 count) private pure {
        bytes memory scratch = m.scratch;
        _hashInit(m, true);
        if (count == 1) {
            _compress(m, scratch, 0);
        } else {
            uint256 data;
            assembly ("memory-safe") { data := add(scratch, 32) }
            _compressBatch(m, data, 64);
        }
        _digestBatch(m, true, count);
    }

    // Memory offsets used below: hashes 0, queries 32, slots 64, data 96,
    // cache 128. Each queue entry is one independent compression block.
    struct PathBatch {
        bytes32[] hashes;
        uint256[7] queries;
        uint256[7] slots;
        uint256 data;
        uint256 cache;
    }

    // Only initialized queue entries are read; callers pass 1 <= count <= 7.
    // Save both full inputs with their digest after computing the compression.
    function _pathNodes(Machine memory m, PathBatch memory s, uint256 count) private pure {
        _nodesBatch(m, count);
        bytes32[7] memory digests = m.batchDigests;
        assembly ("memory-safe") {
            let hashes := add(mload(s), 32)
            let queries := mload(add(s, 32))
            let slots := mload(add(s, 64))
            let data := mload(add(s, 96))
            for { let i := 0 } lt(i, shl(5, count)) { i := add(i, 32) } {
                let h := mload(add(digests, i))
                mstore(add(hashes, shl(5, mload(add(queries, i)))), h)
                let slot := mload(add(slots, i))
                let input := add(data, shl(1, i))
                mstore(slot, mload(input))
                mstore(add(slot, 32), mload(add(input, 32)))
                mstore(add(slot, 64), h)
            }
        }
    }

    function _paths(
        Machine memory m, bytes calldata proof, uint256[] memory indices, uint256 shift,
        uint256 layer, uint256 offset, uint256 leafSize, uint256 depth
    ) private pure returns (bool) {
        // The fixed program bounds all proof offsets and array indices.
        // Process a complete level before advancing. Cache hits leave only
        // independent misses to pack into the seven compression lanes.
        // Advice hashes do not observe or sample the Fiat-Shamir transcript.
        unchecked {
            PathBatch memory s;
            s.hashes = new bytes32[](indices.length);
            if (m.nodeCache == 0) {
                // 256 entries: both complete children and their result.
                // A zero result is always a miss, even if it was computed:
                // recomputing it needs no assumption about SHA's output.
                bytes memory cache = new bytes(24576);
                uint256 pointer;
                assembly ("memory-safe") { pointer := add(cache, 32) }
                m.nodeCache = pointer;
            }
            s.cache = m.nodeCache;
            uint256 stride = leafSize * 16 + depth * 32;
            for (uint256 q; q < indices.length; q += 7) {
                uint256 count = indices.length - q;
                if (count > 7) count = 7;
                _leavesBatch(m, proof, offset + q * stride, stride, leafSize * 16, count);
                bytes32[7] memory digests = m.batchDigests;
                assembly ("memory-safe") {
                    mcopy(add(add(mload(s), 32), shl(5, q)), digests, shl(5, count))
                }
            }
            bytes memory scratch = m.scratch;
            uint256 data;
            assembly ("memory-safe") { data := add(scratch, 32) }
            s.data = data;
            for (uint256 level; level < depth; ++level) {
                uint256 count;
                for (uint256 q; q < indices.length; ++q) {
                    assembly ("memory-safe") {
                        let node := shr(add(shift, level), mload(add(add(indices, 32), shl(5, q))))
                        let hashSlot := add(add(mload(s), 32), shl(5, q))
                        let left := mload(hashSlot)
                        let right := calldataload(add(proof.offset, add(add(offset, mul(q, stride)), add(shl(4, leafSize), shl(5, level)))))
                        if and(node, 1) { let t := left left := right right := t }
                        // The parent index only selects a slot. Both complete
                        // children must match before reusing the same SHA output.
                        // Collisions cause replacement and recomputation.
                        let slot := add(mload(add(s, 128)), mul(96, and(shr(1, node), 255)))
                        switch and(iszero(iszero(mload(add(slot, 64)))), and(eq(mload(slot), left), eq(mload(add(slot, 32)), right)))
                        case 1 { mstore(hashSlot, mload(add(slot, 64))) }
                        default {
                            let p := add(data, shl(6, count))
                            mstore(p, left)
                            mstore(add(p, 32), right)
                            mstore(add(mload(add(s, 32)), shl(5, count)), q)
                            mstore(add(mload(add(s, 64)), shl(5, count)), slot)
                            count := add(count, 1)
                        }
                    }
                    if (count == 7) {
                        _pathNodes(m, s, count);
                        count = 0;
                    }
                }
                if (count != 0) _pathNodes(m, s, count);
            }
            for (uint256 q; q < indices.length; ++q) {
                uint256 position = layer + (indices[q] >> (shift + depth)) * 32;
                if (s.hashes[q] != bytes32(proof[position:position + 32])) return false;
            }
            return true;
        }
    }

    function _layer(Machine memory m, bytes calldata proof, bytes32 root, uint256 offset, uint256 depth)
        private
        pure
        returns (bool)
    {
        uint256 count = 1 << depth;
        bytes32[] memory hashes = new bytes32[](count);
        // The fixed verifier program bounds the complete Merkle cap.
        // Envelope validation has established the exact native proof length.
        assembly ("memory-safe") {
            calldatacopy(add(hashes, 32), add(proof.offset, offset), shl(5, count))
        }
        return _fold(m, hashes) == root;
    }

    function _fold(Machine memory m, bytes32[] memory hashes) private pure returns (bytes32) {
        // The fixed verifier program bounds these sizes and offsets.
        unchecked {
            if (m.scratch.length < 480) m.scratch = new bytes(480);
            for (uint256 n = hashes.length; n > 1; n >>= 1) {
                for (uint256 i; i < n / 2; i += 7) {
                    uint256 count = n / 2 - i;
                    if (count > 7) count = 7;
                    bytes memory scratch = m.scratch;
                    uint256 data;
                    assembly ("memory-safe") {
                        data := add(scratch, 32)
                        mcopy(data, add(add(hashes, 32), shl(6, i)), shl(6, count))
                    }
                    _nodesBatch(m, count);
                    // count <= 7 and i + count <= hashes.length are set
                    // by the enclosing batch. Copy exactly those digest words.
                    bytes32[7] memory digests = m.batchDigests;
                    assembly ("memory-safe") {
                        mcopy(add(add(hashes, 32), shl(5, i)), digests, shl(5, count))
                    }
                }
            }
            return hashes[0];
        }
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
        // The fixed verifier program bounds these sizes and offsets.
        unchecked {
            bytes32[] memory hashes = new bytes32[](1 << depth);
            for (uint256 i; i < hashes.length; i += 7) {
                uint256 count = hashes.length - i;
                if (count > 7) count = 7;
                _leavesBatch(m, proof, offset + i * leafSize * 16, leafSize * 16, leafSize * 16, count);
                // count <= 7 and i + count <= hashes.length are set
                // by the enclosing batch. Copy exactly those digest words.
                bytes32[7] memory digests = m.batchDigests;
                assembly ("memory-safe") {
                    mcopy(add(add(hashes, 32), shl(5, i)), digests, shl(5, count))
                }
            }
            return _fold(m, hashes) == root;
        }
    }
