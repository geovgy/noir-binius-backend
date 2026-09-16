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
        // Dimensions and byte offsets come from the fixed verifier program.
        unchecked {
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
            // The second half stores prefix XORs of basis[1..=i].
            // _friTwiddles later uses its unused zero entry as a table pointer.
            s.basis = new uint256[](2 * s.bits);
            for (uint256 i; i < s.bits; ++i) {
                uint256 value;
                assembly ("memory-safe") { value := shr(128, mload(add(add(program, 32), cursor))) }
                s.basis[i] = value;
                if (i != 0) s.basis[s.bits + i] = s.basis[s.bits + i - 1] ^ value;
                cursor += 16;
            }
            _friTwiddles(s.basis);
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
    }

    // Allocate and initialize every subset-sum word. The immutable FRI
    // configuration bounds the basis length; no prover value selects a length.
    // Prefix entry zero is unused by the butterfly (its delta is always >=1).
    // It holds the table data pointer; every actual basis/prefix value is retained.
    function _friTwiddles(uint256[] memory basis) private pure {
        assembly ("memory-safe") {
            let bits := shr(1, mload(basis))
            let table := mload(0x40)
            let end := add(table, shl(9, shr(2, add(bits, 2))))
            mstore(0x40, end)
            mstore(add(add(basis, 32), shl(5, bits)), table)
            let source := add(basis, 64)
            let sourceEnd := add(add(basis, 32), shl(5, bits))
            for { let chunk := table } lt(chunk, end) { chunk := add(chunk, 512) } {
                mstore(chunk, 0)
                for { let size := 1 } lt(size, 16) { size := shl(1, size) source := add(source, 32) } {
                    let value := 0
                    if lt(source, sourceEnd) { value := mload(source) }
                    for { let j := 0 } lt(j, size) { j := add(j, 1) } {
                        mstore(add(chunk, shl(5, add(size, j))), xor(mload(add(chunk, shl(5, j))), value))
                    }
                }
            }
        }
    }

    function _friRead(FriState memory s, bytes calldata proof, uint256 count) private pure {
        uint256[] memory work = s.work;
        uint256 dest;
        assembly ("memory-safe") { dest := add(work, 32) }
        _readFields(dest, proof, s.offset, count);
    }

    function _normalizeFriChallenges(uint256[] memory challenges, uint256 offset) private pure {
        unchecked {
            for (uint256 i = offset; i < challenges.length; ++i) {
                uint256 r = challenges[i];
                // Keep the original scalar and r/(1+r) together. When r=1,
                // the fold is the XOR of its inputs and needs no division.
                challenges[i] = (r << 128) | (_inverse(r ^ 1) ^ 1);
            }
        }
    }

    // With v=U+V, the native butterfly is
    //   U+t*v+r*(v+U+t*v) = (1+r)*(U+(t+r/(1+r))*v).
    // Pull the common scale through subsequent linear folds and restore its
    // product at the end. For r=1 the butterfly is exactly U+V instead.
    // All point coordinates are canonical 128-bit field elements. The fixed
    // FRI configuration bounds these arrays and masks the query indices.
    function _friCoset(
        uint256[] memory values,
        uint256 count,
        uint256 index,
        uint256[] memory challenges,
        uint256 challengeOffset,
        uint256[] memory basis
    ) private pure returns (uint256) {
        uint256 scale = 1;
        unchecked {
            for (uint256 round; round < count; ++round) {
                uint256 shift = count - round - 1;
                uint256 challenge;
                assembly ("memory-safe") {
                    challenge := mload(add(add(challenges, 32), shl(5, add(challengeOffset, round))))
                }
                uint256 scalar = (challenge >> 128) ^ 1;
                if (scalar == 0) {
                    for (uint256 j; j < (uint256(1) << shift); ++j) {
                        assembly ("memory-safe") {
                            let p := add(add(values, 32), shl(6, j))
                            mstore(add(add(values, 32), shl(5, j)), xor(mload(p), mload(add(p, 32))))
                        }
                    }
                    continue;
                }
                scale = _mul(scale, scalar);
                uint256 twiddle = uint128(challenge);
                assembly ("memory-safe") {
                    // Query indices and shifts are bounded by the immutable FRI
                    // configuration. Every selected digit has an allocated group.
                    let remaining := shl(shift, index)
                    for { let chunk := mload(add(add(basis, 32), shl(5, shr(1, mload(basis))))) } remaining { chunk := add(chunk, 512) remaining := shr(4, remaining) } {
                        twiddle := xor(twiddle, mload(add(chunk, shl(5, and(remaining, 15)))))
                    }
                }
                for (uint256 j; j < (uint256(1) << shift); ++j) {
                    uint256 u;
                    uint256 v;
                    assembly ("memory-safe") {
                        if j {
                            // Advancing j flips exactly its low trailing one bits
                            // and the next zero bit. The table stores prefix XORs.
                            let delta := sub(256, clz(and(j, sub(0, j))))
                            twiddle := xor(twiddle, mload(add(add(basis, 32), shl(5, add(shr(1, mload(basis)), delta)))))
                        }
                        let p := add(add(values, 32), shl(6, j))
                        u := mload(p)
                        v := xor(mload(add(p, 32)), u)
                    }
                    uint256 folded = u ^ _mul(v, twiddle);
                    assembly ("memory-safe") {
                        mstore(add(add(values, 32), shl(5, j)), folded)
                    }
                }
            }
            return _mul(values[0], scale);
        }
    }

    function _fri(
        Machine memory m,
        bytes memory program,
        uint256 cursor,
        uint256[] memory registers,
        bytes calldata proof
    ) private pure returns (bool, uint256) {
        // Dimensions and byte offsets come from the fixed verifier program.
        unchecked {
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
                        uint256[] memory work = s.work;
                        // This single check bounds both halves for every j.
                        if (half > work.length >> 1) return (false, 0);
                        for (uint256 j; j < half; ++j) {
                            uint256 a;
                            uint256 b;
                            assembly ("memory-safe") {
                                let p := add(add(work, 32), shl(5, j))
                                a := mload(p)
                                b := mload(add(p, shl(5, half)))
                            }
                            a ^= _mul(challenge, b ^ a);
                            assembly ("memory-safe") { mstore(add(add(work, 32), shl(5, j)), a) }
                        }
                    }
                    s.claims[q] ^= _mul(s.work[0], scalar);
                    s.offset += 16 * leaf + 32 * pathDepth;
                }
            }
            uint256 challengeOffset = s.early + s.outerBits + s.later;
            _normalizeFriChallenges(s.challenges, challengeOffset);
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
    }
