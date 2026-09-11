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
