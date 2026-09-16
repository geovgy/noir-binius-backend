    // Prefix products skip zero denominators. The backward pass recovers
    // each exact inverse, while r=1 retains the original XOR-fold encoding.
    function _normalizeFriChallenges(uint256[] memory challenges, uint256 offset, uint256 count)
        private pure returns (uint256 scale)
    {
        uint256 start;
        uint256 end;
        // This entire range comes from the circuit's fixed FRI configuration.
        assembly ("memory-safe") {
            start := add(add(challenges, 32), shl(5, offset))
            end := add(start, shl(5, count))
        }
        scale = 1;
        unchecked {
            for (uint256 at = start; at < end; at += 32) {
                uint256 r;
                assembly ("memory-safe") { r := mload(at) }
                uint256 packed = (r << 128) | scale;
                assembly ("memory-safe") { mstore(at, packed) }
                uint256 factor = r ^ 1;
                assembly ("memory-safe") { factor := or(factor, iszero(factor)) }
                scale = _mul(scale, factor);
            }
            uint256 inverse = _inverse(scale);
            while (end > start) {
                end -= 32;
                uint256 packed;
                assembly ("memory-safe") { packed := mload(end) }
                uint256 r = packed >> 128;
                uint256 factor = r ^ 1;
                uint256 ratio = _mul(inverse, uint128(packed));
                assembly ("memory-safe") {
                    ratio := xor(and(ratio, sub(0, iszero(iszero(factor)))), 1)
                    factor := or(factor, iszero(factor))
                }
                inverse = _mul(inverse, factor);
                packed = (r << 128) | ratio;
                assembly ("memory-safe") { mstore(end, packed) }
            }
        }
    }
