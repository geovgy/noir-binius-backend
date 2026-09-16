    function _compressBatch(Machine memory m, uint256 data, uint256 stride) private pure {
        uint256[64] memory w = m.schedule;
        assembly ("memory-safe") {
            // Build the same sum of u32[lane] << (37 * lane), starting at
            // lane six. Every input is bounded to 32 bits; the completed
            // word uses 254 bits, including its six five-bit guard regions.
            for { let dest := w } lt(dest, add(w, 512)) { dest := add(dest, 32) data := add(data, 4) } {
                let p := add(data, mul(stride, 6))
                let value := shr(224, mload(p))
                value := or(shl(37, value), shr(224, mload(add(data, mul(stride, 5)))))
                value := or(shl(37, value), shr(224, mload(add(data, mul(stride, 4)))))
                value := or(shl(37, value), shr(224, mload(add(data, mul(stride, 3)))))
                value := or(shl(37, value), shr(224, mload(add(data, mul(stride, 2)))))
                value := or(shl(37, value), shr(224, mload(add(data, mul(stride, 1)))))
                value := or(shl(37, value), shr(224, mload(data)))
                mstore(dest, value)
            }
        }
        _shaRounds(m, true);
    }
