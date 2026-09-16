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
            let s0 := mload(state)
            let s1 := mload(add(state, 32))
            let s2 := mload(add(state, 64))
            let s3 := mload(add(state, 96))
            let s4 := mload(add(state, 128))
            let s5 := mload(add(state, 160))
            let s6 := mload(add(state, 192))
            let s7 := mload(add(state, 224))
            for { let lane := 0 } lt(lane, count) { lane := add(lane, 1) } {
                // Gather this lane's eight u32 words in native digest order.
                // The seven shifts discard the first word's upper bits.
                let shift := mul(37, lane)
                let result := shr(shift, s0)
                result := or(shl(32, result), and(shr(shift, s1), 0xffffffff))
                result := or(shl(32, result), and(shr(shift, s2), 0xffffffff))
                result := or(shl(32, result), and(shr(shift, s3), 0xffffffff))
                result := or(shl(32, result), and(shr(shift, s4), 0xffffffff))
                result := or(shl(32, result), and(shr(shift, s5), 0xffffffff))
                result := or(shl(32, result), and(shr(shift, s6), 0xffffffff))
                result := or(shl(32, result), and(shr(shift, s7), 0xffffffff))
                if little { result := reverseWords(result) }
                mstore(add(output, shl(5, lane)), result)
            }
        }
    }
