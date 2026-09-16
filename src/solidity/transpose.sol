    function _transpose(uint256[128] memory rows) private pure {
        assembly ("memory-safe") {
            // Pair row i with row i+64 and perform the first butterfly while
            // packing their four 64-bit quarters into one EVM word.
            for { let i := 0 } lt(i, 2048) { i := add(i, 32) } {
                let a := mload(add(rows, i))
                let b := mload(add(add(rows, 2048), i))
                // Swap the middle 64-bit quarters, then pack both rows.
                // Inputs are canonical 128-bit words; the two stores' source
                // words were loaded before either memory location changes.
                let delta := and(xor(shr(64, a), b), 0xffffffffffffffff)
                mstore(add(rows, i), or(xor(a, shl(64, delta)), shl(128, xor(b, delta))))
            }
            let mask := 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff
            for { let shift := 32 } shift {
                shift := shr(1, shift)
                mask := xor(mask, shl(shift, mask))
            } {
                let span := shl(5, shift)
                for { let offset := 0 } lt(offset, 2048) { offset := and(add(offset, add(span, 32)), not(span)) } {
                    let a := add(rows, offset)
                    let b := add(a, span)
                    // The two addresses differ by shift > 0, so writing
                    // the first cannot change the second word's saved value.
                    let av := mload(a)
                    let bv := mload(b)
                    let t := and(xor(shr(shift, av), bv), mask)
                    mstore(a, xor(av, shl(shift, t)))
                    mstore(b, xor(bv, t))
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
