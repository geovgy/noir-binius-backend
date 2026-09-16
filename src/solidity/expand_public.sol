    function _expandPublic(bytes memory compact) private pure returns(bytes memory result) {
        result = new bytes({{NEW_LENGTH}});
        uint256[4] memory previous;
        assembly ("memory-safe") {
            function child(p, slot) -> value, next {
                let octet := byte(0, mload(p))
                let delta := and(octet, 127)
                next := add(p, 1)
                for { let shift := 7 } and(octet, 128) { shift := add(shift, 7) } {
                    octet := byte(0, mload(next))
                    delta := or(delta, shl(shift, and(octet, 127)))
                    next := add(next, 1)
                }
                value := add(mload(slot), xor(shr(1, delta), sub(0, and(delta, 1))))
                mstore(slot, value)
            }
            function finishGroup(header, count) {
                mstore8(add(header, 1), shr(8, count))
                mstore8(add(header, 2), count)
            }
            let input := add(compact, 32)
            let output := add(result, 32)
            mcopy(output, input, {{NODE_START}})
            mstore(add(output, {{LENGTH_OFFSET}}), shl(240, {{PUBLIC_LENGTH}}))
            mcopy(add(output, {{PUBLIC_START}}), add(input, {{PUBLIC_START}}), {{PREFIX_LENGTH}})
            let p := add(input, {{NODE_START}})
            let dest := add(output, {{NODE_START}})
            let groupBit := 256
            let groupHeader := 0
            let groupCount := 0
            for { let i := 0 } lt(i, {{NODE_COUNT}}) { i := add(i, 1) } {
                let code := byte(0, mload(p))
                let bit := shr(2, code)
                if or(iszero(eq(bit, groupBit)), eq(groupCount, 65535)) {
                    if groupCount { finishGroup(groupHeader, groupCount) }
                    groupBit := bit
                    groupCount := 0
                    groupHeader := dest
                    mstore8(dest, bit)
                    dest := add(dest, 3)
                }
                let a
                let b
                a, p := child(add(p, 1), add(previous, shl(5, and(code, 1))))
                b, p := child(p, add(previous, shl(5, add(2, and(shr(1, code), 1)))))
                a := sub(add({{LEAVES}}, i), a)
                b := sub(add({{LEAVES}}, i), b)
                // Generation reserves 32 tail bytes for this store's overhang.
                mstore(dest, or(shl(240, a), shl(224, b)))
                dest := add(dest, 4)
                groupCount := add(groupCount, 1)
            }
            if groupCount { finishGroup(groupHeader, groupCount) }
            mcopy(add(output, {{NEW_END}}), add(input, {{OLD_END}}), {{TAIL_LENGTH}})
        }
    }
