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
            values := add(previous, 64)
            point := add(header, 25)
            mstore(0x40, add(values, shl(5, end)))
            for { let i := 0 } lt(i, 64) { i := add(i, 32) } { mstore(add(previous, i), 0) }
            p := add(point, shl(2, dimensions))
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
        }
        uint256 node;
        uint256 valuesEnd;
        assembly ("memory-safe") {
            node := add(values, shl(5, leaves))
            valuesEnd := add(values, shl(5, end))
        }
        while (node < valuesEnd) {
            uint256 r;
            uint256 groupEnd;
            assembly ("memory-safe") {
                let word := mload(p)
                r := mload(add(add(registers, 32), shl(5, shr(224, mload(add(point, shl(2, byte(0, word))))))))
                groupEnd := add(node, and(shr(227, word), 0x1fffe0))
                p := add(p, 3)
            }
            while (node < groupEnd) {
                uint256 a;
                uint256 b;
                assembly ("memory-safe") {
                    let word := mload(p)
                    a := mload(sub(node, and(shr(235, word), 0x1fffe0)))
                    b := mload(sub(node, and(shr(219, word), 0x1fffe0)))
                    p := add(p, 4)
                }
                uint256 value = a ^ _mul(r, a ^ b);
                assembly ("memory-safe") {
                    mstore(node, value)
                    node := add(node, 32)
                }
            }
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


