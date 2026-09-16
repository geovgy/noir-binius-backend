    function _factoredWiring(uint256 data, uint256 pointX, uint256 pointY, uint256 lambda)
        private pure returns (uint256 result)
    {
        uint256 grouped;
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
            grouped := 1
            nx := and(nx, 127)
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
        if (grouped != 0) {
            uint256 dest = start;
            while (dest < finish) {
                uint256 code;
                uint256 end;
                uint256 r;
                assembly ("memory-safe") {
                    let header := mload(data)
                    code := byte(0, header)
                    end := add(dest, and(shr(227, header), 0x1fffe0))
                    data := add(data, 3)
                    r := mload(add(values, shl(5, add(and(code, 127), 7))))
                }
                if (code < 128) {
                if (code == 0) {
                    while (dest < end) {
                        uint256 a;
                        uint256 b;
                        assembly ("memory-safe") {
                            let word := mload(data)
                            a := mload(sub(dest, and(shr(235, word), 0x1fffe0)))
                            b := mload(sub(dest, and(shr(219, word), 0x1fffe0)))
                            data := add(data, 4)
                        }
                        uint256 value = _mul(a, b);
                        assembly ("memory-safe") { mstore(dest, value) dest := add(dest, 32) }
                    }
                } else {
                    while (dest < end) {
                        uint256 a;
                        uint256 b;
                        assembly ("memory-safe") {
                            let word := mload(data)
                            a := mload(sub(dest, and(shr(235, word), 0x1fffe0)))
                            b := mload(sub(dest, and(shr(219, word), 0x1fffe0)))
                            data := add(data, 4)
                        }
                        uint256 value = a ^ _mul(r, a ^ b);
                        assembly ("memory-safe") { mstore(dest, value) dest := add(dest, 32) }
                    }
                }
                } else {
                {
                    while (dest < end) {
                        uint256 a;
                        uint256 b;
                        assembly ("memory-safe") {
                            let word := mload(data)
                            a := mload(add(values, and(shr(243, word), 0x1fe0)))
                            b := mload(sub(dest, and(shr(227, word), 0x1fffe0)))
                            data := add(data, 3)
                        }
                        uint256 value = _mul(a, b);
                        assembly ("memory-safe") { mstore(dest, value) dest := add(dest, 32) }
                    }
                }
                }
            }
        } else {
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
                    delta := shr(240, mload(streamA))
                    streamA := add(streamA, 2)
                    a := mload(sub(dest, shl(5, delta)))
                    delta := shr(240, mload(streamB))
                    streamB := add(streamB, 2)
                    b := mload(sub(dest, shl(5, delta)))
                    r := mload(add(values, shl(5, add(code, 7))))
                }
                uint256 value = code == 0 ? _mul(a, b) : a ^ _mul(r, a ^ b);
                assembly ("memory-safe") { mstore(dest, value) dest := add(dest, 32) }
            }
        }
        assembly ("memory-safe") {
            result := mload(add(values, shl(5, root)))
            mstore(0x40, scratchStart)
        }
    }
