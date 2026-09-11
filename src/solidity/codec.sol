    // Raw LZMA1, fixed lc=1/lp=0/pb=2. The fixed constructor
    // literal supplies the compressed stream; proof bytes never enter it.
    function _unlzma(bytes memory compressed, uint256 size) private pure returns (bytes memory decoded) {
        decoded = new bytes(size + 32);
        uint256[3382] memory probabilities;
        uint256[9] memory state;
        assembly ("memory-safe") {
            // State: range, code, input pointer, probability pointer, rep[0..3], LZ state.
            function normalize(c) {
                let range := mload(c)
                if lt(range, 0x1000000) {
                    let p := mload(add(c, 64))
                    mstore(c, shl(8, range))
                    mstore(add(c, 32), and(or(shl(8, mload(add(c, 32))), byte(0, mload(p))), 0xffffffff))
                    mstore(add(c, 64), add(p, 1))
                }
            }
            function bit(c, index) -> value {
                let p := add(mload(add(c, 96)), shl(5, index))
                let prob := mload(p)
                let bound := mul(shr(11, mload(c)), prob)
                switch lt(mload(add(c, 32)), bound)
                case 1 {
                    mstore(c, bound)
                    mstore(p, add(prob, shr(5, sub(2048, prob))))
                }
                default {
                    value := 1
                    mstore(c, sub(mload(c), bound))
                    mstore(add(c, 32), sub(mload(add(c, 32)), bound))
                    mstore(p, sub(prob, shr(5, prob)))
                }
                normalize(c)
            }
            function tree(c, base, n) -> value {
                value := 1
                for { let i := 0 } lt(i, n) { i := add(i, 1) } { value := add(shl(1, value), bit(c, add(base, value))) }
                value := sub(value, shl(n, 1))
            }
            function reverseTree(c, base, n) -> value {
                let node := 1
                for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                    let b := bit(c, add(base, node))
                    node := add(shl(1, node), b)
                    value := or(value, shl(i, b))
                }
            }
            function direct(c, n) -> value {
                for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                    let range := shr(1, mload(c))
                    mstore(c, range)
                    let b := iszero(lt(mload(add(c, 32)), range))
                    if b { mstore(add(c, 32), sub(mload(add(c, 32)), range)) }
                    value := or(shl(1, value), b)
                    normalize(c)
                }
            }
            function length(c, base, pos) -> value {
                switch bit(c, base)
                case 0 { value := tree(c, add(add(base, 2), shl(3, pos)), 3) }
                default {
                    switch bit(c, add(base, 1))
                    case 0 { value := add(8, tree(c, add(add(base, 130), shl(3, pos)), 3)) }
                    default { value := add(16, tree(c, add(base, 258), 8)) }
                }
                value := add(value, 2)
            }
            function literal(c, base, matched, prediction) -> value {
                value := 1
                if matched {
                    for {} lt(value, 256) {} {
                        let expected := and(shr(7, prediction), 1)
                        prediction := shl(1, prediction)
                        let b := bit(c, add(add(base, shl(8, add(1, expected))), value))
                        value := add(shl(1, value), b)
                        if iszero(eq(expected, b)) { break }
                    }
                }
                for {} lt(value, 256) {} { value := add(shl(1, value), bit(c, add(base, value))) }
            }
            let start := add(decoded, 32)
            let out := start
            let end := add(start, size)
            let input := add(compressed, 32)
            if byte(0, mload(input)) { revert(0, 0) }
            mstore(state, 0xffffffff)
            mstore(add(state, 32), shr(224, mload(add(input, 1))))
            mstore(add(state, 64), add(input, 5))
            mstore(add(state, 96), probabilities)
            for { let p := probabilities } lt(p, add(probabilities, 108224)) { p := add(p, 32) } { mstore(p, 1024) }
            for {} lt(out, end) {} {
                let pos := and(sub(out, start), 3)
                let machine := mload(add(state, 256))
                switch bit(state, add(shl(4, machine), pos))
                case 0 {
                    let previous := 0
                    if gt(out, start) { previous := byte(0, mload(sub(out, 1))) }
                    let prediction := 0
                    if gt(machine, 6) { prediction := byte(0, mload(sub(sub(out, 1), mload(add(state, 128))))) }
                    mstore8(out, literal(state, add(1846, mul(shr(7, previous), 768)), gt(machine, 6), prediction))
                    out := add(out, 1)
                    switch lt(machine, 4)
                    case 1 { machine := 0 }
                    default { switch lt(machine, 10)
                    case 1 { machine := sub(machine, 3) }
                    default { machine := sub(machine, 6) } }
                }
                default {
                    let n := 0
                    switch bit(state, add(192, machine))
                    case 1 {
                        switch bit(state, add(204, machine))
                        case 0 {
                            if iszero(bit(state, add(240, add(shl(4, machine), pos)))) {
                                n := 1
                                switch lt(machine, 7)
                                case 1 { machine := 9 }
                                default { machine := 11 }
                            }
                        }
                        default {
                            let distance
                            switch bit(state, add(216, machine))
                            case 0 { distance := mload(add(state, 160)) }
                            default {
                                switch bit(state, add(228, machine))
                                case 0 { distance := mload(add(state, 192)) }
                                default {
                                    distance := mload(add(state, 224))
                                    mstore(add(state, 224), mload(add(state, 192)))
                                }
                                mstore(add(state, 192), mload(add(state, 160)))
                            }
                            mstore(add(state, 160), mload(add(state, 128)))
                            mstore(add(state, 128), distance)
                        }
                        if iszero(n) {
                            n := length(state, 1332, pos)
                            switch lt(machine, 7)
                            case 1 { machine := 8 }
                            default { machine := 11 }
                        }
                    }
                    default {
                        mstore(add(state, 224), mload(add(state, 192)))
                        mstore(add(state, 192), mload(add(state, 160)))
                        mstore(add(state, 160), mload(add(state, 128)))
                        n := length(state, 818, pos)
                        switch lt(machine, 7)
                        case 1 { machine := 7 }
                        default { machine := 10 }
                        let lenState := sub(n, 2)
                        if gt(lenState, 3) { lenState := 3 }
                        let slot := tree(state, add(432, shl(6, lenState)), 6)
                        let distance := slot
                        if gt(slot, 3) {
                            let bits := sub(shr(1, slot), 1)
                            distance := shl(bits, or(2, and(slot, 1)))
                            switch lt(slot, 14)
                            case 1 {
                                distance := add(
                                    distance,
                                    reverseTree(state, sub(add(688, distance), add(slot, 1)), bits)
                                )
                            }
                            default {
                                distance := add(distance, shl(4, direct(state, sub(bits, 4))))
                                distance := add(distance, reverseTree(state, 802, 4))
                            }
                        }
                        mstore(add(state, 128), distance)
                    }
                    let distance := add(mload(add(state, 128)), 1)
                    if or(gt(distance, sub(out, start)), gt(n, sub(end, out))) { revert(0, 0) }
                    let source := sub(out, distance)
                    for { let copied := 0 } lt(copied, n) {} {
                        let count := add(distance, copied)
                        if gt(count, sub(n, copied)) { count := sub(n, copied) }
                        mcopy(add(out, copied), source, count)
                        copied := add(copied, count)
                    }
                    out := add(out, n)
                }
                mstore(add(state, 256), machine)
                if gt(mload(add(state, 64)), add(input, mload(compressed))) { revert(0, 0) }
            }
            mstore(decoded, size)
        }
    }

    function _expandProgram(bytes memory encoded, uint256 size) private pure returns (bytes memory program) {
        program = new bytes(size + 32);
        uint256[256] memory previous;
        assembly ("memory-safe") {
            function operand(p, out, base, lane) -> q, next, value {
                let n := 0
                let shift := 0
                q := p
                for {} 1 {} {
                    let b := byte(0, mload(q))
                    q := add(q, 1)
                    n := or(n, shl(shift, and(b, 127)))
                    if iszero(and(b, 128)) { break }
                    shift := add(shift, 7)
                }
                let slot := add(base, shl(5, lane))
                value := add(mload(slot), xor(shr(1, n), sub(0, and(n, 1))))
                mstore(slot, value)
                mstore(out, shl(224, value))
                next := add(out, 4)
            }
            let p := add(encoded, 32)
            let end := add(p, mload(encoded))
            let out := add(program, 32)
            for {} lt(p, end) {} {
                let op := byte(0, mload(p))
                p := add(p, 1)
                mstore8(out, op)
                out := add(out, 1)
                let base := add(previous, shl(8, op))
                let n
                p, out, n := operand(p, out, base, 0)
                let fixed := 0
                let copied := 0
                switch op
                case 0 { copied := 16 }
                case 1 { fixed := 2 }
                case 2 { fixed := 2 }
                case 3 { fixed := 1 }
                case 4 {
                    fixed := 1
                    copied := 1
                }
                case 5 { fixed := 1 }
                case 6 {}
                case 13 {}
                case 7 { copied := 1 }
                case 8 { fixed := 2 }
                case 9 { fixed := 1 }
                case 10 {
                    fixed := 1
                    copied := 1
                }
                case 11 {
                    fixed := 1
                    copied := 1
                }
                case 12 {
                    fixed := 1
                    copied := 1
                }
                case 14 { fixed := 3 }
                case 15 { fixed := 5 }
                case 16 { fixed := 4 }
                case 17 { for { let i := 0 } lt(i, 128) { i := add(i, 1) } { p, out, n := operand(p, out, base, 1) } }
                case 18 {
                    fixed := 1
                    copied := 1
                }
                case 19 {
                    p, out, n := operand(p, out, base, 1)
                    for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                        let ignored
                        p, out, ignored := operand(p, out, base, 2)
                    }
                }
                case 20 { fixed := 3 }
                case 21 { p, out, copied := operand(p, out, base, 1) }
                case 22 {
                    fixed := 1
                    copied := 1
                }
                case 23 { p, out, copied := operand(p, out, base, 1) }
                case 24 {
                    fixed := 4
                    copied := 1
                }
                case 25 { p, out, copied := operand(p, out, base, 1) }
                case 26 {
                    fixed := 2
                    copied := 2
                }
                case 27 { fixed := 1 }
                case 28 { fixed := 1 }
                case 29 {
                    n := byte(0, mload(p))
                    mstore8(out, n)
                    p := add(p, 1)
                    out := add(out, 1)
                    for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                        let ignored
                        p, out, ignored := operand(p, out, base, 1)
                    }
                }
                case 30 { p, out, copied := operand(p, out, base, 1) }
                case 31 { fixed := 1 }
                default { revert(0, 0) }
                for { let i := 1 } iszero(gt(i, fixed)) { i := add(i, 1) } { p, out, n := operand(p, out, base, i) }
                mcopy(out, p, copied)
                out := add(out, copied)
                p := add(p, copied)
            }
            if or(iszero(eq(p, end)), iszero(eq(out, add(add(program, 32), size)))) { revert(0, 0) }
            mstore(program, size)
        }
    }
