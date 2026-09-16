// Constructor-only circuit construction; no proof or transcript is an input.
    function _derive(bytes memory affine, bytes memory order, uint256 maxNodes,
        uint256 hashSlots, uint256 runSlots, uint256 xorSlots)
        internal pure returns (bytes memory graph, uint256 root, uint256 count)
    {
        require(maxNodes < (1 << 20) - 8);
        require(hashSlots > maxNodes && hashSlots & (hashSlots - 1) == 0);
        require(runSlots > 0 && runSlots & (runSlots - 1) == 0);
        require(xorSlots > 0 && xorSlots & (xorSlots - 1) == 0);
        uint256[18] memory context;
        assembly ("memory-safe") {
            // Context: nodes, next ID, limit, intern table, intern byte mask,
            // n, ref width, domain, order, ranks, XOR cache, XOR byte mask,
            // run cache, run byte mask, nx, row mask, roots, input end.
            function alloc(size) -> p {
                p := mload(0x40)
                mstore(0x40, and(add(add(p, size), 31), not(31)))
                calldatacopy(p, calldatasize(), size)
            }
            function readNumber(p, end) -> value, next {
                let shift := 0
                for {} 1 {} {
                    if iszero(lt(p, end)) { revert(0, 0) }
                    let octet := byte(0, mload(p))
                    p := add(p, 1)
                    value := or(value, shl(shift, and(octet, 127)))
                    if iszero(and(octet, 128)) { break }
                    shift := add(shift, 7)
                    if gt(shift, 63) { revert(0, 0) }
                }
                next := p
            }
            function cacheSlot(key, mask) -> offset {
                let mixed := xor(key, shr(64, key))
                mixed := xor(mixed, shr(32, mixed))
                offset := and(shr(26, mul(mixed, 0x9e3779b97f4a7c15)), mask)
            }
            function intern(c, key) -> id {
                let table := mload(add(c, 96))
                let mask := mload(add(c, 128))
                let nodes := mload(c)
                mstore(0, key)
                let slot := and(shl(5, keccak256(0, 32)), mask)
                let initial := slot
                for {} 1 {} {
                    id := mload(add(table, slot))
                    if iszero(id) {
                        id := mload(add(c, 32))
                        if iszero(lt(id, mload(add(c, 64)))) { revert(0, 0) }
                        mstore(add(c, 32), add(id, 1))
                        mstore(add(nodes, shl(5, id)), key)
                        mstore(add(table, slot), id)
                        break
                    }
                    if eq(mload(add(nodes, shl(5, id))), key) { break }
                    slot := and(add(slot, 32), mask)
                    if eq(slot, initial) { revert(0, 0) }
                }
            }
            function branch(c, axis, a, b) -> value {
                if eq(a, b) { value := a leave }
                if iszero(a) { value := or(b, shl(add(20, axis), 1)) leave }
                if iszero(b) { value := or(a, shl(add(add(20, mload(add(c, 160))), axis), 1)) leave }
                let common := and(and(a, b), not(0xfffff))
                let width := mload(add(c, 192))
                let key := or(shl(mul(2, width), axis), or(shl(width, xor(a, common)), xor(b, common)))
                value := or(common, intern(c, key))
            }
            function point(c, r, col, coefficient) -> value {
                let nx := mload(add(c, 448))
                let n := mload(add(c, 160))
                if or(iszero(lt(r, shl(nx, 1))), iszero(lt(col, shl(sub(n, nx), 1)))) { revert(0, 0) }
                let on := or(r, shl(nx, col))
                let off := xor(mload(add(c, 224)), on)
                value := or(coefficient, or(shl(20, on), shl(add(20, n), off)))
            }
            function top(c, value) -> rank {
                let ranks := mload(add(c, 288))
                let id := and(value, 0xfffff)
                if gt(id, 7) {
                    let axis := shr(mul(2, mload(add(c, 192))), mload(add(mload(c), shl(5, id))))
                    rank := and(shr(mul(6, axis), ranks), 63)
                }
                let n := mload(add(c, 160))
                let literals := and(or(shr(20, value), shr(add(20, n), value)), mload(add(c, 224)))
                let rows := and(literals, mload(add(c, 480)))
                if rows {
                    let r := and(shr(mul(6, sub(255, clz(rows))), ranks), 63)
                    if gt(r, rank) { rank := r }
                }
                let columns := shr(mload(add(c, 448)), literals)
                if columns {
                    let r := and(shr(mul(6, add(mload(add(c, 448)), sub(255, clz(columns)))), ranks), 63)
                    if gt(r, rank) { rank := r }
                }
            }
            function cofactor(c, value, axis, high) -> result {
                if iszero(value) { leave }
                let one := shl(add(20, axis), 1)
                let zero := shl(mload(add(c, 160)), one)
                let wrong := one
                let right := zero
                if high { wrong := zero right := one }
                if and(value, wrong) { leave }
                if and(value, right) { result := xor(value, right) leave }
                let id := and(value, 0xfffff)
                if gt(id, 7) {
                    let record := mload(add(mload(c), shl(5, id)))
                    let width := mload(add(c, 192))
                    if eq(shr(mul(2, width), record), axis) {
                        if iszero(high) { record := shr(width, record) }
                        let child := and(record, sub(shl(width, 1), 1))
                        if child { result := or(and(value, not(0xfffff)), child) }
                        leave
                    }
                }
                result := value
            }
            function combine(c, a, b) -> value {
                if iszero(a) { value := b leave }
                if iszero(b) { value := a leave }
                if eq(a, b) { leave }
                let common := and(and(a, b), not(0xfffff))
                a := xor(a, common)
                b := xor(b, common)
                if gt(a, b) { let t := a a := b b := t }
                let key := or(shl(96, a), b)
                let slot := add(mload(add(c, 320)), cacheSlot(key, mload(add(c, 352))))
                switch eq(mload(slot), key)
                case 1 { value := mload(add(slot, 32)) }
                default {
                    let rank := top(c, a)
                    let other := top(c, b)
                    if gt(other, rank) { rank := other }
                    switch rank
                    case 0 { value := xor(a, b) }
                    default {
                        let axis := and(shr(mul(6, sub(rank, 1)), mload(add(c, 256))), 63)
                        let low := combine(c, cofactor(c, a, axis, 0), cofactor(c, b, axis, 0))
                        let high := combine(c, cofactor(c, a, axis, 1), cofactor(c, b, axis, 1))
                        value := branch(c, axis, low, high)
                    }
                    mstore(slot, key)
                    mstore(add(slot, 32), value)
                }
                if value { value := or(value, common) }
            }
            function varying(first, stride, count_) -> mask {
                if stride {
                    let difference := xor(first, add(first, mul(sub(count_, 1), stride)))
                    mask := and(sub(shl(sub(256, clz(difference)), 1), 1), not(sub(stride, 1)))
                }
            }
            function interval(c, coefficient, count_, r, col, dr, dc) -> value {
                if eq(count_, 1) { value := point(c, r, col, coefficient) leave }
                let nx := mload(add(c, 448))
                let n := mload(add(c, 160))
                let vr := varying(r, dr, count_)
                let vc := varying(col, dc, count_)
                let fixed_ := xor(mload(add(c, 224)), or(vr, shl(nx, vc)))
                let on := and(or(r, shl(nx, col)), fixed_)
                let common := or(shl(20, on), shl(add(20, n), xor(fixed_, on)))
                r := and(r, vr)
                col := and(col, vc)
                let key := or(coefficient, or(shl(3, count_), or(shl(35, r), or(shl(67, col), or(shl(99, dr), shl(131, dc))))))
                let slot := add(mload(add(c, 384)), cacheSlot(key, mload(add(c, 416))))
                switch eq(mload(slot), key)
                case 1 { value := mload(add(slot, 32)) }
                default {
                    let axis := sub(255, clz(vr))
                    let columnAxis := add(nx, sub(255, clz(vc)))
                    let ranks := mload(add(c, 288))
                    if or(iszero(vr), and(iszero(iszero(vc)), gt(and(shr(mul(6, columnAxis), ranks), 63), and(shr(mul(6, axis), ranks), 63)))) { axis := columnAxis }
                    let first := r
                    let stride := dr
                    let bit := axis
                    if iszero(lt(axis, nx)) { first := col stride := dc bit := sub(axis, nx) }
                    let boundary := shl(bit, add(shr(bit, first), 1))
                    let split := div(sub(add(sub(boundary, first), stride), 1), stride)
                    if or(iszero(split), iszero(lt(split, count_))) { revert(0, 0) }
                    let a := interval(c, coefficient, split, r, col, dr, dc)
                    let b := interval(c, coefficient, sub(count_, split), add(r, mul(split, dr)), add(col, mul(split, dc)), dr, dc)
                    value := branch(c, axis, xor(a, shl(add(add(axis, 20), n), 1)), xor(b, shl(add(axis, 20), 1)))
                    value := xor(value, shl(add(20, n), fixed_))
                    mstore(slot, key)
                    mstore(add(slot, 32), value)
                }
                value := or(value, common)
            }
            function sort(p, length) {
                if gt(length, 1) {
                    let end := add(p, shl(5, length))
                    let pivot := mload(add(p, shl(5, shr(1, length))))
                    let i := p
                    let j := sub(end, 32)
                    for {} iszero(gt(i, j)) {} {
                        for {} lt(mload(i), pivot) {} { i := add(i, 32) }
                        for {} gt(mload(j), pivot) {} { j := sub(j, 32) }
                        if iszero(gt(i, j)) {
                            let a := mload(i)
                            mstore(i, mload(j))
                            mstore(j, a)
                            i := add(i, 32)
                            j := sub(j, 32)
                        }
                    }
                    if gt(j, p) { sort(p, add(shr(5, sub(j, p)), 1)) }
                    if lt(i, sub(end, 32)) { sort(i, shr(5, sub(end, i))) }
                }
            }
            function reduce(c, p, length, mask) -> value {
                for {} gt(length, 1) {} {
                    let next := 0
                    for { let i := 0 } lt(i, length) { i := add(i, 2) } {
                        let a := and(mload(add(p, shl(5, i))), mask)
                        if lt(add(i, 1), length) { a := combine(c, a, and(mload(add(p, shl(5, add(i, 1)))), mask)) }
                        mstore(add(p, shl(5, next)), a)
                        next := add(next, 1)
                    }
                    length := next
                }
                if length { value := and(mload(p), mask) }
            }
            let c := context
            let p := add(affine, 32)
            let end := add(p, mload(affine))
            mstore(add(c, 544), end)
            let nx, ny, length
            nx, p := readNumber(p, end)
            ny, p := readNumber(p, end)
            length, p := readNumber(p, end)
            let n := add(nx, ny)
            if or(or(iszero(n), gt(n, 36)), or(gt(nx, 32), gt(ny, 32))) { revert(0, 0) }
            if iszero(eq(mload(order), n)) { revert(0, 0) }
            let width := add(20, mul(2, n))
            mstore(add(c, 160), n)
            mstore(add(c, 192), width)
            mstore(add(c, 224), sub(shl(n, 1), 1))
            mstore(add(c, 448), nx)
            mstore(add(c, 480), sub(shl(nx, 1), 1))
            {
                let ordered := 0
                let ranks := 0
                let seen := 0
                for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                    let axis := byte(0, mload(add(add(order, 32), i)))
                    if or(iszero(lt(axis, n)), and(seen, shl(axis, 1))) { revert(0, 0) }
                    if and(iszero(or(iszero(axis), eq(axis, nx))), iszero(and(seen, shl(sub(axis, 1), 1)))) { revert(0, 0) }
                    seen := or(seen, shl(axis, 1))
                    ordered := or(ordered, shl(mul(6, i), axis))
                    ranks := or(ranks, shl(mul(6, axis), add(i, 1)))
                }
                mstore(add(c, 256), ordered)
                mstore(add(c, 288), ranks)
            }
            graph := alloc(add(32, shl(5, add(maxNodes, 8))))
            mstore(c, add(graph, 32))
            mstore(add(c, 32), 8)
            mstore(add(c, 64), add(maxNodes, 8))
            mstore(add(c, 96), alloc(shl(5, hashSlots)))
            mstore(add(c, 128), shl(5, sub(hashSlots, 1)))
            mstore(add(c, 320), alloc(shl(6, xorSlots)))
            mstore(add(c, 352), shl(6, sub(xorSlots, 1)))
            mstore(add(c, 384), alloc(shl(6, runSlots)))
            mstore(add(c, 416), shl(6, sub(runSlots, 1)))
            let roots := alloc(shl(5, length))
            mstore(add(c, 512), roots)
            let previous := alloc(192)
            for { let record := 0 } lt(record, length) { record := add(record, 1) } {
                mstore(add(previous, 64), add(mload(add(previous, 64)), mul(mload(add(previous, 32)), mload(add(previous, 128)))))
                mstore(add(previous, 96), add(mload(add(previous, 96)), mul(mload(add(previous, 32)), mload(add(previous, 160)))))
                for { let j := 0 } lt(j, 192) { j := add(j, 32) } {
                    let delta
                    delta, p := readNumber(p, end)
                    let signed := shr(1, delta)
                    if and(delta, 1) { signed := not(signed) }
                    mstore(add(previous, j), add(mload(add(previous, j)), signed))
                }
                let coefficient := mload(previous)
                let count_ := mload(add(previous, 32))
                let r := mload(add(previous, 64))
                let col := mload(add(previous, 96))
                let dr := mload(add(previous, 128))
                let dc := mload(add(previous, 160))
                if or(or(iszero(coefficient), gt(coefficient, 7)), or(iszero(count_), gt(count_, 0xffffffff))) { revert(0, 0) }
                let value
                switch or(eq(count_, 1), and(and(lt(dr, 0x100000000), iszero(and(dr, sub(dr, 1)))), and(lt(dc, 0x100000000), iszero(and(dc, sub(dc, 1))))))
                case 1 {
                    if and(gt(count_, 1), iszero(or(dr, dc))) { revert(0, 0) }
                    value := interval(c, coefficient, count_, r, col, dr, dc)
                }
                default {
                    let row := alloc(shl(5, count_))
                    for { let i := 0 } lt(i, count_) { i := add(i, 1) } {
                        mstore(add(row, shl(5, i)), point(c, add(r, mul(i, dr)), add(col, mul(i, dc)), coefficient))
                    }
                    value := reduce(c, row, count_, not(0))
                }
                let first := or(r, shl(nx, col))
                let last := or(add(r, mul(sub(count_, 1), dr)), shl(nx, add(col, mul(sub(count_, 1), dc))))
                if lt(last, first) { first := last }
                let key := 0
                for { let rank := 0 } lt(rank, n) { rank := add(rank, 1) } {
                    let axis := and(shr(mul(6, rank), mload(add(c, 256))), 63)
                    key := or(key, shl(rank, and(shr(axis, first), 1)))
                }
                mstore(add(roots, shl(5, record)), or(shl(width, key), value))
            }
            if iszero(eq(p, end)) { revert(0, 0) }
            sort(roots, length)
            root := reduce(c, roots, length, sub(shl(width, 1), 1))
            count := sub(mload(add(c, 32)), 8)
            mstore(graph, shl(5, add(count, 8)))
        }
    }



    function _expressions(bytes memory graph, uint256 graphRoot, uint256 nx, uint256 ny,
        uint256 chunkBits, uint256 maxOps, uint256 opSlots)
        internal pure returns (bytes memory data, uint256 scalarRoot, uint256 scalarCount)
    {
        require(nx + ny > 0 && nx + ny <= 36 && chunkBits > 0 && chunkBits <= 10);
        require(maxOps + 8 + 2 * (nx + ny) < 1 << 20);
        require(opSlots > maxOps && opSlots & (opSlots - 1) == 0);
        uint256[13] memory context;
        assembly ("memory-safe") {
            // Context: ops, next ID, limit, intern table, intern byte mask,
            // n, first operation ID, subsets, chunk bits, chunk count,
            // cube cache, cube cache byte mask, diagram values.
            function alloc(size) -> p {
                p := mload(0x40)
                mstore(0x40, and(add(add(p, size), 31), not(31)))
                calldatacopy(p, calldatasize(), size)
            }
            function instruction(c, code, a, b) -> id {
                let key := or(code, or(shl(8, a), shl(28, b)))
                let table := mload(add(c, 96))
                let mask := mload(add(c, 128))
                let ops := mload(c)
                mstore(0, key)
                let slot := and(shl(5, keccak256(0, 32)), mask)
                let initial := slot
                for {} 1 {} {
                    id := mload(add(table, slot))
                    if iszero(id) {
                        id := mload(add(c, 32))
                        if iszero(lt(id, mload(add(c, 64)))) { revert(0, 0) }
                        mstore(add(c, 32), add(id, 1))
                        mstore(add(ops, shl(5, id)), key)
                        mstore(add(table, slot), id)
                        break
                    }
                    if eq(mload(add(ops, shl(5, id))), key) { break }
                    slot := and(add(slot, 32), mask)
                    if eq(slot, initial) { revert(0, 0) }
                }
            }
            function product(c, a, b) -> value {
                if or(iszero(a), iszero(b)) { leave }
                if eq(a, 1) { value := b leave }
                if eq(b, 1) { value := a leave }
                if gt(a, b) { let t := a a := b b := t }
                value := instruction(c, 0, a, b)
            }
            function cube(c, edge) -> value {
                let key := shr(20, edge)
                if iszero(key) { value := 1 leave }
                mstore(0, key)
                let slot := add(mload(add(c, 320)), and(shl(6, keccak256(0, 32)), mload(add(c, 352))))
                if eq(mload(slot), key) { value := mload(add(slot, 32)) leave }
                let n := mload(add(c, 160))
                let bits := mload(add(c, 256))
                let mask := sub(shl(bits, 1), 1)
                let on := and(key, sub(shl(n, 1), 1))
                let off := shr(n, key)
                let subsets := mload(add(c, 224))
                value := 1
                for { let chunk := mload(add(c, 288)) } chunk {} {
                    chunk := sub(chunk, 1)
                    let shift := mul(bits, chunk)
                    let row := add(subsets, shl(add(bits, 6), chunk))
                    let a := mload(add(row, shl(5, and(shr(shift, on), mask))))
                    let b := mload(add(add(row, shl(add(bits, 5), 1)), shl(5, and(shr(shift, off), mask))))
                    value := product(c, value, product(c, a, b))
                }
                mstore(slot, key)
                mstore(add(slot, 32), value)
            }
            function mapped(ops, id, initial) -> value {
                value := id
                if iszero(lt(id, initial)) { value := and(shr(64, mload(add(ops, shl(5, id)))), 0xfffff) }
            }
            function writeNumber(p, value) -> next {
                for {} gt(value, 127) {} {
                    mstore8(p, or(and(value, 127), 128))
                    p := add(p, 1)
                    value := shr(7, value)
                }
                mstore8(p, value)
                next := add(p, 1)
            }
            let c := context
            let n := add(nx, ny)
            let initial := add(8, mul(2, n))
            let chunks := div(add(n, sub(chunkBits, 1)), chunkBits)
            let ops := alloc(shl(5, add(initial, maxOps)))
            mstore(c, ops)
            mstore(add(c, 32), initial)
            mstore(add(c, 64), add(initial, maxOps))
            mstore(add(c, 96), alloc(shl(5, opSlots)))
            mstore(add(c, 128), shl(5, sub(opSlots, 1)))
            mstore(add(c, 160), n)
            mstore(add(c, 192), initial)
            mstore(add(c, 256), chunkBits)
            mstore(add(c, 288), chunks)
            let subsets := alloc(shl(add(chunkBits, 6), chunks))
            mstore(add(c, 224), subsets)
            mstore(add(c, 320), alloc(65536))
            mstore(add(c, 352), 65472)
            let values := alloc(mload(graph))
            mstore(add(c, 384), values)
            for { let chunk := 0 } lt(chunk, chunks) { chunk := add(chunk, 1) } {
                let start := mul(chunk, chunkBits)
                let bits := chunkBits
                if gt(add(start, bits), n) { bits := sub(n, start) }
                for { let zero := 0 } lt(zero, 2) { zero := add(zero, 1) } {
                    let row := add(subsets, shl(add(chunkBits, 5), add(mul(2, chunk), zero)))
                    mstore(row, 1)
                    for { let mask := 1 } lt(mask, shl(bits, 1)) { mask := add(mask, 1) } {
                        let low := and(mask, sub(0, mask))
                        let coordinate := add(add(add(8, mul(zero, n)), start), sub(255, clz(low)))
                        mstore(add(row, shl(5, mask)), product(c, coordinate, mload(add(row, shl(5, xor(mask, low))))))
                    }
                }
            }
            let nodes := add(graph, 32)
            let total := shr(5, mload(graph))
            let width := add(20, mul(2, n))
            let refMask := sub(shl(width, 1), 1)
            let rootNode := and(graphRoot, 0xfffff)
            if iszero(lt(rootNode, total)) { revert(0, 0) }
            mstore(add(values, shl(5, rootNode)), 1)
            // Child IDs always precede their parents. A descending pass marks
            // exactly the reachable graph, without traversing dead intermediates.
            for { let id := total } gt(id, 8) {} {
                id := sub(id, 1)
                if mload(add(values, shl(5, id))) {
                    let record := mload(add(nodes, shl(5, id)))
                    mstore(add(values, shl(5, and(shr(width, record), 0xfffff))), 1)
                    mstore(add(values, shl(5, and(record, 0xfffff))), 1)
                }
            }
            for { let id := 0 } lt(id, 8) { id := add(id, 1) } { mstore(add(values, shl(5, id)), id) }
            for { let id := 8 } lt(id, total) { id := add(id, 1) } {
                if mload(add(values, shl(5, id))) {
                    let record := mload(add(nodes, shl(5, id)))
                    let low := and(shr(width, record), refMask)
                    let high := and(record, refMask)
                    let a := product(c, cube(c, low), mload(add(values, shl(5, and(low, 0xfffff)))))
                    let b := product(c, cube(c, high), mload(add(values, shl(5, and(high, 0xfffff)))))
                    let code := add(shr(mul(2, width), record), 1)
                    if gt(a, b) { let t := a a := b b := t code := add(code, n) }
                    let value := a
                    if iszero(eq(a, b)) {
                        switch a
                        case 0 { value := product(c, add(7, code), b) }
                        default { value := instruction(c, code, a, b) }
                    }
                    mstore(add(values, shl(5, id)), value)
                }
            }
            scalarRoot := product(c, cube(c, graphRoot), mload(add(values, shl(5, rootNode))))
            // A high-bit mark and the later renumbering share unused bits of
            // each operation word; no second operation graph is allocated.
            let mark := shl(255, 1)
            let opEnd := mload(add(c, 32))
            if iszero(lt(scalarRoot, initial)) {
                let p := add(ops, shl(5, scalarRoot))
                mstore(p, or(mark, mload(p)))
            }
            for { let id := opEnd } gt(id, initial) {} {
                id := sub(id, 1)
                let record := mload(add(ops, shl(5, id)))
                if and(record, mark) {
                    scalarCount := add(scalarCount, 1)
                    let a := and(shr(8, record), 0xfffff)
                    let b := and(shr(28, record), 0xfffff)
                    if iszero(lt(a, initial)) { let p := add(ops, shl(5, a)) mstore(p, or(mark, mload(p))) }
                    if iszero(lt(b, initial)) { let p := add(ops, shl(5, b)) mstore(p, or(mark, mload(p))) }
                }
            }
            if gt(add(initial, scalarCount), 65536) { revert(0, 0) }
            {
                let next := initial
                for { let id := initial } lt(id, opEnd) { id := add(id, 1) } {
                    let p := add(ops, shl(5, id))
                    let record := mload(p)
                    if and(record, mark) { mstore(p, or(record, shl(64, next))) next := add(next, 1) }
                }
            }
            scalarRoot := mapped(ops, scalarRoot, initial)
            data := alloc(add(48, mul(5, scalarCount)))
            let codes := add(data, 32)
            mstore8(codes, 255)
            mstore8(add(codes, 1), nx)
            mstore8(add(codes, 2), ny)
            codes := writeNumber(add(codes, 3), scalarCount)
            codes := writeNumber(codes, scalarRoot)
            codes := writeNumber(codes, mul(2, scalarCount))
            let streamA := add(codes, scalarCount)
            let streamB := add(streamA, mul(2, scalarCount))
            mstore(data, sub(add(streamB, mul(2, scalarCount)), add(data, 32)))
            let next := initial
            for { let id := initial } lt(id, opEnd) { id := add(id, 1) } {
                let record := mload(add(ops, shl(5, id)))
                if and(record, mark) {
                    let a := sub(next, mapped(ops, and(shr(8, record), 0xfffff), initial))
                    let b := sub(next, mapped(ops, and(shr(28, record), 0xfffff), initial))
                    mstore8(codes, and(record, 255))
                    mstore8(streamA, shr(8, a))
                    mstore8(add(streamA, 1), a)
                    mstore8(streamB, shr(8, b))
                    mstore8(add(streamB, 1), b)
                    codes := add(codes, 1)
                    streamA := add(streamA, 2)
                    streamB := add(streamB, 2)
                    next := add(next, 1)
                }
            }
        }
    }


