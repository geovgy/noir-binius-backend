            // Reuse each pruned operation word: code/children occupy bits 0..47;
            // depth uses 48..60, new ID 64..83, next bucket member 84..103.
            // The reachability mark at bit 255 remains separate throughout.
            let maxDepth := 0
            for { let id := initial } lt(id, opEnd) { id := add(id, 1) } {
                let p := add(ops, shl(5, id))
                let record := mload(p)
                if and(record, mark) {
                    let a := and(shr(8, record), 0xfffff)
                    let b := and(shr(28, record), 0xfffff)
                    a := and(shr(48, mload(add(ops, shl(5, a)))), 0x1fff)
                    b := and(shr(48, mload(add(ops, shl(5, b)))), 0x1fff)
                    let depth := a
                    if gt(b, a) { depth := b }
                    depth := add(depth, 1)
                    if gt(depth, 4096) { revert(0, 0) }
                    if gt(depth, maxDepth) { maxDepth := depth }
                    mstore(p, or(record, shl(48, depth)))
                }
            }
            let bucketWidth := mul(2, add(mul(2, n), 1))
            let buckets := alloc(shl(5, mul(bucketWidth, maxDepth)))
            for { let id := initial } lt(id, opEnd) { id := add(id, 1) } {
                let record := mload(add(ops, shl(5, id)))
                if and(record, mark) {
                    let depth := and(shr(48, record), 0x1fff)
                    let shortA := and(iszero(and(record, 255)), lt(and(shr(8, record), 0xfffff), initial))
                    let key := add(mul(sub(depth, 1), bucketWidth), or(shl(1, and(record, 255)), shortA))
                    let p := add(buckets, shl(5, key))
                    let word := mload(p)
                    let head := and(word, 0xfffff)
                    switch head
                    case 0 { head := id }
                    default {
                        let tail := add(ops, shl(5, shr(20, word)))
                        mstore(tail, or(mload(tail), shl(84, id)))
                    }
                    mstore(p, or(head, shl(20, id)))
                }
            }
            // Reserve a 16-byte prefix and the last MSTORE's 29-byte overhang.
            data := alloc(add(80, mul(7, scalarCount)))
            // This allocation's length is written only after emission. Keep
            // the bounded root/count here while neither is used by the loop.
            mstore(data, or(shl(32, scalarRoot), scalarCount))
            scalarRoot := 0
            scalarCount := 0
            let groupStart := add(data, 48)
            let cursor := groupStart
            let header := 0
            let groupCode := 256
            let groupCount := 0
            let next := initial
            for { let depth := 0 } lt(depth, maxDepth) { depth := add(depth, 1) } {
                for { let code := 0 } lt(code, bucketWidth) { code := add(code, 1) } {
                    let id := and(mload(add(buckets, shl(5, add(mul(depth, bucketWidth), code)))), 0xfffff)
                    if id {
                        if iszero(eq(code, groupCode)) {
                            if groupCount {
                                mstore8(add(header, 1), shr(8, groupCount))
                                mstore8(add(header, 2), groupCount)
                            }
                            groupCode := code
                            groupCount := 0
                            header := cursor
                            mstore8(header, or(shr(1, code), shl(7, and(code, 1))))
                            cursor := add(cursor, 3)
                        }
                        for {} id {} {
                            let p := add(ops, shl(5, id))
                            let record := mload(p)
                            let a := mapped(ops, and(shr(8, record), 0xfffff), initial)
                            if iszero(and(code, 1)) { a := sub(next, a) }
                            let b := sub(next, mapped(ops, and(shr(28, record), 0xfffff), initial))
                            mstore(p, or(record, shl(64, next)))
                            let referenceShift := shl(3, and(code, 1))
                            mstore(cursor, or(shl(add(240, referenceShift), a), shl(add(224, referenceShift), b)))
                            cursor := add(cursor, sub(4, and(code, 1)))
                            groupCount := add(groupCount, 1)
                            next := add(next, 1)
                            id := and(shr(84, record), 0xfffff)
                        }
                    }
                }
            }
            scalarRoot := shr(32, mload(data))
            scalarCount := and(mload(data), 0xffffffff)
            if iszero(eq(next, add(initial, scalarCount))) { revert(0, 0) }
            if groupCount {
                mstore8(add(header, 1), shr(8, groupCount))
                mstore8(add(header, 2), groupCount)
            }
            scalarRoot := mapped(ops, scalarRoot, initial)
            header := add(data, 32)
            mstore8(header, 255)
            mstore8(add(header, 1), or(nx, 128))
            mstore8(add(header, 2), ny)
            header := writeNumber(add(header, 3), scalarCount)
            header := writeNumber(header, scalarRoot)
            header := writeNumber(header, mul(2, scalarCount))
            let length := sub(cursor, groupStart)
            mcopy(header, groupStart, length)
            mstore(data, sub(add(header, length), add(data, 32)))
