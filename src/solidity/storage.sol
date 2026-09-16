// Lossless fixed-program storage: construction copies literals; verification decodes them.
    function _packStorage(bytes memory input, bytes memory headers, uint256 length)
        internal pure returns (bytes memory output)
    {
        require(headers.length % 4 == 0);
        // The final mstore can extend past the logical output by 28 bytes.
        output = new bytes(length + 32);
        assembly ("memory-safe") {
            let at := add(input, 32)
            let inputEnd := add(at, mload(input))
            let header := add(headers, 32)
            let headerEnd := add(header, mload(headers))
            let dest := add(output, 32)
            let outputEnd := add(dest, length)
            for {} lt(header, headerEnd) { header := add(header, 4) } {
                let word := mload(header)
                let literal := byte(0, word)
                let count := byte(1, word)
                if or(gt(add(add(at, literal), count), inputEnd), gt(add(add(dest, 4), literal), outputEnd)) { revert(0, 0) }
                mstore(dest, word)
                mcopy(add(dest, 4), at, literal)
                dest := add(add(dest, 4), literal)
                at := add(add(at, literal), count)
            }
            if or(iszero(eq(at, inputEnd)), iszero(eq(dest, outputEnd))) { revert(0, 0) }
            mstore(output, length)
        }
    }


    function _unpackStorage(bytes memory input, uint256 length)
        internal pure returns (bytes memory output)
    {
        output = new bytes(length);
        assembly ("memory-safe") {
            let at := add(input, 32)
            let end := add(at, mload(input))
            let begin := add(output, 32)
            let dest := begin
            let outputEnd := add(begin, length)
            for {} lt(at, end) {} {
                if gt(add(at, 4), end) { revert(0, 0) }
                let word := mload(at)
                let literal := byte(0, word)
                let count := byte(1, word)
                let distance := and(shr(224, word), 65535)
                at := add(at, 4)
                if or(gt(add(at, literal), end), gt(add(add(dest, literal), count), outputEnd)) { revert(0, 0) }
                mcopy(dest, at, literal)
                at := add(at, literal)
                dest := add(dest, literal)
                switch count
                case 0 { if distance { revert(0, 0) } }
                default {
                    if or(iszero(distance), gt(distance, sub(dest, begin))) { revert(0, 0) }
                    let copied := distance
                    if gt(copied, count) { copied := count }
                    mcopy(dest, sub(dest, distance), copied)
                    for {} lt(copied, count) {} {
                        let take := sub(count, copied)
                        if gt(take, copied) { take := copied }
                        mcopy(add(dest, copied), dest, take)
                        copied := add(copied, take)
                    }
                    dest := add(dest, count)
                }
            }
            if iszero(eq(dest, outputEnd)) { revert(0, 0) }
        }
    }


