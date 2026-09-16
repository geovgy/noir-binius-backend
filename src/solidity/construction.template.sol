    constructor() {
        bytes memory joint = _unlzma(hex"{{PAYLOAD}}", {{JOINT_LENGTH}});
        uint256 executable;
        assembly ("memory-safe") {
            executable := add(add(joint, 32), ENCODED_PROGRAM_LENGTH)
            mstore(joint, ENCODED_PROGRAM_LENGTH)
        }
{{PACKING_HEADERS}}
        bytes memory precursor = _expandProgram(joint, {{PRECURSOR_LENGTH}});
        bytes memory affine = new bytes({{AFFINE_LENGTH}});
        assembly ("memory-safe") {
            mcopy(add(affine, 32), add(add(precursor, 32), {{INPUT_OFFSET}}), {{AFFINE_LENGTH}})
        }
        (bytes memory graph, uint256 root,) = _derive(
            affine, hex"{{ORDER}}", {{MAX_NODES}}, {{NODE_SLOTS}}, 8192, 1024
        );
        // The graph precedes the derivation scratch. All scratch reads have
        // ended and subsequent allocations explicitly clear reused memory.
        assembly ("memory-safe") {
            mstore(0x40, and(add(add(graph, mload(graph)), 63), not(31)))
        }
        (bytes memory matrix,,) = _expressions(
            graph, root, {{NX}}, {{NY}}, {{CHUNK_BITS}}, {{MAX_OPS}}, {{OP_SLOTS}}
        );
        require(matrix.length == {{MATRIX_LENGTH}});
        bytes memory data = new bytes(VERIFICATION_PROGRAM_LENGTH);
        assembly ("memory-safe") {
            let dest := add(data, 32)
            mcopy(dest, add(precursor, 32), {{LENGTH_OFFSET}})
            {{WRITE_LENGTH}}
            mcopy(add(dest, {{OUTPUT_OFFSET}}), add(matrix, 32), {{MATRIX_LENGTH}})
            mcopy(
                add(dest, add({{OUTPUT_OFFSET}}, {{MATRIX_LENGTH}})),
                add(add(precursor, 32), add({{INPUT_OFFSET}}, {{AFFINE_LENGTH}})),
                {{TAIL_LENGTH}}
            )
        }
        // Bind every installed equation and operand to the key-only generator.
        require(keccak256(data) == {{PROGRAM_HASH}});
{{PACK_PROGRAM}}
        assembly ("memory-safe") {
            let length := mload(data)
            sstore(verificationProgram.slot, add(mul(length, 2), 1))
            mstore(0, verificationProgram.slot)
            let slot := keccak256(0, 32)
            for { let i := 0 } lt(i, length) { i := add(i, 32) } {
                sstore(add(slot, shr(5, i)), mload(add(add(data, 32), i)))
            }
            {{RETURN_RUNTIME}}
        }
    }
