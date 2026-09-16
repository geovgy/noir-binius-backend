// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.28;
import "../src/BiniusPrimitives.sol";

contract PrimitivesTest {
    BiniusPrimitives p = new BiniusPrimitives();

    function referenceMultiply(uint128 a, uint128 b) private pure returns (uint128 value) {
        for (uint256 i; i < 128; ++i) {
            if (b & 1 != 0) value ^= a;
            bool carry = a >> 127 != 0;
            a <<= 1;
            if (carry) a ^= 0x87;
            b >>= 1;
        }
    }

    function testField() public view {
        require(p.mulTest(1, 1) == 1, "identity");
        require(p.mulTest(0, type(uint128).max) == 0 && p.mulTest(type(uint128).max, 0) == 0, "zero product");
        require(p.mulTest(1 << 127, 2) == 0x87, "reduction");
        require(
            p.mulTest(type(uint128).max, type(uint128).max) == referenceMultiply(type(uint128).max, type(uint128).max),
            "all coefficients"
        );
        // Products of canonical 128-bit polynomials have degrees 0..254.
        // Check every monomial against independent bit-serial arithmetic,
        // covering every coefficient of the linear reduction map. Even
        // degrees also cover every basis input of the squaring operation.
        for (uint256 degree; degree < 255; ++degree) {
            uint256 left = degree < 128 ? degree : 127;
            uint128 expected = referenceMultiply(uint128(uint256(1) << left), uint128(uint256(1) << (degree - left)));
            require(p.mulTest(uint256(1) << left, uint256(1) << (degree - left)) == expected, "product basis reduction");
            if (degree & 1 == 0) require(p.squareTest(uint256(1) << (degree >> 1)) == expected, "square basis reduction");
        }
        require(p.squareTest(1 << 127) == p.mulTest(1 << 127, 1 << 127), "square high");
        uint256 a = 0x9876543210012345567890abcdefffff;
        require(p.squareTest(a) == p.mulTest(a, a), "square");
        require(p.mulTest(a, p.inverseTest(a)) == 1, "inverse");
        require(p.inverseTest(0) == 0, "inverse zero");
        require(p.readTest(hex"00112233445566778899aabbccddeeff") == 0xffeeddccbbaa99887766554433221100, "endian");
    }

    function testInverseBasisAndDenseInputs() public view {
        require(p.inverseTest(0) == 0 && p.inverseTest(1) == 1, "inverse zero/one");
        for (uint256 i; i < 128; ++i) {
            uint128 basis = uint128(uint256(1) << i);
            uint128 dense = type(uint128).max ^ basis;
            uint256 inverseBasis = p.inverseTest(basis);
            uint256 inverseDense = p.inverseTest(dense);
            require(inverseBasis <= type(uint128).max && inverseDense <= type(uint128).max, "canonical inverse");
            require(referenceMultiply(basis, uint128(inverseBasis)) == 1, "inverse basis product");
            require(referenceMultiply(dense, uint128(inverseDense)) == 1, "inverse dense product");
        }
    }

    function testHashes() public view {
        require(p.shaTest(hex"") == sha256(hex""), "sha empty");
        require(p.shaTest(bytes("abc")) == sha256(bytes("abc")), "sha abc");
        require(
            p.nodeTest(bytes32(0), hex"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                == hex"4731c4e3a3190d19dace68db5752af1b4ecf26305e75e85db86217662bbeff74",
            "node"
        );
        bytes memory b = new bytes(150);
        for (uint256 i; i < b.length; i++) {
            b[i] = bytes1(uint8(i));
        }
        require(p.shaTest(b) == sha256(b), "sha multi block");
    }

    function referenceRead(bytes memory data, uint256 offset, uint256 width) private pure returns (uint256 value) {
        for (uint256 i; i < width; ++i) value |= uint256(uint8(data[offset + i])) << (8 * i);
    }

    function checkFieldDecoding(bytes memory data, uint256 offset, uint256 count, uint256 width) private view {
        uint256[] memory values = p.readFieldsTest(data, offset, count);
        require(values[0] == 0x12345678 && values[count + 1] == type(uint256).max, "field decoder overwrote a neighbor");
        for (uint256 i; i < count; ++i) {
            require(values[i + 1] == referenceRead(data, offset + 16 * i, 16), "field order or endian mismatch");
        }
        require(p.readWidthTest(data, offset, width) == referenceRead(data, offset, width), "scalar read width mismatch");
        bytes32 word;
        assembly ("memory-safe") { word := mload(add(add(data, 32), offset)) }
        // Generated Noir input checks still reverse all 32 bytes, including
        // high limbs that the field decoder deliberately does not consume.
        require(p.reverseWordTest(word) == referenceRead(data, offset, 32), "full public input word truncated");
    }

    function testFuzzFieldDecoding(bytes32 seed, uint8 offsetHint, uint8 countHint, uint8 widthHint) public view {
        uint256 offset = uint256(offsetHint) % 33;
        uint256 count = uint256(countHint) % 129;
        bytes memory data = new bytes(offset + 16 * count + 32);
        for (uint256 i; i < data.length; ++i) {
            data[i] = bytes1(uint8(uint256(seed) >> (8 * (i % 32))) ^ uint8(i * 71));
        }
        checkFieldDecoding(data, offset, count, uint256(widthHint) % 17);
    }

    function testFieldReadBoundaries() public view {
        uint256[6] memory counts = [uint256(0), 1, 2, 3, 127, 128];
        bytes memory data = new bytes(32 + 16 * 128 + 32);
        for (uint256 i; i < data.length; ++i) data[i] = 0xff;
        for (uint256 i; i < counts.length; ++i) {
            checkFieldDecoding(data, i % 2 == 0 ? 0 : 31, counts[i], i % 2 == 0 ? 0 : 16);
        }
    }

    function testFuzzVectorArithmetic(bytes32 seed, uint8 shift, uint128 scalar) public view {
        uint128[128] memory left;
        uint128[128] memory right;
        for (uint256 i; i < 128; ++i) {
            left[i] = i % 5 == 0 ? 0 : i % 5 == 1 ? 1 : uint128(uint256(keccak256(abi.encode(seed, i, "left"))));
            right[i] = i % 7 == 0 ? 0 : i % 7 == 1 ? 1 : uint128(uint256(keccak256(abi.encode(seed, i, "right"))));
        }
        // Exercise both identities frequently as well as full-width scalars.
        if (uint256(seed) & 3 == 0) scalar = 0;
        if (uint256(seed) & 3 == 1) scalar = 1;
        uint256 offset = uint256(shift) & 127;
        for (uint256 kind; kind < 4; ++kind) {
            uint256[128] memory actual = p.vectorBinaryTest(left, right, scalar, kind, offset);
            for (uint256 i; i < 128; ++i) {
                uint128 b = kind & 2 == 0 ? right[(i + offset) & 127] : scalar;
                uint128 expected = kind & 1 == 0 ? left[i] ^ b : referenceMultiply(left[i], b);
                require(actual[i] == expected, "vector arithmetic differs from scalar reference");
            }
        }
    }

    function testShaPaddingBoundaries() public view {
        uint256[10] memory lengths = [uint256(1), 55, 56, 63, 64, 119, 120, 127, 128, 129];
        for (uint256 k; k < lengths.length; ++k) {
            bytes memory data = new bytes(lengths[k]);
            for (uint256 i; i < data.length; ++i) {
                data[i] = bytes1(uint8(i * 17 + 3));
            }
            require(p.shaTest(data) == sha256(data), "SHA padding boundary");
        }
    }

    function testFuzzScalarSha(bytes calldata data) public view {
        require(p.shaTest(data) == sha256(data), "scalar SHA differs from SHA-256");
    }

    function testFuzzTranscriptObservation(bytes calldata data, uint8 priorBytes, uint16 split) public view {
        uint256 consumed = uint256(priorBytes) % 97;
        bytes32 digest = sha256(hex"");
        uint256 cursor = consumed;
        while (cursor > 32) {
            digest = sha256(abi.encodePacked(digest));
            cursor -= 32;
        }
        // Independent encoding of the native consumed-byte counter as u64 LE.
        bytes memory encodedCursor = new bytes(8);
        for (uint256 i; i < 8; ++i) encodedCursor[i] = bytes1(uint8(cursor >> (8 * i)));
        digest = sha256(bytes.concat(abi.encodePacked(digest), encodedCursor, data));
        uint256 expectedFirst;
        uint256 expectedSecond;
        for (uint256 i; i < 16; ++i) {
            expectedFirst |= uint256(uint8(digest[i])) << (8 * i);
            expectedSecond |= uint256(uint8(digest[i + 16])) << (8 * i);
        }
        (uint256 first, uint256 second) = p.transcriptTest(data, consumed, uint256(split) % (data.length + 1));
        require(first == expectedFirst && second == expectedSecond, "transcript observation differs from native SHA schedule");
    }

    function checkPackedHashes(uint256 length, uint256 count, bytes32 seed) private view {
        bytes memory combined = new bytes(length * count);
        bytes32[7] memory expected;
        for (uint256 lane; lane < count; ++lane) {
            bytes memory message = new bytes(length);
            for (uint256 i; i < length; ++i) {
                // Deliberately different lanes, including dense coefficients
                // that expose accidental carries between packed words.
                bytes1 value = bytes1(uint8(uint256(seed) >> (8 * (i % 32))) ^ uint8(71 * lane + i));
                message[i] = value;
                combined[lane * length + i] = value;
            }
            expected[lane] = sha256(message);
        }
        bytes32[7] memory actual = p.hashesTest(combined, length, count);
        for (uint256 lane; lane < count; ++lane) {
            require(actual[lane] == expected[lane], "packed SHA lane mismatch");
        }
    }

    function testPackedShaPaddingBoundaries() public view {
        uint256[11] memory lengths = [uint256(0), 1, 55, 56, 63, 64, 119, 120, 127, 128, 129];
        for (uint256 k; k < lengths.length; ++k) {
            for (uint256 count = 1; count <= 7; ++count) {
                checkPackedHashes(lengths[k], count, bytes32(type(uint256).max));
            }
        }
    }

    function testPackedShaDenseLanes() public view {
        // Uniform dense words exercise the largest message-schedule sums;
        // alternating neighboring lanes expose guard-bit contamination.
        uint32[7] memory words = [uint32(0xffffffff), 0, 0xffffffff, 0x80000000, 0x7fffffff, 0xaaaaaaaa, 0x55555555];
        bytes memory combined = new bytes(7 * 256);
        bytes32[7] memory expected;
        for (uint256 lane; lane < 7; ++lane) {
            bytes memory message = new bytes(256);
            for (uint256 i; i < 256; ++i) {
                bytes1 value = bytes1(uint8(words[lane] >> (8 * (3 - i % 4))));
                message[i] = value;
                combined[lane * 256 + i] = value;
            }
            expected[lane] = sha256(message);
        }
        bytes32[7] memory actual = p.hashesTest(combined, 256, 7);
        for (uint256 lane; lane < 7; ++lane) {
            require(actual[lane] == expected[lane], "dense packed SHA lane mismatch");
        }
    }

    function testSingleHashResizesScratch() public view {
        bytes memory message = new bytes(4097);
        for (uint256 i; i < message.length; ++i) message[i] = bytes1(uint8(i * 71));
        bytes32[7] memory actual = p.hashesTest(message, message.length, 1);
        require(actual[0] == sha256(message), "single large leaf hash mismatch");
    }

    function testFuzzPackedHashes(bytes32 seed, uint8 length, uint8 lanes) public view {
        checkPackedHashes(uint256(length), 1 + uint256(lanes) % 7, seed);
        bytes32[14] memory pairs;
        for (uint256 i; i < pairs.length; ++i) {
            pairs[i] = keccak256(abi.encode(seed, i));
        }
        bytes32[7] memory actual = p.nodesTest(pairs);
        for (uint256 lane; lane < 7; ++lane) {
            require(actual[lane] == p.nodeTest(pairs[2 * lane], pairs[2 * lane + 1]), "packed Merkle lane mismatch");
        }
    }

    function testFuzzSquareAndInverse(uint128 a, uint128 b) public view {
        require(p.mulTest(a, b) == referenceMultiply(a, b), "carryless multiplication");
        require(p.mulTest(a, b) == p.mulTest(b, a));
        require(p.squareTest(a) == p.mulTest(a, a));
        if (a != 0) require(p.mulTest(a, p.inverseTest(a)) == 1);
    }

    function testMerkleRepeatedPathsCheckBothChildren() public view {
        bytes32[32] memory leaves;
        bytes32[64] memory tree;
        for (uint256 i; i < 32; ++i) {
            leaves[i] = keccak256(abi.encode(i, "Merkle path leaf"));
            tree[32 + i] = sha256(abi.encodePacked(leaves[i]));
        }
        for (uint256 i = 31; i > 0; --i) tree[i] = p.nodeTest(tree[2 * i], tree[2 * i + 1]);
        uint256[19] memory queries = [uint256(5), 5, 8, 8, 11, 17, 23, 5, 8, 11, 17, 23, 5, 8, 11, 17, 23, 5, 5];
        uint256[] memory indices = new uint256[](queries.length);
        bytes memory proof = abi.encodePacked(tree[4], tree[5], tree[6], tree[7]);
        for (uint256 q; q < queries.length; ++q) {
            uint256 index = queries[q];
            indices[q] = index;
            proof = bytes.concat(proof, abi.encodePacked(leaves[index]));
            uint256 node = 32 + index;
            for (uint256 level; level < 3; ++level) {
                proof = bytes.concat(proof, abi.encodePacked(tree[node ^ 1]));
                node >>= 1;
            }
        }
        (bool first, bool second) = p.pathsReuseTest(proof, proof, indices);
        require(first && second, "repeated valid paths rejected");
        bytes memory changed = bytes.concat(proof);
        // The final query repeats an earlier path. After filling the cache,
        // alter its leaf and each sibling in turn. Neither a matching parent
        // position nor a matching single child permits reusing an old digest.
        for (uint256 word; word < 4; ++word) {
            uint256 position = 128 + 18 * 128 + word * 32;
            changed[position] ^= 0x01;
            (first, second) = p.pathsReuseTest(proof, changed, indices);
            require(first && !second, "changed child reused cached parent");
            changed[position] ^= 0x01;
        }
    }
}
