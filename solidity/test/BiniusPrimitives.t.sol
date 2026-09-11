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
        require(p.mulTest(1 << 127, 2) == 0x87, "reduction");
        require(
            p.mulTest(type(uint128).max, type(uint128).max) == referenceMultiply(type(uint128).max, type(uint128).max),
            "all coefficients"
        );
        require(p.squareTest(1 << 127) == p.mulTest(1 << 127, 1 << 127), "square high");
        uint256 a = 0x9876543210012345567890abcdefffff;
        require(p.squareTest(a) == p.mulTest(a, a), "square");
        require(p.mulTest(a, p.inverseTest(a)) == 1, "inverse");
        require(p.inverseTest(0) == 0, "inverse zero");
        require(p.readTest(hex"00112233445566778899aabbccddeeff") == 0xffeeddccbbaa99887766554433221100, "endian");
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

    function checkPackedHashes(uint256 length, uint256 count, bytes32 seed) private view {
        bytes memory combined = new bytes(length * count);
        bytes32[4] memory expected;
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
        bytes32[4] memory actual = p.hashesTest(combined, length, count);
        for (uint256 lane; lane < count; ++lane) {
            require(actual[lane] == expected[lane], "packed SHA lane mismatch");
        }
    }

    function testPackedShaPaddingBoundaries() public view {
        uint256[11] memory lengths = [uint256(0), 1, 55, 56, 63, 64, 119, 120, 127, 128, 129];
        for (uint256 k; k < lengths.length; ++k) {
            for (uint256 count = 1; count <= 4; ++count) {
                checkPackedHashes(lengths[k], count, bytes32(type(uint256).max));
            }
        }
    }

    function testFuzzPackedHashes(bytes32 seed, uint8 length, uint8 lanes) public view {
        checkPackedHashes(uint256(length), 1 + uint256(lanes) % 4, seed);
        bytes32[8] memory pairs;
        for (uint256 i; i < pairs.length; ++i) {
            pairs[i] = keccak256(abi.encode(seed, i));
        }
        bytes32[4] memory actual = p.nodesTest(pairs);
        for (uint256 lane; lane < 4; ++lane) {
            require(actual[lane] == p.nodeTest(pairs[2 * lane], pairs[2 * lane + 1]), "packed Merkle lane mismatch");
        }
    }

    function testFuzzSquareAndInverse(uint128 a, uint128 b) public view {
        require(p.mulTest(a, b) == referenceMultiply(a, b), "carryless multiplication");
        require(p.mulTest(a, b) == p.mulTest(b, a));
        require(p.squareTest(a) == p.mulTest(a, a));
        if (a != 0) require(p.mulTest(a, p.inverseTest(a)) == 1);
    }
}
