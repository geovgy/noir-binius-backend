// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.35;
import "../src/BiniusPrimitives.sol";

contract TransposeTest {
    BiniusPrimitives p = new BiniusPrimitives();

    function testFuzzTranspose(bytes32 seed) public view {
        uint128[128] memory input;
        for (uint256 i; i < 128; ++i) input[i] = uint128(uint256(keccak256(abi.encode(seed, i))));
        uint256[128] memory actual = p.transposeTest(input);
        for (uint256 column; column < 128; ++column) {
            uint256 expected;
            for (uint256 row; row < 128; ++row) expected |= uint256((input[row] >> column) & 1) << row;
            require(actual[column] == expected, "transpose differs from individual bits");
        }
    }

    function testTransposeDenseAndBoundaries() public view {
        uint128[128] memory input;
        for (uint256 i; i < 128; ++i) input[i] = type(uint128).max;
        uint256[128] memory actual = p.transposeTest(input);
        for (uint256 i; i < 128; ++i) {
            require(actual[i] == type(uint128).max, "transpose lost a dense bit");
            input[i] = 0;
        }
        uint8[8] memory edges = [uint8(0), 1, 2, 63, 64, 65, 126, 127];
        for (uint256 i; i < edges.length; ++i) {
            for (uint256 j; j < edges.length; ++j) {
                input[edges[i]] = uint128(1) << edges[j];
                actual = p.transposeTest(input);
                for (uint256 row; row < 128; ++row) {
                    require(
                        actual[row] == (row == edges[j] ? uint256(1) << edges[i] : 0),
                        "transpose moved a boundary bit incorrectly"
                    );
                }
                input[edges[i]] = 0;
            }
        }
    }
}
