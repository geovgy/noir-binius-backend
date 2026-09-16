// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.28;
import "../src/BiniusPrimitives.sol";

contract FriTest {
    BiniusPrimitives p = new BiniusPrimitives();

    function referenceCoset(
        uint256[] memory values,
        uint256 count,
        uint256 index,
        uint256[] memory challenges,
        uint256 offset,
        uint256[] memory basis
    ) private view returns (uint256) {
        for (uint256 round; round < count; ++round) {
            uint256 shift = count - round - 1;
            for (uint256 j; j < 1 << shift; ++j) {
                uint256 blockIndex = (index << shift) | j;
                uint256 twiddle;
                for (uint256 bit = 1; blockIndex != 0; ++bit) {
                    if (blockIndex & 1 != 0) twiddle ^= basis[bit];
                    blockIndex >>= 1;
                }
                uint256 u = values[2 * j];
                uint256 v = values[2 * j + 1] ^ u;
                u ^= p.mulTest(v, twiddle);
                values[j] = u ^ p.mulTest(v ^ u, challenges[offset + round]);
            }
        }
        return values[0];
    }

    function check(uint256 seed, uint256 count, uint256 index, uint256 offset, uint256 kind) private view {
        uint256[] memory values = new uint256[](1 << count);
        uint256[] memory challenges = new uint256[](offset + count + 1);
        uint256[] memory basis = new uint256[](count + 9);
        for (uint256 i; i < values.length; ++i) {
            values[i] = uint128(uint256(keccak256(abi.encode(seed, i, 0))));
        }
        for (uint256 i; i < basis.length; ++i) {
            basis[i] = uint128(uint256(keccak256(abi.encode(seed, i, 1))));
        }
        for (uint256 i; i < challenges.length; ++i) {
            challenges[i] = uint128(uint256(keccak256(abi.encode(seed, i, 2))));
            if (kind == 0) challenges[i] = 0;
            if (kind == 1) challenges[i] = 1;
            if (kind == 2) challenges[i] = i % 2;
            if (kind == 3 && i % 3 != 2) challenges[i] = i % 3;
        }
        uint256 actual = p.friCosetTest(values, count, index, challenges, offset, basis);
        require(
            actual == referenceCoset(values, count, index, challenges, offset, basis), "native Gao-Mateer fold mismatch"
        );
    }

    function testFriChallengeBoundaries() public view {
        for (uint256 count; count <= 8; ++count) {
            for (uint256 kind; kind < 5; ++kind) {
                check(0x9876, count, 255, 2, kind);
            }
        }
    }

    function testFuzzFriCoset(uint128 seed, uint8 count, uint8 index, uint8 offset, uint8 kind) public view {
        check(seed, uint256(count) % 9, index, uint256(offset) % 4, uint256(kind) % 5);
    }
}
