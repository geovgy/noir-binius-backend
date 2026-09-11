// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.28;
import "../src/BiniusPrimitives.sol";

contract WiringTest {
    BiniusPrimitives p = new BiniusPrimitives();

    function uv(uint256 n) private pure returns (bytes memory b) {
        while (n >= 128) {
            b = bytes.concat(b, bytes1(uint8(n) | 128));
            n >>= 7;
        }
        return bytes.concat(b, bytes1(uint8(n)));
    }

    function zz(int256 n) private pure returns (bytes memory) {
        return uv(uint256(n < 0 ? -2 * n - 1 : 2 * n));
    }

    function eqAt(uint256[] memory point, uint256 index) private view returns (uint256 value) {
        value = 1;
        for (uint256 i; i < point.length; ++i) {
            value = p.mulTest(value, point[i] ^ (((index >> i) & 1) ^ 1));
        }
    }

    function check(
        uint256 seed,
        int256 row,
        int256 column,
        int256 dr,
        int256 dc,
        uint256 n,
        uint256 mask,
        bool booleanPoint
    ) private view {
        uint256[] memory x = new uint256[](7);
        uint256[] memory y = new uint256[](8);
        for (uint256 i; i < x.length; ++i) {
            x[i] = uint128(uint256(keccak256(abi.encode(seed, i))));
        }
        for (uint256 i; i < y.length; ++i) {
            y[i] = uint128(uint256(keccak256(abi.encode(seed, i + 100))));
        }
        if (booleanPoint) {
            for (uint256 i; i < x.length; ++i) {
                x[i] &= 1;
            }
            for (uint256 i; i < y.length; ++i) {
                y[i] &= 1;
            }
        }
        bytes memory data = bytes.concat(
            uv(x.length), uv(y.length), uv(1), zz(int256(mask)), zz(int256(n)), zz(row), zz(column), zz(dr), zz(dc)
        );
        uint256 expected;
        for (uint256 i; i < n; ++i) {
            expected ^= p.mulTest(eqAt(x, uint256(row + int256(i) * dr)), eqAt(y, uint256(column + int256(i) * dc)));
        }
        uint256 lambda = 0xc9349845be83949f873843ed93283932;
        uint256 coefficient = (mask & 1) != 0 ? 1 : 0;
        if (mask & 2 != 0) coefficient ^= lambda;
        if (mask & 4 != 0) coefficient ^= p.mulTest(lambda, lambda);
        require(
            p.wiringTest(data, x, y, lambda) == p.mulTest(expected, coefficient),
            "affine wiring differs from direct sum"
        );
    }

    function testCarryAndIntervalBoundaries() public view {
        check(1, 0, 0, 1, 1, 128, 7, false);
        check(2, 13, 57, 1, 1, 73, 5, false);
        check(3, 3, 9, 2, 4, 59, 3, false);
        check(4, 5, 130, 0, 2, 63, 4, false);
        check(5, 120, 17, -3, 1, 33, 6, false);
        check(6, 63, 255, 0, 0, 1, 1, false);
        check(7, 0, 0, 1, 1, 128, 7, true);
        check(8, 13, 57, 1, 1, 73, 5, true);
        check(9, 1, 3, 2, 4, 64, 7, false);
    }

    function testFuzzAffine(uint64 seed, uint8 a, uint8 b, uint8 r, uint8 c, uint8 count) public view {
        uint256 dr = 1 << (a % 4);
        uint256 dc = 1 << (b % 4);
        uint256 row = uint256(r) % 64;
        uint256 column = uint256(c) % 128;
        uint256 n = 1 + (uint256(count) % 8);
        check(seed, int256(row), int256(column), int256(dr), int256(dc), n, 1 + seed % 7, false);
    }
}
