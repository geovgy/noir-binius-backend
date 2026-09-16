// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.35;
import {BiniusPrimitives} from "../src/BiniusPrimitives.sol";

contract FactoredWiringTest {
    BiniusPrimitives p = new BiniusPrimitives();
    // Generated from the explicit entries below, including duplicate cancellation.
    bytes constant SMALL = hex"ff02020c1b0c0001000002060007000003040710100e020f090310160204040d060b010e050103090101";
    bytes constant WIDE = hex"ff202080018702b20100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000403e40423d3f413c3e403b3d3f3a3c3e393b3d383a3c383a03070b0f13171b3c3e403b3d3f3a3c3e393b3d383a3c37393b36383a363803070b0f13171bba01bc01be01b901bb01bd01b801ba01bc01b701b901bb01b601b801ba01b501b701b901b401b601b801b301b501b7011905090d1115191dba01bc01be01b901bb01bd01b801ba01bc01b701b901bb01b601b801ba01b501b701b901b401b601b801b401b60103070b0f13171bff01fe0102fe0161023d01013c01013b01013a01013901013801013701013701010101010101013b01013a0101390101380101370101360101350101350101010101010101b9010101b8010101b7010101b6010101b5010101b4010101b3010101b20101010101010101010101b9010101b8010101b7010101b6010101b5010101b4010101b3010101b3010101010101010101014001220201";

    function equality(uint256[] memory point, uint256 index) private view returns (uint256 value) {
        value = 1;
        for (uint256 i; i < point.length; ++i) {
            value = p.mulTest(value, point[i] ^ (((index >> i) & 1) ^ 1));
        }
    }

    function entry(uint256[] memory x, uint256[] memory y, uint256 r, uint256 c, uint256 mask, uint256 lambda)
        private view returns (uint256)
    {
        uint256 coefficient = mask & 1;
        if (mask & 2 != 0) coefficient ^= lambda;
        if (mask & 4 != 0) coefficient ^= p.mulTest(lambda, lambda);
        return p.mulTest(coefficient, p.mulTest(equality(x, r), equality(y, c)));
    }

    function checkSmall(uint128 seed, uint256 booleanIndex, bool booleanPoint) private view {
        uint256[] memory x = new uint256[](2);
        uint256[] memory y = new uint256[](2);
        for (uint256 i; i < 2; ++i) {
            x[i] = booleanPoint ? (booleanIndex >> i) & 1 : uint128(uint256(keccak256(abi.encode(seed, i))));
            y[i] = booleanPoint ? (booleanIndex >> (i + 2)) & 1 : uint128(uint256(keccak256(abi.encode(seed, i + 2))));
        }
        uint256 lambda = seed;
        uint256 expected = entry(x, y, 0, 0, 1, lambda) ^ entry(x, y, 0, 1, 2, lambda)
            ^ entry(x, y, 1, 0, 4, lambda) ^ entry(x, y, 1, 2, 7, lambda)
            ^ entry(x, y, 2, 3, 3, lambda) ^ entry(x, y, 3, 1, 5, lambda)
            ^ entry(x, y, 3, 2, 6, lambda);
        require(p.wiringTest(SMALL, x, y, lambda) == expected, "factored sparse polynomial");
        (uint256 a, uint256 b) = p.wiringReuseTest(SMALL, x, y, lambda);
        require(a == expected && b == expected, "factored prepared points or scratch");
        require(p.wiringSharedRowTest(SMALL, x, y, lambda) == expected, "factored shared row");
    }

    function testFuzzFactoredSparsePolynomial(uint128 seed) public view {
        checkSmall(seed, 0, false);
    }

    function testFactoredBooleanCoordinates() public view {
        for (uint256 point; point < 16; ++point) {
            checkSmall(0, point, true);
            checkSmall(1, point, true);
            checkSmall(0x123456789abcdef0123456789abcdef0, point, true);
        }
    }

    function testFactoredFullWidthAndEmptyMatrix() public view {
        uint256[] memory x = new uint256[](32);
        uint256[] memory y = new uint256[](32);
        for (uint256 i; i < 32; ++i) {
            x[i] = uint128(uint256(keccak256(abi.encode(i))));
            y[i] = i % 3 == 0 ? i % 2 : uint128(uint256(keccak256(abi.encode(i + 32))));
        }
        uint256 lambda = 0xc9349845be83949f873843ed93283932;
        uint256 expected = entry(x, y, 0xffffffff, 0, 7, lambda)
            ^ entry(x, y, 0, 0xffffffff, 3, lambda)
            ^ entry(x, y, 0x80000000, 0x80000000, 5, lambda);
        require(p.wiringTest(WIDE, x, y, lambda) == expected, "factored u32 coordinates");
        (uint256 a, uint256 b) = p.wiringReuseTest(WIDE, x, y, lambda);
        require(a == expected && b == expected, "factored full width scratch reuse");
        require(p.wiringSharedRowTest(WIDE, x, y, lambda) == expected, "factored full width shared row");
        require(p.wiringTest(hex"ff2020000000", x, y, lambda) == 0, "factored empty matrix");
    }
}
