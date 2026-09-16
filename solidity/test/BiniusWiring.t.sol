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
        checkDimensions(seed, row, column, dr, dc, n, mask, booleanPoint, 7, 8);
    }

    function checkDimensions(
        uint256 seed,
        int256 row,
        int256 column,
        int256 dr,
        int256 dc,
        uint256 n,
        uint256 mask,
        bool booleanPoint,
        uint256 nx,
        uint256 ny
    ) private view {
        uint256[] memory x = new uint256[](nx);
        uint256[] memory y = new uint256[](ny);
        for (uint256 i; i < x.length; ++i) {
            x[i] = uint128(uint256(keccak256(abi.encode(seed, i))));
        }
        for (uint256 i; i < y.length; ++i) {
            y[i] = uint128(uint256(keccak256(abi.encode(seed, i + 100))));
        }
        if (booleanPoint) {
            // Select a point on the run, so this also exercises nonzero
            // carry-state evaluations at Boolean coordinates.
            uint256 selectedRow = uint256(row + int256(seed % n) * dr);
            uint256 selectedColumn = uint256(column + int256(seed % n) * dc);
            for (uint256 i; i < x.length; ++i) {
                x[i] = (selectedRow >> i) & 1;
            }
            for (uint256 i; i < y.length; ++i) {
                y[i] = (selectedColumn >> i) & 1;
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
        require(
            p.wiringSharedRowTest(data, x, y, lambda) == p.mulTest(expected, coefficient),
            "shared row wiring differs from direct sum"
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
        check(10, 13, 57, 1, 1, 63, 7, false);
        check(11, 27, 57, 2, 4, 29, 3, false);
        check(12, 34, 12, 1, 2, 61, 5, false);
        check(13, 13, 57, 1, 1, 63, 7, true);
        check(14, 27, 57, 2, 4, 29, 3, true);
        check(15, 70, 137, 2, 4, 29, 7, false);
        check(16, 70, 137, 2, 4, 29, 7, true);
        checkDimensions(17, 0xffffffc7, 0xffffff8f, 2, 4, 29, 7, false, 32, 32);
        checkDimensions(18, 0xffffffc7, 0xffffff8f, 2, 4, 29, 7, true, 32, 32);
    }

    function testZeroAndUnitFactors() public view {
        uint256[6] memory values = [
            uint256(0), 1, uint256(1) << 64, uint256(1) << 127,
            (uint256(1) << 127) | 1, uint256(type(uint128).max)
        ];
        uint256[] memory x = new uint256[](1);
        uint256[] memory y = new uint256[](1);
        // One entry at (1,1) evaluates to the binary-field product x[0]*y[0].
        bytes memory matrix = bytes.concat(uv(1), uv(1), uv(1), zz(1), zz(1), zz(1), zz(1), zz(0), zz(0));
        for (uint256 i; i < values.length; ++i) {
            x[0] = values[i];
            for (uint256 j; j < values.length; ++j) {
                y[0] = values[j];
                uint256 expected = p.mulTest(x[0], y[0]);
                require(p.wiringTest(matrix, x, y, 1) == expected, "zero or unit factor differs");
                require(p.wiringSharedRowTest(matrix, x, y, 1) == expected, "shared zero or unit factor differs");
            }
        }
    }

    function testEveryShortPointDimension() public view {
        for (uint256 nx; nx <= 10; ++nx) {
            for (uint256 ny; ny <= 10; ++ny) {
                // Exercise empty points, every single-chunk dimension, and
                // the first multi-chunk dimension with Boolean and field points.
                checkDimensions(nx * 11 + ny, 0, 0, 0, 0, 1, 7, false, nx, ny);
                checkDimensions(nx * 11 + ny, 0, 0, 0, 0, 1, 7, true, nx, ny);
            }
        }
    }

    function testRoundedIntervalCancelsExcludedPoints() public view {
        for (uint256 example; example < 3; ++example) {
            uint256 nx = example == 2 ? 32 : 7;
            uint256 ny = example == 2 ? 32 : 8;
            uint256 row = example == 0 ? 27 : example == 1 ? 70 : 0xffffffc7;
            uint256 column = example == 0 ? 57 : example == 1 ? 137 : 0xffffff8f;
            uint256[] memory x = new uint256[](nx);
            uint256[] memory y = new uint256[](ny);
            bytes memory data = bytes.concat(uv(nx), uv(ny), uv(1), zz(7), zz(29), zz(int256(row)), zz(int256(column)), zz(2), zz(4));
            // Examples 1/2 put the excluded auxiliary points beyond the
            // matrix domain, including beyond u32. Their wrapped equality
            // evaluations must still cancel, leaving exactly the original run.
            for (uint256 t = 29; t < 32; ++t) {
                for (uint256 i; i < x.length; ++i) x[i] = ((row + 2 * t) >> i) & 1;
                for (uint256 i; i < y.length; ++i) y[i] = ((column + 4 * t) >> i) & 1;
                require(p.wiringTest(data, x, y, 7) == 0, "rounded interval kept an excluded entry");
            }
        }
    }

    function testSharedCarryStatesAndPreparedPointReuse() public view {
        uint256[] memory x = new uint256[](7);
        uint256[] memory y = new uint256[](8);
        for (uint256 i; i < x.length; ++i) {
            x[i] = uint128(uint256(keccak256(abi.encode(i))));
        }
        for (uint256 i; i < y.length; ++i) {
            y[i] = uint128(uint256(keccak256(abi.encode(i + 17))));
        }
        bytes memory data = bytes.concat(uv(x.length), uv(y.length), uv(32));
        int256[6] memory previous;
        uint256[3] memory sums;
        for (uint256 run; run < 32; ++run) {
            uint256 dr = 1 << (run % 3);
            uint256 dc = 1 << ((run / 3) % 3);
            uint256 row = run % 7;
            uint256 column = (run * 37) % 11;
            uint256 n = (128 - row) / dr;
            if (n > (256 - column) / dc) n = (256 - column) / dc;
            if (n > 73) n = 73;
            uint256 mask = 1 + run % 7;
            int256[6] memory values = [int256(mask), int256(n), int256(row), int256(column), int256(dr), int256(dc)];
            previous[2] += previous[1] * previous[4];
            previous[3] += previous[1] * previous[5];
            for (uint256 i; i < values.length; ++i) {
                data = bytes.concat(data, zz(values[i] - previous[i]));
                previous[i] = values[i];
            }
            uint256 sum;
            for (uint256 i; i < n; ++i) {
                sum ^= p.mulTest(eqAt(x, row + i * dr), eqAt(y, column + i * dc));
            }
            for (uint256 side; side < 3; ++side) {
                if (mask & (1 << side) != 0) sums[side] ^= sum;
            }
        }
        uint256 lambda = 0xc9349845be83949f873843ed93283932;
        uint256 expected = sums[0] ^ p.mulTest(lambda, sums[1] ^ p.mulTest(lambda, sums[2]));
        require(p.wiringTest(data, x, y, lambda) == expected, "shared carry state differs from scalar sum");
        (uint256 first, uint256 second) = p.wiringReuseTest(data, x, y, lambda);
        require(first == expected && second == expected, "prepared point reuse changed the polynomial");
    }

    function testSuffixCacheWithFullWidthIndices() public view {
        uint256[] memory x = new uint256[](32);
        uint256[] memory y = new uint256[](32);
        for (uint256 i; i < 32; ++i) {
            x[i] = uint128(uint256(keccak256(abi.encode(i, "full width x"))));
            y[i] = uint128(uint256(keccak256(abi.encode(i, "full width y"))));
        }
        uint32[11] memory rows = [
            uint32(0xf0000003),
            0xf0034e83,
            0xf010a703,
            0xf013f583,
            0xf0214e03,
            0xf0249c83,
            0xf02ea683,
            0xf031f503,
            0xf03f4d83,
            0xf0429c03,
            0xf04ff483
        ];
        uint32[11] memory columns = [
            uint32(0xc0000039),
            0xc0034eb9,
            0xc010a739,
            0xc013f5b9,
            0xc01dffb9,
            0xc0214e39,
            0xc02ea6b9,
            0xc031f539,
            0xc03f4db9,
            0xc0429c39,
            0xc04ff4b9
        ];
        bytes memory data = bytes.concat(uv(32), uv(32), uv(24));
        int256[6] memory previous;
        uint256 expected;
        for (uint256 run; run < 24; ++run) {
            uint256 index = run < 12 ? run : 23 - run;
            // These distinct rows/columns collide at lo=0 in the 4096-slot
            // memo. The last distinct run checks maximum u32 indices.
            uint256 row = index == 11 ? type(uint32).max : rows[index];
            uint256 column = index == 11 ? type(uint32).max : columns[index];
            uint256 count = index == 11 || index % 3 == 0 ? 1 : 29;
            uint256 dr = 1 << (index % 3);
            uint256 dc = 1 << ((index / 3) % 3);
            // Different coefficients keep paired repeated runs from cancelling.
            uint256 mask = 1 + run % 7;
            int256[6] memory values = [int256(mask), int256(count), int256(row), int256(column), int256(dr), int256(dc)];
            previous[2] += previous[1] * previous[4];
            previous[3] += previous[1] * previous[5];
            for (uint256 i; i < values.length; ++i) {
                data = bytes.concat(data, zz(values[i] - previous[i]));
                previous[i] = values[i];
            }
            uint256 sum;
            for (uint256 i; i < count; ++i) {
                sum ^= p.mulTest(eqAt(x, row + i * dr), eqAt(y, column + i * dc));
            }
            uint256 coefficient = mask & 1;
            if (mask & 2 != 0) coefficient ^= 7;
            if (mask & 4 != 0) coefficient ^= p.mulTest(7, 7);
            expected ^= p.mulTest(coefficient, sum);
        }
        require(p.wiringTest(data, x, y, 7) == expected, "full-width suffix cache differs from scalar sum");
        (uint256 first, uint256 second) = p.wiringReuseTest(data, x, y, 7);
        require(first == expected && second == expected, "full-width prepared points changed after memory reuse");
    }

    function checkInterval(uint256 seed, uint256 dimension, uint256 start, uint256 shift, uint256 count)
        private view
    {
        uint256[] memory point = new uint256[](dimension);
        uint256[] memory empty = new uint256[](0);
        for (uint256 i; i < dimension; ++i) {
            point[i] = uint128(uint256(keccak256(abi.encode(seed, i, "interval"))));
        }
        uint256 stride = 1 << shift;
        require(start + (count - 1) * stride < 1 << dimension, "invalid reference interval");
        uint256 expected;
        for (uint256 i; i < count; ++i) {
            expected ^= eqAt(point, start + i * stride);
        }
        bytes memory columns = bytes.concat(
            uv(0), uv(dimension), uv(1), zz(1), zz(int256(count)), zz(0), zz(int256(start)), zz(0), zz(int256(stride))
        );
        bytes memory rows = bytes.concat(
            uv(dimension), uv(0), uv(1), zz(1), zz(int256(count)), zz(int256(start)), zz(0), zz(int256(stride)), zz(0)
        );
        require(p.wiringTest(columns, empty, point, 7) == expected, "column interval differs from direct sum");
        require(p.wiringTest(rows, point, empty, 7) == expected, "row interval differs from direct sum");
        (uint256 first, uint256 second) = p.wiringReuseTest(columns, empty, point, 7);
        require(first == expected && second == expected, "cumulative tables changed after memory reuse");
    }

    function testCumulativeIntervalEndpoints() public view {
        uint256[11] memory dimensions = [uint256(0), 1, 5, 7, 8, 9, 15, 16, 17, 31, 32];
        for (uint256 d; d < dimensions.length; ++d) {
            uint256 n = dimensions[d];
            uint256 domain = 1 << n;
            for (uint256 k; k < 3; ++k) {
                uint256 shift = k == 0 ? 0 : k == 1 ? n / 2 : n > 8 ? 8 : n;
                uint256 count = domain >> shift;
                if (count > 19) count = 19;
                checkInterval(d, n, 0, shift, count);
                // Include the final matrix index. The exclusive endpoint is
                // 2^n + stride - 1, including 2^32 and larger at full width.
                checkInterval(d + 100, n, domain - 1 - ((count - 1) << shift), shift, count);
            }
        }
    }

    function testFuzzCumulativeIntervals(uint64 seed, uint8 dimension, uint8 strideBits, uint8 length) public view {
        uint256 n = uint256(dimension) % 33;
        uint256 shift = uint256(strideBits) % (n + 1);
        uint256 count = (1 << n) >> shift;
        if (count > 32) count = 32;
        count = 1 + uint256(length) % count;
        uint256 start = uint256(seed) % ((1 << n) - ((count - 1) << shift));
        checkInterval(seed, n, start, shift, count);
    }

    function testFuzzAffine(uint64 seed, uint8 a, uint8 b, uint8 r, uint8 c, uint8 count) public view {
        uint256 dr = 1 << (a % 4);
        uint256 dc = 1 << (b % 4);
        uint256 n = 1 + (uint256(count) % 8);
        // Exercise products across several cached chunks, including partial
        // final chunks and Boolean coordinates, against the explicit sum.
        uint256 nx = 7 + uint256(r) % 26;
        uint256 ny = 7 + uint256(c) % 26;
        uint256 row = uint256(seed) % ((1 << nx) - (n - 1) * dr);
        uint256 column = uint256(keccak256(abi.encode(seed, a, b))) % ((1 << ny) - (n - 1) * dc);
        checkDimensions(seed, int256(row), int256(column), int256(dr), int256(dc), n, 1 + seed % 7, seed & 1 != 0, nx, ny);
    }
}
