    // Only nonzero (1+r) factors enter the normalized coset scale.
    // The caller retains this common scale while evaluating its query cosets.
    function _friScale(uint256[] memory challenges, uint256 offset, uint256 count)
        private pure returns (uint256 result)
    {
        uint256 scale = 1;
        unchecked {
            for (uint256 i = offset; i < offset + count; ++i) {
                uint256 scalar;
                // The fixed FRI configuration bounds this challenge range.
                assembly ("memory-safe") {
                    scalar := xor(shr(128, mload(add(add(challenges, 32), shl(5, i)))), 1)
                    // A zero (1+r) factor represents the unscaled XOR fold.
                    scalar := or(scalar, iszero(scalar))
                }
                scale = _mul(scale, scalar);
            }
        }
        return scale;
    }
