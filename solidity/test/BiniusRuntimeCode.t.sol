// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.35;
import {BiniusVerifier} from "../src/NativeBiniusVerifier.sol";

contract RuntimeCodeTest {
    function _deploy() internal virtual returns (BiniusVerifier) {
        return new BiniusVerifier();
    }

    // Keep this separately embedded runtime out of the full-proof harness.
    // Combining both makes that test contract exceed 64 KiB; production
    // verifier code is independently checked against normal EVM size limits.
    function testDeployedRuntimeMatchesCompiler() public {
        BiniusVerifier verifier = _deploy();
        require(
            address(verifier).codehash == keccak256(type(BiniusVerifier).runtimeCode),
            "constructor returned different verification code"
        );
    }
}
