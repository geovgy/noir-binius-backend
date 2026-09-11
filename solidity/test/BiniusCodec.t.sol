// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.28;
import "../src/BiniusPrimitives.sol";

interface VmCodec {
    function projectRoot() external view returns (string memory);
    function readFileBinary(string calldata path) external view returns (bytes memory);
}

contract CodecTest {
    VmCodec constant vm = VmCodec(address(uint160(uint256(keccak256("hevm cheat code")))));

    function testExactGeneratedProgram() public {
        BiniusPrimitives primitives = new BiniusPrimitives();
        string memory prefix = string.concat(vm.projectRoot(), "/../target/solidity-test.");
        bytes memory packed = vm.readFileBinary(string.concat(prefix, "compressed"));
        bytes memory encoded = vm.readFileBinary(string.concat(prefix, "encoded"));
        bytes memory program = vm.readFileBinary(string.concat(prefix, "program"));
        bytes memory decoded = primitives.decompressTest(packed, encoded.length);
        require(keccak256(decoded) == keccak256(encoded), "LZMA differs from native encoder");
        bytes memory expanded = primitives.expandTest(decoded, program.length);
        require(keccak256(expanded) == keccak256(program), "program differs from native equations");
    }
}
