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

    function testOperandWidthsAndOpaqueBytes() public {
        // The same delta stream expands at all three widths. Destinations
        // move both forwards and backwards. The table and field constant
        // include full-width values that must not be narrowed.
        bytes memory encoded = hex"060006fe0306fb0306fc0306fd03150010ffffffff800000000002ffffffffffffffffffffffffffffffff";
        bytes memory one = hex"060006ff060106ff0600150008ffffffff800000000001ffffffffffffffffffffffffffffffff";
        bytes memory two = hex"0600000600ff0600010600ff0600001500000008ffffffff80000000000001ffffffffffffffffffffffffffffffff";
        bytes memory four = hex"060000000006000000ff060000000106000000ff0600000000150000000000000008ffffffff800000000000000001ffffffffffffffffffffffffffffffff";
        BiniusCodec1 c1 = new BiniusCodec1();
        BiniusCodec2 c2 = new BiniusCodec2();
        BiniusCodec4 c4 = new BiniusCodec4();
        require(keccak256(c1.expandTest(encoded, one.length)) == keccak256(one), "byte operands");
        require(keccak256(c2.expandTest(encoded, two.length)) == keccak256(two), "short operands");
        require(keccak256(c4.expandTest(encoded, four.length)) == keccak256(four), "wide operands");
        require(keccak256(c2.expandTest(hex"06feff07", 3)) == keccak256(hex"06ffff"), "u16 maximum");
        require(keccak256(c4.expandTest(hex"06feffffff1f", 5)) == keccak256(hex"06ffffffff"), "u32 maximum");
    }
}
