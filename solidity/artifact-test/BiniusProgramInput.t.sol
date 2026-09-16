// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.35;
import {BiniusVerifier, IVerifier} from "../src/NativeBiniusVerifier.sol";
import {ArtifactCreation} from "./BiniusArtifact.t.sol";

interface VmProgramInput {
    function projectRoot() external view returns (string memory);
    function readFileBinary(string calldata path) external view returns (bytes memory);
    function load(address target, bytes32 slot) external view returns (bytes32);
    function coolSlot(address target, bytes32 slot) external;
}

contract ArtifactProgramInputTest is ArtifactCreation {
    VmProgramInput private constant vm = VmProgramInput(address(uint160(uint256(keccak256("hevm cheat code")))));
    event log_named_uint(string name, uint256 value);

    function _file(string memory suffix) private view returns (bytes memory) {
        return vm.readFileBinary(string.concat(vm.projectRoot(), "/../target/solidity-test.", suffix));
    }

    function _programInfo() private view returns (uint256 length, bytes32 digest) {
        uint256 scratch;
        assembly ("memory-safe") { scratch := mload(0x40) }
        bytes memory data = _file("program");
        length = data.length;
        digest = keccak256(data);
        // Only scalar metadata escapes. Proof loading below exceeds this
        // scratch allocation before we measure caller ABI + verification gas.
        assembly ("memory-safe") { mstore(0x40, scratch) }
    }

    function _inputs() private view returns (bytes32[] memory values) {
        bytes memory b = _file("inputs");
        values = new bytes32[](b.length / 32);
        for (uint256 i; i < values.length; ++i) {
            assembly ("memory-safe") {
                mstore(add(add(values, 32), shl(5, i)), mload(add(add(b, 32), shl(5, i))))
            }
        }
    }

    function _check(bool hinted) private {
        BiniusVerifier verifier = _deployArtifact();
        (uint256 length, bytes32 digest) = _programInfo();
        require(vm.load(address(verifier), bytes32(0)) == digest, "constructor digest mismatch");
        bytes memory proof = _file(hinted ? "key-hinted" : "key-binius");
        bytes32[] memory values = _inputs();
        uint256 first = uint256(keccak256(abi.encode(uint256(0))));
        vm.coolSlot(address(verifier), bytes32(0));
        for (uint256 i; i < (length + 31) / 32; ++i) {
            vm.coolSlot(address(verifier), bytes32(first + i));
        }
        uint256 start = gasleft();
        require(IVerifier(address(verifier)).verify(proof, values), "valid program input rejected");
        uint256 used = start - gasleft();
        emit log_named_uint(hinted ? "program input hinted verification gas" : "program input native verification gas", used);
        uint256[3] memory offsets = [uint256(8), 8 + length / 2, 8 + length - 1];
        for (uint256 i; i < offsets.length; ++i) {
            proof[offsets[i]] ^= 0x01;
            require(!verifier.verify(proof, values), "wrong public program accepted");
            proof[offsets[i]] ^= 0x01;
        }
        require(!verifier.verify(proof, new bytes32[](values.length + 1)), "wrong input count accepted");
        if (values.length != 0) {
            values[0] ^= bytes32(uint256(1));
            require(!verifier.verify(proof, values), "wrong public input accepted");
            values[0] ^= bytes32(uint256(1));
        }
        bytes memory positions = _file("corruptions");
        require(positions.length == 64, "missing native query offsets");
        for (uint256 i; i < positions.length; i += 8) {
            uint256 offset;
            assembly ("memory-safe") { offset := shr(192, mload(add(add(positions, 32), i))) }
            offset += 8 + length + (hinted ? 8 : 0);
            proof[offset] ^= 0x01;
            require(!verifier.verify(proof, values), "corrupted zk query accepted");
            proof[offset] ^= 0x01;
        }
        if (hinted) {
            proof[proof.length - 1] ^= 0x01;
            require(!verifier.verify(proof, values), "unchecked SHA hint accepted");
            proof[proof.length - 1] ^= 0x01;
        }
        require(!verifier.verify(bytes.concat(proof, bytes32(0)), values), "unused proof bytes accepted");
    }

    function testProgramInputNative() public { _check(false); }
    function testProgramInputHinted() public { _check(true); }

    function testProgramInputBounds() public {
        BiniusVerifier verifier = _deployArtifact();
        (uint256 length,) = _programInfo();
        bytes memory proof = _file("key-binius");
        bytes32[] memory values = _inputs();
        uint256 total = proof.length;
        uint256[8] memory lengths = [uint256(0), 1, 7, 8, length + 7, length + 8, length + 55, total - 1];
        for (uint256 i; i < lengths.length; ++i) {
            uint256 n = lengths[i];
            assembly ("memory-safe") { mstore(proof, n) }
            require(!verifier.verify(proof, values), "truncated program frame accepted");
        }
        assembly ("memory-safe") { mstore(proof, total) }
        proof[7] ^= 0x01;
        require(!verifier.verify(proof, values), "unknown program frame version accepted");
    }
}
