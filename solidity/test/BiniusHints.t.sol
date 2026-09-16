// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.35;
import {BiniusVerifier, IVerifier} from "../src/NativeBiniusVerifier.sol";
import {BiniusPrimitives} from "../src/BiniusPrimitives.sol";

interface VmHints {
    function projectRoot() external view returns (string memory);
    function readFileBinary(string calldata path) external view returns (bytes memory);
    function load(address target, bytes32 slot) external view returns (bytes32);
    function coolSlot(address target, bytes32 slot) external;
}

contract HintsTest {
    VmHints constant vm = VmHints(address(uint160(uint256(keccak256("hevm cheat code")))));
    event log_named_uint(string name, uint256 n);

    function _deploy() internal virtual returns (BiniusVerifier) {
        return new BiniusVerifier();
    }

    function testHintedProof() public {
        BiniusVerifier v = _deploy();
        bytes memory proof = vm.readFileBinary(string.concat(vm.projectRoot(), "/../target/solidity-test.hinted"));
        bytes memory inputBytes = vm.readFileBinary(string.concat(vm.projectRoot(), "/../target/solidity-test.inputs"));
        bytes32[] memory inputs = new bytes32[](inputBytes.length / 32);
        for (uint256 i; i < inputs.length; ++i) {
            assembly ("memory-safe") { mstore(
                add(add(inputs, 32), shl(5, i)),
                mload(add(add(inputBytes, 32), shl(5, i)))
            ) }
        }
        uint256 n = uint256(vm.load(address(v), bytes32(0))) >> 1;
        uint256 first = uint256(keccak256(abi.encode(uint256(0))));
        vm.coolSlot(address(v), bytes32(0));
        for (uint256 i; i < (n + 31) / 32; ++i) {
            vm.coolSlot(address(v), bytes32(first + i));
        }
        uint256 start = gasleft();
        require(IVerifier(address(v)).verify(proof, inputs), "valid hinted proof rejected");
        emit log_named_uint("hinted verification gas", start - gasleft());
        uint256 nativeLength =
            vm.readFileBinary(string.concat(vm.projectRoot(), "/../target/solidity-test.binius")).length;
        uint256 fullLength = proof.length;
        uint256[8] memory lengths = [uint256(0), 1, 7, 8, 48, nativeLength + 7, nativeLength + 8, fullLength - 1];
        for (uint256 i; i < lengths.length; ++i) {
            uint256 length = lengths[i];
            assembly ("memory-safe") { mstore(proof, length) }
            require(!v.verify(proof, inputs), "malformed hinted envelope accepted");
        }
        assembly ("memory-safe") { mstore(proof, fullLength) }
        proof[7] ^= 0x01;
        require(!v.verify(proof, inputs), "wrong hint version accepted");
        proof[7] ^= 0x01;
        uint256 count = (proof.length - nativeLength - 8) / 32;
        uint256[5] memory indices = [uint256(0), 1, count / 2, count - 2, count - 1];
        for (uint256 i; i < indices.length; ++i) {
            uint256 p = 8 + nativeLength + 32 * indices[i];
            proof[p] ^= 0x01;
            require(!v.verify(proof, inputs), "bad hint accepted");
            proof[p] ^= 0x01;
        }
        bytes memory positions =
            vm.readFileBinary(string.concat(vm.projectRoot(), "/../target/solidity-test.corruptions"));
        for (uint256 i; i < positions.length; i += 8) {
            uint256 position;
            assembly ("memory-safe") { position := shr(192, mload(add(add(positions, 32), i))) }
            position += 8;
            proof[position] ^= 0x01;
            require(!v.verify(proof, inputs), "unauthenticated hinted query");
            proof[position] ^= 0x01;
        }
        if (inputs.length != 0) {
            inputs[0] ^= bytes32(uint256(1));
            require(!v.verify(proof, inputs), "wrong hinted public input");
            inputs[0] ^= bytes32(uint256(1));
        }
        require(!v.verify(bytes.concat(proof, bytes32(0)), inputs), "unused hint accepted");
        assembly ("memory-safe") { mstore(proof, sub(mload(proof), 32)) }
        require(!v.verify(proof, inputs), "missing hint accepted");
    }

    function testFuzzHintMessages(bytes32 seed, uint8 countHint) public {
        BiniusPrimitives h = new BiniusPrimitives();
        uint256 count = 1 + uint256(countHint) % 23;
        bytes[] memory messages = new bytes[](count);
        bytes memory hints;
        for (uint256 i; i < count; ++i) {
            uint256 length = uint256(keccak256(abi.encode(seed, i))) % 321;
            messages[i] = new bytes(length);
            for (uint256 j; j < length; ++j) {
                messages[i][j] = bytes1(uint8(uint256(seed) >> (8 * (j % 32))) ^ uint8(j + 71 * i));
            }
            hints = bytes.concat(hints, sha256(messages[i]));
        }
        require(h.checkHintMessages(messages, hints), "random hint list mismatch");
        uint256 changed = uint256(seed) % hints.length;
        hints[changed] ^= 0x01;
        require(!h.checkHintMessages(messages, hints), "random bad hint accepted");
    }

    function testEveryHintIsChecked() public {
        BiniusPrimitives h = new BiniusPrimitives();
        bytes[] memory messages = new bytes[](23);
        bytes memory hints;
        for (uint256 i; i < messages.length; ++i) {
            messages[i] = new bytes(i < 16 ? 72 : i == 22 ? 4097 : i * 13);
            for (uint256 j; j < messages[i].length; ++j) {
                messages[i][j] = bytes1(uint8(i * 71 + j));
            }
            hints = bytes.concat(hints, sha256(messages[i]));
        }
        require(h.checkHintMessages(messages, hints), "valid SHA hint list rejected");
        for (uint256 i; i < messages.length; ++i) {
            hints[32 * i + 31] ^= 0x01;
            require(!h.checkHintMessages(messages, hints), "unchecked SHA hint");
            hints[32 * i + 31] ^= 0x01;
        }
        require(!h.checkHintMessages(messages, bytes.concat(hints, bytes32(0))), "extra hint");
        assembly ("memory-safe") { mstore(hints, sub(mload(hints), 32)) }
        require(!h.checkHintMessages(messages, hints), "missing hint");
    }

    function testHintLaneRefillAndPaddingBoundaries() public {
        BiniusPrimitives h = new BiniusPrimitives();
        uint256[25] memory lengths = [
            uint256(0), 1, 31, 32, 55, 56, 63, 64, 65, 95, 119, 120, 127,
            128, 129, 447, 448, 449, 511, 512, 513, 4095, 4096, 8191, 8192
        ];
        bytes[] memory messages = new bytes[](lengths.length);
        bytes memory hints;
        for (uint256 i; i < lengths.length; ++i) {
            messages[i] = new bytes(lengths[i]);
            for (uint256 j; j < lengths[i]; ++j) messages[i][j] = bytes1(uint8(31 * i + 17 * j));
            hints = bytes.concat(hints, sha256(messages[i]));
        }
        require(h.checkHintMessages(messages, hints), "mixed padding boundaries");
        // Long and short messages finish in different orders and refill the
        // same lanes. Every original digest must still be checked in full.
        for (uint256 i; i < lengths.length; ++i) {
            uint256 byteIndex = 32 * i + i % 32;
            hints[byteIndex] ^= 0x80;
            require(!h.checkHintMessages(messages, hints), "unchecked refilled lane");
            hints[byteIndex] ^= 0x80;
        }
        messages[24][8191] ^= 0x01;
        require(!h.checkHintMessages(messages, hints), "unchecked final message block");
    }
}
