// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.28;
import "../src/NativeBiniusVerifier.sol";

interface Vm {
    function projectRoot() external view returns (string memory);
    function readFileBinary(string calldata path) external view returns (bytes memory);
    function load(address target, bytes32 slot) external view returns (bytes32);
    function coolSlot(address target, bytes32 slot) external;
}

contract FullVerifierTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    event log_named_uint(string name, uint256 value);

    function testQueryAuthenticationLanes() public {
        BiniusVerifier verifier = new BiniusVerifier();
        bytes memory proof = vm.readFileBinary(string.concat(vm.projectRoot(), "/../target/solidity-test.binius"));
        bytes memory inputBytes = vm.readFileBinary(string.concat(vm.projectRoot(), "/../target/solidity-test.inputs"));
        bytes memory positions = vm.readFileBinary(string.concat(vm.projectRoot(), "/../target/solidity-test.corruptions"));
        bytes32[] memory inputs = new bytes32[](inputBytes.length / 32);
        for (uint256 i; i < inputs.length; ++i) {
            assembly ("memory-safe") {
                mstore(add(add(inputs, 32), mul(i, 32)), mload(add(add(inputBytes, 32), mul(i, 32))))
            }
        }
        // The native query schedule selects one Merkle sibling in each of the
        // first four lanes and in the final path. Each mutation must fail.
        require(positions.length == 40, "missing native path offsets");
        for (uint256 i; i < positions.length; i += 8) {
            uint256 position;
            assembly ("memory-safe") { position := shr(192, mload(add(add(positions, 32), i))) }
            proof[position] ^= bytes1(uint8(1));
            require(!verifier.verify(proof, inputs), "unauthenticated query lane");
            proof[position] ^= bytes1(uint8(1));
        }
    }

    function testFullBiniusProof() public {
        uint256 deploymentStart = gasleft();
        BiniusVerifier verifier = new BiniusVerifier();
        emit log_named_uint("deployment gas", deploymentStart - gasleft());
        bytes memory proof = vm.readFileBinary(string.concat(vm.projectRoot(), "/../target/solidity-test.binius"));
        bytes memory inputBytes = vm.readFileBinary(string.concat(vm.projectRoot(), "/../target/solidity-test.inputs"));
        bytes32[] memory inputs = new bytes32[](inputBytes.length / 32);
        for (uint256 i; i < inputs.length; i++) {
            bytes32 value;
            assembly ("memory-safe") { value := mload(add(add(inputBytes, 32), mul(i, 32))) }
            inputs[i] = value;
        }
        // Model a subsequent call: construction must not make the program's
        // storage reads artificially warm in the measurement below.
        uint256 programLength = uint256(vm.load(address(verifier), bytes32(0))) >> 1;
        uint256 firstSlot = uint256(keccak256(abi.encode(uint256(0))));
        vm.coolSlot(address(verifier), bytes32(0));
        for (uint256 i; i < (programLength + 31) / 32; ++i) {
            vm.coolSlot(address(verifier), bytes32(firstSlot + i));
        }
        uint256 start = gasleft();
        require(IVerifier(address(verifier)).verify(proof, inputs), "valid proof rejected");
        emit log_named_uint("verification gas (cold program storage)", start - gasleft());
        bytes memory extra = bytes.concat(proof, hex"00");
        require(!verifier.verify(extra, inputs), "trailing proof byte accepted");
        uint256 originalLength = proof.length;
        assembly ("memory-safe") { mstore(proof, sub(originalLength, 1)) }
        require(!verifier.verify(proof, inputs), "truncated proof accepted");
        assembly ("memory-safe") { mstore(proof, originalLength) }
        bytes32[] memory wrongCount = new bytes32[](inputs.length + 1);
        require(!verifier.verify(proof, wrongCount), "wrong public input count accepted");
        proof[8] ^= bytes1(uint8(1));
        require(!verifier.verify(proof, inputs), "wrong circuit accepted");
        proof[8] ^= bytes1(uint8(1));
        proof[proof.length - 1] ^= bytes1(uint8(1));
        require(!verifier.verify(proof, inputs), "bad terminal proof accepted");
        proof[proof.length - 1] ^= bytes1(uint8(1));
        if (inputs.length != 0) {
            bytes32 original = inputs[0];
            inputs[0] ^= bytes32(uint256(1));
            require(!verifier.verify(proof, inputs), "wrong public input accepted");
            inputs[0] = original;
        }
        uint256 words;
        for (uint256 i; i < 4; i++) {
            words |= uint256(uint8(proof[44 + i])) << (8 * i);
        }
        proof[56 + 8 * words + 40] ^= bytes1(uint8(1));
        require(!verifier.verify(proof, inputs), "bad transcript accepted");
    }
}
