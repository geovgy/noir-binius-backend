// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.35;
import {BiniusVerifier} from "../src/NativeBiniusVerifier.sol";
import {FullVerifierTest} from "../test/BiniusVerifier.t.sol";
import {HintsTest} from "../test/BiniusHints.t.sol";

interface VmArtifact {
    function projectRoot() external view returns (string memory);
    function readFileBinary(string calldata path) external view returns (bytes memory);
    function load(address target, bytes32 slot) external view returns (bytes32);
}

abstract contract ArtifactCreation {
    VmArtifact internal constant artifactVm = VmArtifact(address(uint160(uint256(keccak256("hevm cheat code")))));

    function _deployArtifact() internal returns (BiniusVerifier verifier) {
        uint256 scratch;
        assembly ("memory-safe") { scratch := mload(0x40) }
        bytes memory code = artifactVm.readFileBinary(
            string.concat(artifactVm.projectRoot(), "/../target/solidity-test.creation")
        );
        require(code.length != 0 && code.length <= 49152, "initcode limit");
        address target;
        assembly ("memory-safe") { target := create(0, add(code, 32), mload(code)) }
        require(target != address(0), "artifact creation failed");
        require(target.code.length <= 24576, "runtime limit");
        verifier = BiniusVerifier(target);
        // Only an address escapes. Match an ordinary new expression's caller
        // memory use so creation-file scratch does not bias verify call gas.
        assembly ("memory-safe") { mstore(0x40, scratch) }
    }
}

contract ArtifactFullVerifierTest is FullVerifierTest, ArtifactCreation {
    function _deploy() internal override returns (BiniusVerifier) { return _deployArtifact(); }
}

contract ArtifactHintsTest is HintsTest, ArtifactCreation {
    function _deploy() internal override returns (BiniusVerifier) { return _deployArtifact(); }
}

contract ArtifactRuntimeCodeTest is ArtifactCreation {
    function testDeployedRuntimeMatchesCompiler() public {
        BiniusVerifier verifier = _deployArtifact();
        // The artifact script independently compiles the emitted Solidity with
        // the recorded settings. Compiling it alongside unrelated test sources
        // can select a different optimized layout, even without metadata hashes.
        bytes memory compiled = artifactVm.readFileBinary(
            string.concat(artifactVm.projectRoot(), "/../target/solidity-test.compiler-runtime")
        );
        require(compiled.length != 0, "missing independent compiler runtime");
        require(address(verifier).codehash == keccak256(compiled), "constructor returned different verification code");
    }
}

contract ArtifactProgramTest is ArtifactCreation {
    event log_named_uint(string name, uint256 value);
    // The artifact runner specializes this from the advertised storage format.
    bool private constant AUTHENTICATED_PROGRAM = false;

    function testInstalledProgramMatchesArtifact() public {
        bytes memory creation = artifactVm.readFileBinary(
            string.concat(artifactVm.projectRoot(), "/../target/solidity-test.creation")
        );
        require(creation.length != 0 && creation.length <= 49152, "initcode limit");
        uint256 start = gasleft();
        address target;
        assembly ("memory-safe") { target := create(0, add(creation, 32), mload(creation)) }
        uint256 creationGas = start - gasleft();
        require(target != address(0), "artifact creation failed");
        require(target.code.length <= 24576, "runtime limit");
        bytes memory runtime = artifactVm.readFileBinary(
            string.concat(artifactVm.projectRoot(), "/../target/solidity-test.runtime")
        );
        require(target.codehash == keccak256(runtime), "artifact runtime mismatch");
        bytes memory expected = artifactVm.readFileBinary(
            string.concat(artifactVm.projectRoot(), "/../target/solidity-test.program")
        );
        bytes32 header = AUTHENTICATED_PROGRAM ? keccak256(expected) : bytes32(2 * expected.length + 1);
        require(artifactVm.load(target, bytes32(0)) == header, "program storage header mismatch");
        uint256 firstSlot = uint256(keccak256(abi.encode(uint256(0))));
        for (uint256 i; i < expected.length; i += 32) {
            uint256 actual = uint256(artifactVm.load(target, bytes32(firstSlot + i / 32)));
            uint256 wanted;
            assembly ("memory-safe") { wanted := mload(add(add(expected, 32), i)) }
            uint256 remaining = expected.length - i;
            if (remaining < 32) {
                uint256 mask = type(uint256).max << (8 * (32 - remaining));
                actual &= mask;
                wanted &= mask;
            }
            require(actual == wanted, "stored circuit program differs");
        }
        emit log_named_uint("creation gas excluding bytecode file read", creationGas);
        emit log_named_uint("program bytes checked", expected.length);
    }
}
