// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

/// @notice Minimal interface implemented by the versioned SP1 verifiers and SP1VerifierGateway.
interface ISP1Verifier {
    function verifyProof(
        bytes32 programVKey,
        bytes calldata publicValues,
        bytes calldata proofBytes
    ) external view;
}

/// @notice Noir-compatible verifier for Binius proofs wrapped by the noir-binius SP1 guest.
/// @dev Deploy this contract with a supported SP1 verifier or SP1VerifierGateway address.
contract BiniusVerifier {
    uint64 private constant SP1_PROOF_MAGIC = 0x4e42494e53503131; // "NBINSP11"
    uint256 private constant SP1_PROOF_HEADER_LENGTH = 12;
    uint256 private constant BN254_SCALAR_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    bytes32 public constant BINIUS_PROGRAM_VKEY = hex"{{SP1_PROGRAM_VKEY}}";
    bytes32 public constant BINIUS_CIRCUIT_VKEY_HASH = hex"{{CIRCUIT_VKEY_HASH}}";
    uint32 public constant NUMBER_OF_PUBLIC_INPUTS = {{PUBLIC_INPUT_COUNT}};

    address public immutable sp1Verifier;

    error InvalidSP1Verifier();

    constructor(address verifier) {
        if (verifier == address(0) || verifier.code.length == 0) {
            revert InvalidSP1Verifier();
        }
        sp1Verifier = verifier;
    }

    /// @notice Verifies a Solidity-target noir-binius proof against ordered Noir public inputs.
    /// @dev Invalid proof data returns false, including reverts from the SP1 verifier.
    function verify(bytes calldata proof, bytes32[] calldata publicInputs)
        external
        view
        returns (bool)
    {
        if (proof.length <= SP1_PROOF_HEADER_LENGTH) return false;

        uint64 magic;
        assembly ("memory-safe") {
            magic := shr(192, calldataload(proof.offset))
        }
        if (magic != SP1_PROOF_MAGIC) return false;

        uint256 publicInputCount = uint256(uint8(proof[8]))
            | (uint256(uint8(proof[9])) << 8)
            | (uint256(uint8(proof[10])) << 16)
            | (uint256(uint8(proof[11])) << 24);
        if (publicInputCount != NUMBER_OF_PUBLIC_INPUTS) return false;
        if (publicInputCount != publicInputs.length) return false;

        uint256 sp1ProofOffset = SP1_PROOF_HEADER_LENGTH + publicInputCount * 32;
        if (sp1ProofOffset >= proof.length) return false;

        for (uint256 i = 0; i < publicInputCount; ++i) {
            bytes32 embeddedInput;
            assembly ("memory-safe") {
                embeddedInput := calldataload(add(add(proof.offset, 12), mul(i, 32)))
            }
            if (uint256(embeddedInput) >= BN254_SCALAR_MODULUS) return false;
            if (embeddedInput != publicInputs[i]) return false;
        }

        bytes memory publicValues = abi.encodePacked(
            BINIUS_CIRCUIT_VKEY_HASH,
            sha256(abi.encodePacked(publicInputs))
        );
        try ISP1Verifier(sp1Verifier).verifyProof(
            BINIUS_PROGRAM_VKEY,
            publicValues,
            proof[sp1ProofOffset:]
        ) {
            return true;
        } catch {
            return false;
        }
    }
}
