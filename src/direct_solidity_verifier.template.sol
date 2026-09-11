// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.28;

/// @notice The Noir Solidity verifier interface.
interface IVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs)
        external view returns (bool);
}

/// @notice Verifies raw Binius64 zero-knowledge proofs inside this contract.
/// @dev Generated for the pinned Binius64 protocol. Deployment initializes all
///      circuit data. Every verification operation executes in this contract.
contract BiniusVerifier is IVerifier {
    bytes8 private constant PROOF_MAGIC = 0x4e42494e5a4b3031; // "NBINZK01"
    uint256 private constant PROOF_FIXED_HEADER_LENGTH = 48;
    uint256 private constant BN254_SCALAR_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    bytes32 private constant BINIUS_VERIFICATION_KEY_HASH = hex"{{CIRCUIT_VKEY_HASH}}";
    bytes32 private constant BINIUS_CIRCUIT_DIGEST = hex"{{CIRCUIT_DIGEST}}";
    uint32 private constant BINIUS_LOG_INV_RATE = {{LOG_INV_RATE}};
    uint32 private constant BINIUS_PUBLIC_WORDS = {{PUBLIC_WORD_COUNT}};
    uint32 private constant NUMBER_OF_PUBLIC_INPUTS = {{PUBLIC_INPUT_COUNT}};
    // One tag byte followed by either a bytes32 constant (tag 0) or four
    // big-endian uint32 public-word offsets (tag 1) for each Noir input.
    bytes private constant PUBLIC_INPUT_LAYOUT = hex"{{PUBLIC_INPUT_LAYOUT}}";

    uint256 private constant EXPECTED_PROOF_LENGTH = {{PROOF_LENGTH}};
    uint256 private constant REGISTER_COUNT = {{REGISTER_COUNT}};
    uint256 private constant VERIFICATION_PROGRAM_LENGTH = {{PROGRAM_LENGTH}};
    uint256 private constant ENCODED_PROGRAM_LENGTH = {{ENCODED_PROGRAM_LENGTH}};
    bytes private verificationProgram;

    constructor() {
        bytes memory data = _expandProgram(
            _unlzma(hex"{{COMPRESSED_PROGRAM}}", ENCODED_PROGRAM_LENGTH), VERIFICATION_PROGRAM_LENGTH
        );
        assembly ("memory-safe") {
            let length := mload(data)
            // Initialize the complete program in this deployment transaction.
            // The runtime only reads these slots.
            sstore(verificationProgram.slot, add(mul(length, 2), 1))
            mstore(0, verificationProgram.slot)
            let slot := keccak256(0, 32)
            for { let i := 0 } lt(i, length) { i := add(i, 32) } {
                sstore(add(slot, shr(5, i)), mload(add(add(data, 32), i)))
            }
        }
    }

    /// @notice Verifies the full Binius ZK transcript and ordered Noir public inputs.
    /// @dev No state is written. Invalid proofs return false. As with any EVM
    ///      computation, the caller must provide enough gas to execute verification.
    function verify(bytes calldata proof, bytes32[] calldata publicInputs)
        external view override returns (bool)
    {
        if (!_validateEnvelope(proof, publicInputs)) return false;
        if (proof.length != EXPECTED_PROOF_LENGTH) return false;
        return _run(verificationProgram, proof);
    }

{{RUNTIME}}

    function _validateEnvelope(bytes calldata proof, bytes32[] calldata publicInputs)
        private
        pure
        returns (bool)
    {
        if (proof.length < PROOF_FIXED_HEADER_LENGTH + 8) return false;
        if (bytes8(proof[0:8]) != PROOF_MAGIC) return false;

        bytes32 circuitDigest;
        assembly ("memory-safe") {
            circuitDigest := calldataload(add(proof.offset, 8))
        }
        if (circuitDigest != BINIUS_CIRCUIT_DIGEST) return false;
        // The minimum header length above covers both fixed u32 fields.
        if (_readLE(proof, 40, 4) != BINIUS_LOG_INV_RATE) return false;

        uint256 publicWordCount = _readLE(proof, 44, 4);
        if (publicWordCount != BINIUS_PUBLIC_WORDS) return false;
        if (publicInputs.length != NUMBER_OF_PUBLIC_INPUTS) return false;

        uint256 transcriptLengthOffset = PROOF_FIXED_HEADER_LENGTH + publicWordCount * 8;
        if (transcriptLengthOffset > proof.length - 8) return false;
        uint256 transcriptLength = _readLE(proof, transcriptLengthOffset, 8);
        if (transcriptLength == 0) return false;
        if (transcriptLength > type(uint256).max - transcriptLengthOffset - 8) return false;
        if (transcriptLengthOffset + 8 + transcriptLength != proof.length) return false;

        return _validateNoirInputs(proof, publicInputs);
    }

    function _validateNoirInputs(bytes calldata proof, bytes32[] calldata publicInputs)
        private pure returns (bool)
    {
        {{NOIR_INPUT_CHECKS}}
    }

    function _validateNoirInputsGeneric(bytes calldata proof, bytes32[] calldata publicInputs)
        private pure returns (bool)
    {
        bytes memory inputLayout = PUBLIC_INPUT_LAYOUT;
        uint256 layoutOffset;
        for (uint256 i = 0; i < publicInputs.length; ++i) {
            if (uint256(publicInputs[i]) >= BN254_SCALAR_MODULUS) return false;
            if (layoutOffset >= inputLayout.length) return false;
            uint8 kind = uint8(inputLayout[layoutOffset++]);
            bytes32 expectedInput;
            if (kind == 0) {
                if (inputLayout.length - layoutOffset < 32) return false;
                assembly ("memory-safe") {
                    expectedInput := mload(add(add(inputLayout, 32), layoutOffset))
                }
                layoutOffset += 32;
            } else if (kind == 1) {
                if (inputLayout.length - layoutOffset < 16) return false;
                expectedInput = _publicInput(proof, inputLayout, layoutOffset);
                layoutOffset += 16;
            } else {
                return false;
            }
            if (expectedInput != publicInputs[i]) return false;
        }
        return layoutOffset == inputLayout.length;
    }

    function _publicInput(
        bytes calldata proof,
        bytes memory inputLayout,
        uint256 layoutOffset
    ) private pure returns (bytes32) {
        uint256 value;
        for (uint256 limb = 0; limb < 4; ++limb) {
            uint256 publicWord = _readU32BE(inputLayout, layoutOffset + limb * 4);
            value |= _publicWord(proof, publicWord) << (limb * 64);
        }
        return bytes32(value);
    }

    function _publicWord(bytes calldata proof, uint256 index)
        private
        pure
        returns (uint256)
    {
        // Generation checks index < BINIUS_PUBLIC_WORDS. Envelope validation
        // establishes that this complete public-word region is in calldata.
        return _readLE(proof, PROOF_FIXED_HEADER_LENGTH + index * 8, 8);
    }

    function _readU32BE(bytes memory input, uint256 offset)
        private
        pure
        returns (uint32 value)
    {
        assembly ("memory-safe") {
            value := shr(224, mload(add(add(input, 32), offset)))
        }
    }
}
