// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

/// @notice Interface for a registry-backed Binius64 verifier engine.
/// @dev The engine resolves `verificationKeyHash` to the portable noir-binius
///      verification key and verifies the raw `NBINZK01` proof transcript.
interface IBinius64Verifier {
    /// @return valid True only when the complete Binius64 verification succeeds.
    function verifyProof(bytes32 verificationKeyHash, bytes calldata proof)
        external
        view
        returns (bool valid);
}

/// @notice Circuit-specific Noir adapter for direct Binius64 ZK-proof verification.
/// @dev This target consumes a raw `noir-binius prove` proof. It does not accept
///      an SP1 wrapper proof. Deploy it with a Binius64 verifier engine that has
///      registered `BINIUS_VERIFICATION_KEY_HASH`.
contract BiniusVerifier {
    bytes8 private constant PROOF_MAGIC = 0x4e42494e5a4b3031; // "NBINZK01"
    uint256 private constant PROOF_FIXED_HEADER_LENGTH = 48;
    uint256 private constant BN254_SCALAR_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    bytes32 public constant BINIUS_VERIFICATION_KEY_HASH = hex"{{CIRCUIT_VKEY_HASH}}";
    bytes32 public constant BINIUS_CIRCUIT_DIGEST = hex"{{CIRCUIT_DIGEST}}";
    uint32 public constant BINIUS_LOG_INV_RATE = {{LOG_INV_RATE}};
    uint32 public constant BINIUS_PUBLIC_WORDS = {{PUBLIC_WORD_COUNT}};
    uint32 public constant NUMBER_OF_PUBLIC_INPUTS = {{PUBLIC_INPUT_COUNT}};
    // One tag byte followed by either a bytes32 constant (tag 0) or four
    // big-endian uint32 public-word offsets (tag 1) for each Noir input.
    bytes private constant PUBLIC_INPUT_LAYOUT = hex"{{PUBLIC_INPUT_LAYOUT}}";

    address public immutable biniusVerifier;

    error InvalidBiniusVerifier();

    constructor(address verifier) {
        // A chain-native verifier may be a code-less precompile. The boolean
        // response is checked exactly, so an EOA or empty response still fails.
        if (verifier == address(0)) revert InvalidBiniusVerifier();
        biniusVerifier = verifier;
    }

    /// @notice Verifies a raw Binius64 proof against ordered Noir public inputs.
    /// @dev Malformed proof data and verifier-engine reverts are reported as false.
    function verify(bytes calldata proof, bytes32[] calldata publicInputs)
        external
        view
        returns (bool)
    {
        if (!_validateEnvelope(proof, publicInputs)) return false;

        (bool success, bytes memory result) = biniusVerifier.staticcall(
            abi.encodeCall(
                IBinius64Verifier.verifyProof,
                (BINIUS_VERIFICATION_KEY_HASH, proof)
            )
        );
        if (!success || result.length != 32) return false;

        uint256 valid;
        assembly ("memory-safe") {
            valid := mload(add(result, 32))
        }
        return valid == 1;
    }

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
        if (_readU32LE(proof, 40) != BINIUS_LOG_INV_RATE) return false;

        uint256 publicWordCount = _readU32LE(proof, 44);
        if (publicWordCount != BINIUS_PUBLIC_WORDS) return false;
        if (publicInputs.length != NUMBER_OF_PUBLIC_INPUTS) return false;

        uint256 transcriptLengthOffset = PROOF_FIXED_HEADER_LENGTH + publicWordCount * 8;
        if (transcriptLengthOffset > proof.length - 8) return false;
        uint256 transcriptLength = _readU64LE(proof, transcriptLengthOffset);
        if (transcriptLength == 0) return false;
        if (transcriptLength > type(uint256).max - transcriptLengthOffset - 8) return false;
        if (transcriptLengthOffset + 8 + transcriptLength != proof.length) return false;

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
        return _readU64LE(proof, PROOF_FIXED_HEADER_LENGTH + index * 8);
    }

    function _readU32LE(bytes calldata input, uint256 offset)
        private
        pure
        returns (uint32 value)
    {
        if (offset > input.length || input.length - offset < 4) return 0;
        value = uint32(uint8(input[offset]))
            | (uint32(uint8(input[offset + 1])) << 8)
            | (uint32(uint8(input[offset + 2])) << 16)
            | (uint32(uint8(input[offset + 3])) << 24);
    }

    function _readU64LE(bytes calldata input, uint256 offset)
        private
        pure
        returns (uint64 value)
    {
        if (offset > input.length || input.length - offset < 8) return 0;
        for (uint256 i = 0; i < 8; ++i) {
            value |= uint64(uint256(uint8(input[offset + i])) << (8 * i));
        }
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
