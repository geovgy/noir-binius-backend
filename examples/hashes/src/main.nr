fn main(
    message: [u8; 5],
    keccak_state: [u64; 25],
    sha_message: [u32; 16],
    sha_state: [u32; 8],
) -> pub ([u8; 32], [u8; 32], [u64; 25], [u32; 8]) {
    (
        std::hash::blake2s(message),
        std::hash::blake3(message),
        std::hash::keccakf1600(keccak_state),
        std::hash::sha256_compression(sha_message, sha_state),
    )
}

