fn main(input: [u8; 1], iv: [u8; 16], key: [u8; 16]) -> pub [u8; 16] {
    std::aes128::aes128_encrypt(input, iv, key)
}
