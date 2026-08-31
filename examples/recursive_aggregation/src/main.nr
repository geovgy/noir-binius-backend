fn main(
    verification_key: [Field; 1579],
    proof: [Field; 16643],
    public_inputs: [Field; 1],
    key_hash: Field,
) {
    std::verify_proof_with_type(
        verification_key,
        proof,
        public_inputs,
        key_hash,
        1112100442,
    );
}
