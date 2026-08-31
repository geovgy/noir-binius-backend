fn main(input: [Field; 4]) -> pub [Field; 4] {
    std::hash::poseidon2_permutation(input, 4)
}
