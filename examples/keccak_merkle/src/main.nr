use dep::keccak256::keccak256;

global LEAF_LENGTH: u32 = 4;
global MAX_DEPTH: u32 = 10;

fn hash_pair(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut preimage: [u8; 64] = [0; 64];
    for i in 0..32 {
        preimage[i] = left[i];
        preimage[i + 32] = right[i];
    }
    keccak256(preimage, preimage.len())
}

fn compute_root(
    leaf: [u8; LEAF_LENGTH],
    siblings: [[u8; 32]; MAX_DEPTH],
    path_indices: [bool; MAX_DEPTH],
) -> [u8; 32] {
    let mut current = keccak256(leaf, leaf.len());

    for level in 0..MAX_DEPTH {
        let left = if path_indices[level] {
            siblings[level]
        } else {
            current
        };
        let right = if path_indices[level] {
            current
        } else {
            siblings[level]
        };
        current = hash_pair(left, right);
    }

    current
}

fn main(
    leaf: [u8; LEAF_LENGTH],
    siblings: [[u8; 32]; MAX_DEPTH],
    path_indices: [bool; MAX_DEPTH],
    root: pub [u8; 32],
) {
    let computed_root = compute_root(leaf, siblings, path_indices);
    assert_eq(computed_root, root, "invalid Merkle proof");
}

fn fixture() -> ([u8; LEAF_LENGTH], [[u8; 32]; MAX_DEPTH], [bool; MAX_DEPTH], [u8; 32]) {
    let mut siblings = [[0; 32]; MAX_DEPTH];
    for level in 0..MAX_DEPTH {
        siblings[level][31] = (level + 1) as u8;
    }

    (
        [76, 69, 65, 70], siblings,
        [false, true, false, true, false, true, false, true, false, true],
        [
            125, 68, 78, 95, 221, 250, 5, 68, 157, 105, 155, 25, 171, 205, 38, 250, 187, 166, 211,
            2, 98, 100, 190, 172, 50, 3, 96, 121, 50, 72, 106, 181,
        ],
    )
}

#[test]
fn accepts_valid_depth_ten_proof() {
    let (leaf, siblings, path_indices, root) = fixture();
    main(leaf, siblings, path_indices, root);
}

#[test(should_fail_with = "invalid Merkle proof")]
fn rejects_invalid_root() {
    let (leaf, siblings, path_indices, mut root) = fixture();
    root[0] = 124;
    main(leaf, siblings, path_indices, root);
}
