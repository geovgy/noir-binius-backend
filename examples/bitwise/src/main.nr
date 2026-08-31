fn main(x: u32, y: u32, expected: pub u32) {
    assert_eq((x & y) ^ x, expected);
}

