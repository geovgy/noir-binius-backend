fn main(mut values: [Field; 4], index: u32, replacement: Field) -> pub Field {
    assert(index < 4);
    values[index] = replacement;
    values[index]
}
