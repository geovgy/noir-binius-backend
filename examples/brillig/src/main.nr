fn main(x: Field) -> pub Field {
    // Safety: the constrained equality below validates the unconstrained result.
    let hinted = unsafe { triple(x) };
    assert_eq(hinted, x * 3);
    hinted
}

unconstrained fn triple(x: Field) -> Field {
    x * 3
}
