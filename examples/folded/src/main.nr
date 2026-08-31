#[fold]
fn square_plus_one(x: Field) -> Field {
    x * x + 1
}

fn main(x: Field) -> pub Field {
    square_plus_one(x) + square_plus_one(x + 1)
}
