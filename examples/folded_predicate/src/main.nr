#[fold]
fn square_plus_one(x: Field) -> Field {
    x * x + 1
}

fn main(x: Field, condition: bool) -> pub Field {
    if condition {
        square_plus_one(x)
    } else {
        0
    }
}
