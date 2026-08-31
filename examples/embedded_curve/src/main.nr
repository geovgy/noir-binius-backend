use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar};

fn main(
    scalar_low: Field,
    scalar_high: Field,
    point_x: Field,
    point_y: Field,
) -> pub (Field, Field, bool, Field, Field, bool) {
    let point = EmbeddedCurvePoint { x: point_x, y: point_y, is_infinite: false };
    let doubled = std::embedded_curve_ops::embedded_curve_add(point, point);
    let product = std::embedded_curve_ops::multi_scalar_mul(
        [point],
        [EmbeddedCurveScalar { lo: scalar_low, hi: scalar_high }],
    );
    (
        doubled.x,
        doubled.y,
        doubled.is_infinite,
        product.x,
        product.y,
        product.is_infinite,
    )
}
