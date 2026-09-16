//! Store canonical factored-graph values in sixteen-byte cells.
//!
//! The graph, operands and field equations are unchanged. Every child refers
//! backward, so a forward MSTORE may clear the following uninitialized cell.
//! The final store has an allocated guard; source points remain full-width.
use anyhow::{Result, ensure};

pub(super) fn render(mut body: String) -> Result<String> {
    for (before, after, count) in [
        (
            r#"            start := add(values, shl(5, add(8, shl(1, n))))
            finish := add(start, shl(5, count))
            mstore(0x40, finish)
            mstore(values, 0)
            mstore(add(values, 32), 1)
            mstore(add(values, 64), lambda)
            mstore(add(values, 96), xor(lambda, 1))
            mstore(add(values, 128), square)
            mstore(add(values, 160), xor(square, 1))
            mstore(add(values, 192), xor(square, lambda))
            mstore(add(values, 224), xor(xor(square, lambda), 1))
            let points := add(values, 256)
            mcopy(points, pointX, shl(5, nx))
            mcopy(add(points, shl(5, nx)), pointY, shl(5, ny))
            for { let i := 0 } lt(i, shl(5, n)) { i := add(i, 32) } {
                mstore(add(add(points, shl(5, n)), i), xor(mload(add(points, i)), 1))
"#,
            r#"            start := add(values, shl(4, add(8, shl(1, n))))
            finish := add(start, shl(4, count))
            mstore(0x40, and(add(finish, 47), not(31)))
            mstore(values, shl(128, 0))
            mstore(add(values, 16), shl(128, 1))
            mstore(add(values, 32), shl(128, lambda))
            mstore(add(values, 48), shl(128, xor(lambda, 1)))
            mstore(add(values, 64), shl(128, square))
            mstore(add(values, 80), shl(128, xor(square, 1)))
            mstore(add(values, 96), shl(128, xor(square, lambda)))
            mstore(add(values, 112), shl(128, xor(xor(square, lambda), 1)))
            let points := add(values, 128)
            for { let i := 0 } lt(i, nx) { i := add(i, 1) } {
                mstore(add(points, shl(4, i)), shl(128, mload(add(pointX, shl(5, i)))))
            }
            for { let i := 0 } lt(i, ny) { i := add(i, 1) } {
                mstore(add(points, shl(4, add(nx, i))), shl(128, mload(add(pointY, shl(5, i)))))
            }
            for { let i := 0 } lt(i, shl(4, n)) { i := add(i, 16) } {
                mstore(add(add(points, shl(4, n)), i), shl(128, xor(shr(128, mload(add(points, i))), 1)))
"#,
            1,
        ),
        (
            r#"                    end := add(dest, and(shr(227, header), 0x1fffe0))
"#,
            r#"                    end := add(dest, and(shr(228, header), 0xffff0))
"#,
            1,
        ),
        (
            r#"                    r := mload(add(values, shl(5, add(and(code, 127), 7))))
"#,
            r#"                    r := shr(128, mload(add(values, shl(4, add(and(code, 127), 7)))))
"#,
            1,
        ),
        (
            r#"                            a := mload(sub(dest, and(shr(235, word), 0x1fffe0)))
                            b := mload(sub(dest, and(shr(219, word), 0x1fffe0)))
"#,
            r#"                            a := shr(128, mload(sub(dest, and(shr(236, word), 0xffff0))))
                            b := shr(128, mload(sub(dest, and(shr(220, word), 0xffff0))))
"#,
            2,
        ),
        (
            r#"                        assembly ("memory-safe") { mstore(dest, value) dest := add(dest, 32) }
"#,
            r#"                        assembly ("memory-safe") { mstore(dest, shl(128, value)) dest := add(dest, 16) }
"#,
            3,
        ),
        (
            r#"                            a := mload(add(values, and(shr(243, word), 0x1fe0)))
                            b := mload(sub(dest, and(shr(227, word), 0x1fffe0)))
"#,
            r#"                            a := shr(128, mload(add(values, and(shr(244, word), 0xff0))))
                            b := shr(128, mload(sub(dest, and(shr(228, word), 0xffff0))))
"#,
            1,
        ),
        (
            r#"                    a := mload(sub(dest, shl(5, delta)))
"#,
            r#"                    a := shr(128, mload(sub(dest, shl(4, delta))))
"#,
            1,
        ),
        (
            r#"                    b := mload(sub(dest, shl(5, delta)))
                    r := mload(add(values, shl(5, add(code, 7))))
"#,
            r#"                    b := shr(128, mload(sub(dest, shl(4, delta))))
                    r := shr(128, mload(add(values, shl(4, add(code, 7)))))
"#,
            1,
        ),
        (
            r#"                assembly ("memory-safe") { mstore(dest, value) dest := add(dest, 32) }
"#,
            r#"                assembly ("memory-safe") { mstore(dest, shl(128, value)) dest := add(dest, 16) }
"#,
            1,
        ),
        (
            r#"            result := mload(add(values, shl(5, root)))
"#,
            r#"            result := shr(128, mload(add(values, shl(4, root))))
"#,
            1,
        ),
    ] {
        ensure!(
            body.matches(before).count() == count,
            "missing or ambiguous packed graph memory template"
        );
        body = body.replace(before, after);
    }
    Ok(body)
}
