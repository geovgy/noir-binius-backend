//! Skip the suffix memo for single-chunk points in constructed verifiers.
//!
//! Constructed outer matrices use factored graphs, so this primarily helps
//! the inner protocol's small affine matrices. Ordinary source verifiers have
//! hot large-point lookups; keep their original evaluator without this branch.
use anyhow::{Result, ensure};

pub(super) fn render(mut source: String) -> Result<String> {
    for (before, after) in [
        (
            r#"                let table := add(memo, 131072)
                calldatacopy(memo, calldatasize(), 131072)"#,
            r#"                // A single chunk answers every suffix directly from its
                // table. Only multi-chunk points allocate a product memo.
                let table := memo
                if gt(n, 9) {
                    table := add(memo, 131072)
                    calldatacopy(memo, calldatasize(), 131072)
                }"#,
        ),
        (
            r#"            function part(point, index, lo) -> value {
                // With u32 matrix indices and lo <= 32, the complete key"#,
            r#"            function part(point, index, lo) -> value {
                let n := mload(add(point, 96))
                if iszero(gt(n, 9)) {
                    value := 1
                    if lt(lo, n) {
                        // Here lo < n <= 9, so div(lo,9)=0 and mod(lo,9)=lo.
                        // This is the same initialized suffix-table entry that
                        // the general path reads before returning its one chunk.
                        let size := shl(sub(9, lo), 1)
                        let base := add(lo, sub(1024, shl(sub(10, lo), 1)))
                        let entry := add(base, and(shr(lo, index), sub(size, 1)))
                        let p := add(mload(add(point, 32)), shl(5, entry))
                        value := xor(mload(p), mload(add(p, 32)))
                    }
                    leave
                }
                // With u32 matrix indices and lo <= 32, the complete key"#,
        ),
        (
            r#"                let n := mload(add(point, 96))
                value := 1
                if lt(lo, n) {"#,
            r#"                value := 1
                if lt(lo, n) {"#,
        ),
    ] {
        ensure!(
            source.matches(before).count() == 1,
            "missing or ambiguous single-chunk wiring template"
        );
        source = source.replace(before, after);
    }
    Ok(source)
}
