//! Bounded, exact partitions of a fixed outer matrix.
//!
//! A region and its complement have disjoint Boolean support. The existing
//! encoders independently check both representations, including multilinearity
//! of the factored part. Adding their extensions is therefore an identity at
//! every field point. Circuit-only cost estimates select among these identities.

use super::{compact_outer, factored_wiring, wiring_cost};
use std::collections::{BTreeSet, HashSet};

type Point = (u32, u32, u8);
type Region = (u8, usize, u32); // axis (0=row, 1=column), low-bit width, prefix

#[derive(Clone, Debug)]
pub(super) struct Partition {
    pub affine: Vec<u8>,
    pub factored: Vec<u8>,
    pub saved_muls: u64,
    packed_bytes: usize,
    regions: Vec<Region>,
}

fn inside(point: Point, regions: &[Region]) -> bool {
    regions.iter().any(|&(axis, width, prefix)| {
        (if axis == 0 { point.0 } else { point.1 }) >> width == prefix
    })
}

fn build(
    points: &[Point],
    nx: usize,
    ny: usize,
    regions: Vec<Region>,
    baseline: u64,
    larger: bool,
) -> Option<Partition> {
    let (part, rest): (Vec<_>, Vec<_>) = points.iter().copied().partition(|&p| inside(p, &regions));
    if part.is_empty() || part.len() > if larger { 32_768 } else { 16_384 } {
        return None;
    }
    // These checks cover the entire support, independently of any proof.
    let mut recovered: Vec<_> = part.iter().chain(&rest).copied().collect();
    recovered.sort_unstable();
    assert_eq!(recovered, points, "matrix partition changed support");
    let factored = if larger {
        factored_wiring::encode_for_deployment(&part, nx, ny)?
    } else {
        factored_wiring::encode(&part, nx, ny)?
    };
    let affine = compact_outer::encode_points(rest, nx, ny);
    let work =
        wiring_cost::multiplications(&affine) + factored_wiring::operation_count(&factored) as u64;
    let packed_bytes =
        super::super::codec::compress(&[affine.as_slice(), factored.as_slice()].concat()).len();
    Some(Partition {
        affine,
        factored,
        saved_muls: baseline.saturating_sub(work),
        packed_bytes,
        regions,
    })
}

pub(super) fn candidates(data: &[u8]) -> Vec<Partition> {
    candidates_inner(data, false)
}

pub(super) fn deployment_candidates(data: &[u8]) -> Vec<Partition> {
    candidates_inner(data, true)
}

fn candidates_inner(data: &[u8], larger: bool) -> Vec<Partition> {
    let (nx, ny, runs) = compact_outer::decode_matrix(data);
    if nx > 32 || ny > 32 || nx + ny == 0 {
        return vec![];
    }
    let count: usize = runs.iter().map(|r| usize::try_from(r[1]).unwrap()).sum();
    // Bound compiler work independently of how compactly a huge matrix happens
    // to serialize. The original affine verifier remains available above it.
    if count > 1 << 20 {
        return vec![];
    }
    let mut points = Vec::with_capacity(count);
    for [mask, count, row, column, dr, dc] in runs {
        for i in 0..count {
            points.push((
                u32::try_from(row + i * dr).unwrap(),
                u32::try_from(column + i * dc).unwrap(),
                mask as u8,
            ));
        }
    }
    points.sort_unstable();
    // Refuse to optimize a representation whose canonical reconstruction is
    // different. This also checks cancellations and coefficient-mask merging.
    assert_eq!(compact_outer::encode_points(points.clone(), nx, ny), data);
    let baseline = wiring_cost::multiplications(data);
    let baseline_bytes = super::super::codec::compress(data).len();
    let mut result = Vec::new();
    // Solidity keeps its original 496 row regions / 16384-entry bound. The
    // Yul format checks at most 632 row/column regions / 32768 entries. Neither
    // proof values nor witnesses choose a region or relax its identity checks.
    for axis in 0..=u8::from(larger) {
        let dimension = if axis == 0 { nx } else { ny };
        let first = dimension.saturating_sub(if axis == 0 { 8 } else { 6 });
        let last = dimension.saturating_sub(if larger { 2 } else { 4 });
        for width in first..=last {
            let groups: BTreeSet<_> = points
                .iter()
                .map(|p| (if axis == 0 { p.0 } else { p.1 }) >> width)
                .collect();
            for group in groups {
                if let Some(part) = build(
                    &points,
                    nx,
                    ny,
                    vec![(axis, width, group)],
                    baseline,
                    larger,
                ) && part.saved_muls >= 256
                {
                    result.push(part);
                }
            }
        }
    }
    // Join up to six promising regions. Favor estimated work saved
    // per extra compressed byte, then deterministic circuit-derived tie breaks.
    result.sort_by(|a, b| {
        let ac = a.packed_bytes.saturating_sub(baseline_bytes).max(1) as u128;
        let bc = b.packed_bytes.saturating_sub(baseline_bytes).max(1) as u128;
        (u128::from(b.saved_muls) * ac)
            .cmp(&(u128::from(a.saved_muls) * bc))
            .then_with(|| b.saved_muls.cmp(&a.saved_muls))
            .then_with(|| a.regions.cmp(&b.regions))
    });
    let mut regions: Vec<Region> = vec![];
    for part in &result {
        let (axis, width, prefix) = part.regions[0];
        let start = u64::from(prefix) << width;
        let end = start + (1u64 << width);
        if regions.iter().all(|&(other_axis, w, p)| {
            let other = u64::from(p) << w;
            axis != other_axis || end <= other || start >= other + (1u64 << w)
        }) {
            // Row and column regions may intersect. `inside` takes their
            // Boolean union once, so no matrix entry is counted twice.
            regions.push((axis, width, prefix));
            if regions.len() == 6 {
                break;
            }
        }
    }
    let mut seen: HashSet<_> = result
        .iter()
        .map(|p| (p.affine.clone(), p.factored.clone()))
        .collect();
    for mask in 1usize..1 << regions.len() {
        if mask.count_ones() < 2 {
            continue;
        }
        let union = regions
            .iter()
            .enumerate()
            .filter_map(|(i, &r)| (mask >> i & 1 != 0).then_some(r))
            .collect();
        if let Some(part) = build(&points, nx, ny, union, baseline, larger)
            && part.saved_muls >= 256
            && seen.insert((part.affine.clone(), part.factored.clone()))
        {
            result.push(part);
        }
    }
    result.sort_by(|a, b| {
        b.saved_muls
            .cmp(&a.saved_muls)
            .then_with(|| a.packed_bytes.cmp(&b.packed_bytes))
            .then_with(|| a.regions.cmp(&b.regions))
    });
    // Keep the work/size frontier plus nearby alternatives: whole-program
    // compression can change local ordering. Final generation compiles the
    // actual runtime and enforces both EVM code-size limits.
    let mut smallest = usize::MAX;
    let mut frontier = Vec::new();
    let mut nearby = Vec::new();
    for part in result {
        if part.packed_bytes < smallest {
            smallest = part.packed_bytes;
            frontier.push(part);
        } else if nearby.len() < 8 {
            nearby.push(part);
        }
    }
    frontier.extend(nearby);
    frontier.sort_by(|a, b| {
        b.saved_muls
            .cmp(&a.saved_muls)
            .then_with(|| a.packed_bytes.cmp(&b.packed_bytes))
            .then_with(|| a.regions.cmp(&b.regions))
    });
    frontier
}

#[cfg(test)]
mod tests {
    use super::super::{F, Field};
    use super::*;

    #[test]
    fn disjoint_parts_match_the_original_extension_including_boolean_points() {
        let points: Vec<_> = (0..8)
            .flat_map(|row| {
                (0..8).filter_map(move |col| {
                    ((row * 5 + col * 3) % 4 != 0).then_some((
                        row,
                        col,
                        ((row + 2 * col) % 7 + 1) as u8,
                    ))
                })
            })
            .collect();
        let original = compact_outer::encode_points(points.clone(), 3, 3);
        let parts = [
            build(&points, 3, 3, vec![(0, 1, 0), (0, 1, 2)], 0, false).unwrap(),
            build(&points, 3, 3, vec![(1, 1, 0), (1, 1, 2)], 0, true).unwrap(),
            build(&points, 3, 3, vec![(0, 1, 0), (1, 2, 0)], 0, true).unwrap(),
        ];
        let evaluate =
            |p: &[u8], x: &[F], y: &[F], lambda| compact_outer::evaluate_matrix(p, x, y, lambda, 4);
        for seed in 0..80u128 {
            let coordinates: Vec<_> = (0..6)
                .map(|i| {
                    if seed < 64 {
                        F::new((seed >> i) & 1)
                    } else {
                        F::new(
                            (seed * 0x3243f6a8885a308d + i as u128)
                                .wrapping_mul(0x9e3779b97f4a7c15d1b54a32d192ed03),
                        )
                    }
                })
                .collect();
            let (x, y) = coordinates.split_at(3);
            for lambda in [F::ZERO, F::ONE, F::new(0xa219314c826fa35b17)] {
                for part in &parts {
                    assert_eq!(
                        evaluate(&original, x, y, lambda),
                        evaluate(&part.affine, x, y, lambda)
                            + evaluate(&part.factored, x, y, lambda)
                    );
                }
            }
        }
    }
}
