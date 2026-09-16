//! Circuit-only performance estimate for the affine evaluator in runtime.sol.
//!
//! Count full field multiplications at generic coordinates, including the
//! evaluator's bounded carry and suffix caches. This deliberately does not
//! predict gas exactly: control flow, decoding, memory and exceptional field
//! values affect it. No estimate is used to accept a proof or validate a matrix.

use std::collections::HashSet;

// 0 and 1 are constants; U is a nonconstant polynomial. Distinct nonempty
// carry classes have disjoint Boolean support, so their sum is nonconstant.
const U: u8 = 2;
fn sum(values: &[u8]) -> u8 {
    if values.contains(&U) {
        U
    } else {
        values.iter().fold(0, |a, b| a ^ b)
    }
}
fn power(n: i64) -> bool {
    n > 0 && n & (n - 1) == 0
}
fn log(n: u64) -> usize {
    assert!(n > 0);
    n.ilog2() as usize
}

struct Model {
    dimensions: [usize; 2],
    suffix: [Vec<u64>; 2],
    carry: Vec<u128>,
    products: HashSet<(usize, usize)>,
    muls: u64,
}
impl Model {
    fn times(&mut self, a: u8, b: u8) -> u8 {
        if a == U && b == U {
            self.muls += 1;
        }
        if a == 0 || b == 0 {
            0
        } else if a == U || b == U {
            U
        } else {
            1
        }
    }
    fn prefix(&mut self, side: usize, n: usize) -> u8 {
        assert!(n <= self.dimensions[side]);
        if (6..10).contains(&n) {
            return U; // The runtime marginalizes its existing equality table.
        }
        self.muls += n.saturating_sub(1) as u64;
        if n == 0 { 1 } else { U }
    }
    fn part(&mut self, side: usize, index: u64, lo: usize) -> u8 {
        let key = ((1 + (index >> lo)) << 6) | lo as u64;
        let slot = ((u128::from(key) * 0x9e3779b97f4a7c15) >> 52) as usize & 4095;
        let value = if lo >= self.dimensions[side] { 1 } else { U };
        if self.suffix[side][slot] == key {
            return value;
        }
        let boundary = (lo / 9 + 1) * 9;
        if lo < self.dimensions[side] && boundary < self.dimensions[side] {
            if boundary + 9 < self.dimensions[side] {
                self.part(side, index, boundary);
            }
            // This call uses fm directly, even at an exceptional field value.
            self.muls += 1;
        }
        self.suffix[side][slot] = key;
        value
    }
    fn mass(&mut self, side: usize, index: u64, mut lo: usize) -> u8 {
        let n = self.dimensions[side];
        if index >> lo == 0 {
            return 0;
        }
        if index >> n != 0 {
            return 1;
        }
        let mut value = 0;
        while lo < n {
            let boundary = (lo / 9 + 1) * 9;
            let before = if (index >> lo) & ((1 << (boundary - lo)) - 1) == 0 {
                0
            } else {
                U
            };
            value = sum(&[before, self.times(U, value)]);
            lo = boundary;
        }
        value
    }
    fn interval(&mut self, side: usize, start: u64, stride: u64, count: u64) -> u8 {
        let shift = log(stride);
        let low = self.prefix(side, shift);
        let left = self.mass(side, start, shift);
        let right = self.mass(side, start + stride * count, shift);
        self.times(low, sum(&[left, right]))
    }
    fn states(k: usize, row: u64, column: u64) -> [u8; 4] {
        if k == 0 {
            return [1, 0, 0, 0];
        }
        let mask = (1 << k) - 1;
        let (row, column) = (row & mask, column & mask);
        // For t in [0,2^k), carries change at 2^k-row and 2^k-column.
        [
            U,
            if column > row { U } else { 0 },
            if row > column { U } else { 0 },
            if row != 0 && column != 0 { U } else { 0 },
        ]
    }
    fn key(a: usize, b: usize, k: usize, row: u64, column: u64) -> u128 {
        let mask = (1 << k) - 1;
        ((a as u128 + 1) << 80)
            | ((b as u128) << 72)
            | ((k as u128) << 64)
            | (u128::from(row & mask) << 32)
            | u128::from(column & mask)
    }
    fn slot(&self, key: u128) -> usize {
        let h = (key ^ (key >> 41)).wrapping_mul(0x9e3779b97f4a7c15);
        // Only the low 48 product bits affect a cache of at most 2048 slots;
        // truncation above bit127 agrees with the EVM's 256-bit arithmetic.
        (h ^ (h >> 37)) as usize & (self.carry.len() - 1)
    }
    fn carry(&mut self, a: usize, b: usize, k: usize, row: u64, column: u64) -> [u8; 4] {
        let mut level = k;
        while level > 0 {
            let key = Self::key(a, b, level, row, column);
            if self.carry[self.slot(key)] == key {
                break;
            }
            level -= 1;
        }
        while level < k {
            let s = Self::states(level, row, column);
            let bits = (((row >> level) & 1) * 2 + ((column >> level) & 1)) as usize;
            if self.products.insert((a + level, b + level)) {
                self.times(U, U);
            }
            if bits < 2 && s[2] == 0 && s[3] == 0 {
                self.times(U, sum(&s[..2]));
                self.times(U, s[usize::from(bits == 0)]);
            } else {
                let flip = (bits >> 1) * 3;
                self.times(U, sum(&s));
                if (bits ^ (bits >> 1)) & 1 == 0 {
                    for i in [1, 2, 3] {
                        self.times(U, s[i ^ flip]);
                    }
                } else {
                    for i in [0, 2, 2, 3] {
                        self.times(U, s[i ^ flip]);
                    }
                }
            }
            level += 1;
            let key = Self::key(a, b, level, row, column);
            let slot = self.slot(key);
            self.carry[slot] = key;
        }
        Self::states(k, row, column)
    }
    fn rounded(&mut self, row: u64, column: u64, a: usize, b: usize, k: usize) -> u8 {
        let s = self.carry(a, b, k, row >> a, column >> b);
        let x0 = self.part(0, row, a + k);
        let y0 = self.part(1, column, b + k);
        let x1 = if s[2] != 0 || s[3] != 0 {
            self.part(0, row + (1 << (a + k)), a + k)
        } else {
            0
        };
        let y1 = if s[1] != 0 || s[3] != 0 {
            self.part(1, column + (1 << (b + k)), b + k)
        } else {
            0
        };
        let left = sum(&[self.times(s[0], y0), self.times(s[1], y1)]);
        let right = sum(&[self.times(s[2], y0), self.times(s[3], y1)]);
        sum(&[self.times(x0, left), self.times(x1, right)])
    }
    fn progression(
        &mut self,
        mut row: u64,
        mut column: u64,
        a: usize,
        b: usize,
        mut count: u64,
    ) -> u8 {
        let x = self.prefix(0, a);
        let y = self.prefix(1, b);
        let low = self.times(x, y);
        let k = log(count - 1) + 1;
        let size = 1 << k;
        if count > 8
            && size - count < 4
            && row + ((size - 1) << a) < 1 << self.dimensions[0]
            && column + ((size - 1) << b) < 1 << self.dimensions[1]
        {
            let rounded = self.rounded(row, column, a, b, k);
            let mut value = self.times(low, rounded);
            for i in count..size {
                let x = self.part(0, row + (i << a), 0);
                let y = self.part(1, column + (i << b), 0);
                value = sum(&[value, self.times(x, y)]);
            }
            return value;
        }
        let mut value = 0;
        while count > 0 {
            let start = row >> a;
            let k = if start == 0 {
                log(count)
            } else {
                log(count).min(start.trailing_zeros() as usize)
            };
            let size = 1 << k;
            let s = self.carry(a, b, k, 0, column >> b);
            let y0 = self.part(1, column, b + k);
            let mut high = self.times(s[0], y0);
            if s[1] != 0 && column + (1 << (b + k)) < 1 << self.dimensions[1] {
                let y1 = self.part(1, column + (1 << (b + k)), b + k);
                high = sum(&[high, self.times(s[1], y1)]);
            }
            let x = self.part(0, row, a + k);
            value = sum(&[value, self.times(x, high)]);
            row += size << a;
            column += size << b;
            count -= size;
        }
        self.times(value, low)
    }
}

pub(super) fn multiplications(data: &[u8]) -> u64 {
    let (nx, ny, runs) = super::compact_outer::decode_matrix(data);
    assert!(nx <= 32 && ny <= 32);
    let mut capacity = 16;
    while capacity < runs.len() && capacity < 2048 {
        capacity *= 2;
    }
    let mut model = Model {
        dimensions: [nx, ny],
        suffix: [vec![0; 4096], vec![0; 4096]],
        carry: vec![0; capacity],
        products: HashSet::new(),
        muls: 0,
    };
    for n in [nx, ny] {
        for start in (0..n).step_by(9) {
            model.muls += (1 << (n - start).min(9)) - 2;
        }
    }
    for [_, count, row, column, dr, dc] in runs {
        let (count, row, column) = (count as u64, row as u64, column as u64);
        if dr == 0 && power(dc) {
            let x = model.part(0, row, 0);
            let y = model.interval(1, column, dc as u64, count);
            model.times(x, y);
        } else if dc == 0 && power(dr) {
            let x = model.interval(0, row, dr as u64, count);
            let y = model.part(1, column, 0);
            model.times(x, y);
        } else if power(dr) && power(dc) && count > 3 {
            model.progression(row, column, log(dr as u64), log(dc as u64), count);
        } else {
            for i in 0..count {
                let x = model.part(0, (row as i64 + i as i64 * dr) as u64, 0);
                let y = model.part(1, (column as i64 + i as i64 * dc) as u64, 0);
                model.times(x, y);
            }
        }
    }
    model.muls + 2 // Final lambda contraction.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carry_classes_match_all_small_integer_overflows() {
        for k in 0..=6 {
            let size = 1u64 << k;
            for row in 0..size {
                for column in 0..size {
                    let mut reachable = [false; 4];
                    for t in 0..size {
                        reachable[((row + t) / size * 2 + (column + t) / size) as usize] = true;
                    }
                    assert_eq!(Model::states(k, row, column).map(|v| v != 0), reachable);
                }
            }
        }
    }
}
