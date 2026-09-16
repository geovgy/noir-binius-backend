//! Lossless compression of fixed verifier instructions, independent of proofs.
//! Predict instruction operands per opcode/position, then encode a raw LZMA stream
//! (lc=1, lp=0, pb=0). Expanded operands use the smallest lossless 1/2/4-byte width;
//! field constants and the contents of circuit tables retain their own encodings.

use std::io::{Read, Write};

struct Operands<'a> {
    input: &'a [u8],
    position: usize,
    output: Vec<u8>,
    previous: [[i64; 8]; 32],
    encoding: bool,
    word_bytes: usize,
    maximum: u32,
}
impl Operands<'_> {
    fn copy(&mut self, n: usize) {
        self.output
            .extend_from_slice(&self.input[self.position..self.position + n]);
        self.position += n;
    }
    fn byte(&mut self) -> u8 {
        let b = self.input[self.position];
        self.copy(1);
        b
    }
    fn number(&mut self, op: usize, lane: usize) -> usize {
        let value;
        if self.encoding {
            let mut bytes = [0; 4];
            bytes[4 - self.word_bytes..]
                .copy_from_slice(&self.input[self.position..self.position + self.word_bytes]);
            value = i64::from(u32::from_be_bytes(bytes));
            self.position += self.word_bytes;
            let difference = value - self.previous[op][lane];
            let mut n = if difference < 0 {
                (-2 * difference - 1) as u64
            } else {
                (2 * difference) as u64
            };
            while n >= 128 {
                self.output.push((n as u8) | 128);
                n >>= 7;
            }
            self.output.push(n as u8);
        } else {
            let mut n = 0u64;
            let mut shift = 0;
            loop {
                let b = self.input[self.position];
                self.position += 1;
                n |= u64::from(b & 127) << shift;
                if b & 128 == 0 {
                    break;
                }
                shift += 7;
            }
            let difference = if n & 1 == 0 {
                (n / 2) as i64
            } else {
                -((n / 2) as i64) - 1
            };
            value = self.previous[op][lane] + difference;
            let number = u32::try_from(value).expect("verifier operand exceeds u32");
            assert!(
                u64::from(number) < 1u64 << (8 * self.word_bytes),
                "verifier operand exceeds selected word width"
            );
            self.output
                .extend_from_slice(&number.to_be_bytes()[4 - self.word_bytes..]);
        }
        self.previous[op][lane] = value;
        self.maximum = self.maximum.max(u32::try_from(value).unwrap());
        value as usize
    }
}
fn translate_ranges(
    input: &[u8],
    encoding: bool,
    word_bytes: usize,
    data_opcode: usize,
) -> (Vec<u8>, u32, Vec<std::ops::Range<usize>>) {
    assert!(matches!(word_bytes, 1 | 2 | 4));
    let mut c = Operands {
        input,
        position: 0,
        output: vec![],
        previous: [[0; 8]; 32],
        encoding,
        word_bytes,
        maximum: 0,
    };
    let mut byte_ranges = Vec::new();
    while c.position < input.len() {
        let op = c.byte() as usize;
        c.number(op, 0);
        match op {
            0 => c.copy(16),
            1 | 2 | 8 => {
                c.number(op, 1);
                c.number(op, 2);
            }
            3 | 5 | 9 | 27 | 28 | 31 => {
                c.number(op, 1);
            }
            4 | 10 | 11 | 12 | 18 | 22 => {
                c.number(op, 1);
                c.copy(1);
            }
            6 | 13 => {}
            7 => c.copy(1),
            14 | 20 => {
                for i in 1..4 {
                    c.number(op, i);
                }
            }
            15 => {
                for i in 1..6 {
                    c.number(op, i);
                }
            }
            16 | 24 => {
                for i in 1..5 {
                    c.number(op, i);
                }
                if op == 24 {
                    c.copy(1);
                }
            }
            17 => {
                for _ in 0..128 {
                    c.number(op, 1);
                }
            }
            19 => {
                let n = c.number(op, 1);
                for _ in 0..n {
                    c.number(op, 2);
                }
            }
            21 | 23 | 25 | 30 => {
                let start = c.position;
                let n = c.number(op, 1);
                c.copy(n);
                if encoding && op == data_opcode {
                    // Input range includes the fixed-width length word. Never
                    // interpret bytes inside an opaque table as instructions.
                    byte_ranges.push(start..c.position);
                }
            }
            26 => {
                c.number(op, 1);
                c.number(op, 2);
                c.copy(2);
            }
            29 => {
                let n = c.byte();
                for _ in 0..n {
                    c.number(op, 1);
                }
            }
            _ => panic!("unsupported compact opcode {op}"),
        }
    }
    (c.output, c.maximum, byte_ranges)
}

fn translate(
    input: &[u8],
    encoding: bool,
    word_bytes: usize,
) -> (Vec<u8>, u32, Vec<std::ops::Range<usize>>) {
    translate_ranges(input, encoding, word_bytes, 21)
}

pub(super) fn operands(input: &[u8], encoding: bool, word_bytes: usize) -> Vec<u8> {
    translate(input, encoding, word_bytes).0
}

pub(super) fn byte_ranges(input: &[u8], word_bytes: usize) -> Vec<std::ops::Range<usize>> {
    translate(input, true, word_bytes).2
}

pub(super) fn public_ranges(input: &[u8], word_bytes: usize) -> Vec<std::ops::Range<usize>> {
    translate_ranges(input, true, word_bytes, 23).2
}

/// Narrow only the top-level instruction operands. The delta stream does not
/// depend on their storage width. Widening must reproduce every original byte,
/// including opaque FRI/wiring tables that still contain full u32 addresses.
pub(super) fn narrow(program: &[u8]) -> (Vec<u8>, usize) {
    let (encoded, maximum, _) = translate(program, true, 4);
    let word_bytes = if maximum <= u8::MAX.into() {
        1
    } else if maximum <= u16::MAX.into() {
        2
    } else {
        4
    };
    let narrowed = operands(&encoded, false, word_bytes);
    let recoded = operands(&narrowed, true, word_bytes);
    assert_eq!(recoded, encoded, "operand narrowing changed delta stream");
    assert_eq!(
        operands(&recoded, false, 4),
        program,
        "operand narrowing changed verifier equations"
    );
    (narrowed, word_bytes)
}

pub(super) fn pack(program: &[u8], word_bytes: usize) -> (Vec<u8>, usize) {
    let encoded = operands(program, true, word_bytes);
    let packed = compress(&encoded);
    assert_eq!(
        operands(&encoded, false, word_bytes),
        program,
        "verifier operand coding failed roundtrip"
    );
    (packed, encoded.len())
}

pub(super) fn compress(encoded: &[u8]) -> Vec<u8> {
    let mut options = lzma_rust2::LzmaOptions::with_preset(9);
    options.dict_size = 1 << 20;
    options.lc = 1;
    options.lp = 0;
    options.pb = 0;
    // Circuit tables contain long repetitions, but taking the longest match
    // does not always yield the shortest stream. Try both 64- and 273-byte
    // match thresholds instead of relying only on the library's 64-byte preset.
    // Match length, search depth, and the match finder affect constructor size
    // without changing the decoder format. Retain both previous candidates so
    // adding these bounded alternatives cannot make any key's stream larger.
    use lzma_rust2::MfType::{Bt4, Hc4};
    let packed = [
        (Bt4, 273, 0),
        (Bt4, 273, 512),
        (Bt4, 273, 16),
        (Bt4, 64, 16),
        (Hc4, 273, 128),
        (Hc4, 273, 256),
    ]
    .into_iter()
    .map(|(finder, nice, depth)| {
        let mut candidate = options.clone();
        candidate.mf = finder;
        candidate.nice_len = nice;
        candidate.depth_limit = depth;
        let mut writer =
            lzma_rust2::LzmaWriter::new_no_header(Vec::new(), &candidate, false).unwrap();
        writer.write_all(encoded).unwrap();
        writer.finish().unwrap()
    })
    .min_by_key(Vec::len)
    .unwrap();
    let mut reader = lzma_rust2::LzmaReader::new_with_props(
        packed.as_slice(),
        encoded.len() as u64,
        options.get_props(),
        options.dict_size,
        None,
    )
    .unwrap();
    let mut decoded = Vec::new();
    reader.read_to_end(&mut decoded).unwrap();
    assert_eq!(decoded, encoded, "verifier compression failed roundtrip");
    packed
}

/// One extra bounded encoder search for an otherwise oversized constructor.
/// Keep the ordinary encoding byte-for-byte stable. Match-finder depth does
/// not change the decoder format or any uncompressed circuit/runtime byte.
pub(super) fn compress_size_retry(encoded: &[u8]) -> Vec<u8> {
    let baseline = compress(encoded);
    let mut options = lzma_rust2::LzmaOptions::with_preset(9);
    options.dict_size = 1 << 20;
    options.lc = 1;
    options.lp = 0;
    options.pb = 0;
    options.mf = lzma_rust2::MfType::Hc4;
    options.nice_len = 273;
    options.depth_limit = 100;
    let mut writer = lzma_rust2::LzmaWriter::new_no_header(Vec::new(), &options, false).unwrap();
    writer.write_all(encoded).unwrap();
    let candidate = writer.finish().unwrap();
    let mut reader = lzma_rust2::LzmaReader::new_with_props(
        candidate.as_slice(),
        encoded.len() as u64,
        options.get_props(),
        options.dict_size,
        None,
    )
    .unwrap();
    let mut decoded = Vec::new();
    reader.read_to_end(&mut decoded).unwrap();
    assert_eq!(
        decoded, encoded,
        "constructor compression retry failed roundtrip"
    );
    if candidate.len() < baseline.len() {
        candidate
    } else {
        baseline
    }
}

#[cfg(test)]
mod tests {
    use super::{narrow, operands};

    #[test]
    fn size_retry_preserves_bytes_and_never_enlarges_the_stream() {
        use std::io::Read;

        for length in [0, 1, 31, 256, 4096] {
            let data: Vec<u8> = (0..length)
                .map(|i| ((i * 73) ^ (i >> 5) ^ (i / 257)) as u8)
                .collect();
            let ordinary = super::compress(&data);
            let retried = super::compress_size_retry(&data);
            assert!(retried.len() <= ordinary.len());
            if retried.len() == ordinary.len() {
                assert_eq!(retried, ordinary, "ties must retain the ordinary stream");
            }
            // The constructor's fixed decoder properties remain lc=1, lp=pb=0.
            let mut reader = lzma_rust2::LzmaReader::new_with_props(
                retried.as_slice(),
                data.len() as u64,
                1,
                1 << 20,
                None,
            )
            .unwrap();
            let mut actual = Vec::new();
            reader.read_to_end(&mut actual).unwrap();
            assert_eq!(actual, data);
        }
    }

    // Repeated Sample destinations exercise positive and negative deltas.
    // The opaque table deliberately includes values larger than u16.
    fn wide_program(maximum: u32) -> Vec<u8> {
        let mut program = vec![];
        for value in [0, maximum, 1, maximum, 0] {
            program.push(6);
            program.extend_from_slice(&value.to_be_bytes());
        }
        program.extend_from_slice(&[21, 0, 0, 0, 0, 0, 0, 0, 8]);
        program.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0x80, 0, 0, 0]);
        program.extend_from_slice(&[0, 0, 0, 0, 1]);
        program.extend_from_slice(&u128::MAX.to_be_bytes());
        program
    }

    #[test]
    fn operand_width_boundaries_preserve_equations_and_delta_stream() {
        for (maximum, expected_width) in [(255, 1), (256, 2), (65535, 2), (65536, 4), (u32::MAX, 4)]
        {
            let wide = wide_program(maximum);
            let (small, width) = narrow(&wide);
            assert_eq!(width, expected_width);
            // Eight top-level words, with field/table bytes left untouched.
            assert_eq!(small.len(), wide.len() - 8 * (4 - width));
            let encoded = operands(&small, true, width);
            assert_eq!(encoded, operands(&wide, true, 4));
            assert_eq!(operands(&encoded, false, 4), wide);
        }
    }

    #[test]
    fn operand_width_never_silently_truncates() {
        for (maximum, width) in [(256, 1), (65536, 2)] {
            let encoded = operands(&wide_program(maximum), true, 4);
            assert!(std::panic::catch_unwind(|| operands(&encoded, false, width)).is_err());
        }
    }

    #[test]
    fn byte_ranges_exclude_instruction_words_and_other_opaque_tables() {
        for maximum in [255, 256, 65536] {
            let (program, width) = narrow(&wide_program(maximum));
            let start = 5 * (1 + width) + 1 + width;
            assert_eq!(
                super::byte_ranges(&program, width),
                [start..start + width + 8]
            );
            assert!(super::public_ranges(&program, width).is_empty());
            let mut other = program.clone();
            for opcode in [23, 25, 30] {
                other[5 * (1 + width)] = opcode;
                assert!(super::byte_ranges(&other, width).is_empty());
                assert_eq!(
                    super::public_ranges(&other, width),
                    if opcode == 23 {
                        vec![start..start + width + 8]
                    } else {
                        vec![]
                    }
                );
            }
        }
    }
}
