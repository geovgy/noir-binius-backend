//! Lossless compression of fixed verifier instructions, independent of proofs.
//! Predict u32 operands per opcode/position, then encode a raw LZMA stream (lc=1, lp=0, pb=2).

use std::io::{Read, Write};

struct Operands<'a> {
    input: &'a [u8],
    position: usize,
    output: Vec<u8>,
    previous: [[i64; 8]; 32],
    encoding: bool,
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
            value = u32::from_be_bytes(
                self.input[self.position..self.position + 4]
                    .try_into()
                    .unwrap(),
            ) as i64;
            self.position += 4;
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
            self.output
                .extend_from_slice(&u32::try_from(value).unwrap().to_be_bytes());
        }
        self.previous[op][lane] = value;
        value as usize
    }
}
pub(super) fn operands(input: &[u8], encoding: bool) -> Vec<u8> {
    let mut c = Operands {
        input,
        position: 0,
        output: vec![],
        previous: [[0; 8]; 32],
        encoding,
    };
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
                let n = c.number(op, 1);
                c.copy(n);
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
    c.output
}

pub(super) fn pack(program: &[u8]) -> (Vec<u8>, usize) {
    let encoded = operands(program, true);
    let mut options = lzma_rust2::LzmaOptions::with_preset(9);
    options.dict_size = 1 << 20;
    options.lc = 1;
    options.lp = 0;
    options.pb = 2;
    let mut writer = lzma_rust2::LzmaWriter::new_no_header(Vec::new(), &options, false).unwrap();
    writer.write_all(&encoded).unwrap();
    let packed = writer.finish().unwrap();
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
    assert_eq!(
        operands(&decoded, false),
        program,
        "verifier operand coding failed roundtrip"
    );
    (packed, encoded.len())
}
