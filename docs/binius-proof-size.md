# Native Binius64 ZK proof sizes

These measurements use the pinned Binius64 revision
`06fb4b86843d27930ee4af62781e6ac6acdecda7`, the compiled Noir `arithmetic`
example (`x*x+5=expected`, with private `x=3` and public `expected=14`),
and the existing native prover and verifier. All four proofs were freshly
proved and accepted by the native verifier. No query count or security
parameter was reduced.

| log inverse rate | Native transcript bytes | NBINZK01 bundle bytes | FRI queries |
| ---: | ---: | ---: | ---: |
| 1 (default) | 515,808 | 515,896 | 232 |
| 2 | 392,256 | 392,344 | 142 |
| 3 | 373,888 | 373,976 | 116 |
| 4 | 383,296 | 383,384 | 106 |

The bundle adds exactly 88 bytes: magic, circuit digest, rate, four public
u64 limbs and transcript length. It contains no verification program.

For this circuit, rate 3 gives the smallest native serialization in the
checked range 1–13. The exact native FRI size calculation and an independent
fold-arity minimization agree over that range. At rates 14 and above, the
terminal vector alone occupies at least `16 * 2^14 = 262,144` bytes.
Consequently a 200 KB target cannot be reached merely by changing the
existing rate setting for this compiled circuit. This is a statement about
this backend, circuit and serialization, not a lower bound on other Binius
protocols or new proof encodings.

At rate 3, the 373,888-byte transcript comprises:

| Component | Bytes |
| --- | ---: |
| FRI commitment roots | 288 |
| Shared Merkle layers | 32,768 |
| Query branch digests | 207,872 |
| Opened field values | 92,800 |
| Terminal vector | 8,192 |
| Other protocol messages | 31,968 |

Noir BN254 field arithmetic translates into multiple binary and integer
constraints. This example has 199 AND constraints and 48 integer
multiplications. The pinned zero-knowledge construction additionally uses
an outer Spartan proof of the masked inner verification. Its outer
multiplication matrix pads to 262,144 rows, with a 131,072-element private
segment. These are internal proof-system dimensions, not external public
inputs. Native serialization sends each query's branch independently.

Reproduce each rate with matching keys:

```sh
cargo build --release --locked
# Substitute 1, 2, 3 or 4 for the rate below.
target/release/noir-binius prove \
  -b examples/arithmetic/target/arithmetic.json \
  -w examples/arithmetic/target/arithmetic.gz \
  -o /tmp/arithmetic-r3.binius --log-inv-rate 3
target/release/noir-binius verify \
  -b examples/arithmetic/target/arithmetic.json -p /tmp/arithmetic-r3.binius
target/release/noir-binius write_vk \
  -b examples/arithmetic/target/arithmetic.json \
  -o /tmp/arithmetic-r3.vk --log-inv-rate 3
```

The source of the query formula, arity selection and size accounting is
`crates/iop/src/fri/{common,size_estimation}.rs` in the pinned dependency.
The native query-phase target is 96 bits and chooses
`ceil(96 / -log2((1 + 2^(-log_inv_rate))/2))` queries. This target is
specifically for FRI queries; it is not a claim of a security audit of the
complete construction or this Solidity implementation.
