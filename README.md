# noir-binius

`noir-binius` is an experimental proving backend that translates Noir's BN254 ACIR into a
Binius64 word circuit, then creates and verifies a zero-knowledge Binius proof.

The important compatibility layer is exact rather than heuristic: every ACIR `Field` value is
represented by four little-endian 64-bit Binius words, constrained to be below the BN254 scalar
modulus, and ACIR quadratic expressions are evaluated modulo that modulus with Binius64's
big-integer gadgets.

## Status

The current end-to-end MVP supports:

| ACIR feature | Status |
| --- | --- |
| `AssertZero` quadratic field expressions | Supported |
| `RANGE` | Supported up to the 254-bit ACIR field width |
| `AND`, `XOR` | Supported up to the 254-bit ACIR field width |
| Brillig witness-generation calls | Accepted; Nargo executes them before proving |
| Memory opcodes and multi-function calls | Rejected |
| Other black-box functions | Rejected with the opcode index and function name |

Unsupported constrained opcodes are never silently skipped. This is prototype software and has
not been audited; do not use it for production or security-critical proofs.

## Prerequisites

- Rust 1.97.1 (selected by `rust-toolchain.toml`)
- Nargo 1.0.0-beta.18
- A 64-bit target supported by Binius64

The dependency revisions are pinned in `Cargo.toml`:

- Noir `99bb8b5cf33d7669adbdef096b12d80f30b4c0c9` (1.0.0-beta.18)
- Binius64 `06fb4b86843d27930ee4af62781e6ac6acdecda7`

## Build and use

Compile and execute a Noir program with Nargo:

```console
cd examples/arithmetic
nargo execute
cd ../..
```

Check whether its ACIR is supported:

```console
cargo run --release -- info \
  -b examples/arithmetic/target/arithmetic.json
```

Generate a zero-knowledge proof:

```console
cargo run --release -- prove \
  -b examples/arithmetic/target/arithmetic.json \
  -w examples/arithmetic/target/arithmetic.gz \
  -o examples/arithmetic/target/arithmetic.binius
```

Verify it without the private witness:

```console
cargo run --release -- verify \
  -b examples/arithmetic/target/arithmetic.json \
  -p examples/arithmetic/target/arithmetic.binius
```

The proof bundle contains the raw Binius transcript, the public input words, the proof parameters,
and a digest binding it to the exact Noir artifact. As with other proof formats that carry their
public inputs, an application must compare those inputs with the statement it intended to verify.

## Tests

Fast Rust tests and compile checks:

```console
cargo test
```

The full check compiles, proves, and verifies the arithmetic and bitwise Noir fixtures, then
confirms that a same-length, byte-tampered proof is rejected cryptographically:

```console
RUSTFLAGS="-C target-cpu=native" scripts/e2e.sh
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for the lowering design and extension points.

## License

Licensed under either Apache-2.0 or MIT, at your option.
