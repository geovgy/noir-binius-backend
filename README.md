# noir-binius

`noir-binius` is an experimental proving backend that translates Noir's BN254 ACIR into a
Binius64 word circuit, then creates and verifies a zero-knowledge Binius proof.

The important compatibility layer is exact rather than heuristic: every ACIR `Field` value is
represented by four little-endian 64-bit Binius words, constrained to be below the BN254 scalar
modulus, and ACIR quadratic expressions are evaluated modulo that modulus with Binius64's
big-integer gadgets.

## Status

All six ACIR opcode variants and all fourteen black-box variants in the pinned Noir beta.18 ACIR
schema are handled. This includes dynamic memory, multi-function and conditional calls, AES-128,
BLAKE2s, BLAKE3, Keccak-f1600, SHA-256 compression, Poseidon2, both supported ECDSA curves,
Grumpkin addition/MSM, and recursive aggregation. See [SUPPORT.md](SUPPORT.md) for the exhaustive
matrix and semantic notes.

Recursive aggregation uses ACIR's permitted final-verifier delegation: recursive key, proof, and
public-input fields are bound into the outer Binius public statement, and the final verifier checks
the nested Binius ZK proof. This is sound but currently non-succinct and reveals the recursive
payload. The pinned Binius recursion crate only records its transparent verifier, not the
Iron-Spartan `ZKVerifier` used here.

This is experimental software and has not been audited; do not use it for production or
security-critical proofs.

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
and a digest binding it to the exact serialized ACIR bytecode. As with other proof formats that
carry their public inputs, an application must compare those inputs with the statement it intended
to verify.

## TypeScript

The [`@noir-binius/backend`](packages/noir-binius-backend) package exposes a `BiniusBackend` with
the same proof-data shape as `@aztec/bb.js`'s `UltraHonkBackend`. Build the native backend and the
package first:

```console
cargo build --release
cd packages/noir-binius-backend
bun install
bun run build
```

The compressed witness returned by `@noir-lang/noir_js` can be passed directly to the backend:

```typescript
import { Noir } from "@noir-lang/noir_js";
import { BiniusBackend } from "@noir-binius/backend";
import circuit from "../target/my_circuit.json" with { type: "json" };

const noir = new Noir(circuit);
const backend = new BiniusBackend(circuit.bytecode);
const { witness } = await noir.execute({ x: 3, expected: 14 });
const proofData = await backend.generateProof(witness);
console.log(await backend.verifyProof(proofData));
```

The package invokes the native `noir-binius` executable and is currently Node.js-only. See its
[README](packages/noir-binius-backend/README.md) for binary discovery and API details.

To use a verified proof as a recursive Noir input, export the backend-specific fields as JSON or a
generated `Prover.toml`:

```console
cargo run --release -- recursive-inputs \
  -b examples/arithmetic/target/arithmetic.json \
  -p examples/arithmetic/target/arithmetic.binius \
  -o examples/recursive_aggregation/Prover.toml \
  --toml
```

The exporter supplies the required proof-type tag and refuses an invalid inner proof.

## Tests

Fast Rust tests and compile checks:

```console
cargo test
```

The smoke check compiles, proves, and verifies the small fixtures and confirms that a same-length,
byte-tampered proof is rejected cryptographically:

```console
RUSTFLAGS="-C target-cpu=native" scripts/e2e.sh
```

The exhaustive script exercises every pinned opcode and black-box fixture, including an active
recursive proof:

```console
RUSTFLAGS="-C target-cpu=native" scripts/e2e-full.sh
```
