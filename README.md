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

## Solidity verifiers

Write the portable verification key, then select one of the two Solidity targets supported by the
Noir-compatible `write_solidity_verifier` command:

```console
cargo run --release -- write_vk \
  -b examples/arithmetic/target/arithmetic.json \
  -o examples/arithmetic/target/arithmetic.vk

# Verify the original NBINZK01 proof entirely inside the generated contract.
cargo run --release -- write_solidity_verifier \
  -k examples/arithmetic/target/arithmetic.vk \
  -o examples/arithmetic/target/BiniusVerifier.sol \
  --verifier_target evm

# Verify a succinct SP1 proof wrapping that Binius64 proof.
cargo run --release -- write_solidity_verifier \
  -k examples/arithmetic/target/arithmetic.vk \
  -o examples/arithmetic/target/BiniusSP1Verifier.sol \
  --verifier_target evm-sp1
```

The command also accepts the usual `--vk_path`, `--output_path`, `-t`, and `--optimized` spellings.
For the optional factored wiring evaluator, pass `--solidity_compiler /path/to/solc`.
This requires solc 0.8.35 during generation and compresses the complete compiled
runtime into the constructor. It reduces verification gas at the cost of higher
deployment gas; the contract still takes no constructor arguments and is ready
immediately. Use the compiler settings printed in the generated source. See
[the measured tradeoff](docs/direct-solidity-verification.md#optional-factored-deployment).

For compact creation bytecode and a larger fixed-matrix optimization budget, use
the explicit deployment-artifact command:

```console
cargo run --release -- write_verifier_deployment \
  -k examples/arithmetic/target/arithmetic.vk \
  -o examples/arithmetic/target/BiniusVerifier.deployment.json \
  --solc /path/to/solc-0.8.35
```

Deploy the JSON artifact's `bytecode` with its `abi` and **no arguments**. It also
contains the complete `BiniusVerifier is IVerifier` Solidity implementation, Yul
creation source, compiler settings, and runtime bytecode. Generation checks that
the constructor installs the runtime compiled from that implementation. The
ordinary constructor compiled directly from the accompanying Solidity source can
exceed the initcode limit; use the artifact's tested Yul creation bytecode for this
mode. The constructor can derive the complete fixed matrix before storing it;
no installation call is needed after deployment. In the last completed four-key
generator validation, the rate-3 example used 168.6 million verification call gas
and 518.1 million creation gas.
An artifact advertising `construction.programInput` also accepts the public
circuit bytes alongside the proof, authenticated against the constructor's
stored digest. `withVerifierProgram(proof, deployment)` prepares this optional
input; that validation measured 159.3 million call gas, or 135.4 million with fully checked SHA
hints. Bare native proofs remain accepted. The native proof is 373,976 bytes;
the circuit bytes are additional calldata. The 10-million-gas target remains unmet.
See [compact deployment](docs/direct-solidity-verification.md#compact-yul-deployment).

The two targets deliberately have the same `verify(bytes,bytes32[])` application ABI, but accept
different proof formats:

| target | accepted proof | verification |
| --- | --- | --- |
| `evm` (default) | raw `NBINZK01`, optionally with checked `NBINH001` SHA hints | complete Binius64 ZK verification in Solidity/Yul in one contract |
| `evm-sp1` | `NBINSP11` envelope made by `noir-binius-sp1` | SP1 wrapper verification through the separately deployed SP1 verifier |

For optional hash batching, prepare proof bytes for that same direct contract:

```console
cargo run --release -- write_solidity_proof \
  -k examples/arithmetic/target/arithmetic.vk \
  -p examples/arithmetic/target/arithmetic.binius \
  -o examples/arithmetic/target/arithmetic.hinted
```

The contract recomputes and checks every supplied SHA digest. This preserves the
native proof and all verifier equations. The original `.binius` file remains
accepted by the contract and is still used for native verification.

The default contract inherits `IVerifier` and exposes
`verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool)`.
It checks the envelope and Noir inputs, reconstructs the exact SHA-256 Fiat-Shamir transcript,
checks public wiring and the outer Spartan ZK proof, and verifies all combined BaseFold/FRI
openings with GHASH-field arithmetic and Binius's custom SHA-256 Merkle compression. These
operations execute in the contract, including SHA-256; there are no external calls or precompiles.

Deploy `BiniusVerifier` with **no constructor arguments**, using Solidity 0.8.35,
optimizer 200 runs, `viaIR`, Osaka, and `metadata.bytecodeHash: "none"` as tested. The constructor decodes and stores the complete
circuit program. The deployed contract is immediately ready for `verify`;
there is no upload function or subsequent initialization. Circuit data is generated
from the verification key, independently of any proof or private witness.

The last completed four-key public-generation validation of `write_verifier_deployment`
measured the arithmetic rate-3 proof at **135,395,587 call gas** with authenticated public circuit data and
checked SHA hints, or **168,627,101 call gas** for the original proof alone.
Its constructor takes no arguments; its 49,065-byte creation code installs the
24,492-byte runtime and all circuit data. The public generator emits exactly the
creation/runtime bytes tested with two independently blinded zk proofs. These
measurements include caller ABI encoding and exclude transaction intrinsic/calldata
gas. **The 10-million-gas target remains unmet.**

The implementation uses compact FRI loops, sparse matrix contractions and shared
multilinear interpolations. For the source-returning APIs, with cold program storage, the native equality fixture
measures about **149.8 million gas with checked SHA hints** and the compiled Noir arithmetic example at
rate 3 measures about **187.7 million gas with checked SHA hints** (211.2 million for
the original-proof path). The hinted rate-3 envelope is 389,120 bytes, including
the 373,976-byte native proof and 15,136 bytes of hints; the 10-million-gas target
remains unmet. Decoding and installing the circuit data
in the constructor costs about **88 million** and **190 million gas**, respectively.
Both generated contracts fit the checked creation/runtime bytecode size limits.
The local tests raise the gas limit for deployment and verification.
The large `keccak_merkle` circuit currently exceeds the initcode data limit and
generation returns an explicit error. See [measurements and verification design](docs/direct-solidity-verification.md).

Proof bytes are separate from circuit-program bytes. The pinned native prover emits
515,896-byte bundles for the compiled Noir arithmetic example at its default rate,
or 373,976 bytes with `--log-inv-rate 3`. Those proofs are native-verified; Solidity
does not add instructions to them. See the [proof-size recheck](docs/binius-proof-size.md).
The direct generator rejects delegated recursive-proof metadata because those checks
are performed separately by the backend and must not be omitted.

To build and create the optional SP1 wrapper proof (SP1 proving is intentionally kept outside the
root Cargo workspace), install the SP1 6.6.0 toolchain first (`sp1up -v 6.6.0`):

```console
cd sp1/guest
cargo prove build --locked --output-directory ../elf
cd ../..

cargo run --release --manifest-path sp1/prover/Cargo.toml -- prove \
  --elf sp1/elf/noir-binius-sp1-guest \
  --vk_path examples/arithmetic/target/arithmetic.vk \
  --proof_path examples/arithmetic/target/arithmetic.binius \
  --output_path examples/arithmetic/target/arithmetic.sp1 \
  --system groth16
```

The wrapper host performs native Binius verification before proving, and the guest verifies the
same complete proof (including delegated recursive calls). Its public values bind the SHA-256 hash
of the exact portable key and the SHA-256 hash of the ordered Solidity public inputs. SP1 setup and
proving can require several gigabytes of RAM; use a sufficiently large host or the SP1 network.

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

const directVerifier = await backend.generateSolidityVerifier();
const wrappedVerifier = await backend.generateSolidityVerifier({
  verifierTarget: 'evm-sp1',
});
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

The direct Solidity verification test generates a real ZK proof, generates and deploys the
contract in Foundry's EVM, calls `IVerifier.verify` immediately after construction,
and checks rejection of altered proofs and public inputs:

```console
scripts/solidity-e2e.sh
# Run the same complete path for a compiled Noir example:
scripts/solidity-e2e.sh arithmetic
```

This test executes the verification math in the EVM with raised local gas limits. It does not
install an engine, mock a verifier, or allowlist proof hashes. `SKIP_NARGO=1` reuses an existing
compiled Noir artifact and witness. `FORGE_BIN` and `NARGO_BIN` can select tool installations.

## License
MIT
