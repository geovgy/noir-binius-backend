# Direct Binius64 ZK verification

The `evm` target generates one `BiniusVerifier is IVerifier` contract. Its
`verify(bytes,bytes32[])` entry point is `external view returns (bool)` and accepts
the existing `NBINZK01` bundle. Neither the proof format nor the native prover is
changed. The contract contains all cryptographic execution, including the hash
functions. It makes no calls to other contracts or precompiles.

Deployment takes no arguments and initializes all circuit data in the contract's
own storage. There is no program-upload function or subsequent installation step.
The fixed data is losslessly compressed in the constructor's source; it is not
part of the proof. Code generation receives only the verification key.

Deployment and verification still need a raised local gas limit. The measurements
below are from the generated contract in Foundry, with cold program storage, Solidity
0.8.35, optimizer 200 runs and via IR. These costs exceed ordinary Ethereum
transaction limits even when creation and runtime bytecode fit their size limits.

| Circuit | Proof bytes | Deployment gas | Verification gas | Initcode bytes | Runtime bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| Native equality, rate 1 | 379,072 | 100,621,941 | 484,965,706 | 32,968 | 19,184 |
| Noir arithmetic, rate 1 (default) | 515,896 | 228,485,281 | 704,285,216 | 49,020 | 19,338 |
| Noir arithmetic, rate 2 | 392,344 | 228,340,573 | 626,196,214 | 49,065 | 19,338 |
| Noir arithmetic, rate 3 | 373,976 | 228,439,164 | 613,120,471 | 49,095 | 19,338 |

Gas measures construction and the verification call in the EVM test, excluding
transaction intrinsic/calldata gas. Program storage is cold; the contract account
is warm. Each fixture passes 11 EVM tests, including 256-case randomized field,
hash and wiring tests, and the ABI/bytecode audit. The arithmetic contracts have
little initcode headroom: use the tested compiler/settings and check each output.
The public ABI consists of the no-argument constructor and `verify` only.

The compiled Noir arithmetic example's native proof is 515,896 bytes at the
default inverse rate. Rate 3 reduces it to 373,976 bytes without changing the
native query security setting. These are the existing backend's actual proof
sizes, including an 88-byte envelope, not expanded verifier instructions.
See [native size measurements and parameter analysis](binius-proof-size.md).

## What is being verified

The source of truth is the pinned `binius64` revision
`06fb4b86843d27930ee4af62781e6ac6acdecda7`. In that revision, zero knowledge uses
an outer Spartan circuit to attest the masked inner verifier messages. Replaying
the ordinary non-ZK verifier on those messages would be incorrect.

The contract executes these checks:

1. Validate proof magic, circuit digest, inverse rate, public-word count, exact
   transcript length and absence of trailing bytes. Reconstruct the ordered Noir
   inputs from the generated word layout and compare every input, including
   canonical BN254 scalar-field encoding.
2. Receive the outer precommit commitment, then observe the public words. Replay
   the inner verifier's interaction schedule and reconstruct the outer public
   instance `[constants | inout | derived]`. Masked private values are attested
   by the outer proof. The public wiring evaluation is recomputed and checked
   explicitly outside that outer circuit.
3. Verify the outer Spartan masked multiplication check, its sumchecks, and its
   public, precommit, private and mask wiring claims.
4. Run the single combined BaseFold opening over every inner and outer oracle.
   This includes relation batching, masking, the batched degree-two sumcheck,
   transparent-polynomial evaluations, padding factors, and the combined
   degree-one MLE check interleaved with FRI commitments.
5. Derive every FRI query index from the transcript, authenticate each Merkle
   layer and queried leaf, check the additive Gao–Mateer folds between rounds,
   authenticate the full terminal vector, check its repetition condition, and
   compare the terminal FRI value to the final MLE-check value.

The reachable upstream implementations include `verifier/src/zk_config.rs`,
`spartan-verifier/src/wrapper/zk_wrapped_channel.rs`, `spartan-verifier/src/lib.rs`,
`iop/src/basefold/{channel,opening}.rs`, `iop/src/fri/{verify,batch}.rs`,
`iop/src/merkle_channel.rs`, and `iop/src/merkle_tree/scheme.rs`, under upstream
`crates/`. [The upstream verifier documentation](https://docs.binius.xyz/binius_verifier/index.html)
describes the protocol modules; the pinned source, rather than an unversioned
documentation page, determines compatibility here.

## Specialization and trust boundary

`src/solidity/program.rs` runs the pinned generic verifier over symbolic
`FieldOps` and channel implementations. Arithmetic becomes fixed program
instructions, while Fiat-Shamir samples, proof reads and query indices remain
runtime inputs. The compiler receives only a verification key. It does not
receive a proof, run a proof-specific trace, fix challenges, or use private
witness data.

The specialized ZK wrapper preserves the original constant/public/private
distinctions and derived-wire allocation order. It checks that every public
instance slot was populated, then freezes that instance before evaluating
deferred transparent functions. The ordinary pinned outer Spartan and
BaseFold/FRI implementations supply the equations. All assertions and transcript
transitions survive dead-code elimination. Registers are reused only after their
last reference.

To keep the generated data small, the compiler replaces expanded calculations
with implementations of the same polynomials:

- Inner wiring contracts the operation, constraint, operand, inner-shift,
  outer-shift and value-address axes. Generation requires its scalar replay to
  reproduce the pinned native `WiringEvalFn` operation graph exactly.
- Outer wiring stores the exact sparse matrix entries as affine index runs.
  Every run is expanded and compared with the original matrix during generation.
  In characteristic two, duplicate entries cancel by XOR. The public columns
  use a shared decision DAG, evaluated as `a + r*(a+b)` at each node.
- For a run, Solidity computes the full sum of
  `eq(x,row_i) * eq(y,column_i)`, batched with the native A/B/C weights.
  Aligned dyadic intervals are contracted algebraically. Addition of an offset
  uses both carry states; arbitrary remaining strides use the explicit sum.
  Caches store exact products of at most eight equality coordinates.
- Vector operations, bit transposition, equality tensors and Frobenius powers
  retain the original field values and public-wire allocation order.
- The compact FRI kernel must reproduce the native query verifier's complete
  symbolic graph and final transcript offset before generation succeeds.

Instruction operands and circuit tables are delta-coded, then compressed with
raw LZMA1 (fixed `lc=1, lp=0, pb=2`). The generator checks the entire compression
roundtrip. The constructor reverses both encodings once and stores the expanded
instructions. Each `verify` call reads those instructions. Its private
storage has no runtime writer, and callers cannot supply verification programs.
Unused interpreter operations are removed from each generated runtime. None of
these transformations reduces the query count, omits an assertion, or fixes a
Fiat–Shamir challenge in advance.

Creation and runtime bytecode must still fit the destination chain's limits.
Circuit size and structure affect the generated data. The depth-10
`keccak_merkle` example currently expands to 15,947,475 program bytes and
compresses to 441,026 bytes. Its fixed data alone exceeds the 49,152-byte
initcode limit, so the generator now returns an explicit error for that circuit.
It does not emit a deployable verifier for this example. The circuit's existing
native proof is 670,520 bytes; these program and proof sizes are separate.
Streaming the exact inner-wiring comparison allows compilation within about
4.62 GiB of resident memory, but does not solve the deployment-size limitation.

The generator rejects a compressed literal that already exceeds the initcode
limit. This is only a lower-bound check; the complete compiled contract still
requires a size check.
The EVM test script explicitly checks both bytecode size limits and rejects
external-call, creation, storage-write and self-destruct instructions in the
executable runtime. It uses Solc's instruction source map to separate constant
tables from code, then requires an `INVALID` separator and no possible
`JUMPDEST` in those tables.

## Arithmetic and transcript compatibility

- The challenge field is GHASH: `GF(2^128)` with modulus
  `x^128 + x^7 + x^2 + x + 1`. Addition/subtraction are XOR. Yul performs carryless
  multiplication and polynomial reduction, squaring, and inversion by an
  exponentiation addition chain.
- Field elements are 16 little-endian bytes; public words are 8 little-endian
  bytes. Merkle digests remain uninterpreted 32-byte strings.
- The challenger starts with `SHA256(empty)`. Switching from sampling to
  observing prepends the current digest and the consumed sample-buffer index as
  a little-endian u64. Further sample buffers are hash-chain outputs. Bit samples
  always consume four bytes and are masked to the requested width.
- Merkle roots and protocol messages are observed. Query decommitment advice is
  not observed. The compiler fixes all proof-read offsets and the complete proof
  length from the circuit and FRI parameters.
- Leaves use ordinary SHA-256. Inner Merkle nodes use exactly one *unpadded*
  SHA-256 compression block. The initial state is the little-endian u32 words of
  `SHA256("BINIUS SHA-256 COMPRESS")`; output state words are little endian too.
  The zero-left / `00..1f`-right known-answer vector is
  `4731c4e3a3190d19dace68db5752af1b4ecf26305e75e85db86217662bbeff74`.

Merkle hashing processes four independent SHA-256 states in each EVM word.
Each 32-bit state word occupies a 64-bit lane, leaving 32 guard bits. Sigma
outputs are masked before addition, and the largest round sum contains five
32-bit terms, so neither rotations nor carries can reach another lane. All
64 rounds and every query path are retained. Batching only reorders independent
authentication calculations; it does not change the transcript schedule.

## Reproducing the checks

Use Rust from `rust-toolchain.toml`, Foundry with Solidity 0.8.35 available, and
Nargo for the optional Noir example:

```sh
cargo test --locked --workspace
scripts/solidity-e2e.sh
scripts/solidity-e2e.sh arithmetic
LOG_INV_RATE=3 scripts/solidity-e2e.sh arithmetic
```

The default EVM fixture creates actual ZK proofs with a private witness and a
public equality constraint. Native tests cover zero and nonzero public words
and corruptions to both transcript messages and decommitment advice. The
contract test deploys the actual generated verifier and immediately calls
`IVerifier.verify`. It checks changed public inputs and counts, circuit digest,
transcript data and terminal data. The codec test compares every reconstructed
program byte with the native generator's output. Primitive tests compare
SHA-256 outputs, the native Merkle compression vector, and randomized field
operations against a separate bit-serial multiplication. Wiring tests compare
the optimized interval/carry evaluator with explicit scalar sums, including
unaligned offsets, negative strides, Boolean points and randomized cases.
Packed SHA tests compare every active lane with the EVM's independent SHA-256
implementation across padding boundaries and randomized messages. The verifier
itself never calls that precompile. Native path offsets select tampered siblings
in each of the first four lanes and in the final query; all must be rejected.
No verifier mock is involved.

The optional example command compiles/executes Noir, proves with the backend,
generates the verifier from that artifact's key, and runs the same contract test.
`SKIP_NARGO=1` reuses compiled artifacts and witnesses. Generated source and
fixtures remain under ignored `target/` and `solidity/src/` paths.

The current direct generator rejects delegated recursive-proof metadata because
the backend verifies those recursive calls separately from the Binius
transcript. It must not silently omit those checks. The existing explicit SP1
target is a separate proof format and is not used by this implementation.

Independent cryptographic review and further reductions in gas remain
necessary before practical use under ordinary Ethereum gas limits. The tests establish implementation evidence, not a soundness proof or an
audit certification.
