# ACIR support matrix

This matrix is exhaustive for the ACIR schema at Noir revision
`99bb8b5cf33d7669adbdef096b12d80f30b4c0c9` (1.0.0-beta.18). Rust's exhaustive enum matches make
an upstream variant addition a compile error until it is classified and implemented.

## Opcodes

| ACIR opcode | Status | Implementation and evidence |
| --- | --- | --- |
| `AssertZero` | Supported | Exact BN254 quadratic-expression arithmetic over four canonical 64-bit limbs; `arithmetic` fixture and invalid-witness unit test. |
| `BlackBoxFuncCall` | Supported | Every pinned variant is listed below. |
| `MemoryInit` | Supported | Initializes field-valued blocks. |
| `MemoryOp` | Supported | Bounds-constrained dynamic indexing plus expression-selected reads and writes; `memory` fixture. |
| `BrilligCall` | Supported as an ACIR hint | Nargo executes unconstrained bytecode while solving the witness; every value used by the constrained program remains constrained by subsequent ACIR. Covered by `brillig`. |
| `Call` | Supported | Whole-program witness stacks, repeated calls, nested calls, and dynamic predicates. Inactive frames are zero-filled and constraints are gated. Covered by `folded` and both branches of `folded_predicate`. Static recursive call cycles have no finite circuit expansion and are rejected. |

## Black-box functions

| Black box | Status | Notes / fixture |
| --- | --- | --- |
| `AES128Encrypt` | Supported | ACIR AES-128-CBC including block padding; `aes128`. |
| `AND` | Supported | Width-constrained through the 254-bit ACIR field width; `bitwise`. |
| `XOR` | Supported | Width-constrained through the 254-bit ACIR field width; `bitwise`. |
| `RANGE` | Supported | Width-constrained through 254 bits; emitted throughout typed fixtures. |
| `Blake2s` | Supported | Arbitrary artifact-fixed byte length; `hashes`. |
| `Blake3` | Supported | Arbitrary artifact-fixed byte length; `hashes`. |
| `EcdsaSecp256k1` | Supported | Big-endian ACIR packing, canonical scalar checks, digest/r reduction, low-S rule, and native Binius secp256k1 gadget; `ecdsa_k1`. |
| `EcdsaSecp256r1` | Supported | Constrained projective P-256 verification with canonical and low-S checks; `ecdsa_r1`. |
| `MultiScalarMul` | Supported | Grumpkin points and 256-bit scalars with scalar-modulus checks; `embedded_curve`. |
| `EmbeddedCurveAdd` | Supported | Grumpkin affine input/output semantics and infinity flag; `embedded_curve`. |
| `Keccakf1600` | Supported | Exact 25×64-bit permutation; `hashes`. |
| `RecursiveAggregation` | Supported for Binius ZK proof type `0x42494e5a` | Sound final-verifier delegation. `recursive-inputs` serializes a Binius ZK verification key and proof into canonical 31-byte field chunks. All fields and the activity flag are public-bound by the outer proof; final verification checks the key hash, public inputs, nested proof, and any nested recursive calls. Active end-to-end fixture: `recursive_aggregation`. Non-succinct and payload-revealing; other backend proof types are rejected. |
| `Poseidon2Permutation` | Supported | BN254 width 4, 8 full + 56 partial rounds with Noir beta.18 constants; `poseidon2`. |
| `Sha256Compression` | Supported | 16 message words and 8 chaining words; `hashes`. |

## Representation and predicates

- Each ACIR `Field` is four little-endian Binius words and is constrained below the BN254 scalar
  modulus.
- Public parameters and return values use deterministic witness order. Recursive payload fields
  add backend-private public words to bind final-verifier work.
- ACIR predicates are constrained to Boolean field values. Binius comparisons use MSB-Boolean
  wires; conversions to and from ACIR `0/1` values are explicit.
- Disabled calls, black boxes, and recursive checks preserve ACIR predicate semantics.

## Version boundary

The matrix applies to the pinned revisions in `Cargo.toml`. It is not a claim about future Noir or
Binius enum variants, proof encodings, constants, or gadget semantics. Updating either revision
requires rerunning the inventory and exhaustive proof suite.
