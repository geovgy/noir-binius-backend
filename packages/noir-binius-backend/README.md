# @noir-binius/backend

`BiniusBackend` is a Node.js proof backend for the pinned Noir 1.0.0-beta.18 toolchain. Its core API
matches `@aztec/bb.js`'s `UltraHonkBackend`: `generateProof` accepts the compressed witness returned
by `Noir.execute`, and `generateProof`/`verifyProof` exchange `{ proof, publicInputs }` objects.

```ts
import { Noir, type CompiledCircuit } from '@noir-lang/noir_js';
import { BiniusBackend } from '@noir-binius/backend';
import circuit from '../target/my_circuit.json' with { type: 'json' };

const compiledCircuit = circuit as CompiledCircuit;
const noir = new Noir(compiledCircuit);
const backend = new BiniusBackend(compiledCircuit.bytecode);

const { witness } = await noir.execute({ x: 3, expected: 14 });
const proofData = await backend.generateProof(witness);
const verified = await backend.verifyProof(proofData);

console.log(proofData.publicInputs, verified);
await backend.destroy();
```

## Native backend

This package invokes the native `noir-binius` executable and is therefore Node.js-only. Build the
binary from the repository before using the local package:

```console
cargo build --release
cd packages/noir-binius-backend
bun install
bun run build
```

The package finds this repository's `target/release/noir-binius` automatically. For an installed
or relocated package, put `noir-binius` on `PATH`, set `NOIR_BINIUS_BINARY`, or pass
`{ binaryPath: '/absolute/path/to/noir-binius' }` to the constructor.

`getVerificationKey`, Solidity verifier generation, and Binius recursive proof artifacts are
supported. The direct Binius64 target is the default; select the succinct SP1 wrapper explicitly:

```ts
const directSource = await backend.generateSolidityVerifier();
// Optional: faster fixed-matrix evaluation, with higher deployment gas.
const factoredSource = await backend.generateSolidityVerifier({
  solidityCompiler: '/path/to/solc-0.8.35',
});
const wrappedSource = await backend.generateSolidityVerifier({
  verifierTarget: 'evm-sp1',
});

const key = await backend.getVerificationKey();
const sameWrappedSource = await backend.getSolidityVerifier(key, {
  verifierTarget: 'evm-sp1',
});
```

`verifierTarget: 'evm'` accepts the original `NBINZK01` proof. The generated `BiniusVerifier`
inherits `IVerifier` and performs the complete Binius64 ZK verification in Solidity/Yul, including
field arithmetic, the SHA-256 transcript, Spartan, BaseFold/FRI and Merkle openings. It takes no
constructor arguments and makes no external calls. Its constructor decodes and stores the complete
circuit program, so `verify` works immediately after deployment. There is no
program-upload API. Deployment and verification require large gas budgets; see the repository
[deployment instructions and measured costs](../../README.md#solidity-verifiers).
The optional `solidityCompiler` path selects factored wiring and compressed
runtime deployment for the direct target. Generation compiles the complete
verification implementation and checks that the constructor returns those exact
runtime bytes. Compile the emitted source with solc 0.8.35, optimizer 200 runs,
`viaIR`, Osaka, and `metadata.bytecodeHash: "none"`. This option changes the fixed
program representation and deployment cost; it accepts the same proof bytes.

`generateVerifierDeployment` returns an explicit artifact with compact creation
code; `getVerifierDeployment(key, options)` does the same from an existing key:

```ts
const deployment = await backend.generateVerifierDeployment({
  solidityCompiler: '/path/to/solc-0.8.35',
  logInvRate: 3,
});
// Pass deployment.abi and deployment.bytecode to your deployment library,
// with no constructor arguments. The contract exposes verify immediately.
```

Use the same `logInvRate` when generating the proof and the verification key.

The artifact includes `soliditySource`, `yulSource`, `deployedBytecode`, compiler
settings and code sizes. The Yul constructor copies the same compressed circuit
data from a code section and, where beneficial, derives the complete fixed matrix
before storing it. It can also apply a fixed literal-copy plan to reduce storage
reads during verification, and expand the public graph's child references during
construction to avoid decoding them on each call. Consecutive nodes share a
coordinate header while retaining every original child reference. The optional
`construction` metadata records the logical program, storage encoding and hashes
for review. Deployment takes no metadata arguments.
When `runtimeCompilation.kind` is `yul-sha-rounds-v1` through
`yul-sha-rounds-v11`, independently compile the
complete `yulSource` as `BiniusVerifier.yul` to reproduce creation and runtime
bytes. This mode schedules the same 64 SHA rounds directly on the EVM stack.
Version 2 also schedules the unchanged message-expansion body and binds its exact
opcodes with `wordBlockSha256`. Version 3 changes only the proved placement of
round operands on the stack and pins that block's separate hash. Earlier versions
remain supported.
Version 4 advances an absolute cursor through the same 64 constant/schedule
address pairs; its `roundBlockSha256` pins that block separately.
Version 5 keeps the cursor block and binds a new word block that removes four
stack swaps from the same message-address calculations.
Version 6 binds four rounds per loop and `scalarCore: "packed"`. It shares the
packed core with scalar calls, clearing their pending padding-cache request.
The complete scalar and packed functions must match the checked equations under
either compiler name ordering. Canonical lanes and masked feed-forward preserve
the scalar low-lane digest; all 64 SHA rounds still execute.
Version 7 retains intermediate stack layouts across four rounds and advances
their shared cursor by 128, preserving every constant and schedule address.
Version 8 additionally binds the complete message-expansion loop: a Boolean
cache hit skips it, and a miss computes all 48 original expansion words.
Its `wordBlockSha256` pins the loop and unchanged word equation together.
Version 9 pairs a smaller, equivalent round block with two expansion words per
loop. It retains all 48 message-expansion steps and all 64 rounds, binding both
opcode blocks by their distinct hashes. The complete callee/source binding and
`scalarCore: "packed"` requirement remain.
Version 10 retains masks and a base cursor across four expansion words. Its
separate word-block hash binds all four original equations and their rebased
addresses, twelve loop iterations, the cache skip and complete stack cleanup.
The complete Solidity body remains the semantic reference, whose ordinary runtime
hash is recorded separately. Without this optional field the runtime is the
ordinary Solidity compiler output. `solidityInitcodeBytes` records the ordinary
Solidity creation size in both modes.
Use its `bytecode`: ordinary compilation of `soliditySource` can produce oversized
creation code. The deployed runtime is the complete Solidity `IVerifier`
implementation. It accepts the original proof and recomputes all optional SHA
hints; it needs no other verifier or post-deployment upload. The existing
`generateSolidityVerifier` and `getSolidityVerifier` methods still return Solidity
source. See [deployment validation and gas](../../docs/direct-solidity-verification.md#compact-yul-deployment).
Version 11 retains all six round masks and the two preceding schedule words.
Its word loop still performs all 48 ordered stores, using a checked stack
invariant in place of repeated W[i-2] reads. The new round/word hashes and
`scalarCore: "packed"` are required together; older bindings remain distinct.

When `deployment.construction?.programInput` is present, the same contract also
accepts public circuit data alongside the proof to avoid cold storage reads:

```ts
import { withVerifierProgram } from '@noir-binius/backend';

const proofArgument = deployment.construction?.programInput
  ? withVerifierProgram(proofData.proof, deployment)
  : proofData.proof;
// Call verify(proofArgument, proofData.publicInputs) on the deployed contract.
```

This adds an `NBINK001` frame around the public program and the original native
zk proof (or a proof with checked SHA hints). The constructor fixes the program's
Keccak digest; `verify` authenticates every supplied byte before executing the
same Binius verifier. The helper only frames input and does not verify a proof.
Raw proofs remain accepted. The generator advertises this option only when the
complete compiled artifact fits both EVM code limits.

`verifierTarget: 'evm-sp1'` accepts the `NBINSP11` wrapper created by the repository's
`sp1/prover` binary and delegates succinct verification to an SP1 verifier gateway. Both generated
contracts expose `verify(bytes, bytes32[])` and bind the ordered `ProofData.publicInputs`.

The backend-specific value for Noir's recursive aggregation API is exported as
`BINIUS_ZK_PROOF_TYPE`. Direct Solidity generation rejects circuits with delegated recursive proof
calls; the SP1 target supports them.

The backend and package are experimental and unaudited. Do not use them for production or
security-critical proofs.
