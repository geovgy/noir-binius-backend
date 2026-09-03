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
const wrappedSource = await backend.generateSolidityVerifier({
  verifierTarget: 'evm-sp1',
});

const key = await backend.getVerificationKey();
const sameWrappedSource = await backend.getSolidityVerifier(key, {
  verifierTarget: 'evm-sp1',
});
```

`verifierTarget: 'evm'` accepts the original `NBINZK01` proof and delegates complete transcript
verification to the `IBinius64Verifier` engine or precompile address supplied when the generated
contract is deployed. The engine must have the generated contract's
`BINIUS_VERIFICATION_KEY_HASH` registered; the package does not ship that universal engine.
`verifierTarget: 'evm-sp1'` accepts the `NBINSP11` wrapper created by the repository's
`sp1/prover` binary and delegates succinct verification to an SP1 verifier gateway. Both generated
contracts expose `verify(bytes, bytes32[])` and bind the ordered `ProofData.publicInputs`.

The backend-specific value for Noir's recursive aggregation API is exported as
`BINIUS_ZK_PROOF_TYPE`. Direct Solidity generation rejects circuits with delegated recursive proof
calls; the SP1 target supports them.

The backend and package are experimental and unaudited. Do not use them for production or
security-critical proofs.
