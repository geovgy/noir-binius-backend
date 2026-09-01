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

`getVerificationKey` and Binius recursive proof artifacts are supported. Solidity verifier
generation is not available because this backend does not currently have a Solidity verifier. The
backend-specific value for Noir's recursive aggregation API is exported as
`BINIUS_ZK_PROOF_TYPE`.

The backend and package are experimental and unaudited. Do not use them for production or
security-critical proofs.
