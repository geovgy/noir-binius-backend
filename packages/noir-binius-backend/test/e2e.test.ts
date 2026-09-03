import { describe, expect, test } from 'bun:test';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';

import { Noir, type CompiledCircuit } from '@noir-lang/noir_js';

import { BiniusBackend } from '../src/index.js';

const repositoryRoot = resolve(import.meta.dir, '..', '..', '..');
const artifactPath = resolve(
  repositoryRoot,
  'examples',
  'arithmetic',
  'target',
  'arithmetic.json',
);
const binaryPath =
  process.env.NOIR_BINIUS_BINARY ??
  resolve(repositoryRoot, 'target', 'release', 'noir-binius');
const execFileAsync = promisify(execFile);

describe('BiniusBackend', () => {
  test('proves and verifies a noir_js witness with bb.js-shaped proof data', async () => {
    const circuit = JSON.parse(await readFile(artifactPath, 'utf8')) as CompiledCircuit;
    const noir = new Noir(circuit);
    const backend = new BiniusBackend(circuit.bytecode, { binaryPath });
    const { witness } = await noir.execute({ x: 3, expected: 14 });

    const proofData = await backend.generateProof(witness);
    expect(proofData.proof).toBeInstanceOf(Uint8Array);
    expect(proofData.proof.length).toBeGreaterThan(0);
    expect(proofData.publicInputs).toEqual([
      '0x000000000000000000000000000000000000000000000000000000000000000e',
    ]);
    expect(await backend.verifyProof(proofData)).toBe(true);

    const verificationKey = await backend.getVerificationKey();
    expect(verificationKey.length).toBeGreaterThan(0);
    const directVerifier = await backend.getSolidityVerifier(verificationKey);
    expect(directVerifier).toContain('interface IBinius64Verifier');
    expect(directVerifier).toContain('NBINZK01');
    const wrappedVerifier = await backend.getSolidityVerifier(verificationKey, {
      verifierTarget: 'evm-sp1',
    });
    expect(wrappedVerifier).toContain('interface ISP1Verifier');
    expect(wrappedVerifier).toContain('NBINSP11');
    const recursiveArtifacts = await backend.generateRecursiveProofArtifacts(
      proofData.proof,
      proofData.publicInputs.length,
    );
    expect(recursiveArtifacts.proofAsFields.length).toBeGreaterThan(0);
    expect(recursiveArtifacts.vkAsFields.length).toBeGreaterThan(0);
    expect(recursiveArtifacts.vkHash).toMatch(/^0x[0-9a-f]+$/);

    const cliDirectory = await mkdtemp(join(tmpdir(), 'noir-binius-js-test-'));
    try {
      const cliProofPath = join(cliDirectory, 'proof.binius');
      await writeFile(cliProofPath, proofData.proof);
      const { stdout } = await execFileAsync(binaryPath, [
        'verify',
        '--bytecode',
        artifactPath,
        '--proof',
        cliProofPath,
      ]);
      expect(stdout).toContain('Proof verified successfully');
    } finally {
      await rm(cliDirectory, { force: true, recursive: true });
    }

    expect(
      await backend.verifyProof({ ...proofData, publicInputs: ['0x0f'] }),
    ).toBe(false);

    const tamperedProof = proofData.proof.slice();
    const lastByte = tamperedProof.length - 1;
    tamperedProof[lastByte] = tamperedProof[lastByte]! ^ 1;
    expect(
      await backend.verifyProof({ ...proofData, proof: tamperedProof }),
    ).toBe(false);

    await backend.destroy();
  });
});
