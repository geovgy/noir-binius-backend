import { afterEach, describe, expect, test } from 'bun:test';
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { BiniusBackend, BiniusBackendError, withVerifierProgram, type VerifierDeployment } from '../src/index.js';

const deploymentFixture: VerifierDeployment = {
  contractName: 'BiniusVerifier',
  abi: [
    { type: 'constructor', inputs: [], stateMutability: 'nonpayable' },
    { type: 'function', name: 'verify', stateMutability: 'view',
      inputs: [{ name: 'proof', type: 'bytes', internalType: 'bytes' },
        { name: 'publicInputs', type: 'bytes32[]', internalType: 'bytes32[]' }],
      outputs: [{ name: '', type: 'bool', internalType: 'bool' }] },
  ],
  bytecode: '0x00', deployedBytecode: '0x00',
  soliditySource: 'contract BiniusVerifier is IVerifier {}', yulSource: 'object "BiniusVerifier" {}',
  compilerSettings: { version: '0.8.35',
    solidity: { optimizer: { enabled: true, runs: 200 }, viaIR: true,
      evmVersion: 'osaka', metadata: { bytecodeHash: 'none' } },
    yul: { optimizer: { enabled: true, runs: 200 }, evmVersion: 'osaka' } },
  initcodeBytes: 1, runtimeBytes: 1, solidityInitcodeBytes: 1,
  construction: {
    kind: 'affine-matrix-v1', verificationProgram: '0x00', programKeccak256: '0x00',
    precursorLength: 12, matrixLengthOffset: 4, matrixInputOffset: 6,
    matrixOutputOffset: 6, affineLength: 1, matrixLength: 1, escapedMatrixLength: false,
    publicExpansion: {
      kind: 'grouped-relative-u16-v1', sourceLength: 10, instructionOffset: 0, fixedLength: 7,
    },
    privateGrouping: {
      kind: 'depth-code-product-terminal-u16-v1', originalLength: 10, nodes: 1, groups: 1, maxDepth: 1,
    },
    precommitGrouping: {
      kind: 'code-grouped-u16-v1', instructionOffset: 0, originalLength: 10,
      nodes: 1, groups: 1, maxDepth: 1,
    },
  },
};

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) =>
      rm(directory, { force: true, recursive: true }),
    ),
  );
});

async function fakeBackend(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), 'noir-binius-solidity-test-'));
  temporaryDirectories.push(directory);
  const binary = join(directory, 'noir-binius');
  await writeFile(
    binary,
    `#!/usr/bin/env node
const fs = require('node:fs');
const args = process.argv.slice(2);
const value = (name) => args[args.indexOf(name) + 1];
if (args[0] === 'write_vk') {
  if (!value('--bytecode_path') || !value('--output_path') || !value('--log-inv-rate')) {
    process.stderr.write('write_vk used incompatible flags: ' + JSON.stringify(args));
    process.exit(3);
  }
  fs.writeFileSync(value('--output_path'), Buffer.from('verification-key'));
} else if (args[0] === 'write_solidity_verifier') {
  if (!value('--vk_path') || !value('--output_path') || !value('--verifier_target')) {
    process.stderr.write('write_solidity_verifier used incompatible flags: ' + JSON.stringify(args));
    process.exit(4);
  }
  fs.writeFileSync(value('--output_path'), args.includes('--solidity_compiler')
    ? JSON.stringify([value('--verifier_target'), value('--solidity_compiler')])
    : value('--verifier_target'));
} else if (args[0] === 'write_verifier_deployment') {
  if (!['--vk_path', '--output_path', '--solidity_compiler'].every(name => args.includes(name))) {
    process.stderr.write('missing deployment arguments'); process.exit(5);
  }
  const artifact = ${JSON.stringify(deploymentFixture)};
  artifact.yulSource = value('--solidity_compiler');
  if (artifact.yulSource === 'inconsistent') artifact.initcodeBytes = 2;
  if (artifact.yulSource === 'wrong-settings') artifact.compilerSettings.yul.optimizer.runs = 1;
  if (artifact.yulSource === 'upload-abi') artifact.abi[1].name = 'loadVerificationProgramChunk';
  if (artifact.yulSource === 'wrong-size') delete artifact.solidityInitcodeBytes;
  fs.writeFileSync(value('--output_path'), JSON.stringify(artifact));
} else {
  process.stderr.write('unexpected command: ' + JSON.stringify(args));
  process.exit(2);
}
`,
  );
  await chmod(binary, 0o755);
  return binary;
}

describe('Solidity verifier generation', () => {
  test('frames native and hinted zk proofs only for an advertised program input format', () => {
    const artifact = structuredClone(deploymentFixture);
    const digest = `0x${'11'.repeat(32)}` as const;
    artifact.construction!.programKeccak256 = digest;
    artifact.construction!.programInput = {
      kind: 'keccak-calldata-v1', magic: '0x4e42494e4b303031',
      programLength: 1, programKeccak256: digest,
    };
    for (const prefix of ['NBINZK01', 'NBINH001NBINZK01']) {
      const proof = new TextEncoder().encode(prefix + 'example');
      const before = proof.slice();
      const framed = withVerifierProgram(proof, artifact);
      expect(framed).toEqual(Uint8Array.from([...Buffer.from('NBINK001'), 0, ...proof]));
      expect(proof).toEqual(before);
      expect(() => withVerifierProgram(framed, artifact)).toThrow('NBINZK01');
    }
    expect(() => withVerifierProgram(Buffer.from('NBINSP11'), artifact)).toThrow('NBINZK01');
    expect(() => withVerifierProgram(Buffer.from('NBINZK01'), deploymentFixture)).toThrow('does not support');
    artifact.construction!.storageCompression = {
      kind: 'literal-copy-v1', minimumMatch: 8, storedProgram: '0x010203',
      storedProgramKeccak256: digest, packingHeaders: '0x',
    };
    artifact.construction!.programInput!.programLength = 3;
    expect(withVerifierProgram(Buffer.from('NBINZK01'), artifact).slice(8, 11)).toEqual(new Uint8Array([1, 2, 3]));
    artifact.construction!.programInput!.programLength = 2;
    expect(() => withVerifierProgram(Buffer.from('NBINZK01'), artifact)).toThrow('inconsistent');
  });
  test('defaults to direct Binius64 and forwards the SP1 target when selected', async () => {
    const binaryPath = await fakeBackend();
    const backend = new BiniusBackend('non-empty-acir', { binaryPath });

    expect(await backend.generateSolidityVerifier()).toBe('evm');
    expect(
      await backend.generateSolidityVerifier({
        verifierTarget: 'evm-sp1',
        logInvRate: 2,
      }),
    ).toBe('evm-sp1');
  });

  test('rejects an unknown verifier target before invoking the backend', async () => {
    const binaryPath = await fakeBackend();
    const backend = new BiniusBackend('non-empty-acir', { binaryPath });

    await expect(
      backend.generateSolidityVerifier({
        verifierTarget: 'unknown' as 'evm',
      }),
    ).rejects.toBeInstanceOf(BiniusBackendError);
  });

  test('passes the optional compiler as one executable argument', async () => {
    const binaryPath = await fakeBackend();
    const backend = new BiniusBackend('non-empty-acir', { binaryPath });
    const solidityCompiler = '/local tools/solc 0.8.35';
    expect(
      await backend.generateSolidityVerifier({ solidityCompiler }),
    ).toBe(JSON.stringify(['evm', solidityCompiler]));
    await expect(
      backend.getSolidityVerifier(new Uint8Array([1]), {
        solidityCompiler,
        verifierTarget: 'evm-sp1',
      }),
    ).rejects.toBeInstanceOf(BiniusBackendError);
    await expect(
      backend.getSolidityVerifier(new Uint8Array([1]), { solidityCompiler: '' }),
    ).rejects.toBeInstanceOf(BiniusBackendError);
  });

  test('rejects an empty verification key before invoking the backend', async () => {
    const binaryPath = await fakeBackend();
    const backend = new BiniusBackend('non-empty-acir', { binaryPath });

    await expect(
      backend.getSolidityVerifier(new Uint8Array()),
    ).rejects.toBeInstanceOf(BiniusBackendError);
  });

  test('returns an explicit deployment artifact without changing Solidity source methods', async () => {
    const backend = new BiniusBackend('non-empty-acir', { binaryPath: await fakeBackend() });
    const solidityCompiler = '/local tools/solc 0.8.35';
    const artifact = await backend.generateVerifierDeployment({ solidityCompiler, logInvRate: 3 });
    expect(artifact).toEqual({ ...deploymentFixture, yulSource: solidityCompiler });
    expect(await backend.getVerifierDeployment(new Uint8Array([1]), { solidityCompiler })).toEqual(artifact);
    expect(await backend.generateSolidityVerifier()).toBe('evm');
  });

  test('rejects invalid deployment inputs and inconsistent backend artifacts', async () => {
    const backend = new BiniusBackend('non-empty-acir', { binaryPath: await fakeBackend() });
    await expect(backend.generateVerifierDeployment({ solidityCompiler: '' })).rejects.toThrow('solidityCompiler');
    await expect(backend.getVerifierDeployment(new Uint8Array(), { solidityCompiler: 'solc' })).rejects.toThrow('verificationKey');
    await expect(backend.getVerifierDeployment(new Uint8Array([1]), { solidityCompiler: 'inconsistent' })).rejects.toThrow('inconsistent');
    for (const solidityCompiler of ['wrong-settings', 'upload-abi', 'wrong-size']) {
      await expect(backend.getVerifierDeployment(new Uint8Array([1]), { solidityCompiler })).rejects.toThrow('inconsistent');
    }
  });
});
