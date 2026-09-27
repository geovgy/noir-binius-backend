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
  if (artifact.yulSource.startsWith('runtime-')) {
    artifact.runtimeCompilation = {
      kind: 'yul-sha-rounds-v1', runtimeSource: 'BiniusVerifier.yul',
      solidityReferenceRuntimeSha256: '0x' + 'ab'.repeat(32),
      roundBlockSha256: '0x25aaa3f04cee1446d5901296eecd247b0dbd9d6d2fca036533802f7485d09fbd',
    };
    if (artifact.yulSource === 'runtime-null') artifact.runtimeCompilation = null;
    if (artifact.yulSource === 'runtime-kind') artifact.runtimeCompilation.kind = 'trust-me';
    if (artifact.yulSource === 'runtime-source') artifact.runtimeCompilation.runtimeSource = 'BiniusVerifier.sol';
    if (artifact.yulSource === 'runtime-reference') artifact.runtimeCompilation.solidityReferenceRuntimeSha256 = '0xab';
    if (artifact.yulSource === 'runtime-block') artifact.runtimeCompilation.roundBlockSha256 = '0x' + '00'.repeat(32);
    if (artifact.yulSource.startsWith('runtime-words')) {
      artifact.runtimeCompilation.kind = 'yul-sha-rounds-v2';
      artifact.runtimeCompilation.wordBlockSha256 = '0x4c6cc06c6965224f123533b5ad7b855828b107042ebde9993c31516bd1e11bda';
      if (artifact.yulSource === 'runtime-words-missing') delete artifact.runtimeCompilation.wordBlockSha256;
      if (artifact.yulSource === 'runtime-words-hash') artifact.runtimeCompilation.wordBlockSha256 = '0x' + '00'.repeat(32);
      if (artifact.yulSource === 'runtime-words-old') artifact.runtimeCompilation.kind = 'yul-sha-rounds-v1';
    }
    if (artifact.yulSource.startsWith('runtime-placement')) {
      artifact.runtimeCompilation.kind = 'yul-sha-rounds-v3';
      artifact.runtimeCompilation.roundBlockSha256 = '0xfcb13ca730f9b4f8a65662a14d75ee0731a31d7251addfe3931873f2c67e3717';
      artifact.runtimeCompilation.wordBlockSha256 = '0x4c6cc06c6965224f123533b5ad7b855828b107042ebde9993c31516bd1e11bda';
      if (artifact.yulSource === 'runtime-placement-missing') delete artifact.runtimeCompilation.wordBlockSha256;
      if (artifact.yulSource === 'runtime-placement-hash') artifact.runtimeCompilation.roundBlockSha256 = '0x25aaa3f04cee1446d5901296eecd247b0dbd9d6d2fca036533802f7485d09fbd';
      if (artifact.yulSource === 'runtime-placement-old') artifact.runtimeCompilation.kind = 'yul-sha-rounds-v2';
    }
    if (artifact.yulSource.startsWith('runtime-cursor')) {
      artifact.runtimeCompilation.kind = 'yul-sha-rounds-v4';
      artifact.runtimeCompilation.roundBlockSha256 = '0xb95b04dd62c7769294246ea85f6ae6e5fce78e954ec8e0c0b87b7b88d1bde25f';
      artifact.runtimeCompilation.wordBlockSha256 = '0x4c6cc06c6965224f123533b5ad7b855828b107042ebde9993c31516bd1e11bda';
      if (artifact.yulSource === 'runtime-cursor-missing') delete artifact.runtimeCompilation.wordBlockSha256;
      if (artifact.yulSource === 'runtime-cursor-hash') artifact.runtimeCompilation.roundBlockSha256 = '0xfcb13ca730f9b4f8a65662a14d75ee0731a31d7251addfe3931873f2c67e3717';
      if (artifact.yulSource === 'runtime-cursor-old') artifact.runtimeCompilation.kind = 'yul-sha-rounds-v3';
    }
    if (artifact.yulSource.startsWith('runtime-order')) {
      artifact.runtimeCompilation.kind = 'yul-sha-rounds-v5';
      artifact.runtimeCompilation.roundBlockSha256 = '0xb95b04dd62c7769294246ea85f6ae6e5fce78e954ec8e0c0b87b7b88d1bde25f';
      artifact.runtimeCompilation.wordBlockSha256 = '0x4e56b829a8c054a5388a18673f804cfc74f71ce617feb5b788fcb78747b02776';
      if (artifact.yulSource === 'runtime-order-missing') delete artifact.runtimeCompilation.wordBlockSha256;
      if (artifact.yulSource === 'runtime-order-hash') artifact.runtimeCompilation.wordBlockSha256 = '0x4c6cc06c6965224f123533b5ad7b855828b107042ebde9993c31516bd1e11bda';
      if (artifact.yulSource === 'runtime-order-round') artifact.runtimeCompilation.roundBlockSha256 = '0xfcb13ca730f9b4f8a65662a14d75ee0731a31d7251addfe3931873f2c67e3717';
      if (artifact.yulSource === 'runtime-order-old') artifact.runtimeCompilation.kind = 'yul-sha-rounds-v4';
    }
    if (artifact.yulSource.startsWith('runtime-four')) {
      artifact.runtimeCompilation.kind = 'yul-sha-rounds-v6';
      artifact.runtimeCompilation.roundBlockSha256 = '0x89d86e1aa7d12b47bc53ddd4391018dc61f0b5560e6a5e10aa4ebdc2869f846a';
      artifact.runtimeCompilation.wordBlockSha256 = '0x4e56b829a8c054a5388a18673f804cfc74f71ce617feb5b788fcb78747b02776';
      artifact.runtimeCompilation.scalarCore = 'packed';
      if (artifact.yulSource === 'runtime-four-missing') delete artifact.runtimeCompilation.wordBlockSha256;
      if (artifact.yulSource === 'runtime-four-hash') artifact.runtimeCompilation.wordBlockSha256 = '0x4c6cc06c6965224f123533b5ad7b855828b107042ebde9993c31516bd1e11bda';
      if (artifact.yulSource === 'runtime-four-round') artifact.runtimeCompilation.roundBlockSha256 = '0xb95b04dd62c7769294246ea85f6ae6e5fce78e954ec8e0c0b87b7b88d1bde25f';
      if (artifact.yulSource === 'runtime-four-scalar-missing') delete artifact.runtimeCompilation.scalarCore;
      if (artifact.yulSource === 'runtime-four-scalar-wrong') artifact.runtimeCompilation.scalarCore = 'scalar';
      if (artifact.yulSource === 'runtime-four-old') {
        artifact.runtimeCompilation.kind = 'yul-sha-rounds-v5';
        artifact.runtimeCompilation.roundBlockSha256 = '0xb95b04dd62c7769294246ea85f6ae6e5fce78e954ec8e0c0b87b7b88d1bde25f';
      }
    }
    if (artifact.yulSource.startsWith('runtime-group')) {
      artifact.runtimeCompilation.kind = 'yul-sha-rounds-v7';
      artifact.runtimeCompilation.roundBlockSha256 = '0xc6b97f9bf6025e0ed5cdb7ecbf46f5b2099dba4f09d28c601edcef6a5d38e741';
      artifact.runtimeCompilation.wordBlockSha256 = '0x4e56b829a8c054a5388a18673f804cfc74f71ce617feb5b788fcb78747b02776';
      artifact.runtimeCompilation.scalarCore = 'packed';
      if (artifact.yulSource === 'runtime-group-missing') delete artifact.runtimeCompilation.wordBlockSha256;
      if (artifact.yulSource === 'runtime-group-hash') artifact.runtimeCompilation.wordBlockSha256 = '0x4c6cc06c6965224f123533b5ad7b855828b107042ebde9993c31516bd1e11bda';
      if (artifact.yulSource === 'runtime-group-round') artifact.runtimeCompilation.roundBlockSha256 = '0x89d86e1aa7d12b47bc53ddd4391018dc61f0b5560e6a5e10aa4ebdc2869f846a';
      if (artifact.yulSource === 'runtime-group-scalar-missing') delete artifact.runtimeCompilation.scalarCore;
      if (artifact.yulSource === 'runtime-group-scalar-wrong') artifact.runtimeCompilation.scalarCore = 'scalar';
      if (artifact.yulSource === 'runtime-group-old') artifact.runtimeCompilation.kind = 'yul-sha-rounds-v6';
    }
    if (artifact.yulSource.startsWith('runtime-loop')) {
      artifact.runtimeCompilation.kind = 'yul-sha-rounds-v8';
      artifact.runtimeCompilation.roundBlockSha256 = '0xc6b97f9bf6025e0ed5cdb7ecbf46f5b2099dba4f09d28c601edcef6a5d38e741';
      artifact.runtimeCompilation.wordBlockSha256 = '0x6234a2eab2cd341248e9c642e3d588a1f1cfcbfefe8b4af95802a28c0db80a30';
      artifact.runtimeCompilation.scalarCore = 'packed';
      if (artifact.yulSource === 'runtime-loop-missing') delete artifact.runtimeCompilation.wordBlockSha256;
      if (artifact.yulSource === 'runtime-loop-hash') artifact.runtimeCompilation.wordBlockSha256 = '0x4e56b829a8c054a5388a18673f804cfc74f71ce617feb5b788fcb78747b02776';
      if (artifact.yulSource === 'runtime-loop-round') artifact.runtimeCompilation.roundBlockSha256 = '0x89d86e1aa7d12b47bc53ddd4391018dc61f0b5560e6a5e10aa4ebdc2869f846a';
      if (artifact.yulSource === 'runtime-loop-scalar-missing') delete artifact.runtimeCompilation.scalarCore;
      if (artifact.yulSource === 'runtime-loop-scalar-wrong') artifact.runtimeCompilation.scalarCore = 'scalar';
      if (artifact.yulSource === 'runtime-loop-old') artifact.runtimeCompilation.kind = 'yul-sha-rounds-v7';
    }
    if (artifact.yulSource.startsWith('runtime-double')) {
      artifact.runtimeCompilation.kind = 'yul-sha-rounds-v9';
      artifact.runtimeCompilation.roundBlockSha256 = '0x8747454f3932cbbc93ac3ddaa05fc4d4ffcb30142ef0f88b8d51c1e4bf1ac55b';
      artifact.runtimeCompilation.wordBlockSha256 = '0x4dd2efd40dc163b484fc7b6526cdba1f1d82bece8845961aa0067939bf0930e9';
      artifact.runtimeCompilation.scalarCore = 'packed';
      if (artifact.yulSource === 'runtime-double-missing') delete artifact.runtimeCompilation.wordBlockSha256;
      if (artifact.yulSource === 'runtime-double-hash') artifact.runtimeCompilation.wordBlockSha256 = '0x6234a2eab2cd341248e9c642e3d588a1f1cfcbfefe8b4af95802a28c0db80a30';
      if (artifact.yulSource === 'runtime-double-round') artifact.runtimeCompilation.roundBlockSha256 = '0xc6b97f9bf6025e0ed5cdb7ecbf46f5b2099dba4f09d28c601edcef6a5d38e741';
      if (artifact.yulSource === 'runtime-double-scalar-missing') delete artifact.runtimeCompilation.scalarCore;
      if (artifact.yulSource === 'runtime-double-scalar-wrong') artifact.runtimeCompilation.scalarCore = 'scalar';
      if (artifact.yulSource === 'runtime-double-old') artifact.runtimeCompilation.kind = 'yul-sha-rounds-v8';
    }
    if (artifact.yulSource.startsWith('runtime-wgroup')) {
      artifact.runtimeCompilation.kind = 'yul-sha-rounds-v10';
      artifact.runtimeCompilation.roundBlockSha256 = '0x8747454f3932cbbc93ac3ddaa05fc4d4ffcb30142ef0f88b8d51c1e4bf1ac55b';
      artifact.runtimeCompilation.wordBlockSha256 = '0x12fbd5916a21d830f2707a3ab5a7849c4d1f90f1c1b3e417cf7c06dcd05cbb52';
      artifact.runtimeCompilation.scalarCore = 'packed';
      if (artifact.yulSource === 'runtime-wgroup-missing') delete artifact.runtimeCompilation.wordBlockSha256;
      if (artifact.yulSource === 'runtime-wgroup-hash') artifact.runtimeCompilation.wordBlockSha256 = '0x4dd2efd40dc163b484fc7b6526cdba1f1d82bece8845961aa0067939bf0930e9';
      if (artifact.yulSource === 'runtime-wgroup-round') artifact.runtimeCompilation.roundBlockSha256 = '0xc6b97f9bf6025e0ed5cdb7ecbf46f5b2099dba4f09d28c601edcef6a5d38e741';
      if (artifact.yulSource === 'runtime-wgroup-scalar-missing') delete artifact.runtimeCompilation.scalarCore;
      if (artifact.yulSource === 'runtime-wgroup-scalar-wrong') artifact.runtimeCompilation.scalarCore = 'scalar';
      if (artifact.yulSource === 'runtime-wgroup-old') artifact.runtimeCompilation.kind = 'yul-sha-rounds-v9';
    }
    if (artifact.yulSource.startsWith('runtime-pair')) {
      artifact.runtimeCompilation.kind = 'yul-sha-rounds-v11';
      artifact.runtimeCompilation.roundBlockSha256 = '0xc42783843e8233d2402c8f174feea2ffd8ae2ade1f503a60aa888ee2bc67c4ad';
      artifact.runtimeCompilation.wordBlockSha256 = '0x997d259dd8aece2235a17177f6422949b27ec974286b968ba83aa0a25ea96071';
      artifact.runtimeCompilation.scalarCore = 'packed';
      if (artifact.yulSource === 'runtime-pair-missing') delete artifact.runtimeCompilation.wordBlockSha256;
      if (artifact.yulSource === 'runtime-pair-hash') artifact.runtimeCompilation.wordBlockSha256 = '0x4dd2efd40dc163b484fc7b6526cdba1f1d82bece8845961aa0067939bf0930e9';
      if (artifact.yulSource === 'runtime-pair-round') artifact.runtimeCompilation.roundBlockSha256 = '0xc6b97f9bf6025e0ed5cdb7ecbf46f5b2099dba4f09d28c601edcef6a5d38e741';
      if (artifact.yulSource === 'runtime-pair-scalar-missing') delete artifact.runtimeCompilation.scalarCore;
      if (artifact.yulSource === 'runtime-pair-scalar-wrong') artifact.runtimeCompilation.scalarCore = 'scalar';
      if (artifact.yulSource === 'runtime-pair-old') artifact.runtimeCompilation.kind = 'yul-sha-rounds-v10';
    }
  }
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

  test('accepts explicit Yul runtime provenance and rejects unknown or malformed bindings', async () => {
    const backend = new BiniusBackend('non-empty-acir', { binaryPath: await fakeBackend() });
    const artifact = await backend.getVerifierDeployment(new Uint8Array([1]), { solidityCompiler: 'runtime-valid' });
    expect(artifact.runtimeCompilation).toEqual({
      kind: 'yul-sha-rounds-v1', runtimeSource: 'BiniusVerifier.yul',
      solidityReferenceRuntimeSha256: `0x${'ab'.repeat(32)}`,
      roundBlockSha256: '0x25aaa3f04cee1446d5901296eecd247b0dbd9d6d2fca036533802f7485d09fbd',
    });
    const expanded = await backend.getVerifierDeployment(new Uint8Array([1]), { solidityCompiler: 'runtime-words' });
    expect(expanded.runtimeCompilation).toEqual({
      ...artifact.runtimeCompilation, kind: 'yul-sha-rounds-v2',
      wordBlockSha256: '0x4c6cc06c6965224f123533b5ad7b855828b107042ebde9993c31516bd1e11bda',
    });
    const placed = await backend.getVerifierDeployment(new Uint8Array([1]), { solidityCompiler: 'runtime-placement' });
    expect(placed.runtimeCompilation).toEqual({
      ...expanded.runtimeCompilation, kind: 'yul-sha-rounds-v3',
      roundBlockSha256: '0xfcb13ca730f9b4f8a65662a14d75ee0731a31d7251addfe3931873f2c67e3717',
    });
    const cursor = await backend.getVerifierDeployment(new Uint8Array([1]), { solidityCompiler: 'runtime-cursor' });
    expect(cursor.runtimeCompilation).toEqual({
      ...expanded.runtimeCompilation, kind: 'yul-sha-rounds-v4',
      roundBlockSha256: '0xb95b04dd62c7769294246ea85f6ae6e5fce78e954ec8e0c0b87b7b88d1bde25f',
    });
    const ordered = await backend.getVerifierDeployment(new Uint8Array([1]), { solidityCompiler: 'runtime-order' });
    expect(ordered.runtimeCompilation).toEqual({
      ...cursor.runtimeCompilation, kind: 'yul-sha-rounds-v5',
      wordBlockSha256: '0x4e56b829a8c054a5388a18673f804cfc74f71ce617feb5b788fcb78747b02776',
    });
    const four = await backend.getVerifierDeployment(new Uint8Array([1]), { solidityCompiler: 'runtime-four' });
    expect(four.runtimeCompilation).toEqual({
      ...ordered.runtimeCompilation, kind: 'yul-sha-rounds-v6', scalarCore: 'packed',
      roundBlockSha256: '0x89d86e1aa7d12b47bc53ddd4391018dc61f0b5560e6a5e10aa4ebdc2869f846a',
    });
    const group = await backend.getVerifierDeployment(new Uint8Array([1]), { solidityCompiler: 'runtime-group' });
    expect(group.runtimeCompilation).toEqual({
      ...four.runtimeCompilation, kind: 'yul-sha-rounds-v7',
      roundBlockSha256: '0xc6b97f9bf6025e0ed5cdb7ecbf46f5b2099dba4f09d28c601edcef6a5d38e741',
    });
    const loop = await backend.getVerifierDeployment(new Uint8Array([1]), { solidityCompiler: 'runtime-loop' });
    expect(loop.runtimeCompilation).toEqual({
      ...group.runtimeCompilation, kind: 'yul-sha-rounds-v8',
      wordBlockSha256: '0x6234a2eab2cd341248e9c642e3d588a1f1cfcbfefe8b4af95802a28c0db80a30',
    });
    const double = await backend.getVerifierDeployment(new Uint8Array([1]), { solidityCompiler: 'runtime-double' });
    expect(double.runtimeCompilation).toEqual({
      ...loop.runtimeCompilation, kind: 'yul-sha-rounds-v9',
      roundBlockSha256: '0x8747454f3932cbbc93ac3ddaa05fc4d4ffcb30142ef0f88b8d51c1e4bf1ac55b',
      wordBlockSha256: '0x4dd2efd40dc163b484fc7b6526cdba1f1d82bece8845961aa0067939bf0930e9',
    });
    const wgroup = await backend.getVerifierDeployment(new Uint8Array([1]), { solidityCompiler: 'runtime-wgroup' });
    expect(wgroup.runtimeCompilation).toEqual({
      ...double.runtimeCompilation, kind: 'yul-sha-rounds-v10',
      wordBlockSha256: '0x12fbd5916a21d830f2707a3ab5a7849c4d1f90f1c1b3e417cf7c06dcd05cbb52',
    })
    const pair = await backend.getVerifierDeployment(new Uint8Array([1]), { solidityCompiler: 'runtime-pair' });
    expect(pair.runtimeCompilation).toEqual({
      ...wgroup.runtimeCompilation, kind: 'yul-sha-rounds-v11',
      roundBlockSha256: '0xc42783843e8233d2402c8f174feea2ffd8ae2ade1f503a60aa888ee2bc67c4ad',
      wordBlockSha256: '0x997d259dd8aece2235a17177f6422949b27ec974286b968ba83aa0a25ea96071',
    });;
    for (const suffix of ['null', 'kind', 'source', 'reference', 'block', 'words-missing', 'words-hash', 'words-old',
      'placement-missing', 'placement-hash', 'placement-old', 'cursor-missing', 'cursor-hash', 'cursor-old',
      'order-missing', 'order-hash', 'order-round', 'order-old',
      'four-missing', 'four-hash', 'four-round', 'four-scalar-missing', 'four-scalar-wrong', 'four-old',
      'group-missing', 'group-hash', 'group-round', 'group-scalar-missing', 'group-scalar-wrong', 'group-old',
      'loop-missing', 'loop-hash', 'loop-round', 'loop-scalar-missing', 'loop-scalar-wrong', 'loop-old',
      'double-missing', 'double-hash', 'double-round', 'double-scalar-missing', 'double-scalar-wrong', 'double-old',
      'wgroup-missing', 'wgroup-hash', 'wgroup-round', 'wgroup-scalar-missing', 'wgroup-scalar-wrong', 'wgroup-old',
      'pair-missing', 'pair-hash', 'pair-round', 'pair-scalar-missing', 'pair-scalar-wrong', 'pair-old']) {
      await expect(backend.getVerifierDeployment(new Uint8Array([1]), {
        solidityCompiler: `runtime-${suffix}`,
      })).rejects.toThrow('inconsistent');
    }
  });
});
