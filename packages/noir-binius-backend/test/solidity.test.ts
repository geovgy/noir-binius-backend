import { afterEach, describe, expect, test } from 'bun:test';
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { BiniusBackend, BiniusBackendError } from '../src/index.js';

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
  fs.writeFileSync(value('--output_path'), value('--verifier_target'));
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

  test('rejects an empty verification key before invoking the backend', async () => {
    const binaryPath = await fakeBackend();
    const backend = new BiniusBackend('non-empty-acir', { binaryPath });

    await expect(
      backend.getSolidityVerifier(new Uint8Array()),
    ).rejects.toBeInstanceOf(BiniusBackendError);
  });
});
