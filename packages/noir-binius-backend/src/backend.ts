import { execFile } from 'node:child_process';
import { accessSync, constants as fsConstants } from 'node:fs';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const DEFAULT_NOIR_VERSION =
  '1.0.0-beta.18+99bb8b5cf33d7669adbdef096b12d80f30b4c0c9';
const BN254_SCALAR_MODULUS = BigInt(
  '21888242871839275222246405745257275088548364400416034343698204186575808495617',
);

/** Backend-specific proof type accepted by Noir's recursive aggregation opcode. */
export const BINIUS_ZK_PROOF_TYPE = 0x4249_4e5a;

/** The proof representation used by @aztec/bb.js backends. */
export type ProofData = {
  publicInputs: string[];
  proof: Uint8Array;
};

export type RecursiveProofArtifacts = {
  proofAsFields: string[];
  vkAsFields: string[];
  vkHash: string;
};

export type BiniusProofOptions = {
  /** log2 of the inverse Reed-Solomon rate. Must be at least one. */
  logInvRate?: number;
};

export type BiniusBackendOptions = BiniusProofOptions & {
  /** Path to the native noir-binius executable. */
  binaryPath?: string;
  /** Version string placed in the minimal Noir artifact passed to the backend. */
  noirVersion?: string;
};

type JsonProofData = {
  publicInputs: string[];
};

type RecursiveInputs = {
  verification_key: string[];
  proof: string[];
  public_inputs: string[];
  key_hash: string;
  proof_type: number;
};

type Workspace = {
  artifactPath: string;
  directory: string;
};

class BiniusProcessError extends Error {
  constructor(
    message: string,
    readonly exitCode: number | null,
    readonly stderr: string,
  ) {
    super(message);
    this.name = 'BiniusProcessError';
  }
}

export class BiniusBackendError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'BiniusBackendError';
  }
}

/**
 * A Noir proof backend with the same generateProof/verifyProof data contract as
 * bb.js's UltraHonkBackend.
 *
 * The backend runs the native `noir-binius` executable. `Noir.execute()` from
 * @noir-lang/noir_js can be passed directly to generateProof without converting
 * or decompressing its witness.
 */
export class BiniusBackend {
  private readonly artifact: string;
  private readonly binaryPath: string;
  private readonly defaultLogInvRate: number;

  constructor(
    acirBytecode: string,
    options: BiniusBackendOptions = {},
  ) {
    if (acirBytecode.length === 0) {
      throw new BiniusBackendError('ACIR bytecode must not be empty');
    }
    this.binaryPath = options.binaryPath ?? findDefaultBinary();
    this.defaultLogInvRate = validateLogInvRate(options.logInvRate ?? 1);
    this.artifact = JSON.stringify({
      noir_version: options.noirVersion ?? DEFAULT_NOIR_VERSION,
      bytecode: acirBytecode,
    });
  }

  async generateProof(
    compressedWitness: Uint8Array,
    options: BiniusProofOptions = {},
  ): Promise<ProofData> {
    if (compressedWitness.length === 0) {
      throw new BiniusBackendError('Witness must not be empty');
    }
    const logInvRate = validateLogInvRate(
      options.logInvRate ?? this.defaultLogInvRate,
    );
    return this.withWorkspace(async ({ directory, artifactPath }) => {
      const witnessPath = join(directory, 'witness.gz');
      const proofPath = join(directory, 'proof.binius');
      await writeFile(witnessPath, compressedWitness);
      const stdout = await runBinary(this.binaryPath, [
        'prove',
        '--bytecode',
        artifactPath,
        '--witness',
        witnessPath,
        '--output',
        proofPath,
        '--log-inv-rate',
        String(logInvRate),
        '--json',
      ]);
      const result = parseJson<JsonProofData>(stdout, 'proof result');
      assertStringArray(result.publicInputs, 'publicInputs');
      const proof = new Uint8Array(await readFile(proofPath));
      return { proof, publicInputs: result.publicInputs };
    });
  }

  async verifyProof(
    proofData: ProofData,
    _options: BiniusProofOptions = {},
  ): Promise<boolean> {
    if (!(proofData.proof instanceof Uint8Array)) {
      throw new BiniusBackendError('proof must be a Uint8Array');
    }
    if (!Array.isArray(proofData.publicInputs)) {
      throw new BiniusBackendError('publicInputs must be an array');
    }
    try {
      return await this.withWorkspace(async ({ directory, artifactPath }) => {
        const proofPath = join(directory, 'proof.binius');
        await writeFile(proofPath, proofData.proof);
        const stdout = await runBinary(this.binaryPath, [
          'verify',
          '--bytecode',
          artifactPath,
          '--proof',
          proofPath,
          '--json',
        ]);
        const result = parseJson<JsonProofData>(stdout, 'verification result');
        assertStringArray(result.publicInputs, 'publicInputs');
        return equalFieldArrays(result.publicInputs, proofData.publicInputs);
      });
    } catch (error) {
      // A normal non-zero verifier exit represents an invalid proof. Failures to
      // launch the backend (ENOENT, EACCES, and similar) remain actionable errors.
      if (error instanceof BiniusProcessError && error.exitCode !== null) {
        return false;
      }
      throw error;
    }
  }

  async getVerificationKey(
    options: BiniusProofOptions = {},
  ): Promise<Uint8Array> {
    const logInvRate = validateLogInvRate(
      options.logInvRate ?? this.defaultLogInvRate,
    );
    return this.withWorkspace(async ({ directory, artifactPath }) => {
      const keyPath = join(directory, 'verification-key.binius');
      await runBinary(this.binaryPath, [
        'write-vk',
        '--bytecode',
        artifactPath,
        '--output',
        keyPath,
        '--log-inv-rate',
        String(logInvRate),
      ]);
      return new Uint8Array(await readFile(keyPath));
    });
  }

  async generateRecursiveProofArtifacts(
    proof: Uint8Array,
    numOfPublicInputs: number,
    _options: BiniusProofOptions = {},
  ): Promise<RecursiveProofArtifacts> {
    if (!Number.isSafeInteger(numOfPublicInputs) || numOfPublicInputs < 0) {
      throw new BiniusBackendError(
        'numOfPublicInputs must be a non-negative safe integer',
      );
    }
    return this.withWorkspace(async ({ directory, artifactPath }) => {
      const proofPath = join(directory, 'proof.binius');
      await writeFile(proofPath, proof);
      const stdout = await runBinary(this.binaryPath, [
        'recursive-inputs',
        '--bytecode',
        artifactPath,
        '--proof',
        proofPath,
      ]);
      const result = parseJson<RecursiveInputs>(stdout, 'recursive proof artifacts');
      assertStringArray(result.verification_key, 'verification_key');
      assertStringArray(result.proof, 'proof');
      assertStringArray(result.public_inputs, 'public_inputs');
      if (result.public_inputs.length !== numOfPublicInputs) {
        throw new BiniusBackendError(
          `Expected ${numOfPublicInputs} public inputs, but the proof contains ${result.public_inputs.length}`,
        );
      }
      if (typeof result.key_hash !== 'string') {
        throw new BiniusBackendError('Backend returned an invalid key_hash');
      }
      if (result.proof_type !== BINIUS_ZK_PROOF_TYPE) {
        throw new BiniusBackendError(
          `Backend returned unsupported proof type ${result.proof_type}`,
        );
      }
      return {
        proofAsFields: result.proof,
        vkAsFields: result.verification_key,
        vkHash: result.key_hash,
      };
    });
  }

  async getSolidityVerifier(
    _verificationKey: Uint8Array,
    _options: BiniusProofOptions = {},
  ): Promise<string> {
    throw new BiniusBackendError(
      'Binius Solidity verification is not supported by noir-binius',
    );
  }

  /** No long-lived native process is retained, so destruction is a no-op. */
  async destroy(): Promise<void> {}

  private async withWorkspace<T>(
    operation: (workspace: Workspace) => Promise<T>,
  ): Promise<T> {
    const directory = await mkdtemp(join(tmpdir(), 'noir-binius-js-'));
    const artifactPath = join(directory, 'circuit.json');
    try {
      await writeFile(artifactPath, this.artifact, 'utf8');
      return await operation({ artifactPath, directory });
    } finally {
      await rm(directory, { force: true, recursive: true });
    }
  }
}

function findDefaultBinary(): string {
  const configured = process.env.NOIR_BINIUS_BINARY;
  if (configured !== undefined && configured.length > 0) {
    return configured;
  }

  const moduleDirectory = dirname(fileURLToPath(import.meta.url));
  const executable = process.platform === 'win32' ? 'noir-binius.exe' : 'noir-binius';
  const candidates = [
    resolve(moduleDirectory, '..', 'bin', executable),
    resolve(moduleDirectory, '..', '..', '..', 'target', 'release', executable),
    resolve(moduleDirectory, '..', '..', '..', 'target', 'debug', executable),
  ];
  for (const candidate of candidates) {
    try {
      accessSync(candidate, fsConstants.X_OK);
      return candidate;
    } catch {
      // Try the next local candidate, then finally defer to PATH resolution.
    }
  }
  return executable;
}

function validateLogInvRate(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > 0xffff_ffff) {
    throw new BiniusBackendError(
      'logInvRate must be an integer between 1 and 4294967295',
    );
  }
  return value;
}

function runBinary(binaryPath: string, args: string[]): Promise<string> {
  return new Promise((resolvePromise, rejectPromise) => {
    execFile(
      binaryPath,
      args,
      { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 },
      (error, stdout, stderr) => {
        if (error === null) {
          resolvePromise(stdout);
          return;
        }
        const exitCode = typeof error.code === 'number' ? error.code : null;
        const detail = stderr.trim() || error.message;
        rejectPromise(
          new BiniusProcessError(
            `noir-binius failed: ${detail}`,
            exitCode,
            stderr,
          ),
        );
      },
    );
  });
}

function parseJson<T>(stdout: string, description: string): T {
  try {
    return JSON.parse(stdout.trim()) as T;
  } catch (error) {
    throw new BiniusBackendError(
      `Backend returned an invalid ${description}: ${stdout.trim()}`,
      { cause: error },
    );
  }
}

function assertStringArray(value: unknown, name: string): asserts value is string[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) {
    throw new BiniusBackendError(`Backend returned an invalid ${name} array`);
  }
}

function equalFieldArrays(lhs: string[], rhs: string[]): boolean {
  if (lhs.length !== rhs.length) {
    return false;
  }
  try {
    return lhs.every((field, index) => {
      const other = rhs[index];
      return other !== undefined && normalizeField(field) === normalizeField(other);
    });
  } catch {
    return false;
  }
}

function normalizeField(field: string): bigint {
  const value = BigInt(field);
  if (value < 0n || value >= BN254_SCALAR_MODULUS) {
    throw new BiniusBackendError(`Invalid BN254 field element: ${field}`);
  }
  return value;
}
