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

/** Solidity proof/verifier format selected by the native backend. */
export type SolidityVerifierTarget = 'evm' | 'evm-sp1';

export type SolidityVerifierOptions = BiniusProofOptions & {
  /**
   * `evm` verifies the raw Binius64 proof inside the generated Solidity contract.
   * `evm-sp1` verifies a succinct SP1 wrapper proof and is the lower-gas option.
   */
  verifierTarget?: SolidityVerifierTarget;
  /**
   * Optional solc 0.8.35 executable for factored wiring and compressed runtime
   * deployment. The emitted source requires its documented compiler settings.
   * This lowers verification gas and increases deployment gas for the evm target.
   */
  solidityCompiler?: string;
};

export type VerifierDeploymentOptions = BiniusProofOptions & {
  /** solc 0.8.35 executable used to compile the complete direct verifier. */
  solidityCompiler: string;
};

/** ABI of the Solidity IVerifier implementation contained in every deployment. */
export type DirectVerifierAbi = readonly [
  { type: 'constructor'; inputs: readonly []; stateMutability: 'nonpayable' },
  {
    type: 'function'; name: 'verify'; stateMutability: 'view';
    inputs: readonly [
      { name: 'proof'; type: 'bytes'; internalType: 'bytes' },
      { name: 'publicInputs'; type: 'bytes32[]'; internalType: 'bytes32[]' },
    ];
    outputs: readonly [{ name: ''; type: 'bool'; internalType: 'bool' }];
  },
];

/** Deploy bytecode with abi and no arguments. Both source forms are included
 * for review; the ordinary Solidity constructor can exceed its size limit. */
export type VerifierDeployment = {
  contractName: 'BiniusVerifier';
  abi: DirectVerifierAbi;
  bytecode: `0x${string}`;
  deployedBytecode: `0x${string}`;
  soliditySource: string;
  yulSource: string;
  compilerSettings: {
    version: '0.8.35';
    solidity: {
      optimizer: { enabled: true; runs: 200 }; viaIR: true;
      evmVersion: 'osaka'; metadata: { bytecodeHash: 'none' };
    };
    yul: { optimizer: { enabled: true; runs: 200 }; evmVersion: 'osaka' };
  };
  initcodeBytes: number;
  runtimeBytes: number;
  solidityInitcodeBytes: number;
  /** Circuit review data; deployment still takes only bytecode and no arguments. */
  construction?: {
    kind: 'affine-matrix-v1';
    verificationProgram: string;
    programKeccak256: string;
    precursorLength: number;
    matrixLengthOffset: number;
    matrixInputOffset: number;
    matrixOutputOffset: number;
    affineLength: number;
    matrixLength: number;
    escapedMatrixLength: boolean;
    /** Constructor expands the compact public graph to exact u16 child references. */
    publicExpansion?: {
      kind: 'relative-u16-v1' | 'grouped-relative-u16-v1';
      sourceLength: number;
      instructionOffset: number;
      fixedLength: number;
    };
    /** Constructor orders the same private scalar DAG by depth and operation code. */
    privateGrouping?: {
      kind: 'depth-code-grouped-u16-v1' | 'depth-code-product-terminal-u16-v1';
      originalLength: number;
      nodes: number;
      groups: number;
      maxDepth: number;
    };
    /** Generator groups the fixed precommit DAG without changing its equations. */
    precommitGrouping?: {
      kind: 'code-grouped-u16-v1';
      instructionOffset: number;
      originalLength: number;
      nodes: number;
      groups: number;
      maxDepth: number;
    };
    storageCompression?: {
      kind: 'literal-copy-v1';
      minimumMatch: number;
      storedProgram: string;
      storedProgramKeccak256: string;
      packingHeaders: string;
    };
    /** Optional NBINK001 || public program || native/hinted proof input.
     * The contract checks this fixed program digest before running the proof. */
    programInput?: {
      kind: 'keccak-calldata-v1';
      magic: '0x4e42494e4b303031';
      programLength: number;
      programKeccak256: `0x${string}`;
    };
  };
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
        'write_vk',
        '--bytecode_path',
        artifactPath,
        '--output_path',
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
    verificationKey: Uint8Array,
    options: SolidityVerifierOptions = {},
  ): Promise<string> {
    if (!(verificationKey instanceof Uint8Array) || verificationKey.length === 0) {
      throw new BiniusBackendError(
        'verificationKey must be a non-empty Uint8Array',
      );
    }
    return this.withWorkspace(async ({ directory }) => {
      const verifierTarget = validateSolidityVerifierTarget(
        options.verifierTarget ?? 'evm',
      );
      if (options.solidityCompiler !== undefined) {
        if (
          verifierTarget !== 'evm' ||
          typeof options.solidityCompiler !== 'string' ||
          options.solidityCompiler.length === 0
        ) {
          throw new BiniusBackendError(
            'solidityCompiler must be a non-empty executable path for the evm target',
          );
        }
      }
      const keyPath = join(directory, 'verification-key.binius');
      const verifierPath = join(directory, 'BiniusVerifier.sol');
      await writeFile(keyPath, verificationKey);
      await runBinary(this.binaryPath, [
        'write_solidity_verifier',
        '--vk_path',
        keyPath,
        '--output_path',
        verifierPath,
        '--verifier_target',
        verifierTarget,
        ...(options.solidityCompiler === undefined
          ? []
          : ['--solidity_compiler', options.solidityCompiler]),
      ]);
      return readFile(verifierPath, 'utf8');
    });
  }

  /** Computes the circuit verification key and returns its Solidity verifier. */
  async generateSolidityVerifier(
    options: SolidityVerifierOptions = {},
  ): Promise<string> {
    // Validate before constructing the key and specializing its verifier equations.
    const verifierTarget = validateSolidityVerifierTarget(
      options.verifierTarget ?? 'evm',
    );
    const verificationKey = await this.getVerificationKey(options);
    return this.getSolidityVerifier(verificationKey, {
      ...options,
      verifierTarget,
    });
  }

  /** Return a direct verifier's ABI, compact creation bytecode and complete
   * Solidity/Yul sources. The contract installs its own data during creation. */
  async getVerifierDeployment(
    verificationKey: Uint8Array,
    options: VerifierDeploymentOptions,
  ): Promise<VerifierDeployment> {
    if (!(verificationKey instanceof Uint8Array) || verificationKey.length === 0) {
      throw new BiniusBackendError('verificationKey must be a non-empty Uint8Array');
    }
    validateDeploymentCompiler(options?.solidityCompiler);
    return this.withWorkspace(async ({ directory }) => {
      const keyPath = join(directory, 'verification-key.binius');
      const outputPath = join(directory, 'BiniusVerifier.deployment.json');
      await writeFile(keyPath, verificationKey);
      await runBinary(this.binaryPath, [
        'write_verifier_deployment', '--vk_path', keyPath,
        '--output_path', outputPath, '--solidity_compiler', options.solidityCompiler,
      ]);
      return parseVerifierDeployment(await readFile(outputPath, 'utf8'));
    });
  }

  /** Compute the circuit key and return its single-deployment direct verifier. */
  async generateVerifierDeployment(
    options: VerifierDeploymentOptions,
  ): Promise<VerifierDeployment> {
    validateDeploymentCompiler(options?.solidityCompiler);
    const key = await this.getVerificationKey(options);
    return this.getVerifierDeployment(key, options);
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

function validateDeploymentCompiler(compiler: unknown): asserts compiler is string {
  if (typeof compiler !== 'string' || compiler.length === 0) {
    throw new BiniusBackendError('solidityCompiler must be a non-empty solc 0.8.35 executable path');
  }
}

function parseVerifierDeployment(source: string): VerifierDeployment {
  let artifact: VerifierDeployment;
  try {
    artifact = JSON.parse(source) as VerifierDeployment;
  } catch {
    throw new BiniusBackendError('backend returned an invalid verifier deployment JSON artifact');
  }
  const code = (value: unknown) => typeof value === 'string' && /^0x(?:[0-9a-f]{2})+$/.test(value);
  const solidity = artifact?.compilerSettings?.solidity;
  const yul = artifact?.compilerSettings?.yul;
  if (
    artifact?.contractName !== 'BiniusVerifier' ||
    !code(artifact.bytecode) || !code(artifact.deployedBytecode) ||
    artifact.initcodeBytes !== (artifact.bytecode.length - 2) / 2 ||
    artifact.runtimeBytes !== (artifact.deployedBytecode.length - 2) / 2 ||
    artifact.initcodeBytes > 49_152 || artifact.runtimeBytes > 24_576 ||
    !Number.isSafeInteger(artifact.solidityInitcodeBytes) || artifact.solidityInitcodeBytes < 1 ||
    typeof artifact.soliditySource !== 'string' || artifact.soliditySource.length === 0 ||
    typeof artifact.yulSource !== 'string' || artifact.yulSource.length === 0 ||
    artifact.compilerSettings?.version !== '0.8.35' ||
    solidity?.optimizer?.enabled !== true || solidity.optimizer.runs !== 200 ||
    solidity.viaIR !== true || solidity.evmVersion !== 'osaka' || solidity.metadata?.bytecodeHash !== 'none' ||
    yul?.optimizer?.enabled !== true || yul.optimizer.runs !== 200 || yul.evmVersion !== 'osaka' ||
    !Array.isArray(artifact.abi) || artifact.abi.length !== 2 ||
    artifact.abi[0]?.type !== 'constructor' || artifact.abi[0].stateMutability !== 'nonpayable' ||
    !Array.isArray(artifact.abi[0].inputs) || artifact.abi[0].inputs.length !== 0 ||
    artifact.abi[1]?.type !== 'function' || artifact.abi[1].name !== 'verify' ||
    artifact.abi[1].stateMutability !== 'view' || !Array.isArray(artifact.abi[1].inputs) ||
    artifact.abi[1].inputs.length !== 2 ||
    artifact.abi[1].inputs[0]?.type !== 'bytes' || artifact.abi[1].inputs[0].internalType !== 'bytes' ||
    artifact.abi[1].inputs[0].name !== 'proof' || artifact.abi[1].inputs[1]?.type !== 'bytes32[]' ||
    artifact.abi[1].inputs[1].internalType !== 'bytes32[]' || artifact.abi[1].inputs[1].name !== 'publicInputs' ||
    !Array.isArray(artifact.abi[1].outputs) || artifact.abi[1].outputs.length !== 1 ||
    artifact.abi[1].outputs[0]?.type !== 'bool' || artifact.abi[1].outputs[0].internalType !== 'bool' ||
    artifact.abi[1].outputs[0].name !== ''
  ) {
    throw new BiniusBackendError('backend returned an inconsistent direct verifier deployment artifact');
  }
  if (artifact.construction?.programInput !== undefined) verifierProgramBytes(artifact);
  return artifact;
}

function verifierProgramBytes(deployment: VerifierDeployment): Uint8Array {
  const construction = deployment.construction;
  const info = construction?.programInput;
  if (!info) throw new BiniusBackendError('deployment does not support authenticated program input');
  const storage = construction?.storageCompression;
  const program = storage?.storedProgram ?? construction?.verificationProgram;
  const digest = storage?.storedProgramKeccak256 ?? construction?.programKeccak256;
  if (
    info.kind !== 'keccak-calldata-v1' || info.magic !== '0x4e42494e4b303031' ||
    !Number.isSafeInteger(info.programLength) || info.programLength < 1 ||
    typeof program !== 'string' || !/^0x(?:[0-9a-f]{2})+$/.test(program) ||
    (program.length - 2) / 2 !== info.programLength ||
    !/^0x[0-9a-f]{64}$/.test(info.programKeccak256) || info.programKeccak256 !== digest
  ) throw new BiniusBackendError('inconsistent authenticated program metadata');
  return Uint8Array.from(Buffer.from(program.slice(2), 'hex'));
}

/** Frame a native or SHA-hinted zk Binius proof with optional public circuit data.
 * This prepares the proof argument; it does not verify a proof or trust the data.
 * The contract authenticates every program byte and performs native verification.
 * Raw proofs still work, and deployments without this capability reject the helper. */
export function withVerifierProgram(proof: Uint8Array, deployment: VerifierDeployment): Uint8Array {
  const program = verifierProgramBytes(deployment);
  const starts = (prefix: string) => proof.length >= prefix.length &&
    [...prefix].every((character, i) => proof[i] === character.charCodeAt(0));
  if (!(proof instanceof Uint8Array) || !(starts('NBINZK01') || starts('NBINH001NBINZK01'))) {
    throw new BiniusBackendError('expected native NBINZK01 proof or NBINH001 hash hints');
  }
  const framed = new Uint8Array(8 + program.length + proof.length);
  framed.set(new TextEncoder().encode('NBINK001'));
  framed.set(program, 8);
  framed.set(proof, 8 + program.length);
  return framed;
}

function validateSolidityVerifierTarget(
  value: SolidityVerifierTarget,
): SolidityVerifierTarget {
  if (value !== 'evm' && value !== 'evm-sp1') {
    throw new BiniusBackendError(
      `verifierTarget must be either "evm" or "evm-sp1", received ${JSON.stringify(value)}`,
    );
  }
  return value;
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
