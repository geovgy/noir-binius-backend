# Direct Binius64 ZK verification

The `evm` target generates one `BiniusVerifier is IVerifier` contract. Its
`verify(bytes,bytes32[])` entry point is `external view returns (bool)`. It accepts
the existing `NBINZK01` bundle and an optional `NBINH001` envelope containing that
same bundle plus untrusted SHA digest hints. Every hinted hash is recomputed in
the contract before acceptance. The native prover, its hashes and its proof bytes
are unchanged. The contract makes no calls to other contracts or precompiles.

Deployment takes no arguments and initializes all circuit data in the contract's
own storage. There is no program-upload function or subsequent installation step.
The fixed data is losslessly compressed in the constructor's source; it is not
part of the proof. Code generation receives only the verification key.

The completed four-key public-generator validation measured **120,243,678 CALL gas**
for arithmetic rate 3 with checked SHA hints and authenticated circuit data, or **162,331,325 gas** for
the original proof alone. These use the key-only deployment-artifact path
described below. The initial tables record the ordinary Solidity-source API;
the later constructed-deployment tables contain that complete validation.
The 10-million-call-gas target remains unmet.

Deployment and verification still need a raised local gas limit. These measurements
use Solidity 0.8.35, optimizer 200 runs, via IR, Osaka, and `bytecode_hash = "none"`
(the corresponding solc setting is `metadata.bytecodeHash: "none"`). Compiler version
metadata is retained; the omitted metadata content hash is unrelated to the
contract's explicit circuit and proof binding. These costs exceed ordinary Ethereum
transaction limits even when creation and runtime bytecode fit their size limits.

| Circuit | Native proof bytes | With SHA hints, bytes | Original-proof call gas | Hinted call gas |
| --- | ---: | ---: | ---: | ---: |
| Native equality, rate 1 | 379,072 | 383,688 | 155,901,402 | 149,836,858 |
| Noir arithmetic, rate 1 (default) | 515,896 | 531,520 | 253,243,260 | 229,494,987 |
| Noir arithmetic, rate 2 | 392,344 | 407,616 | 218,783,293 | 195,236,751 |
| Noir arithmetic, rate 3 | 373,976 | 389,120 | 211,217,785 | 187,723,019 |

| Circuit | Deployment gas | Initcode bytes | Runtime bytes |
| --- | ---: | ---: | ---: |
| Native equality, rate 1 | 87,551,992 | 33,919 | 20,569 |
| Noir arithmetic, rate 1 (default) | 190,522,939 | 48,966 | 20,724 |
| Noir arithmetic, rate 2 | 190,000,860 | 49,021 | 20,724 |
| Noir arithmetic, rate 3 | 189,991,299 | 49,031 | 20,724 |

Gas measures construction and the verification call in the EVM test, excluding
transaction intrinsic/calldata gas. Program storage is cold; the contract account
is warm. All four default fixtures were rerun through the complete original-proof,
hinted-proof, malformed-proof and deployed-runtime identity tests. The same math
kernels also pass 17 targeted primitive and FRI tests, including randomized
field, hash, transcript and vector properties.
The default rate-3 constructor has **121 bytes** of initcode headroom: use the tested
compiler/settings and check every generated output. Its ABI consists only of the
no-argument constructor and `verify`. The runtime uses Osaka's `CLZ` opcode.
The shared runtime uses bounded memory copies and accesses, a compact full-field
squaring permutation, and a four-bit XOR table for FRI basis sums. These retain
the exact field reduction and support arbitrary basis entries. Complete source
outputs and their installed runtimes were regenerated and tested.

The preceding packed SHA change shares a mask between the ROTR6 and ROTR11 wrap terms. This
saved **511,104 gas** on the default rate-3 original-proof call and
**576,384 gas** with hints when introduced. The actual
old and new expressions agree on all 224 independent packed payload bits;
dense, complement and random checks also pass. All guard bits, additions,
other SHA expressions and verification equations are preserved. Scalar SHA
retains its four-round grouping. All measured native files are zero-knowledge
Binius proofs using the `NBINZK01` format.

These default-mode checks total 16 EVM tests. The compact deployment below also
checks an independently blinded proof against the same deployed runtime. Gas
varies with proof-derived values: repeated Merkle inputs can reuse computed
hashes, and polynomial inversion takes a variable number of cancellations.

The packed SHA kernel now combines the wrap terms of several rotations before
correcting bits that cross a lane. It shares this correction in both schedule
sigmas and the round's Sigma1, retaining the existing Sigma0 implementation.
Complete generated-contract benchmarks select this combination: applying the
same transformation to Sigma0 was slower. The actual old and new expressions
agree on all 224 canonical basis bits, their complements, dense inputs and
16,384 random packed inputs, including the retained guard bits. All 64 rounds,
constants, schedule words and digest bytes remain unchanged.

The preceding SHA summand ordering saved 288,192 gas on the default
hinted rate-3 call when introduced. It reorders the same five terms of SHA's T1 expression in
the packed and scalar kernels. All 64 rounds, rotations, masks, constants,
message words and verification equations remain. A symbolic comparison checks
equivalence under associativity and commutativity of addition modulo 2^256,
with unchanged control flow. Complete generated-contract tests measure the result;
the larger gains seen in some isolated compiler benchmarks did not carry over.

The preceding balanced binary-field XOR trees and SHA expression grouping remain.
Every one of the 25 field products, five parity masks and final reduction steps
is preserved. The EVM tests compare field operations with bit-serial arithmetic
and SHA results with known vectors and independent SHA computations.

The earlier zero/unit multiplication identities and packed bit transpose remain.
Integer multiplication agrees exactly with binary-field multiplication when
one factor is zero or one. The transpose processes two canonical 128-bit rows
in each EVM word; independent bit-by-bit checks cover random matrices, boundaries
and all 16,384 single-bit positions. These arithmetic kernels and the preceding
matrix partitioning remain in use. Earlier changes reduce repeated shifts
and masks in packed SHA. The fixed verification programs, native proof,
transcript schedule, hash suite and security parameters remain unchanged.
**The 10-million-gas target remains unmet.** Proof size is reported for context;
there is no proof-size target. The optional envelope adds 8 envelope
bytes and 15,136 hint bytes. The default rate adds 8 + 15,616 bytes.

Total transaction gas is a separate constraint: under
[EIP-7623](https://eips.ethereum.org/EIPS/eip-7623), the rate-3 native proof bytes
alone impose a 14,934,920-gas floor before counting the ABI envelope. The call
measurements above exclude that transaction accounting.
See [native size measurements and parameter analysis](binius-proof-size.md).

## Optional factored deployment

`write_solidity_verifier --solidity_compiler /path/to/solc-0.8.35` selects a
factored representation of the small precommit wiring matrix and searches for
useful factored regions of the private matrix. The Rust API is
`solidity::generate_verifier_with_compiler(key, "evm", compiler_path)`; the
TypeScript option is `solidityCompiler`. Generation needs only the verification
key and compiler. The native proof, transcript schedule, SHA suite and security
parameters are unchanged.

The generator builds decision diagrams for the exact sparse matrix. Eight
coefficient-mask terminals represent combinations of `1`, `lambda`, and
`lambda²`. Shared literal products and identical subexpressions reduce field
multiplications. Each decision evaluates `lo + r * (lo + hi)` in the native
binary field; there are no divisions, including at coordinates zero and one.
Before serialization, generation expands the complete Boolean support and
compares every entry and coefficient against the native matrix. It also rejects
repeated coordinates on every path, establishing multilinearity. This extra
check matters because a wrong expression such as `(1 + r)²` agrees on Boolean
points but differs in the extension field. Encoded backward offsets are decoded
again and compared against every generated scalar operation.

For the private matrix, generation searches bounded row regions and their
combinations. It represents a chosen region with a factored graph and its
complement with affine runs. The two parts are disjoint and reconstruct every
original matrix entry, so XOR of their multilinear extensions equals the
original extension at every field point. Both encoders retain their complete
support checks. No proof, witness or sampled transcript chooses the partition.

A performance model follows the existing carry-state and suffix-cache rules
and estimates generic field multiplications. It is a selection heuristic, not a
verification check or an exact gas predictor. Compiler liveness proves that the
matrix register has no remaining reads before reusing it for three extra pure
instructions: load the graph, evaluate it, and XOR the two results. Liveness
includes registers referenced inside FRI and other opaque configurations.
Earlier uses of that byte definition must only prepare its unchanged dimensions;
matrices evaluated more than once are retained in their original representation.
Original transcript operations and verification checks retain their order.

Generation estimates whole-program compression, reserves 512 bytes for estimation
error, and then recompiles the actual candidate. The real compiler output must
pass runtime identity and both code-size limits. A size failure can select another
candidate or retain the original representation; other compiler errors are
reported. Search is bounded to 496 single regions and combinations of at most six
disjoint regions, with at most 16,384 entries in each factored part.

The additional fixed data needs more constructor space. Generation compiles the
full Solidity implementation, compresses its runtime together with the encoded
program, and compiles the emitted source again. It requires byte-for-byte runtime
identity and enforces the 24,576-byte runtime and 49,152-byte initcode limits.
The constructor decompresses both, initializes its own storage, and returns the
verified executable suffix. The complete verification implementation remains in
the Solidity source. No contract address, external call, precompile, constructor
argument, or later installation step is introduced.

This mode requires solc **0.8.35**, optimizer **200** runs, **viaIR**, **Osaka**,
and **metadata.bytecodeHash: "none"**, as recorded in the emitted source. The
source pins the compiler version. Without content-hash metadata, changing the
constructor literal preserves the runtime; generation rejects a mismatch.

All four optional-mode fixtures pass four complete EVM tests each. The same proof bytes as
in the default table produce these measurements:

| Circuit | Original-proof call gas | Hinted call gas | Deployment gas | Initcode bytes | Runtime bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| Native equality, rate 1 | 154,828,837 | 148,764,665 | 139,503,714 | 29,734 | 21,959 |
| Noir arithmetic, rate 1 | 249,186,227 | 225,441,639 | 260,551,157 | 48,437 | 22,022 |
| Noir arithmetic, rate 2 | 214,728,824 | 191,185,968 | 260,160,664 | 48,523 | 22,022 |
| Noir arithmetic, rate 3 | 207,163,318 | 183,672,237 | 260,134,271 | 48,539 | 22,022 |

The rate-3 hinted call saves **4,050,782** gas against the current default, while
deployment increases by **70,142,972** gas. Both source modes use the same SHA,
bounded-memory, field-square and FRI kernels. The fixed matrix partition and all other verification
instructions are unchanged. The rate-3 constructor has **613 bytes** of
initcode headroom.
Storage is cold, using the same accounting as the default table. The native
proof remains **373,976** bytes, or **389,120** bytes with SHA hints.
The 10-million-gas target remains unmet.

The current checks total **32 complete EVM tests** across these two source
modes, plus **17 primitive/FRI tests** for the shared runtime. ABI and bytecode
audits enforce normal code-size limits and the absence of external calls.
The current build passes **45 Rust library tests and four CLI tests**. These
cover the pinned native verifier, exact matrix identities and ordering, codecs,
compiler AST relocation and malformed inputs. The compact constructor's later grouping checks are described below.
All eight fixed verification programs, original proofs, keys, public-input files
and corruption offsets remain byte-for-byte identical to the preceding baseline.
Their latest shared changes are bounded memory operations, field squaring and FRI
basis lookup; each compressed constructor was regenerated from its actual
compiler-produced runtime. The cached verifier also passes four deployment/proof
tests with bytecode identical to the fresh optional rate-1 output. Evidence is in
`target/solidity-reports/source-api-fri-square-validation/`.

For the full native-to-EVM script, set `SOLIDITY_COMPILER=/path/to/solc-0.8.35`.
It uses the factored native reference evaluator and tests the complete generated
contract. The separate runtime-identity test compares deployed code against
`type(BiniusVerifier).runtimeCode`; the existing full-proof tests still exercise
the ordinary `IVerifier.verify` entry point.

## Compact Yul deployment

`write_verifier_deployment -k key -o BiniusVerifier.deployment.json --solc /path/to/solc-0.8.35`
emits an explicit deployment artifact. The Rust API is
`solidity::generate_verifier_deployment(key, compiler_path)`. The TypeScript API
provides `generateVerifierDeployment({ solidityCompiler, logInvRate })` and
`getVerifierDeployment(key, { solidityCompiler })`. Generation needs only the
verification key and the pinned compiler, independently of proof bytes.

Deploy the artifact's `bytecode` with its `abi` and no constructor arguments.
It contains the complete Solidity implementation in `soliditySource`, the complete
Yul object in `yulSource`, and the installed runtime in `deployedBytecode`.
It also records compiler settings and both code sizes. Without `runtimeCompilation`,
the runtime is the ordinary Solidity compiler output. An artifact advertising
`runtimeCompilation.kind` of `yul-sha-rounds-v1` through `yul-sha-rounds-v11`
uses `BiniusVerifier.yul` as the
compilation unit for both creation and runtime. Its complete Solidity body is the
semantic reference; the metadata binds its ordinary runtime by SHA-256 and pins
the exact SHA round opcode block. Version 2 additionally pins `wordBlockSha256`
for the exact message-expansion body. Version 3 pins the improved round stack
placement with a different round-block hash, preserving the same equations.
Version 4 uses an absolute cursor through the same 64 round-constant and
schedule addresses, with its own checked block hash. Version 5 preserves that
round block and binds a new message-expansion block with four fewer stack swaps.
Version 6 binds a new round block and `scalarCore: "packed"`: three retained
mask constants allow four exact round bodies per loop, with sixteen iterations.
Both complete scalar/packed functions must match, including cached schedules,
state copies and masked feed-forward. Solc may swap their specialization names;
the transform checks the equations for either ordering. Scalar calls clear the
pending padding request, receive canonical low-lane words, preserve canonical
state lanes across feed-forward, and expose only their unchanged low-lane digest.
`solidityInitcodeBytes` always records the actual
ordinary Solidity creation size, including for this explicit Yul mode.
The accompanying Solidity constructor can exceed 49,152 bytes; this mode's
deployment artifact uses the checked Yul creation code. Existing APIs that return
Solidity source retain their original behavior and their own size checks.

Solc emits a long Solidity bytes literal as many individual `MSTORE` instructions.
Generation reads the actual optimized Yul AST, finds the one contiguous sequence
that writes the compressed constructor payload, and checks every address and
every constant word, including padding. Printable string literals emitted by
the compiler are decoded from their exact AST bytes and padded on the right to
one word; malformed or oversized literals are rejected. It replaces only those stores with
`datacopy` from a Yul data section. The payload, decompression, storage installation
and returned runtime remain identical. Unknown AST layouts and compiler failures
produce errors. The actual Yul creation code must fit 49,152 bytes; the verified
installed runtime must fit 24,576 bytes. ABI and executable-bytecode checks exclude
external verifier calls, precompiles, state updates during verification and any
entry point other than the read-only `IVerifier.verify`.

For supported matrices, the constructor derives the complete outer private
matrix's factored equations from its compact affine runs. These are circuit
constants, independent of any proof or transcript. Dyadic runs are split into
coordinate intervals, common coordinate factors are shared, and XOR combines
their supports. The generator checks the complete Boolean support and that no
coordinate occurs twice in a product. These checks preserve the full
multilinear polynomial, including extension-field coordinates and zero or one
challenges. The constructor checks a circuit-specific Keccak hash of every
installed program byte before storing it.

Both outer matrices then use factored evaluation. Their shared row descriptor
holds just the evaluation point; the inner protocol's affine matrices retain
all their original preparation and evaluation. Factored equations use two-byte
back-references, checked without truncation. A matrix length of 65,535 or greater
uses a two-byte sentinel followed by its four-byte length. The compact precursor
has ordinary lengths; the constructor installs the explicit extended length.
The artifact's optional `construction` field records the final program and its
hash for review. These are not proof bytes or deployment arguments.

Before emitting those equations, the backend searches bounded interleavings of
row and column coordinates. Coordinates stay in increasing order within each
axis; their native evaluation-point indices are preserved. At most 256 candidates
and 16 sweeps are considered, and small graphs keep their existing order. Every
candidate checks the complete native matrix support, multilinearity and all
serialized operations. Only a candidate with fewer scalar operations replaces
the current choice. The arithmetic fixture drops from 17,335 to 16,900 operations;
rate 2 has 16,901 because its native matrix differs. The search preserves the
constructor and runtime field polynomials. Tests cover all 20 interleavings of
three row and three column coordinates at zero, one and extension-field points.

For suitable public graphs, the constructor also expands predictive child
references into fixed u16 backward distances. Consecutive nodes with the same
coordinate share a header; every node retains both original children and its
position in the graph. The compact original graph remains in the deployment
payload. Generation independently reconstructs every child index and coordinate
from the new records; leaf sources and root equations are identical. The runtime
reads the unchanged coordinate register once per group and computes the same
`lo + r * (lo + hi)` polynomial at every node. The complete final program hash
covers this expansion as well as the private matrix construction. The optional
`construction.publicExpansion` metadata records the representation and offsets;
the current kind is `grouped-relative-u16-v1`.

The backend also tries a lossless storage encoding of that complete program.
It searches for repeated byte ranges offchain and includes a fixed copying plan
in the constructor payload. The constructor copies the selected literals from
its newly built program and checks the stored encoding's hash. Verification
loads fewer storage slots, checks all decoding bounds and backward distances,
and reconstructs the identical program before running its equations. Overlapping
copies extend only initialized history. This path does not expand operand deltas
on each verification call.

The optional `construction.storageCompression` metadata records the stored bytes,
copying plan and hash. The planner has bounded input size and search depth, and
it independently decodes every candidate and replays every constructor copy.
The generator selects a candidate only after its size and decoding-cost estimates
predict a saving; actual compilation must still satisfy both code limits.
The uncompressed representation remains the fallback. No additional deployment
arguments, transactions or proof data are required.

Construction has explicit bounds on dimensions, entries, graph nodes, and
recursive work. The generator selects it only when its estimate predicts a
verification saving including the additional cold storage reads. Actual compiled
code-size limits still apply. Unsupported or oversized candidates fall back to
the existing disjoint partition search and fixed-reference encoding. Source-only
APIs retain their source-returning interface and encodings. None of these representations
changes the native Binius equations, transcript, hash suite, proof format or
security parameters.

The compact generator can additionally order the private scalar graph by
dependency depth, operation code and original ID. It checks a bijection of every
operation and both ordered operands, including the root; no equation is removed
or changed. The constructor emits the same ordering directly from its existing
pruned graph. A dimension flag selects grouped records in the runtime, while
the inner-protocol matrices retain their existing affine evaluator paths.
Bounds limit the graph to 65,536 values and 4,096 dependency levels. Unsupported
or oversized choices retain the existing representation. The complete installed
program and its stored encoding remain hash-bound in the constructor.
The optional `construction.privateGrouping` metadata records the representation,
original size, operation count, group count and maximum dependency depth.

When both outer definitions have the supported layout, the generator can also
group the fixed precommit graph. It chooses the largest queue of operations
whose inputs are ready, then drains that operation code. An exact bijection
retains every operation, both ordered inputs and the root. Both outer graphs
then use grouped records, allowing the compiler to remove the legacy decoding
path. The optional `construction.precommitGrouping` metadata records the graph
and its final instruction offset. All affected precursor lengths and offsets
are updated before compression. The generator keeps its previous artifact if
the bounded candidates do not predict a gas saving or fit the compiled code
limits. Source-returning APIs retain their existing encodings.

The generator can then narrow the first input of private product nodes when
it refers to a terminal. Those inputs use a one-byte absolute reference;
all remaining references retain their two-byte backward distance. Stable
ordering by depth, operation code and the terminal flag preserves every node,
both ordered inputs and the root. The optional private-grouping kind is
`depth-code-product-terminal-u16-v1`. Constructor emission derives the same
ordering, and the complete installed program remains hash-bound. The precursor
and precommit graph remain unchanged. The same bounded compilation search
selects this representation only when a candidate predicts a saving and fits.

The latest validated arithmetic rate-3 artifact stores temporary factored-graph
field values in 16-byte cells. Every field equation, serialized operand and node
remains unchanged. Forward stores may clear the next uninitialized cell; the
allocation includes a final guard, and coordinate input arrays remain full width.
The generator tries this layout after selecting the storage and authenticated-input
formats. On an actual code-size failure, it tries the bounded lossless storage
encodings with minimum match lengths 32, 24, 20, 18, 16, 12 and 8, deduplicating
identical encodings. Every attempt preserves the full logical program and the
authenticated-input option. If none fits, it retains the complete preceding
artifact. Other compiler errors propagate. The
current selection excludes private graphs smaller than 12,000 nodes. The lower
threshold also admits the measured equality graph: its matched full-contract
comparison saves 62,931 original-proof call gas and 60,491 hinted call gas, with
eight actual-CREATE tests for each layout. The public generator emits that exact
packed equality artifact; its creation/runtime bytes, ABI, settings and metadata
are all checked against the tested version.

The construction path also uses direct suffix-table lookup for points of at most
nine coordinates, and releases consumed SHA working words before computing
Sigma0. These preserve the native polynomial and hash equations. Ordinary source
APIs retain their previous output. The packed layout and SHA schedule do not change
the proof, transcript, Merkle compression or security parameters.

The constructed reader now shares the byte-reversal steps within each 128-bit
half. Field and challenge reads select the required half directly; paired reads
exchange their stores. The complete 256-bit reversal remains for Noir public
inputs. The generator accepts this version only after checking the complete
constructor and runtime. The later FRI scale stage computes the product of
nonzero normalization factors once per oracle and applies it to every query and
terminal result before the original comparison. It regenerates the same lossless
storage format with minimum match length 40. All four circuit keys fit with the
shared reader and scale reuse; only an actual code-size failure triggers fallback.
The normalization stage then obtains each oracle's inverses from one inversion
of the product of its nonzero denominators. Zero denominators keep their original
handling, and every query and terminal value retains its final scale multiplication
before the original comparison. The complete constructor/runtime is checked again.

The subsequent SHA stages gather the same seven input words using repeated
37-bit shifts, and load each immutable state word once before extracting the
seven digests. Lane order, guard bits, endianness, partial-batch bounds, all
compression rounds and every digest comparison remain unchanged. Each stage
compiles the complete artifact and falls back only on an actual code-size failure;
other compiler errors propagate. Ordinary source APIs retain their prior output.
The next stage performs the same binary transpose using byte offsets and saved
butterfly inputs. Every basis bit and every pair of memory addresses is checked;
the field representation and all proof checks stay identical.
The following SHA stage replaces `x XOR (x AND mask)` with `x AND NOT(mask)`
when clearing rotation source bits. The expressions agree for every 256-bit
word; all packed lanes, guard bits and compression rounds remain identical.
The next stage uses bounded cursors for those same SHA round addresses. The
following stage factors common products in the fixed precommit polynomial, retaining
factor multiplicities and exact equality for arbitrary field coordinates.
After an actual initcode-size failure, the stage tries one additional lossless
compression option before retaining the complete preceding artifact. The
measured rate-1 key now fits with that option.

The fixed-arena stage reserves and clears call-local SHA scratch before allocating
the program. Literal addresses replace loads of the same constants, schedule and
state pointers; every SHA expression, round and comparison stays unchanged. The
generator checks the compiler's initial allocation and the Machine field layout,
then checks the complete constructor and runtime before selecting the artifact.
These four-key measurements also include the padding-schedule cache. It reuses
only the schedule of an identical final padding block, checks its length key,
and retains the complete compression rounds and digest comparisons.

The following stage shares the existing packed interpolation body across groups.
It preserves every operand, product and write in the original order. Groups larger
than 256 cells are split into consecutive halves; their 16-bit lengths bound the
additional split depth to eight. Its complete prototypes pass 40 deployment/proof
tests, including an independently blinded proof. Arithmetic CALL gas decreases
by 43,526, reaching **132,957,470** with program data and checked SHA hints;
equality saves 39,996. Runtime decreases by 91 bytes. Rate 1 fits after the existing
lossless compression retry. All four fresh public generations match those
tested artifacts. Evidence is in
`target/solidity-reports/group-chunk-padding-context/` and
`target/solidity-reports/shared-interpolation-integration/`.

A subsequent prototype schedules the same packed SHA rounds directly on the EVM
stack. It executes all 64 rounds with the original schedule, constants, masks,
rotations, choice and majority. Symbolic comparison of the actual optimized Yul
and decoded opcodes preserves every state output; independent scalar vectors and
EVM fuzz tests also pass. Its 40 complete deployment/proof tests across four keys
and two blinded rate-3 proofs measure **129,796,813 CALL gas** for the primary
program-plus-hinted path, a reduction of **3,160,657**. The second blinded proof
uses 130,637,683. The primary creation/runtime sizes are 48,876/24,503 bytes.

The backend now integrates this stage after shared interpolation, with an explicit
artifact binding. It matches the exact optimized equations as Yul tokens, confined
to the runtime object. An unrecognized optional layout or actual code-size failure
retains the preceding complete artifact; compiler failures propagate. Constructor
regeneration uses the typed circuit plan and the new compressed runtime. It checks
every preceding payload byte against the reconstructed prefix and requires the
final Yul compilation to preserve the candidate runtime exactly.

Solc maps the entire verbatim block to one source-map entry. The runtime checker
validates its exact opcodes, stack depth and internal loop before advancing that
entry, then retains every existing opcode and unmapped-tail check. The independent
EVM runner compiles both sources, checks that the complete runtime source differs
only by the proved round substitution, and compares deployed code to the fresh
Yul compiler output. The integrated deployments pass 40 fresh tests across all four keys and two
independently blinded rate-3 proofs. The primary rate-3 result is
**129,797,148 CALL gas**; its creation/runtime sizes are 48,905/24,503 bytes.
The small CALL difference from the prototype includes caller preparation for the
rebuilt creation artifact; the installed runtime is byte-for-byte identical.
Prototype evidence is in `target/solidity-reports/sha-stack-schedule/`;
generation and integration evidence is in
`target/solidity-reports/sha-stack-integration/`.

The optional version-2 stage also schedules the original SHA message-expansion
body on the stack. Its four input addresses, word equation and single output
store are unchanged, as are the enclosing loop and padding cache. The maintained
checker compares the decoded opcodes with the exact original 256-bit expression,
then independently checks 20,321 scalar steps and 896 complete lane expansions.
Both opcode blocks consume one source-map entry each and receive separate checks;
the remaining runtime is checked in full. An incompatible or oversized version-2
artifact falls back to the complete version-1 artifact. The primary rate-3
deployment measures **128,540,095 CALL gas**, saving 1,257,053 against version 1;
the independent proof measures **129,361,093**. Both use the same actual CREATE
artifact. All four keys and the independently blinded proof pass 40 fresh
deployment/proof tests. Rate-3 creation/runtime sizes are 48,905/24,499 bytes;
rate-2, rate-1 and equality program-plus-hinted CALLs are 134,926,932,
166,320,822 and 108,905,986 gas. Generation and integration evidence is in
`target/solidity-reports/sha-word-stack-integration/`.

Version 3 improves operand placement in the same round equations. It passes
40 fresh deployment/proof tests across four keys and an independently blinded
rate-3 proof. The primary and independent program-plus-hinted CALLs are
**128,251,903** and **129,068,485** gas; creation/runtime sizes are 48,905/24,498
bytes. Rate-2, rate-1 and equality calls are 134,609,172, 165,902,262 and
108,596,674. Generation and integration evidence is in
`target/solidity-reports/sha-round-placement-integration/`.

Version 4 advances a cursor through the constant table. Its block starts at
`0x1000`, advances by 32 and ends at `0x1800`; the schedule address is always
the cursor plus `0xa00`. The independent checker proves the original state
equations and all 64 address pairs. It passes 40 fresh CREATE/proof tests.
Program-plus-hinted CALLs measure **127,677,020** for the primary rate-3 proof
and **128,484,793** for the independent proof, using the same 48,905-byte
creation code and 24,496-byte runtime. Rate-2, rate-1 and equality measure
133,975,307, 165,067,322 and 107,979,661. Generation and integration evidence is
in `target/solidity-reports/sha-absolute-cursor-integration/`.

Version 5 removes four stack swaps from the message-expansion address calculations,
retaining the version-4 round block. The 288-byte word block has the same four
reads, one write and unrestricted 256-bit expression as the original Yul. Its
independent scalar check covers 20,321 steps and 896 complete lane expansions.
All 40 fresh deployment/proof tests pass across four circuit keys and both
blinded rate-3 proofs. Program-plus-hinted CALLs cost **126,838,940** for the
primary proof and **127,633,465** for the independent proof. Rate-2, rate-1 and
equality cost 133,055,435, 163,848,506 and 107,088,589 gas. Primary creation/runtime
sizes are 48,905/24,492 bytes and CREATE costs 517,544,983 gas. Generation and
integration evidence is in
`target/solidity-reports/sha-word-order-integration/`.

A later research prototype shares the packed core with scalar hashing, then
retains three masks on the stack to fit four rounds per loop. It preserves
all 64 rounds and passes independent round, continuation and digest models.
Its two genuine zk proof profiles save 1,446,424 / 1,556,759 instruction gas
over version 5 and fit in 24,545 runtime bytes. These are diagnostic profiles
with initialized storage, not deployment or verification CALL measurements.
Its research compiler object retains the preceding constructor payload and must
not be deployed. Version-6 integration regenerates that constructor from the
typed plan and binds both complete SHA functions before replacing them. Rust,
TypeScript and Python guards cover function-name reversal and unrelated source
changes. Independent opcode models check 2,254 lane compressions and 50 scalar
messages spanning 422 compression blocks against hashlib. See
`target/solidity-reports/sha-unified-stack-core/` for the sealed research evidence.

Version 6 now passes all 40 fresh actual deployment/proof tests across the four
circuit keys and both blinded rate-3 proofs. Program-plus-hinted CALLs cost
**125,392,516** for the primary proof and **126,076,706** for the independent
proof. Rate-2, rate-1 and equality cost 131,105,215, 161,350,126 and 105,256,671
gas. Primary CREATE costs 516,616,477 gas, with 48,617/24,545-byte init/runtime
and 56,763-byte ordinary Solidity init. Generation and integration evidence is
in `target/solidity-reports/sha-four-round-integration/`.
The measured optimization benefits fully checked hints; sharing the packed core
increases primary native-proof CALL from 160,343,160 to **170,878,475 gas**.
Raw native proofs still receive complete verification. This tradeoff does not
meet the 10-million target.

Version 7 retains intermediate stack layouts across the four
rounds and advances the cursor once per group. All 64 original constant/schedule
address pairs and 36 per-round output equations are checked independently.
All 40 fresh actual deployment/proof tests pass. Program-plus-hinted CALLs cost
**123,226,564** for the primary proof and **123,889,874** for the independent proof,
savings of 2,165,952 / 2,186,832 relative to version 6. Rate-2, rate-1 and equality
cost 128,766,655, 158,259,886 and 102,971,007 gas. Primary CREATE costs 517,132,896
gas, with 48,877/24,516-byte init/runtime and 57,042-byte ordinary Solidity init.
The native-only CALL costs 167,307,995, still above version 5's 160,343,160.
All native proof checks remain. Generation and integration evidence is
in `target/solidity-reports/sha-group-cursor-integration/`.

Version 8 preserves the ordered SHA word
equation and moves the complete 48-step expansion loop into a checked opcode block.
The complete original callee binds the Boolean cache flag and all surrounding
copies, cache updates and feed-forward. Independent models check 1,806 scalar
expansions and both cache outcomes. All 40 fresh actual deployment/proof tests
pass across the four keys and independently blinded proof. Program-plus-hinted
CALLs cost **122,478,194** for the primary proof and **123,134,079** for the
independent proof, saving 748,370 / 755,795 relative to version 7. Rate-2, rate-1
and equality cost 127,962,605, 157,191,386 and 102,188,617 gas. Primary CREATE
costs 517,142,024 gas, with 48,877/24,514-byte init/runtime and 57,057-byte
ordinary Solidity init. Primary native-only CALL is 166,060,170, still above
version 5's 160,343,160. Every native proof check is retained.

Validation includes 70 Rust/CLI tests, 8 TypeScript tests with 70 assertions,
9 source/runtime provenance tests, both word bodies, five round blocks, the
new expansion-loop model and three scalar continuation models. Generation and
integration evidence is in `target/solidity-reports/sha-word-loop-integration/`.
The 10-million CALL gas target remains unmet.

Version 9 shares the ROTR13/22 wrap correction under explicit stack scheduling.
Its smaller round block makes space for two unchanged word bodies per expansion
iteration. All 48 word steps and 64 SHA rounds still execute, including the
original ROTR2 guard bits. The round block temporarily owns 17 stack words while
every DUP/SWAP accesses only its own values at a depth of at most 16.

All 40 fresh deployment/proof tests pass across four keys and both blinded
rate-3 proofs. Program-plus-hinted CALLs cost **121,463,474** for the primary proof
and **122,109,279** for the independent proof, saving 1,014,720 / 1,024,800 relative
to version 8. Rate-2, rate-1 and equality cost 126,872,621, 155,742,554 and
101,128,201 gas. Primary CREATE costs 517,026,385 gas, with 48,745/24,563-byte
init/runtime and 56,904-byte ordinary Solidity init. Primary native-only CALL
is 164,367,402, still above version 5's 160,343,160. Every native proof check
is retained; the 10-million target remains unmet.

Validation includes 71 Rust/CLI tests, 8 TypeScript tests with 77 assertions,
10 source/runtime provenance tests, six round blocks, both word bodies and
expansion loops, and four scalar continuation models. Generation and integration
evidence is in `target/solidity-reports/sha-double-word-integration/`.

Version 10 retains the word cursor and six masks across four specialized word
bodies. It preserves every original word equation and ordered memory access.
All 40 fresh deployment/proof tests pass across four circuit keys and both
blinded rate-3 proofs. Program-plus-hinted CALLs cost **120,693,374** for the
primary proof and **121,331,529** for the independent proof, saving 770,100 /
777,750 relative to version 9. Rate-2, rate-1 and equality cost 126,045,401,
154,642,994 and 100,323,421 gas. Primary CREATE costs 517,087,415 gas, with
48,877/24,552-byte init/runtime and 57,033-byte ordinary Solidity init.
Primary native-only CALL is 163,082,712, improving by 1,284,690 from version 9
but still above version 5's 160,343,160. The 10-million target remains unmet.

Validation includes 72 Rust/CLI tests, 8 TypeScript tests with 84 assertions,
12 provenance tests, all six round models, the grouped-word model and five
scalar continuation models. Generation and integration evidence is in
`target/solidity-reports/sha-word-group-integration/`. The generated constructor
is rebuilt from the typed circuit plan; the earlier research constructor remains obsolete.

Version 11 retains all six round masks and carries W[i-2]/W[i-1] on the stack
through expansion. The exact word recurrence, all 48 ordered stores and all
64 rounds remain. The predecessor invariant replaces 46 repeated memory reads.
Derived mask prefixes are evaluated with exact 256-bit arithmetic, and both
complete SHA functions remain bound to their reference equations.

All **40 fresh deployment/proof tests pass** across four keys and both blinded
rate-3 proofs. Program-plus-hinted CALLs cost **120,243,678** for the primary
proof and **120,877,348** for the independent proof, saving 449,696 / 454,181
relative to version 10. Rate-2, rate-1 and equality cost 125,562,685,
154,000,846 and 99,854,095 gas. Primary CREATE costs 517,093,227 gas, with
48,877/24,544-byte init/runtime and 57,037-byte ordinary Solidity init.
Primary native-only CALL is 162,331,325, improving by 751,387 from version 10
but still above version 5's 160,343,160. The **10-million target remains unmet**.

Validation passes 73 Rust/CLI tests, 8 TypeScript tests with 91 assertions,
14 source/runtime provenance tests, seven round models, the paired-word model
and six scalar continuation models. All four public key-only generations are
complete and match the tested version-11 artifacts. Their bytecode, runtime,
ABI, compiler settings, construction metadata, sizes and runtime bindings are
identical; both complete source forms match except for comments and whitespace.
The validated generation records are in
`target/solidity-reports/sha-word-pair-integration/`. The prototype reports `sha-resident-round-masks`
and `sha-word-carry-pair` contain instruction profiles, while the integration
report contains the new actual CREATE/CALL measurements.

The read-only `sha-pair-cost-profile` binds those profiles to the identical
deployed runtime and attributes every executed instruction once. The primary
profile charges 49,535,222 gas to the two SHA blocks and 24,564,816 to the general
field multiplier. Its full instruction total is 117,265,507; the separate actual
CALL is 120,243,678 including caller preparation. These are current implementation
costs, not lower bounds on other algorithms or evidence that any proof check can
be skipped.

| Circuit and proof | Original-proof CALL gas | Hinted CALL gas | Program + original | Program + hinted |
| --- | ---: | ---: | ---: | ---: |
| Equality, rate 1 | 114,070,838 | 105,358,298 | 108,558,665 | 99,854,095 |
| Arithmetic, rate 1 | 195,955,580 | 162,849,601 | 187,059,331 | 154,000,846 |
| Arithmetic, rate 2 | 167,679,922 | 134,786,476 | 158,409,717 | 125,562,685 |
| Arithmetic, rate 3 | 162,331,325 | 129,525,526 | 153,003,442 | 120,243,678 |
| Independently blinded arithmetic, rate 3 | 162,964,995 | 130,159,196 | 153,637,112 | 120,877,348 |

The four fresh key-only public generations of version 11
match all ten checked artifact fields and both complete source forms of the measured
artifacts. Their binding reuses 40 successful actual CREATE/proof tests, including
an independently blinded rate-3 proof; it adds no duplicate EVM executions. The
integration build passes 69 Rust Solidity tests and four CLI tests. The transforms
match all four complete sources and reject incompatible equation/layout cases.
Every interpolation cell, field product, child reference, SHA round and word
recurrence remains. Generation bindings and actual tests are sealed in
`target/solidity-reports/sha-word-pair-integration/`.
Earlier padding, factoring, transpose, SHA and FRI comparisons remain in their
respective reports.

| Circuit | CREATE gas | Initcode bytes | Runtime bytes |
| --- | ---: | ---: | ---: |
| Equality, rate 1 | 343,939,352 | 32,162 | 24,438 |
| Arithmetic, rate 1 | 517,656,560 | 48,941 | 24,544 |
| Arithmetic, rate 2 | 516,749,433 | 48,743 | 24,544 |
| Arithmetic, rate 3 | 517,093,227 | 48,877 | 24,544 |

Rate 1 has **211 bytes** of initcode headroom; rate 3 has **275 bytes**. The
arithmetic runtime has **32 bytes** of headroom. The rate-3
ordinary companion Solidity initcode is 57,037 bytes; deploy the checked
artifact's creation code. CREATE costs exclude the artifact file read.

These call measurements include caller ABI encoding, cold program/digest storage
and a warm account; they exclude transaction intrinsic/calldata gas. The native
proof remains 373,976 bytes. **The 10-million-call-gas target remains unmet.**

The preceding authenticated-program checkpoint has these measured costs. Call gas includes the
test caller's ABI encoding, uses cold program storage and a warm account, and
excludes transaction intrinsic/calldata gas. Creation gas measures `CREATE`
after loading the artifact file, excluding the file read. These executions use
a raised local gas limit.

| Circuit | Original-proof call gas | Hinted call gas | Creation gas | Yul initcode bytes | Runtime bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| Native equality, rate 1 | 134,525,625 | 128,448,491 | 342,605,187 | 33,176 | 23,738 |
| Noir arithmetic, rate 1 | 218,289,399 | 194,559,731 | 517,607,600 | 49,119 | 23,948 |
| Noir arithmetic, rate 2 | 183,501,830 | 159,973,924 | 518,323,101 | 49,149 | 23,948 |
| Noir arithmetic, rate 3 | 175,619,601 | 152,143,500 | 517,149,094 | 49,151 | 23,948 |

In the preceding checkpoint, rate-3 product terminal references saved **318,169 original-proof
call gas** and **319,890 hinted call gas** against the preceding
precommit-grouping artifact. Creation used **936,533 more gas**.
The 16,900 private operations form
**469 groups**; the precommit graph retains
2,391 operations in 345 groups.
The complete logical program occupies **177,062 bytes**,
stored as **159,031 bytes**. The native field, SHA suite,
transcript, zero-knowledge checks, FRI checks and security parameters are unchanged.

That preceding checkpoint's companion Solidity constructor is **57,374 bytes**;
deploy the artifact's **49,151-byte** creation code, which has
**one byte** of headroom. It takes no arguments and
completes all initialization in one deployment. These code-size checks do not
imply that the transaction fits a chain's gas limit.

The original proofs retain the sizes listed in the first table. Rate 3 remains
**373,976 bytes**, or **389,120 with hints**. The native
file contains an **88-byte envelope and a 373,888-byte transcript**; no
verification program is included in that count. **The 10-million-call-gas
target remains unmet.** A separately blinded proof passes against the same
rate-3 artifact at **176,570,213 original-proof call gas** and
**153,094,112 hinted call gas**. Original proofs, hints, keys,
public inputs and corruption offsets remain unchanged.

The four generated artifacts and independent proof pass **40 complete EVM tests**:
real CREATE, complete native zero-knowledge and hinted verification, authenticated
circuit input, corrupted proofs and circuit bytes, runtime identity, the stored
digest and comparison of every stored byte. The generator passes **45 Rust
library tests**, **four CLI tests**, TypeScript checking and **seven Solidity API tests**.
The Rust CLI and TypeScript helper produce the exact inputs tested in the EVM
for all five cases; inconsistent metadata is rejected by the CLI.
Both source-returning modes were regenerated for all four keys; all eight
outputs are byte-for-byte identical to the preceding tested checkpoint.
The preceding six constructor EVM tests and five evaluator EVM tests cover product terminals,
including independent polynomial reference vectors and graph boundary cases.

The preceding 32 source API EVM tests and 17 primitive/FRI EVM tests cover
unchanged sources; these counts are historical. Remaining native instructions,
proof files, hints and public inputs are unchanged. Executable opcode checks
retain the ban on external calls, creation and storage writes during
verification. Evidence and exact measurements are recorded in
`target/solidity-reports/authenticated-program-integration/validation.json`.

The artifact EVM test reuses the full-proof and malformed-proof tests through an
overridden deployment function. The script independently compiles the emitted
Solidity as `BiniusVerifier.sol` with the recorded settings. It requires ABI equality
and, for ordinary artifacts, runtime-byte equality. For explicit Yul runtime mode,
it checks the reference runtime hash and the exact runtime source substitution,
then independently compiles the emitted Yul for both runtime and creation identity.
The EVM compares deployed code against that fresh compiler output. The compilation unit matters: solc
can emit a different optimized layout when identical source is compiled alongside
test contracts. A negative test with an altered SHA rotation is rejected before
deployment. The test performs a real `CREATE` from the emitted bytes and checks every stored
program byte against an independent decoder of the constructor payload. It also
recompiles the emitted Yul and requires identical creation bytecode. Caller
creation scratch is reclaimed before verification, and program storage is cooled
for call-gas measurements. Run it with a fixture produced by `solidity-e2e.sh`:

```console
python3 scripts/solidity-deployment-e2e.py \
  --fixture target/solidity-test \
  --output-dir target/deployment-e2e \
  --solc /path/to/solc-0.8.35
```

`--artifact path/to/BiniusVerifier.deployment.json` tests an existing deployment
against another proof for that key. The script uses a local EVM with raised gas
limits and writes all generated files under `--output-dir`.

## Optional authenticated circuit data

A deployment with `construction.programInput.kind == "keccak-calldata-v1"`
accepts `NBINK001 || public program bytes || native-or-hinted proof` through the
same `IVerifier.verify(bytes,bytes32[])` view function. The fixed program length
and digest appear in `programInput`; the bytes are `storageCompression.storedProgram`
when storage compression is present, otherwise `construction.verificationProgram`.
The helper `withVerifierProgram(proof, deployment)` is exported by the TypeScript
package; Rust exposes `solidity::with_verifier_program(&artifact, proof)`.
These framing helpers do not verify proofs. The contract performs verification.

The existing CLI can prepare a native proof with checked SHA hints and include
this circuit data in the same output:

```console
noir-binius write_solidity_proof -k circuit.vk -p circuit.binius \
  -o circuit.solidity-proof --deployment_path BiniusVerifier.deployment.json
```

The constructor first derives and checks the complete logical verification
program and any storage encoding. It records the resulting stored bytes' Keccak
digest in slot zero, then installs the same bytes at slots beginning at
`keccak256(abi.encode(uint256(0)))`. Its compile-time length replaces the old
length word in slot zero. Every constructor-rendering pass carries this typed
option, including the pass that embeds the compiler's complete runtime.

For framed input, `verify` bounds both calldata slices, checks the original native
or hinted envelope, copies exactly the fixed number of program bytes and requires
its Keccak digest to equal slot zero. Only then does it decompress the program
and run the native verification equations. Second-preimage resistance binds the
caller to the same circuit data already checked at construction. No proof values
select equations or replace proof checks. The Binius SHA suite and zero-knowledge
protocol remain unchanged; Keccak authenticates only this public circuit data.

Bare native and hinted proofs use the same installed storage and still work
immediately after deployment. There is no upload method, constructor argument,
external address or verifier call. If the optional code does not fit, generation
retains the preceding complete artifact and omits `programInput`; the framing
helper rejects unsupported artifacts. The extra public bytes are call data,
separate from the native proof, and proof size has no optimization target.

Calls with this optional input at the preceding authenticated-program checkpoint
were as follows. The completed version-11 four-key generator validation measured
**120,243,678 gas** for rate 3 with checked SHA hints, as recorded in the
compact-deployment section above.

| Circuit | Program + native proof call gas | Program + hinted proof call gas | Public program bytes |
| --- | ---: | ---: | ---: |
| Native equality, rate 1 | 129,395,441 | 123,325,700 | 86,786 |
| Noir arithmetic, rate 1 | 209,414,002 | 185,732,142 | 159,040 |
| Noir arithmetic, rate 2 | 174,251,569 | 150,769,974 | 159,018 |
| Noir arithmetic, rate 3 | 166,313,610 | 142,883,433 | 159,031 |

Rate 3 saves **9,305,991 gas** for native proofs and **9,260,067 gas** for hinted
proofs against the same artifact's storage path. The complete framed inputs are
533,015 and 548,159 bytes, including the eight-byte prefix. These are input
lengths, not native proof sizes. The separately blinded proof passes against the
same creation bytecode at 167,264,222 and 143,834,045 call gas respectively.
These measurements include caller ABI encoding, cold digest/data storage and a
warm account, and exclude transaction intrinsic/calldata gas. **The 10-million
call-gas target remains unmet.**

## Optional checked SHA hints

The generated contract accepts both formats immediately after deployment. Prepare
an optional hinted proof from its original native proof and matching key:

```console
cargo run --release -- write_solidity_proof \
  -k examples/arithmetic/target/arithmetic.vk \
  -p examples/arithmetic/target/arithmetic.binius \
  -o examples/arithmetic/target/arithmetic.hinted
```

Pass the resulting file bytes as the `proof` argument of the same `verify` call.
This command needs no witness and is not a contract initialization step. Native
`verify` and recursive aggregation continue to use the original `.binius` file.
The Rust API is `solidity::prepare_solidity_proof(verification_key, proof)`.

The wire format is `NBINH001 || original NBINZK01 bundle || 32-byte digests`.
The backend first validates the original proof and its metadata, then records
hash outputs using the pinned native `HasherChallenger` and `StdDigest`. Scoped
capture restores any enclosing recorder on errors or unwinding, and separate
threads have separate buffers. The initial SHA256(empty) is omitted from the
hints because the contract already fixes that value.

During verification, a hint temporarily supplies each Fiat-Shamir digest. The
contract copies the exact hash message, including the prior digest and native
little-endian consumed-byte counter, before reusing the transcript buffer. It
queues the copied, padded messages and recomputes them with the existing
seven-lane SHA implementation. After each compression block, a completed lane
checks its digest, takes the next message and resets only that lane's SHA state.
Longer messages keep their state while other lanes advance through shorter ones.
Every complete
32-byte digest must match before `verify` can return true. Starting from the fixed
initial digest, these equalities force the entire challenger state to match the
native challenger by induction. Missing, unused, malformed or incorrect hints are
rejected; zero digest values are not treated as empty queue entries.

The tests corrupt every hint in a multi-batch primitive case, random hinted
messages, representative hints in full proofs, and all eight sampled Merkle
advice offsets in both proof formats. They also reject changed public inputs,
truncated envelopes and trailing data. Mixed message lengths exercise padding
boundaries from empty through 8,192 bytes, lane replacement, scratch growth and
memory canaries around each retained message. All original sumcheck, field, wiring,
Merkle and FRI checks remain in the success path.

## What is being verified

The source of truth is the pinned `binius64` revision
`06fb4b86843d27930ee4af62781e6ac6acdecda7`. In that revision, zero knowledge uses
an outer Spartan circuit to attest the masked inner verifier messages. Replaying
the ordinary non-ZK verifier on those messages would be incorrect.

The contract executes these checks:

1. Validate proof magic, circuit digest, inverse rate, public-word count, exact
   transcript length and absence of trailing bytes. Reconstruct the ordered Noir
   inputs from the generated word layout and compare every input, including
   canonical BN254 scalar-field encoding.
2. Receive the outer precommit commitment, then observe the public words. Replay
   the inner verifier's interaction schedule and reconstruct the outer public
   instance `[constants | inout | derived]`. Masked private values are attested
   by the outer proof. The public wiring evaluation is recomputed and checked
   explicitly outside that outer circuit.
3. Verify the outer Spartan masked multiplication check, its sumchecks, and its
   public, precommit, private and mask wiring claims.
4. Run the single combined BaseFold opening over every inner and outer oracle.
   This includes relation batching, masking, the batched degree-two sumcheck,
   transparent-polynomial evaluations, padding factors, and the combined
   degree-one MLE check interleaved with FRI commitments.
5. Derive every FRI query index from the transcript, authenticate each Merkle
   layer and queried leaf, check the additive Gao–Mateer folds between rounds,
   authenticate the full terminal vector, check its repetition condition, and
   compare the terminal FRI value to the final MLE-check value.

The reachable upstream implementations include `verifier/src/zk_config.rs`,
`spartan-verifier/src/wrapper/zk_wrapped_channel.rs`, `spartan-verifier/src/lib.rs`,
`iop/src/basefold/{channel,opening}.rs`, `iop/src/fri/{verify,batch}.rs`,
`iop/src/merkle_channel.rs`, and `iop/src/merkle_tree/scheme.rs`, under upstream
`crates/`. [The upstream verifier documentation](https://docs.binius.xyz/binius_verifier/index.html)
describes the protocol modules; the pinned source, rather than an unversioned
documentation page, determines compatibility here.

## Specialization and trust boundary

`src/solidity/program.rs` runs the pinned generic verifier over symbolic
`FieldOps` and channel implementations. Arithmetic becomes fixed program
instructions, while Fiat-Shamir samples, proof reads and query indices remain
runtime inputs. The compiler receives only a verification key. It does not
receive a proof, run a proof-specific trace, fix challenges, or use private
witness data.

The specialized ZK wrapper preserves the original constant/public/private
distinctions and derived-wire allocation order. It checks that every public
instance slot was populated, then freezes that instance before evaluating
deferred transparent functions. The ordinary pinned outer Spartan and
BaseFold/FRI implementations supply the equations. All assertions and Fiat–Shamir
sampling boundaries survive dead-code elimination, and every observed byte
remains in order. Registers are reused only after their last reference.
The encoder checks that every referenced register fits its fixed allocation
and every scalar field read is at most 16 bytes. The interpreter reads register
slots and opcode metadata directly from memory: their addresses come from the
fixed generated program, never from proof values. The constructor is the only
writer of that program.

To keep the generated data small, the compiler replaces expanded calculations
with implementations of the same polynomials:

- Inner wiring contracts the operation, constraint, operand, inner-shift,
  outer-shift and value-address axes. Generation requires its scalar replay to
  reproduce the pinned native `WiringEvalFn` operation graph exactly.
- Outer wiring stores the exact sparse matrix entries as affine index runs.
  Every run is expanded and compared with the original matrix during generation.
  The encoding predicts the next row and column from the previous run's endpoint,
  then stores signed corrections. Decoding recovers every coordinate and stride;
  predictions and corrections retain more than 32 bits so endpoints beyond the
  maximum matrix index cannot truncate.
  In characteristic two, duplicate entries cancel by XOR. The public columns
  use a shared decision DAG, evaluated as `a + r*(a+b)` at each node.
- For a run, Solidity computes the full sum of
  `eq(x,row_i) * eq(y,column_i)`, batched with the native A/B/C weights.
  Aligned dyadic intervals are contracted algebraically. Four states track carries
  into row and column indices. Their total has a simpler recurrence than each
  state separately, so one outgoing state is recovered from the total instead
  of expanding all its products. When the row-offset bit and both row-carry
  states are zero, a two-state recurrence computes the next column carries with
  two field multiplications. The other two outgoing states remain zero. For a
  run whose length is within three entries of the next power of
  two, the evaluator can sum the complete interval and cancel its extra entries
  by XOR, after checking that the larger interval remains within both matrices.
  Arbitrary remaining strides use the explicit sum. Repeated carry prefixes share
  values only after an exact key match; collisions evict cached entries and cause
  recomputation. Each point pair has a fresh cache, including a directly indexed
  table of coordinate products `x_i*y_j`. Complemented coordinates use
  `(x+1)*(y+1)=x*y+x+y+1`. Each carry record stores all four 128-bit field values
  and its complete key in three EVM words. The key fits below bit 88; unpacking
  into separate scratch buffers preserves every state through cache replacement.
  The number of slots is a power of two, between 16 and 2,048, chosen from the
  run count. Coordinate-product entries use zero as a cache miss: an actual zero
  product is recomputed, so this requires no nonzero-field assumption. Carry and
  coordinate-product cache entries are cleared before a new point pair.
  The two outer matrices share their row point. Its equality tables and suffix
  memo are prepared at the first opening evaluation and retained for the second.
  Each matrix prepares its own column point in temporary memory and clears the
  carry and coordinate-product cache for that pair. Only values depending on the
  unchanged row point are reused. The compiler lets the prepared descriptor
  replace its raw-array register only after that array's final use; its point
  coordinates remain in their original memory allocation.
  Suffix equality tensors use
  chunks of up to nine coordinates, stored as cumulative sums. Adjacent
  differences recover individual entries. A strided interval is the difference
  of its two cumulative endpoints times the equality product of its fixed low
  coordinates. Combining higher and lower chunks uses
  `F_H + eq_H * F_L`; both zero and the exclusive domain endpoint are handled
  explicitly. Partial final chunks initialize only their actual coordinates.
  Fixed low coordinates use a short scalar product or marginalize the first
  chunk's tensor when at most three high coordinates remain.
  Suffix products spanning multiple chunks are memoized recursively at chunk
  boundaries. A recursive lookup of the last chunk reads its existing tensor
  entry directly, avoiding an additional memo lookup and insertion. Distinct low
  indices therefore reuse the product of their shared high coordinates. At most
  four chunks cover a u32 index. Repeated suffix evaluations use a separate cache
  owned by each prepared point.
  It has 4,096 slots and uses the high bits of a multiplicative hash to distribute
  the complete key across those slots.
  Its complete key includes the starting coordinate and all remaining index bits;
  a slot collision causes recomputation. Keys remain distinct at the maximum u32
  matrix index. These caches are local to the verification call.
- Vector operations, bit transposition, equality tensors and Frobenius powers
  retain the original field values and public-wire allocation order.
  Vector multiplication handles zero and one directly, with every other value
  using the field multiplier. An inner-wiring group whose axis coefficient is
  zero contributes exactly zero; its pure matrix evaluation can be omitted.
  Transcript operations and proof assertions are outside that evaluation.
- The compact FRI kernel must reproduce the native query verifier's complete
  symbolic graph and final transcript offset before generation succeeds.
  Its Gao–Mateer butterfly is evaluated using the identity
  `U + t*v + r*(v + U + t*v) = (1+r)*(U + (t+r/(1+r))*v)`, where `v=U+V`.
  For `r != 1`, the common scales are multiplied once after the linear folds,
  leaving one field multiplication per butterfly. For `r=1`, the butterfly is
  exactly `U+V`; that case is handled explicitly. Challenge normalization is
  computed from the actual transcript at runtime. Prefix XORs of the additive
  basis update consecutive twiddle factors without re-expanding each index.

Before serialization, contiguous proof observations are combined across arithmetic
operations, which do not access the challenger. Noncontiguous ranges stay in
order, and pending observations are flushed before any sample or verification
check. Rate 3 performs 432 observation copies instead of 1,119, without changing
a challenge or its input bytes.

Instruction operands and circuit tables are delta-coded, then compressed with
raw LZMA1 (fixed `lc=1, lp=0, pb=0`).
The encoder tries six combinations of match finder, search depth, and 64- or
273-byte match thresholds, keeping the shortest stream. All candidates use the
same decoder format, and include the previous two candidates so the expanded
search cannot increase any key's compressed size.
The generator checks the entire compression roundtrip. The constructor reverses
both encodings once. Expanded instruction operands use the smallest 1-, 2- or
4-byte width that fits every value in the fixed program. Field constants and
the contents of FRI/wiring tables keep their original encodings. The generator
requires widening to reproduce the complete program before operand narrowing
and checks that narrowing leaves its delta stream unchanged. With observation
coalescing, operand narrowing, matrix-coordinate prediction and shared row
preparation, rate 3 stores 123,523 program bytes instead of 171,098. Its compressed
constructor data occupies 20,929 bytes. Each `verify` call
copies the fixed number of storage slots into memory. The contract has no runtime
writer for this private storage. An optional calldata copy must match the fixed
program's authenticated digest, as described above; callers cannot choose a
different verification program.
Temporary wiring allocations are reclaimed
after their scalar result has been computed. The shared row descriptor is retained
across the two outer-matrix evaluations. The hash workspace is sized from
the largest observation epoch and scalar Merkle leaf in the fixed operation
schedule, rather than from the whole proof. Sampling resets the epoch; unobserved
query decommitments do not inflate this bound.
Unused interpreter operations are removed from each generated runtime. None of
these transformations reduces the query count, omits an assertion, or fixes a
Fiat–Shamir challenge in advance.

Creation and runtime bytecode must still fit the destination chain's limits.
Circuit size and structure affect the generated data. The depth-10
`keccak_merkle` example currently has circuit data that compresses to 472,997
bytes. Its fixed data alone exceeds the 49,152-byte initcode limit, so the
generator returns an explicit error for that circuit. The coordinate prediction
reduces the equality/arithmetic fixtures' data, but this example's compressed
data exceeds its earlier 432,730 bytes; it remains unsupported in either encoding.
It does not emit a deployable verifier for this example. The circuit's existing
native proof is 670,520 bytes; these program and proof sizes are separate.
Streaming the exact inner-wiring comparison allows compilation within about
4.62 GiB of resident memory, but does not solve the deployment-size limitation.

The generator rejects a compressed literal that already exceeds the initcode
limit. This is only a lower-bound check; the complete compiled contract still
requires a size check.
The EVM test script explicitly checks both bytecode size limits and rejects
external-call, creation, storage-write and self-destruct instructions in the
executable runtime. It uses Solc's instruction source map to separate constant
tables from code, then requires an `INVALID` separator and no possible
`JUMPDEST` in those tables. In explicit Yul mode the exact, separately checked
SHA opcode block consumes one source-map item; no remaining executable bytes are
skipped or exempted from the checks.

## Arithmetic and transcript compatibility

- The challenge field is GHASH: `GF(2^128)` with modulus
  `x^128 + x^7 + x^2 + x + 1`. Addition/subtraction are XOR. Yul performs carryless
  multiplication and polynomial reduction, squaring, and inversion by
  polynomial extended Euclid.
  Multiplication and squaring fuse the two reduction steps. Write the polynomial
  product as `L + x^128 H` and let `q = 1+x+x^2+x^7`. Canonical 128-bit inputs
  give a product of degree at most 254. The overflow of `q H` is therefore
  `E = (H >> 126) XOR (H >> 121)`, and the result is the low 128 bits of
  `L + q(H+E)`. Since `q E` has degree below 128, no further reduction remains.
  Proof field reads are always 16 bytes; word packing and bit decomposition also
  stay within 128 bits, including for malformed proofs.
  For nonzero `a`, inversion starts at `(u,v,r,t) = (a,P,1,0)`, where
  `P = x^128+x^7+x^2+x+1`. It preserves `r*a = u (mod P)` and
  `t*a = v (mod P)`. Swapping when the integer `u < v` orders their polynomial
  degrees; XORing `v << (CLZ(v)-CLZ(u))` into `u` cancels its leading term,
  with the same shifted update to `r`. At `u=1`, `r` is the inverse.
  The exact polynomial determinant `r*v XOR t*u = P` and the decreasing degree
  sum bound execution by 255 iterations. Coefficients stay below degree 128,
  so the EVM shifts cannot truncate them. Zero still maps to zero. Independent
  bit-serial products, comparison with the preceding exponentiation routine,
  basis/complement cases, and full native proofs check this implementation.
- Field elements are 16 little-endian bytes; public words are 8 little-endian
  bytes. Merkle digests remain uninterpreted 32-byte strings.
  Consecutive field vectors decode two elements from each 32-byte calldata word:
  reversing that word places the first field in its low half and the second in
  its high half. Each output occupies its own memory word and is exactly 128 bits.
  An odd final element uses a single 16-byte read. Scalar reads and challenge
  samples reverse only the first 16 input bytes and mask to the requested width.
  Generated Noir public-input checks retain the full 32-byte reversal, including
  all high limbs.
- The challenger starts with `SHA256(empty)`. Switching from sampling to
  observing prepends the current digest and the consumed sample-buffer index as
  a little-endian u64. Further sample buffers are hash-chain outputs. Bit samples
  always consume four bytes and are masked to the requested width.
- Merkle roots and protocol messages are observed. Query decommitment advice is
  not observed. The compiler fixes all proof-read offsets and the complete proof
  length from the circuit and FRI parameters.
- Leaves use ordinary SHA-256. Inner Merkle nodes use exactly one *unpadded*
  SHA-256 compression block. The initial state is the little-endian u32 words of
  `SHA256("BINIUS SHA-256 COMPRESS")`; output state words are little endian too.
  The zero-left / `00..1f`-right known-answer vector is
  `4731c4e3a3190d19dace68db5752af1b4ecf26305e75e85db86217662bbeff74`.

The original-proof path computes Fiat–Shamir hashes with a dedicated scalar
SHA-256 round function. The hinted path checks those same hashes in packed lanes.
For a 32-bit
word `x`, multiplying by `2^32+1` stores two identical copies. Right-shifting that
64-bit value by `n` yields `ROTR32(x,n)` in its low 32 bits. The message schedule
and working-state additions reduce modulo `2^32`; each new working word is then
duplicated again. Four rounds update the cyclic working-state roles in place
before exchanging the two groups of four working words. Sixteen groups execute all 64 SHA rounds,
with the same padding, constants and initial states as the backend. Scalar
feed-forward and digest extraction consume only the low 32 bits. Starting a
packed hash reinitializes every lane.

Both SHA implementations share the same 64 round constants and two initial
states, broadcast to seven lanes once when the verification call initializes its
hash workspace. The 80-word table contains the round constants, then the eight
standard SHA state words and eight Binius Merkle state words. Each new hash copies
its initial state from that table; compression never writes the table. Scalar
rounds use the low 32 bits; higher lanes cannot affect addition modulo `2^32`.
The message-schedule loops advance a memory pointer by one word, reading the
same four preceding words at byte displacements 480, 64, 512 and 224. They still
compute every schedule word from 16 through 63 in order.

Merkle hashing processes seven independent SHA-256 states in each EVM word.
Adjacent 32-bit state words are separated by five guard bits. For canonical
packed input `x` and lane-repeat constant `R`, the wrap term for a rotation by
`n` is `W_n = (x & (R * (2^n - 1))) << (32 - n)`. The cross-lane spill of
`x >> n` is exactly `W_n >> 32`. Therefore an XOR of rotations equals
`XOR(x >> n) ^ W ^ (W >> 32)`, where `W = XOR(W_n)`. Every wrap term stays
within its 32-bit payload, including the highest lane. The two schedule sigmas
and the round's Sigma1 share that correction. Sigma0 retains the split-input
rotation implementation, and general logical shifts mask their result.
Two operations can retain high guard bits until the existing
output mask. The schedule's right shift by three leaves at most `7*2^34` in
guard positions 34 through 36. Its four 32-bit summands add at most
`4*(2^32-1)`, giving `2^37-4`, below the next lane. Similarly, the round's
rotation by two can leave `3*2^35` in guard positions 35 and 36; its seven
32-bit summands keep the total below `2^37`. Neither case changes a payload
bit or permits a carry into another lane. Every schedule output and final A/E
word is masked back to 32 bits per lane. Working state and
feed-forward state use separate arrays to reduce stack spills during the rounds.
Packing each input block advances its input pointer by four bytes and its
schedule pointer by 32 bytes for all 16 words. Digest serialization gathers all
eight state words with fixed offsets, avoiding an inner indexing loop for every
lane. It shares the per-word byte reversal with proof decoding. All 64 rounds and
every query path are retained. Merkle caps are copied directly from calldata
using circuit-fixed bounds, then every parent hash is computed and the root
compared with its commitment. Authentication processes a complete
path level at a time, packing independent cache misses into the seven lanes.
A batch containing just one leaf or Merkle node uses the existing scalar rounds.
Leaves keep standard SHA padding; nodes keep the Binius domain IV, one unpadded
block and little-endian output. A singleton leaf sizes its scratch buffer before
copying the message, including room for the wide padding stores, even if no
previous batch allocated a larger buffer. Merkle compression preserves the input
children in scratch for the subsequent cache insertion.
A 256-entry cache stores the complete left child, right child, compression
result in three words. The parent index only chooses a slot: both full
32-byte children must match before reuse. Collisions cause recomputation, and
a zero result always causes recomputation, including when SHA actually produces
zero. This distinguishes empty entries without assuming a nonzero digest. Only
computed digests enter this cache, which lives in memory for one verification
call. Each original query still compares its result with the authenticated
layer. Advice hashing neither observes nor samples the challenger, so this
reordering leaves the Fiat–Shamir schedule unchanged.

## Reproducing the checks

Use Rust from `rust-toolchain.toml`, Foundry with Solidity 0.8.35 available, and
Nargo for the optional Noir example:

```sh
cargo test --locked --workspace
bun run --cwd packages/noir-binius-backend check
bun test ./packages/noir-binius-backend/test/solidity.test.ts
python3 scripts/sha_stack_check.py
python3 scripts/sha_word_stack_check.py
python3 scripts/sha_word_loop_check.py
python3 scripts/sha_word_group_check.py
python3 scripts/sha_pair_stack_check.py
python3 scripts/test_sha_stack_check.py
python3 scripts/test_solidity_gas_log.py
scripts/solidity-e2e.sh
scripts/solidity-e2e.sh arithmetic
LOG_INV_RATE=3 scripts/solidity-e2e.sh arithmetic
```

The default EVM fixture creates actual ZK proofs with a private witness and a
public equality constraint. Native tests cover zero and nonzero public words
and corruptions to both transcript messages and decommitment advice. The
contract test deploys the actual generated verifier and immediately calls
`IVerifier.verify`. It checks changed public inputs and counts, circuit digest,
transcript data and terminal data. The codec test compares every reconstructed
program byte with the native generator's output. Primitive tests compare
SHA-256 outputs, the native Merkle compression vector, and randomized field
operations against a separate bit-serial multiplication. Products at every
polynomial degree from 0 through 254 check the complete reduction basis; the
even degrees also check every basis input of squaring. Vector tests compare all
four operation modes, rotations, and zero/one/full-width operands against the
same independent scalar arithmetic. Field-decoding tests compare every output
with a byte-by-byte little-endian reference, including unaligned offsets, empty
and odd-length vectors, all-one inputs, and reads from zero through 16 bytes.
Sentinels check that vector decoding does not overwrite adjacent memory. The
same tests independently check all 32 bytes of Noir public-input reversal.
Wiring tests compare
the optimized interval/carry evaluator with explicit scalar sums, including
unaligned offsets, negative strides, Boolean points and randomized cases with
up to 32 coordinates. They
also check cancellation of excluded padding entries, cache collisions at large
and maximum u32 indices, and reuse of prepared points after temporary memory has
been overwritten. Envelope tests independently corrupt
the magic, circuit digest, rate, public-word count and transcript-length word.
Packed SHA tests compare every active lane with the EVM's independent SHA-256
implementation across padding boundaries, randomized messages, and dense words
with alternating neighboring lanes over multiple blocks. The helper starts with
small scratch space and checks neighboring memory after each hash; a 4,097-byte
singleton regression requires buffer growth before copying and padding. The verifier
itself never calls that precompile. Native path offsets select tampered siblings
in each of the first seven lanes and in the final query; all must be rejected.
A separate repeated-path test fills the cache with valid authentication paths,
then changes the leaf and each sibling of a repeated query in turn. Every
change must be rejected even when its parent index matches a cached entry.
FRI tests compare the normalized folds with the original butterfly formula for
zero through eight rounds, different query indices and challenge offsets, and
randomized field values. They explicitly include all-zero, all-one and mixed
challenge sequences. A Rust test checks transcript-workspace bounds across
consecutive observations, scalar/vector sampling, and scalar Merkle leaves.
No verifier mock is involved.

The optional example command compiles/executes Noir, proves with the backend,
generates the verifier from that artifact's key, and runs the same contract test.
`SKIP_NARGO=1` reuses compiled artifacts and witnesses. Generated source is written
under `solidity/src/`; fixtures and diagnostic reports are under `target/`.

The current direct generator rejects delegated recursive-proof metadata because
the backend verifies those recursive calls separately from the Binius
transcript. It must not silently omit those checks. The existing explicit SP1
target is a separate proof format and is not used by this implementation.

Independent cryptographic review and further reductions in gas remain
necessary before practical use under ordinary Ethereum gas limits. The tests
establish implementation evidence, not a soundness proof or an audit certification.
