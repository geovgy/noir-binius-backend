# Packed SHA round and message stack schedules

`rounds.yul` is the exact optimized equation sequence recognized by the generator.
It includes the eight state loads, all 64 rounds, and eight state stores. Matching
uses tokens inside the runtime object. Comments do not change eligibility;
different arithmetic, masks, addresses or loop bounds do. Versions 6 and later
also bind both complete scalar/packed functions under the two recognized solc
specialization-name orderings.

`round-block.hex` is the 488-byte replacement. It has zero net stack effect and
uses at most 13 of its own stack words. It neither reads nor modifies stack words
below its entry height. Its sole PC-relative branch returns to its internal loop
entry; all 64 rounds run. `round.asm` gives the readable 410-byte round body.

`round-placement-block.hex` and `round-placement.asm` retain exactly those
equations with improved last-use operand placement. The block is 487 bytes,
its round body is 409 bytes, and it preserves the same stack/memory invariants.
The original files remain available to validate version-1 and version-2 artifacts.

`round-cursor-block.hex` and `round-cursor.asm` use an absolute cursor into the
round constants: `p = 0x1000 + 32*i`. The constants load reads `p`; the schedule
load reads `p + 0xa00`. The block starts at `0x1000`, increments by 32, and stops
at `0x1800`, preserving all 64 pairs of addresses and all round equations.
This removes one address calculation per round. Its 485 bytes retain the same
13-word stack bound, internal branch, and eight working-state stores.

`round-four-block.hex` retains three literal masks below the nine working stack
values and concatenates four exact round bodies. Sixteen iterations still execute
all 64 rounds. The 1,290-byte block has a maximum of 16 owned stack words and
exactly eight working-state writes. Version 6 shares this packed core with scalar
calls after clearing the pending padding-cache request. Canonical state lanes and
masked feed-forward preserve the low-lane scalar digest across continued blocks.
The two full function references are `scalar-rounds.yul` and `packed-rounds.yul`;
`scalar-packed.yul` is the replacement wrapper. Unused scalar upper lanes can differ.

`round-group-block.hex`, the four `round-group-N.asm` files and
`round-group-orders.json` describe version 7. Each round retains its resulting
stack layout for the next round, with only the fourth restoring the entry layout.
The first three retain the group base cursor and read offsets 0/32/64; the fourth
reads offset 96 and advances the cursor by 128. The 1,261-byte block preserves all
64 constant/schedule address pairs, all 36 per-round output equations, the three
masks and the underlying stack. Its four bodies cost 1,245 gas per group, with
at most 16 owned stack words. The independent checker reconstructs the complete
prologue, all four bodies, sixteen iterations, relative branch and eight stores.

Each state or schedule word contains seven canonical 32-bit lanes at offsets
`37*i`. The pre-existing caller and schedule expansion preserve this invariant.
Constants start at `0x1000`, the schedule at `0x1a00`, and the working state at
`0x2300`. Only the eight state words through `0x23e0` are written. The input
schedule, constants, feed-forward state, padding cache and free pointer are
unchanged. All arithmetic is performed with ordinary EVM instructions.

`words.yul` is the optional exact message-expansion body. `word-block.hex` and
`word.asm` encode its 292-byte replacement: one cursor input, four reads at
cursor minus 480, 64, 512 and 224 bytes, then exactly one store at the cursor.
It uses at most seven stack words, has no branches, and preserves the original
loop bounds and padding cache. Its 256-bit expressions are exactly equal even
before restricting the inputs to canonical lanes. The independent scalar checker
also verifies 20,321 lane steps and 896 complete lane expansions.

`word-order-block.hex` and `word-order.asm` reorder the four constant-offset
subtractions: `DUPn; PUSH c; SWAP1; SUB` becomes `PUSH c; DUP(n+1); SUB`.
The same cursor remains live, so all four addresses and the final word are
unchanged. The block uses 288 bytes and 237 instruction gas instead of 292 bytes
and 249 gas. Both word blocks are checked against the original Yul equations
and the same independent scalar vectors.

Run from the repository root:

```sh
python3 scripts/sha_stack_check.py
python3 scripts/sha_word_stack_check.py
python3 scripts/sha_word_group_check.py
python3 scripts/sha_pair_stack_check.py
python3 scripts/test_sha_stack_check.py
cargo test --no-default-features --lib solidity::sha_stack::
```

The symbolic checker parses the actual Yul equations and decodes the actual
opcodes. It compares all nine loop outputs. Integer additions (including carries)
and nonlinear ANDs remain exact expressions; it normalizes only valid bit-linear
operations and associative/commutative operations. The independent numeric
interpreter checks 322 packed compressions against 2,254 scalar compressions,
including canonical basis, dense and random inputs, exact writes and stack
canaries. The Rust checker also pins the block hash and decodes the complete
stack/branch structure. These checks do not replace full native-proof EVM tests.

The deployment stage preserves the entire compiler object context. It regenerates
the constructor from the typed circuit plan and checks the complete compressed
prefix and candidate runtime. Both normal EVM bytecode limits still apply.
`runtimeCompilation` identifies the emitted Yul as the runtime compilation unit;
`yul-sha-rounds-v1` binds the round block, while `yul-sha-rounds-v2` additionally
binds `wordBlockSha256`. Version 3 uses the new round-placement block with the
same word block. The generator tries versions 3, 2 and 1 in order, retaining an
earlier complete artifact on incompatibility or ordinary code-size failure.
Version 4 adds the absolute constant-table cursor and is tried before version 3;
its separate hash binds the changed cursor initialization, bound and address math.
Version 5 retains the cursor block and pins the new word-operand-order block.
It is tried before version 4; all older block files and metadata hashes remain
available for independent verification of earlier artifacts.
Version 6 additionally requires `scalarCore: "packed"` and the checked four-round
block. Version 7 retains that source binding and the ordered word block while
pinning the group-cursor block separately. Version 8 also binds the complete
message-expansion initializer and loop with `word-loop.yul`. Its input is the
original Boolean cache flag: a hit skips expansion, and a miss computes exactly
W16 through W63 using the unchanged ordered word body. `sha_word_loop_check.py`
checks the branch structure, all reads and writes, both cache outcomes and 1,806
scalar expansions. Scalar continuation is also checked through these opcodes.
The Rust decoder verifies the fixed branch/loop shell and decodes the complete
word body, including its owned stack bound.
Version 9 shares the exact ROTR13/22 wrap correction and retains its two wrap
masks, reducing the round block's size without changing its gas. All 36 original
output equations, including ROTR2's guard bits, are checked. Its 17-word temporary
peak still uses only DUP1..16/SWAP1..16 and preserves the underlying stack.
The freed code space fits two unchanged expansion bodies per loop: the first
writes p and the second writes p+32, then p advances by64. Twenty-four iterations
perform all48 ordered word steps; the original Boolean cache hit skips them.
Both pinned loops are independently checked and exercised through scalar SHA
continuation against hashlib.
Version 10 retains six masks and a base cursor across four message words. Its
four `word-group-N.asm` bodies read and write at the original offsets relative
to `p + 32*N`; only the group advances p, by 128. Twelve groups execute all 48
steps in their original order. The third word's W[i-2] is exactly the base
cursor, so it needs no offset calculation. The 596-byte `word-group-block.hex`
has a maximum of 13 owned stack words, a cached-schedule skip, and seven final
POPs that remove the cursor and masks. `word-group-masks.json` gives the six
retained constants; one is derived by AND with a two-bit left shift of another.
The checker reconstructs the complete prefix, four bodies, branches and exit.
It compares each actual word expression with the original unrestricted 256-bit
equation and normalizes only its affine memory addresses. Full schedule and
scalar continuation models preserve all cache, stack and memory invariants.
The generator now prefers version 10,
then tries the earlier complete variants in order if source geometry or ordinary
code-size limits require a fallback. No external verifier call, precompile,
protocol change or weakening of proof checks is involved.
The complete Solidity body and its ordinary runtime hash remain available as the
semantic reference. Solc assigns the opaque block one source-map entry, so the
opcode checker validates the block separately before continuing the ordinary
scan and unmapped-tail checks.

Version 11 uses `round-retained-block.hex` and `word-pair-block.hex` together.
The round frame retains all six masks, whose exact values are checked against
seven copies of their 32-bit masks. The constant-only prefix derives two masks;
its uint256 shifts and Boolean operations are independently evaluated. The four
round bodies keep their existing equations and output order. Their20-word owned
stack peak still uses only DUP/SWAP depths through16 and preserves the caller
stack. Sixteen groups execute all64rounds, then remove allsixretainedmasks.

The word prefix uses checked constant identities and preloads W15/W14. At each
body entry the frame is [masks,p,W[i-1],W[i-2]]. Each body consumes the older word,
performs the other three original reads, and computes the original equation. It
stores W[i] at the original address and retains [W[i],W[i-1]] for the next body.
Eight specialized bodies and six iterations compute all48words in their original
order. The base advances by256 below the retained pair. Nine final POPs clean up
the frame; the original Boolean cache hit skips initialization and all writes.
This invariant replaces46repeatedreads without changing the full recurrence.

`sha_pair_stack_check.py` decodes each actual body, checks the predecessor order,
compares all original expressions, reconstructs both complete blocks and models
both cache outcomes with dirty schedule memory and stack canaries. Scalar SHA
continuation executes these same bytes. Rust also evaluates the constant prefixes
and decodes stack, memory and branch effects. The generator prefers version11
before version10 and the older exact variants, subject to ordinary size limits.
All full-source/callee/cache/feed-forward bindings and native zk checks remain.
