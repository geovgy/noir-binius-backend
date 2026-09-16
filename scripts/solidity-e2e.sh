#!/usr/bin/env bash
# Full native-prover -> generated Solidity -> local EVM verification.
set -euo pipefail
repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_dir"
forge_bin="${FORGE_BIN:-${HOME}/.foundry/bin/forge}"
if command -v forge >/dev/null 2>&1; then forge_bin="${FORGE_BIN:-forge}"; fi
solidity_options=()
if [[ -n "${SOLIDITY_COMPILER:-}" ]]; then
  solidity_options+=(--solidity_compiler "$SOLIDITY_COMPILER")
  export BINIUS_FACTORED_WIRING=1
fi

cargo build --locked
if [[ -n "${1:-}" ]]; then
  fixture="$1"
  if [[ ! "$fixture" =~ ^[a-z0-9_]+$ ]]; then
    echo "Expected an example name, such as arithmetic" >&2
    exit 1
  fi
  fixture_dir="$repo_dir/examples/$fixture"
  if [[ "${SKIP_NARGO:-0}" != "1" ]]; then
    (cd "$fixture_dir" && "${NARGO_BIN:-nargo}" execute)
  fi
  target/debug/noir-binius prove -b "$fixture_dir/target/$fixture.json" \
    -w "$fixture_dir/target/$fixture.gz" -o "$fixture_dir/target/$fixture.binius" \
    --log-inv-rate "${LOG_INV_RATE:-1}"
  NOIR_SOLIDITY_FIXTURE="$fixture" cargo test --locked solidity::program::tests::compiled_noir_fixture -- --ignored --nocapture
else
  BINIUS_EVM_FIXTURE=1 cargo test --locked solidity::program::tests::specialized_program_checks_real_zk_proofs -- --nocapture
fi
target/debug/noir-binius write_solidity_verifier \
  -k target/solidity-test.vk -o target/SolidityTestVerifier.sol "${solidity_options[@]}"
target/debug/noir-binius write_solidity_proof \
  -k target/solidity-test.vk -p target/solidity-test.binius -o target/solidity-test.hinted

# Compile the complete generated source, including its constructor circuit data.
mkdir -p solidity/src
python3 - <<'PY'
from pathlib import Path
import re
source = Path('target/SolidityTestVerifier.sol').read_text()
Path('solidity/src/NativeBiniusVerifier.sol').write_text(source)
runtime = Path('src/solidity/runtime.sol').read_text() + Path('src/solidity/fri.sol').read_text() + Path('src/solidity/codec.sol').read_text()
harness = '''// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.35;
contract BiniusPrimitives {
    uint256 private constant REGISTER_COUNT = 1;
    uint256 private constant HASH_CAPACITY = 0;
'''+re.search(r'    uint256 private constant PROGRAM_WORD_BYTES = \d+;', source)[0]+'\n'+runtime+'''
    function wiringTest(bytes memory data,uint256[] memory x,uint256[] memory y,uint256 lambda) external pure returns(uint256 value) {
        uint256 d;uint256 xp;uint256 yp;
        assembly ("memory-safe") { d:=add(data,32) xp:=add(x,32) yp:=add(y,32) }
        return _wiring(d,xp,yp,lambda,1);
    }
    function wiringReuseTest(bytes memory data,uint256[] memory x,uint256[] memory y,uint256 lambda) external pure returns(uint256 first,uint256 second) {
        uint256 d;uint256 xp;uint256 yp;
        assembly ("memory-safe") { d:=add(data,32) xp:=add(x,32) yp:=add(y,32) }
        xp=_wiring(d,xp,0,0,0);yp=_wiring(d,0,yp,0,3);
        first=_wiring(d,xp,yp,lambda,2);
        // Reuse reclaimed evaluation memory before using the prepared points
        // again. A stale carry-cache pointer must not affect the next call.
        assembly ("memory-safe") {
            let start:=mload(0x40)
            for {let i:=0} lt(i,131072) {i:=add(i,32)} {mstore(add(start,i),not(i))}
        }
        second=_wiring(d,xp,yp,lambda,2);
    }
    function wiringSharedRowTest(bytes memory data,uint256[] memory x,uint256[] memory y,uint256 lambda) external pure returns(uint256 first) {
        uint256 d;uint256 xp;uint256 yp;
        assembly ("memory-safe") { d:=add(data,32) xp:=add(x,32) yp:=add(y,32) }
        uint256 prepared=_wiring(d,xp,yp,lambda,0);
        first=_wiring(d,prepared,yp,lambda,4);
        // A different column point must not reuse carry products from the
        // first evaluation. Poison reclaimed scratch before preparing it.
        if(y.length!=0)y[0]^=1;
        assembly ("memory-safe") {
            let start:=mload(0x40)
            for {let i:=0} lt(i,131072) {i:=add(i,32)} {mstore(add(start,i),not(i))}
        }
        uint256 second=_wiring(d,prepared,yp,lambda,4);
        require(second==_wiring(d,xp,yp,lambda,1),"shared row kept stale column products");
    }
    function friCosetTest(
        uint256[] memory values, uint256 count, uint256 index,
        uint256[] memory challenges, uint256 offset, uint256[] memory basis
    ) external pure returns (uint256) {
        require(count <= 8 && values.length == 1 << count && offset + count <= challenges.length);
        require(basis.length > count && basis.length < 64 && index < 1 << (basis.length - count));
        uint256[] memory expanded = new uint256[](basis.length * 2);
        for (uint256 i; i < basis.length; ++i) {
            expanded[i] = basis[i];
            if (i != 0) expanded[basis.length + i] = expanded[basis.length + i - 1] ^ basis[i];
        }
        _friTwiddles(expanded);
        _normalizeFriChallenges(challenges, offset);
        return _friCoset(values, count, index, challenges, offset, expanded);
    }
    function vectorBinaryTest(uint128[128] memory left,uint128[128] memory right,uint128 scalar,uint256 kind,uint256 shift)
        external pure returns(uint256[128] memory output)
    {
        require(kind < 4 && shift < 128);
        uint256 a; uint256 b;
        assembly ("memory-safe") { a := left b := right }
        uint256 pointer = _vectorBinary(a,kind & 2 == 0 ? b : scalar,kind,shift);
        assembly ("memory-safe") { output := pointer }
    }
    function transposeTest(uint128[128] calldata input) external pure returns(uint256[128] memory output) {
        uint256[130] memory guarded;
        guarded[0] = 0x12345678;
        guarded[129] = type(uint256).max;
        for (uint256 i; i < 128; ++i) guarded[i + 1] = input[i];
        assembly ("memory-safe") { output := add(guarded, 32) }
        _transpose(output);
        require(guarded[0] == 0x12345678 && guarded[129] == type(uint256).max, "transpose crossed its allocation");
    }
    function decompressTest(bytes memory b,uint256 n) external pure returns(bytes memory){return _unlzma(b,n);}
    function expandTest(bytes memory b,uint256 n) external pure returns(bytes memory){return _expandProgram(b,n);}
    function mulTest(uint a,uint b) external pure returns(uint){return _mul(a,b);}
    function squareTest(uint a) external pure returns(uint){return _square(a);}
    function inverseTest(uint a) external pure returns(uint){return _inverse(a);}
    function checkHintMessages(bytes[] memory messages, bytes calldata hints) external pure returns (bool) {
        Machine memory m = _machine(0);
        uint256 start;
        assembly ("memory-safe") { start := hints.offset }
        m.hintAt = start;
        m.hintEnd = start + hints.length;
        bytes32[2] memory beforeRecords = [bytes32(uint256(123)), bytes32(type(uint256).max)];
        for (uint256 i; i < messages.length; ++i) {
            require(messages[i].length <= 8192);
            _recordSha(m, messages[i], 0, messages[i].length);
        }
        bytes32[2] memory afterRecords = [bytes32(type(uint256).max - 1), bytes32(uint256(456))];
        bool valid = _checkShaHints(m);
        require(beforeRecords[0] == bytes32(uint256(123)) && beforeRecords[1] == bytes32(type(uint256).max), "hint memory before");
        require(afterRecords[0] == bytes32(type(uint256).max - 1) && afterRecords[1] == bytes32(uint256(456)), "hint memory after");
        return valid;
    }
    function shaTest(bytes calldata b) external pure returns(bytes32){Machine memory m=_machine(b.length);return _shaCalldata(m,b,0,b.length);}
    function nodeTest(bytes32 a,bytes32 b) external pure returns(bytes32){Machine memory m=_machine(64);return _node(m,a,b);}
    function pathsReuseTest(bytes calldata first,bytes calldata second,uint256[] memory indices) external pure returns(bool,bool) {
        require(first.length == 128 + indices.length * 128 && second.length == first.length);
        for (uint256 q; q < indices.length; ++q) require(indices[q] < 32);
        Machine memory m = _machine(480);
        bool a = _paths(m,first,indices,0,0,128,2,3);
        bool b = _paths(m,second,indices,0,0,128,2,3);
        return (a,b);
    }
    function readTest(bytes calldata b) external pure returns(uint){return _readLE(b,0,16);}
    function readFieldsTest(bytes calldata b,uint256 offset,uint256 count) external pure returns(uint256[] memory values) {
        require(offset <= b.length && count <= (b.length - offset) / 16 && count <= 128);
        values = new uint256[](count + 2);
        values[0] = 0x12345678;
        values[count + 1] = type(uint256).max;
        uint256 dest;
        assembly ("memory-safe") { dest := add(values, 64) }
        _readFields(dest,b,offset,count);
    }
    function readWidthTest(bytes calldata b,uint256 offset,uint256 width) external pure returns(uint256) {
        require(width <= 16 && offset <= b.length && width <= b.length - offset);
        return _readLE(b,offset,width);
    }
    function reverseWordTest(bytes32 word) external pure returns(uint256) { return _reverse(uint256(word)); }
    function transcriptTest(bytes calldata data,uint256 priorBytes,uint256 split) external pure returns(uint256 first,uint256 second) {
        require(priorBytes <= 96 && split <= data.length);
        Machine memory m = _machine(data.length + 40);
        for (uint256 consumed; consumed < priorBytes;) {
            uint256 n = priorBytes - consumed;
            if (n > 16) n = 16;
            _sample(m,n);consumed += n;
        }
        _observe(m,data,0,split);
        _observe(m,data,split,data.length-split);
        first = _sample(m,16);second = _sample(m,16);
    }
    function hashesTest(bytes calldata data,uint256 length,uint256 count) external pure returns(bytes32[7] memory) {
        require(data.length == count * length && count > 0 && count <= 7);
        // Start with small scratch space so every large leaf must resize it.
        Machine memory m = _machine(0);
        bytes32[2] memory sentinel = [bytes32(uint256(0x12345678)),bytes32(type(uint256).max)];
        _leavesBatch(m,data,0,length,length,count);
        bytes32 first; bytes32 second;
        assembly ("memory-safe") { first := mload(sentinel) second := mload(add(sentinel,32)) }
        require(first == bytes32(uint256(0x12345678)) && second == bytes32(type(uint256).max), "hash scratch overwrote its neighbor");
        return m.batchDigests;
    }
    function nodesTest(bytes32[14] calldata data) external pure returns(bytes32[7] memory) {
        Machine memory m = _machine(480);
        bytes memory scratch=m.scratch;
        uint256 p;
        assembly ("memory-safe") {p:=add(scratch,32) calldatacopy(p,data,448)}
        _hashInit(m,true);_compressBatch(m,p,64);_digestBatch(m,true,7);
        return m.batchDigests;
    }
}
'''
codec = Path('src/solidity/codec.sol').read_text()
for width in [1, 2, 4]:
    harness += f'''\ncontract BiniusCodec{width} {{
    uint256 private constant PROGRAM_WORD_BYTES = {width};
'''+codec+'''
    function expandTest(bytes memory b,uint256 n) external pure returns(bytes memory){return _expandProgram(b,n);}
}
'''
Path('solidity/src/BiniusPrimitives.sol').write_text(harness)
PY
"$forge_bin" test --root solidity --match-path 'test/Binius*.t.sol' -vv

# Audit the compiled verifier's instructions as well as exercising its ABI.
python3 - <<'PY'
import json
from pathlib import Path
artifact = json.loads(Path('solidity/out/NativeBiniusVerifier.sol/BiniusVerifier.json').read_text())
constructor = [entry for entry in artifact['abi'] if entry['type'] == 'constructor']
assert len(constructor) == 1 and constructor[0]['inputs'] == []
functions = [entry for entry in artifact['abi'] if entry['type'] == 'function']
assert len(functions) == 1 and functions[0]['name'] == 'verify'
assert functions[0]['stateMutability'] == 'view'
assert [v['type'] for v in functions[0]['inputs']] == ['bytes', 'bytes32[]']
assert [v['type'] for v in functions[0]['outputs']] == ['bool']
runtime = artifact['deployedBytecode']
code = bytes.fromhex(runtime['object'].removeprefix('0x'))
metadata = len(code) - int.from_bytes(code[-2:], 'big') - 2
assert 0 <= metadata <= len(code)
# Solc may pool the field/SHA masks in a CODECOPY data table. The source map
# describes executable instructions, including PUSH immediates, but excludes
# that table. Also check that the unmapped table cannot be entered: INVALID
# prevents fallthrough and it must contain no possible JUMPDEST byte.
assert runtime['sourceMap'], 'missing executable source map'
offset = 0
for _ in runtime['sourceMap'].split(';'):
    assert offset < metadata, 'source map crosses into metadata'
    opcode = code[offset]
    assert opcode not in (0x55, 0x5d, 0xf0, 0xf1, 0xf2, 0xf4, 0xf5, 0xfa, 0xff), (offset, hex(opcode))
    offset += 1 + (opcode - 0x5f if 0x60 <= opcode <= 0x7f else 0)
assert offset <= metadata
if offset < metadata:
    assert code[offset] == 0xfe, 'unmapped data lacks an INVALID separator'
    assert 0x5b not in code[offset:metadata], 'unmapped data contains a possible jump destination'
assert len(code) <= 24576, 'runtime exceeds EIP-170'
initcode = bytes.fromhex(artifact['bytecode']['object'].removeprefix('0x'))
assert len(initcode) <= 49152, 'initcode exceeds EIP-3860'
print(f'Verifier initcode: {len(initcode)} bytes; ready immediately after construction')
print(f'Verifier runtime: {len(code)} bytes; no external-call, creation or storage-write instructions')
PY
