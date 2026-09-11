#!/usr/bin/env bash
# Full native-prover -> generated Solidity -> local EVM verification.
set -euo pipefail
repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_dir"
forge_bin="${FORGE_BIN:-${HOME}/.foundry/bin/forge}"
if command -v forge >/dev/null 2>&1; then forge_bin="${FORGE_BIN:-forge}"; fi

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
  -k target/solidity-test.vk -o target/SolidityTestVerifier.sol

# Compile the complete generated source, including its constructor circuit data.
mkdir -p solidity/src
python3 - <<'PY'
from pathlib import Path
source = Path('target/SolidityTestVerifier.sol').read_text()
Path('solidity/src/NativeBiniusVerifier.sol').write_text(source)
runtime = Path('src/solidity/runtime.sol').read_text() + Path('src/solidity/fri.sol').read_text() + Path('src/solidity/codec.sol').read_text()
harness = '''// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.28;
contract BiniusPrimitives {
    uint256 private constant REGISTER_COUNT = 1;
'''+runtime+'''
    function wiringTest(bytes memory data,uint256[] memory x,uint256[] memory y,uint256 lambda) external pure returns(uint256 value) {
        uint256 d;uint256 xp;uint256 yp;
        assembly ("memory-safe") { d:=add(data,32) xp:=add(x,32) yp:=add(y,32) }
        return _wiring(d,xp,yp,lambda,1);
    }
    function decompressTest(bytes memory b,uint256 n) external pure returns(bytes memory){return _unlzma(b,n);}
    function expandTest(bytes memory b,uint256 n) external pure returns(bytes memory){return _expandProgram(b,n);}
    function mulTest(uint a,uint b) external pure returns(uint){return _mul(a,b);}
    function squareTest(uint a) external pure returns(uint){return _square(a);}
    function inverseTest(uint a) external pure returns(uint){return _inverse(a);}
    function shaTest(bytes calldata b) external pure returns(bytes32){Machine memory m=_machine(b.length);return _shaCalldata(m,b,0,b.length);}
    function nodeTest(bytes32 a,bytes32 b) external pure returns(bytes32){Machine memory m=_machine(64);return _node(m,a,b);}
    function readTest(bytes calldata b) external pure returns(uint){return _readLE(b,0,16);}
    function hashesTest(bytes calldata data,uint256 length,uint256 count) external pure returns(bytes32[4] memory) {
        require(data.length == count * length && count > 0 && count <= 4);
        Machine memory m = _machine(data.length);
        _leaves4(m,data,0,length,length,count);
        return m.batchDigests;
    }
    function nodesTest(bytes32[8] calldata data) external pure returns(bytes32[4] memory) {
        Machine memory m = _machine(288);
        bytes memory scratch=m.scratch;
        uint256 p;
        assembly ("memory-safe") {p:=add(scratch,32) calldatacopy(p,data,256)}
        _hashInit(m,true);_compress4(m,p,64);_digest4(m,true);
        return m.batchDigests;
    }
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
