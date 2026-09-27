#!/usr/bin/env python3
"""Generate and test a direct verifier deployment from a native proof fixture.

The fixture prefix names .vk, .binius, .inputs and .corruptions files produced
by solidity-e2e.sh. All generated files stay in --output-dir. No chain RPC is
used. --artifact tests an existing deployment against another matching proof.
"""
import argparse
import hashlib
import json
import lzma
import os
from pathlib import Path
import re
import shutil
import subprocess


def gas_measurement(log, label):
    """Read one complete label, independent of parallel test output order."""
    matches = re.findall(r'^[ \t]*' + re.escape(label) + r': ([0-9]+)[ \t]*$', log, re.MULTILINE)
    assert len(matches) == 1, f'expected one gas measurement for {label!r}, found {len(matches)}'
    return int(matches[0])


def expand_operands(encoded, width, byte_ranges=None):
    """Independent decoder for the fixed program's delta operand stream."""
    assert width in (1, 2, 4)
    at = 0
    output = bytearray()
    previous = [[0] * 8 for _ in range(32)]

    def copy(count):
        nonlocal at
        assert 0 <= count <= len(encoded) - at, "truncated instruction data"
        data = encoded[at:at + count]
        at += count
        output.extend(data)
        return data

    def number(op, lane):
        nonlocal at
        value = shift = 0
        while True:
            assert at < len(encoded) and shift < 64, "invalid operand varint"
            byte = encoded[at]
            at += 1
            value |= (byte & 127) << shift
            if not byte & 128:
                break
            shift += 7
        delta = -(value // 2) - 1 if value & 1 else value // 2
        value = previous[op][lane] + delta
        assert 0 <= value < 1 << (8 * width), "operand exceeds selected width"
        previous[op][lane] = value
        output.extend(value.to_bytes(width, 'big'))
        return value

    while at < len(encoded):
        op = copy(1)[0]
        assert op < 32, "unknown verifier opcode"
        number(op, 0)
        if op == 0:
            copy(16)
        elif op in (1, 2, 8):
            number(op, 1)
            number(op, 2)
        elif op in (3, 5, 9, 27, 28, 31):
            number(op, 1)
        elif op in (4, 10, 11, 12, 18, 22):
            number(op, 1)
            copy(1)
        elif op in (6, 13):
            pass
        elif op == 7:
            copy(1)
        elif op in (14, 20):
            for lane in range(1, 4):
                number(op, lane)
        elif op == 15:
            for lane in range(1, 6):
                number(op, lane)
        elif op in (16, 24):
            for lane in range(1, 5):
                number(op, lane)
            if op == 24:
                copy(1)
        elif op == 17:
            for _ in range(128):
                number(op, 1)
        elif op == 19:
            for _ in range(number(op, 1)):
                number(op, 2)
        elif op in (21, 23, 25, 30):
            length = number(op, 1)
            start = len(output) - width
            copy(length)
            if op == 21 and byte_ranges is not None:
                byte_ranges.append((start, len(output)))
        elif op == 26:
            number(op, 1)
            number(op, 2)
            copy(2)
        elif op == 29:
            for _ in range(copy(1)[0]):
                number(op, 1)
        else:
            raise AssertionError(f'unknown verifier opcode {op}')
    return bytes(output)


def expand_public(program, config, byte_ranges):
    """Independently expand the public graph's exact child-reference records."""
    assert config['kind'] in ['relative-u16-v1', 'grouped-relative-u16-v1']
    grouped = config['kind'] == 'grouped-relative-u16-v1'
    assert len(program) == config['sourceLength']
    start = config['instructionOffset']
    assert 0 <= start <= len(program) - 5 and program[start] == 23
    length = int.from_bytes(program[start + 3:start + 5], 'big')
    data = program[start + 5:start + 5 + length]
    assert len(data) == length and length >= 25
    leaves = int.from_bytes(data[:4], 'big')
    nodes = int.from_bytes(data[4:8], 'big')
    dimensions = data[8]
    assert leaves > 0 and dimensions <= 64
    assert all(int.from_bytes(data[i:i + 4], 'big') < leaves + nodes for i in [9, 13, 17])
    at = 25 + 4 * dimensions
    assert at <= len(data)

    def number():
        nonlocal at
        value = 0
        for shift in range(0, 35, 7):
            assert at < len(data)
            byte = data[at]
            at += 1
            value |= (byte & 127) << shift
            if byte < 128:
                assert value < 1 << 32
                return value
        raise AssertionError('invalid public operand varint')

    def delta(value):
        return value // 2 if value % 2 == 0 else -1 - value // 2

    previous = [0, 0]
    for _ in range(leaves):
        value = number()
        kind = value & 1
        previous[kind] += delta(value >> 1)
        assert 0 <= previous[kind] < 1 << 32
        if kind:
            assert at < len(data) and data[at] < 128
            at += 1
    fixed = bytearray(data[:at])
    previous = [0] * 4
    group_at = None
    group_bit = 256
    group_count = 0
    for i in range(nodes):
        assert at < len(data)
        code = data[at]
        at += 1
        assert code >> 2 < dimensions
        bit = code >> 2
        if grouped:
            if bit != group_bit or group_count == 65535:
                if group_at is not None:
                    fixed[group_at + 1:group_at + 3] = group_count.to_bytes(2, 'big')
                group_at = len(fixed)
                fixed.extend([bit, 0, 0])
                group_bit = bit
                group_count = 0
            group_count += 1
        else:
            fixed.append(bit)
        for j in range(2):
            kind = (code >> j) & 1
            lane = 2 * j + kind
            previous[lane] += delta(number())
            child = previous[lane]
            assert 0 <= child < leaves + i and int(child >= leaves) == kind
            distance = leaves + i - child
            assert 0 < distance < 65536
            fixed.extend(distance.to_bytes(2, 'big'))
    if grouped and group_at is not None:
        fixed[group_at + 1:group_at + 3] = group_count.to_bytes(2, 'big')
    assert at == len(data) and len(fixed) == config['fixedLength'] < 65536
    extra = len(fixed) - len(data)
    output = program[:start + 3] + len(fixed).to_bytes(2, 'big') + fixed + program[start + 5 + length:]
    ranges = [(a + (extra if a > start + 3 else 0), b + (extra if b > start + 3 else 0)) for a, b in byte_ranges]
    return output, ranges


def expand_storage(data, length):
    """Independent bytewise decoder, including overlapping backward copies."""
    at = 0
    output = bytearray()
    while at < len(data):
        assert at + 4 <= len(data), 'truncated storage record'
        literal, count = data[at], data[at + 1]
        distance = int.from_bytes(data[at + 2:at + 4], 'big')
        at += 4
        assert at + literal <= len(data) and len(output) + literal + count <= length
        output.extend(data[at:at + literal])
        at += literal
        if count:
            assert 0 < distance <= len(output)
            for _ in range(count):
                output.append(output[-distance])
        else:
            assert distance == 0
    assert len(output) == length
    return bytes(output)


def copy_storage_literals(program, headers):
    """Independently reproduce the constructor's fixed copying plan."""
    assert len(headers) % 4 == 0
    output = bytearray()
    at = 0
    for start in range(0, len(headers), 4):
        header = headers[start:start + 4]
        literal, count = header[0], header[1]
        assert at + literal + count <= len(program)
        output.extend(header)
        output.extend(program[at:at + literal])
        at += literal + count
    assert at == len(program)
    return bytes(output)


def check_private_grouping(data, config):
    """Check all grouped references, plus depth/code ordering when specified."""
    assert config['kind'] in ['depth-code-grouped-u16-v1', 'code-grouped-u16-v1', 'depth-code-product-terminal-u16-v1']
    by_depth = config['kind'] != 'code-grouped-u16-v1'
    products = config['kind'] == 'depth-code-product-terminal-u16-v1'
    assert data[0] == 255 and data[1] & 128
    nx, ny = data[1] & 127, data[2]
    assert 0 < nx + ny <= 36
    first = 8 + 2 * (nx + ny)
    at = 3

    def number():
        nonlocal at
        value = 0
        for shift in range(0, 28, 7):
            octet = data[at]
            at += 1
            value |= (octet & 127) << shift
            if octet < 128:
                return value
        raise AssertionError('oversized grouped graph varint')

    count, root, a_bytes = number(), number(), number()
    assert count == config['nodes'] and count + first <= 65536
    assert root < count + first and a_bytes == 2 * count
    depth = [0] * first
    groups = 0
    previous = (0, 0, False)
    while len(depth) < count + first:
        code = data[at]
        short = products and code == 128
        if short:
            code = 0
        length = int.from_bytes(data[at + 1:at + 3], 'big')
        assert code <= 2 * (nx + ny) and 0 < length <= count + first - len(depth)
        at += 3
        groups += 1
        for _ in range(length):
            width = 1 if short else 2
            assert at + width + 2 <= len(data)
            a = int.from_bytes(data[at:at + width], 'big')
            b = int.from_bytes(data[at + width:at + width + 2], 'big')
            assert 0 < b <= len(depth)
            b = len(depth) - b
            if short:
                assert a < first
            else:
                assert 0 < a <= len(depth)
                a = len(depth) - a
            if products:
                assert short == (code == 0 and a < first)
            value = 1 + max(depth[a], depth[b])
            assert value <= 4096
            if by_depth:
                assert previous <= (value, code, short)
            previous = (value, code, short)
            depth.append(value)
            at += width + 2
    assert at == len(data) and groups == config['groups']
    assert max(depth) == config['maxDepth']
    assert len(data) < config['originalLength']


def main():
    repo = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--solc', type=Path, required=True)
    parser.add_argument('--binary', type=Path, default=repo / 'target/release/noir-binius')
    parser.add_argument('--forge', type=Path, default=Path.home() / '.foundry/bin/forge')
    parser.add_argument('--artifact', type=Path)
    args = parser.parse_args()
    fixture = args.fixture.resolve()
    dest = args.output_dir.resolve()
    dest.mkdir(parents=True, exist_ok=True)
    binary, solc, forge = map(lambda path: str(path.resolve()), (args.binary, args.solc, args.forge))

    def run(command, log, **kwargs):
        with (dest / log).open('w') as file:
            completed = subprocess.run(command, stdout=file, stderr=subprocess.STDOUT, **kwargs)
        if completed.returncode:
            raise SystemExit(f'Command failed ({completed.returncode}); see {dest / log}\n'
                             + (dest / log).read_text()[-4000:])

    for ext in ('vk', 'binius', 'inputs', 'corruptions'):
        source, target = Path(f'{fixture}.{ext}'), dest / f'fixture.{ext}'
        if source != target:
            shutil.copyfile(source, target)
    output = dest / 'BiniusVerifier.deployment.json'
    if args.artifact:
        if args.artifact.resolve() != output:
            shutil.copyfile(args.artifact, output)
    else:
        run([binary, 'write_verifier_deployment', '-k', str(dest / 'fixture.vk'),
             '-o', str(output), '--solc', solc], 'generation.log')
    # This runs the pinned native verifier before recording any optional hint.
    run([binary, 'write_solidity_proof', '-k', str(dest / 'fixture.vk'),
         '-p', str(dest / 'fixture.binius'), '-o', str(dest / 'fixture.hinted')], 'native-verification.log')
    artifact = json.loads(output.read_text())
    source = artifact['soliditySource']
    creation = bytes.fromhex(artifact['bytecode'].removeprefix('0x'))
    runtime = bytes.fromhex(artifact['deployedBytecode'].removeprefix('0x'))
    assert artifact['contractName'] == 'BiniusVerifier'
    assert 0 < len(creation) == artifact['initcodeBytes'] <= 49152
    assert 0 < len(runtime) == artifact['runtimeBytes'] <= 24576
    assert artifact['compilerSettings']['version'] == '0.8.35'
    assert 'contract BiniusVerifier is IVerifier' in source
    key_hash = hashlib.sha256((dest / 'fixture.vk').read_bytes()).hexdigest()
    assert f'BINIUS_VERIFICATION_KEY_HASH = hex"{key_hash}";' in source, 'artifact uses a different verification key'
    assert [entry['type'] for entry in artifact['abi']] == ['constructor', 'function']
    assert artifact['abi'][0]['inputs'] == []
    function = artifact['abi'][1]
    assert function['name'] == 'verify' and function['stateMutability'] == 'view'
    assert [item['type'] for item in function['inputs']] == ['bytes', 'bytes32[]']
    assert [item['type'] for item in function['outputs']] == ['bool']

    # Independently recover every installed program byte and the runtime suffix.
    def constant(name):
        return int(re.search(r'uint256 private constant ' + name + r' = (\d+);', source)[1])

    payload = re.search(r'_unlzma\(hex"([0-9a-f]+)", (\d+)\)', source)
    assert payload, 'missing joint constructor payload'
    compressed = bytes.fromhex(payload[1])
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=[
        dict(id=lzma.FILTER_LZMA1, dict_size=1 << 20, lc=1, lp=0, pb=0)
    ])
    joint = decoder.decompress(compressed, max_length=int(payload[2]))
    assert len(joint) == int(payload[2])
    encoded_length = constant('ENCODED_PROGRAM_LENGTH')
    encoded = joint[:encoded_length]
    construction = artifact.get('construction')
    storage = construction.get('storageCompression') if construction else None
    headers = bytes.fromhex(storage['packingHeaders'].removeprefix('0x')) if storage else b''
    assert joint[encoded_length:encoded_length + len(headers)] == headers
    assert joint[encoded_length + len(headers):] == runtime, 'constructor runtime differs from artifact'
    byte_ranges = []
    precursor = expand_operands(encoded, constant('PROGRAM_WORD_BYTES'), byte_ranges)
    if construction and construction.get('publicExpansion'):
        assert constant('PROGRAM_WORD_BYTES') == 2
        precursor, byte_ranges = expand_public(precursor, construction['publicExpansion'], byte_ranges)
    if construction is None:
        program = precursor
    else:
        assert construction['kind'] == 'affine-matrix-v1'
        assert constant('PROGRAM_WORD_BYTES') == 2
        assert len(precursor) == construction['precursorLength']
        program = bytes.fromhex(construction['verificationProgram'].removeprefix('0x'))
        length_at = construction['matrixLengthOffset']
        input_at = construction['matrixInputOffset']
        output_at = construction['matrixOutputOffset']
        affine_length = construction['affineLength']
        matrix_length = construction['matrixLength']
        assert (length_at, input_at + affine_length) in byte_ranges
        assert input_at == length_at + 2
        assert int.from_bytes(precursor[length_at:input_at], 'big') == affine_length
        if construction['escapedMatrixLength']:
            assert matrix_length >= 65535 and output_at == length_at + 6
            assert program[length_at:output_at] == b'\xff\xff' + matrix_length.to_bytes(4, 'big')
        else:
            assert matrix_length < 65535 and output_at == length_at + 2
            assert program[length_at:output_at] == matrix_length.to_bytes(2, 'big')
        assert program[:length_at] == precursor[:length_at]
        assert program[output_at + matrix_length:] == precursor[input_at + affine_length:]
        assert program[output_at] == 255
        if construction.get('privateGrouping'):
            assert construction['privateGrouping']['kind'] in ['depth-code-grouped-u16-v1', 'depth-code-product-terminal-u16-v1']
            if construction['privateGrouping']['kind'] == 'depth-code-product-terminal-u16-v1':
                assert construction.get('precommitGrouping') and len(byte_ranges) == 2
            check_private_grouping(program[output_at:output_at + matrix_length], construction['privateGrouping'])
        else:
            assert program[output_at + 1] & 128 == 0, 'grouped matrix metadata is missing'
        if construction.get('precommitGrouping'):
            config = construction['precommitGrouping']
            assert config['kind'] == 'code-grouped-u16-v1'
            assert construction.get('privateGrouping') and len(byte_ranges) == 2
            start, end = byte_ranges[0]
            assert start == config['instructionOffset'] + 3
            assert byte_ranges[1] == (length_at, input_at + affine_length)
            assert precursor[config['instructionOffset']] == 21
            assert int.from_bytes(precursor[start:start + 2], 'big') == end - start - 2
            assert end <= length_at
            check_private_grouping(precursor[start + 2:end], config)
        else:
            for start, end in byte_ranges:
                if start != length_at and precursor[start + 2] == 255:
                    assert precursor[start + 3] & 128 == 0, 'precommit grouping metadata is missing'
        assert f"keccak256(data) == {construction['programKeccak256']}" in source
        (dest / 'precursor.program').write_bytes(precursor)
    assert len(program) == constant('VERIFICATION_PROGRAM_LENGTH')
    stored = program
    if storage:
        assert storage['kind'] == 'literal-copy-v1'
        stored = bytes.fromhex(storage['storedProgram'].removeprefix('0x'))
        assert expand_storage(stored, len(program)) == program
        assert copy_storage_literals(program, headers) == stored
        assert f"keccak256(data) == {storage['storedProgramKeccak256']}" in source
    program_input = construction.get('programInput') if construction else None
    if program_input:
        assert program_input['kind'] == 'keccak-calldata-v1'
        assert program_input['magic'] == '0x4e42494e4b303031'
        assert program_input['programLength'] == len(stored)
        digest = storage['storedProgramKeccak256'] if storage else construction['programKeccak256']
        assert program_input['programKeccak256'] == digest
        assert 'bytes32 private verificationProgramHash;' in source
        assert 'sstore(verificationProgramHash.slot, keccak256(add(data, 32), length))' in source
        assert 'sload(verificationProgramHash.slot)' in source
        for ext in ('binius', 'hinted'):
            (dest / f'fixture.key-{ext}').write_bytes(b'NBINK001' + stored + (dest / f'fixture.{ext}').read_bytes())
    (dest / 'stored.program').write_bytes(stored)
    (dest / 'packing.headers').write_bytes(headers)
    for name, value in [('fixture.program', program), ('fixture.encoded', encoded),
                        ('joint.lzma', compressed), ('creation.bin', creation), ('runtime.bin', runtime)]:
        (dest / name).write_bytes(value)
    (dest / 'BiniusVerifier.sol').write_text(source)
    (dest / 'BiniusVerifier.yul').write_text(artifact['yulSource'])
    # Recompile the exact reference Solidity and the advertised runtime unit.
    # Unrelated test contracts can change solc's optimized runtime layout; their
    # type(...).runtimeCode is not this artifact's compiler output. Do not trust
    # the runtime stored in the artifact as the independent compiler reference.
    solidity_settings = artifact['compilerSettings']['solidity']
    assert solidity_settings == {
        'optimizer': {'enabled': True, 'runs': 200}, 'viaIR': True,
        'evmVersion': 'osaka', 'metadata': {'bytecodeHash': 'none'},
    }
    compiler_input = {
        'language': 'Solidity', 'sources': {'BiniusVerifier.sol': {'content': source}},
        'settings': solidity_settings | {'outputSelection': {'*': {'BiniusVerifier': [
            'abi', 'irOptimized', 'evm.bytecode.object', 'evm.deployedBytecode.object', 'evm.deployedBytecode.sourceMap',
        ]}}},
    }
    (dest / 'BiniusVerifier.compiler-input.json').write_text(json.dumps(compiler_input) + '\n')
    result = subprocess.run([solc, '--standard-json'], text=True, capture_output=True, check=True,
                            input=json.dumps(compiler_input))
    result = json.loads(result.stdout)
    assert not [error for error in result.get('errors', []) if error['severity'] == 'error'], result
    contract = result['contracts']['BiniusVerifier.sol']['BiniusVerifier']
    compiled = {'abi': contract['abi'], **contract['evm']}
    compiler_runtime = bytes.fromhex(compiled['deployedBytecode']['object'])
    binding = artifact.get('runtimeCompilation')
    if binding is None:
        assert compiler_runtime == runtime, 'emitted Solidity compiles to a different artifact runtime'
    else:
        from sha_stack_check import BLOCK_HASH, PLACEMENT_HASH, CURSOR_HASH, FOUR_HASH, GROUP_HASH, SIGMA_HASH, RETAINED_HASH, load_block, validate_runtime, validate_source
        assert binding['kind'] in ('yul-sha-rounds-v1', 'yul-sha-rounds-v2', 'yul-sha-rounds-v3', 'yul-sha-rounds-v4', 'yul-sha-rounds-v5', 'yul-sha-rounds-v6', 'yul-sha-rounds-v7', 'yul-sha-rounds-v8', 'yul-sha-rounds-v9', 'yul-sha-rounds-v10', 'yul-sha-rounds-v11')
        placement = binding['kind'] == 'yul-sha-rounds-v3'
        cursor = binding['kind'] in ('yul-sha-rounds-v4', 'yul-sha-rounds-v5')
        four = binding['kind'] == 'yul-sha-rounds-v6'
        group = binding['kind'] in ('yul-sha-rounds-v7', 'yul-sha-rounds-v8')
        retained = binding['kind'] == 'yul-sha-rounds-v11'
        sigma = binding['kind'] in ('yul-sha-rounds-v9', 'yul-sha-rounds-v10')
        assert binding.get('scalarCore') == ('packed' if four or group or sigma or retained else None)
        if not (four or group or sigma or retained):
            assert 'scalarCore' not in binding
        assert binding['runtimeSource'] == 'BiniusVerifier.yul'
        assert binding['roundBlockSha256'] == '0x' + (RETAINED_HASH if retained else SIGMA_HASH if sigma else GROUP_HASH if group else FOUR_HASH if four else CURSOR_HASH if cursor else PLACEMENT_HASH if placement else BLOCK_HASH)
        assert binding['solidityReferenceRuntimeSha256'] == '0x' + hashlib.sha256(compiler_runtime).hexdigest()
        block = load_block(placement, cursor, four, group, sigma, retained)
        word_block = None
        if retained:
            from sha_pair_stack_check import WORD_HASH, load_word
            assert binding['wordBlockSha256'] == '0x' + WORD_HASH
            word_block = load_word()
        elif binding['kind'] == 'yul-sha-rounds-v10':
            from sha_word_group_check import BLOCK_HASH as WORD_GROUP_HASH, load_block as load_word_group
            assert binding['wordBlockSha256'] == '0x' + WORD_GROUP_HASH
            word_block = load_word_group()
        elif binding['kind'] in ('yul-sha-rounds-v8', 'yul-sha-rounds-v9'):
            from sha_word_loop_check import LOOP_HASH, DOUBLE_HASH, load_block as load_loop
            assert binding['wordBlockSha256'] == '0x' + (DOUBLE_HASH if sigma else LOOP_HASH)
            word_block = load_loop(sigma)
        elif binding['kind'] != 'yul-sha-rounds-v1':
            from sha_word_stack_check import BLOCK_HASH as WORD_HASH, ORDER_HASH, load_block as load_word_block
            order = binding['kind'] in ('yul-sha-rounds-v5', 'yul-sha-rounds-v6', 'yul-sha-rounds-v7')
            assert binding['wordBlockSha256'] == '0x' + (ORDER_HASH if order else WORD_HASH)
            word_block = load_word_block(order)
        else:
            assert 'wordBlockSha256' not in binding
        validate_source(contract['irOptimized'], artifact['yulSource'], word_block, block, binding.get('scalarCore'))
    assert compiled['abi'] == artifact['abi']
    assert len(bytes.fromhex(compiled['bytecode']['object'])) == artifact['solidityInitcodeBytes']
    (dest / 'BiniusVerifier.compiled.json').write_text(json.dumps(compiled) + '\n')
    settings = artifact['compilerSettings']['yul'] | {'outputSelection': {'*': {'*': [
        'evm.bytecode.object', 'evm.deployedBytecode.object', 'evm.deployedBytecode.sourceMap',
    ]}}}
    result = subprocess.run([solc, '--standard-json'], text=True, capture_output=True, check=True,
                            input=json.dumps({'language': 'Yul', 'settings': settings,
                                              'sources': {'BiniusVerifier.yul': {'content': artifact['yulSource']}}}))
    result = json.loads(result.stdout)
    assert not [error for error in result.get('errors', []) if error['severity'] == 'error'], result
    contracts = result['contracts']['BiniusVerifier.yul']
    assert len(contracts) == 1
    yul_compiled = next(iter(contracts.values()))['evm']
    assert bytes.fromhex(yul_compiled['bytecode']['object']) == creation
    if binding is not None:
        compiler_runtime = bytes.fromhex(yul_compiled['deployedBytecode']['object'])
        assert compiler_runtime == runtime, 'emitted Yul compiles to a different artifact runtime'
        audit = validate_runtime(runtime, yul_compiled['deployedBytecode']['sourceMap'], block, word_block)
        (dest / 'runtime-audit.json').write_text(json.dumps(audit, indent=2) + '\n')
    (dest / 'BiniusVerifier.yul-compiled.json').write_text(json.dumps(yul_compiled) + '\n')

    root = dest / 'evm'
    for directory in ('solidity/src', 'solidity/test', 'solidity/artifact-test', 'target'):
        (root / directory).mkdir(parents=True, exist_ok=True)
    config = (repo / 'solidity/foundry.toml').read_text()
    config = config.replace('src = "src"', 'src = "src"\ntest = "artifact-test"')
    (root / 'solidity/foundry.toml').write_text(config)
    shutil.copyfile(repo / 'solidity/src/BiniusPrimitives.sol', root / 'solidity/src/BiniusPrimitives.sol')
    (root / 'solidity/src/NativeBiniusVerifier.sol').write_text(source)
    for name in ('BiniusVerifier.t.sol', 'BiniusHints.t.sol', 'BiniusRuntimeCode.t.sol'):
        shutil.copyfile(repo / 'solidity/test' / name, root / 'solidity/test' / name)
    shutil.copyfile(repo / 'solidity/artifact-test/BiniusArtifact.t.sol', root / 'solidity/artifact-test/BiniusArtifact.t.sol')
    if program_input:
        # Slot zero now holds a digest. Cooling must still cover every actual
        # program slot; use the independently checked fixed byte length.
        for name, variable in [('BiniusVerifier.t.sol', 'verifier'), ('BiniusHints.t.sol', 'v')]:
            path = root / 'solidity/test' / name
            text = path.read_text()
            marker = f'uint256(vm.load(address({variable}), bytes32(0))) >> 1'
            assert text.count(marker) == 1
            path.write_text(text.replace(marker, str(len(stored))))
        path = root / 'solidity/artifact-test/BiniusArtifact.t.sol'
        text = path.read_text()
        marker = 'bool private constant AUTHENTICATED_PROGRAM = false;'
        assert text.count(marker) == 1
        path.write_text(text.replace(marker, 'bool private constant AUTHENTICATED_PROGRAM = true;'))
        shutil.copyfile(repo / 'solidity/artifact-test/BiniusProgramInput.t.sol', root / 'solidity/artifact-test/BiniusProgramInput.t.sol')
        for ext in ('binius', 'hinted'):
            shutil.copyfile(dest / f'fixture.key-{ext}', root / f'target/solidity-test.key-{ext}')
    for ext in ('binius', 'hinted', 'inputs', 'corruptions', 'program'):
        expected = dest / ('stored.program' if ext == 'program' else f'fixture.{ext}')
        shutil.copyfile(expected, root / f'target/solidity-test.{ext}')
    (root / 'target/solidity-test.creation').write_bytes(creation)
    (root / 'target/solidity-test.runtime').write_bytes(runtime)
    (root / 'target/solidity-test.compiler-runtime').write_bytes(compiler_runtime)
    test_environment = os.environ.copy()
    test_environment.pop('FOUNDRY_TEST', None)
    # Foundry matches the function signature, including its argument list.
    run([forge, 'test', '--root', str(root / 'solidity'), '--use', solc,
         '--match-contract', '^Artifact', '--match-test',
         '^test(FullBiniusProof|QueryAuthenticationLanes|HintedProof|DeployedRuntimeMatchesCompiler|InstalledProgramMatchesArtifact|ProgramInput)',
         '-vv'], 'evm.log', cwd=root / 'solidity', env=test_environment)
    log = (dest / 'evm.log').read_text()
    tests = 8 if program_input else 5
    assert f'{tests} tests passed, 0 failed' in log
    measurement = {
        'proof_bytes': (dest / 'fixture.binius').stat().st_size,
        'hinted_proof_bytes': (dest / 'fixture.hinted').stat().st_size,
        'initcode_bytes': len(creation), 'runtime_bytes': len(runtime),
        'ordinary_solidity_initcode_bytes': artifact['solidityInitcodeBytes'],
        'program_bytes_checked': len(stored), 'uncompressed_program_bytes': len(program), 'evm_tests': tests,
        'native_verified': True, 'constructor_arguments': 0,
        'independent_compiler_unit': 'BiniusVerifier.yul' if binding is not None else 'BiniusVerifier.sol',
        'yul_source_and_creation_bytecode_identical': True,
    }
    measurement['yul_and_deployed_runtime_identical' if binding is not None
                else 'solidity_and_deployed_runtime_identical'] = True
    if binding is not None:
        measurement['runtime_compilation'] = binding
    for name, label in [('raw_call_gas', 'verification gas (cold program storage)'),
                        ('hinted_call_gas', 'hinted verification gas'),
                        ('creation_gas', 'creation gas excluding bytecode file read')]:
        measurement[name] = gas_measurement(log, label)
    if program_input:
        for kind in ('native', 'hinted'):
            measurement[f'key_{kind}_call_gas'] = gas_measurement(log, f'program input {kind} verification gas')
        measurement['key_native_bytes'] = (dest / 'fixture.key-binius').stat().st_size
        measurement['key_hinted_bytes'] = (dest / 'fixture.key-hinted').stat().st_size
    for name, value in [('program', program), ('stored_program', stored), ('runtime', runtime), ('creation', creation)]:
        measurement[f'{name}_sha256'] = hashlib.sha256(value).hexdigest()
    (dest / 'measurements.json').write_text(json.dumps(measurement, indent=2) + '\n')
    print(json.dumps(measurement), flush=True)


if __name__ == '__main__':
    main()
