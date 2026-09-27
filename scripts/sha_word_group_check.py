#!/usr/bin/env python3
"""Check all four SHA word bodies, retained masks and the complete cache loop.

The actual opcodes are compared with the original unrestricted 256-bit word
expression. Only affine memory addresses are normalized; carries and nonlinear
SHA arithmetic are preserved. A second interpreter checks complete schedules.
"""
import hashlib
import json
import random

import sha_stack_check as rounds
import sha_word_stack_check as words

DATA = rounds.DATA
BLOCK_HASH = '12fbd5916a21d830f2707a3ab5a7849c4d1f90f1c1b3e417cf7c06dcd05cbb52'


def masks():
    actual = [int(s, 16) for s in json.loads((DATA/'word-group-masks.json').read_text())]
    expected = [rounds.REP*((1 << bits)-1) << shift
                for bits, shift in [(19, 13), (17, 15), (22, 0), (18, 14), (7, 25), (32, 0)]]
    assert actual == expected and actual[-1] == rounds.MASK
    assert actual[1] == actual[0] & ((actual[0] << 2) & rounds.U)
    return actual


def instructions(code):
    pc = 0
    while pc < len(code):
        at = pc
        op = code[pc]
        pc += 1
        if 0x60 <= op <= 0x7f:
            pc += op-0x5f
        assert pc <= len(code)
        yield at, op, code[at:pc]


def address(node):
    """Normalize only affine addresses modulo 2^256, never SHA values."""
    if node == 'p':
        return 1, 0
    if isinstance(node, int):
        return 0, node & rounds.U
    op = node[0]
    if op == 'not':
        a, v = address(node[1])
        assert a == 0
        return 0, rounds.U ^ v
    assert op in ['add', 'sub']
    a, x = address(node[1])
    b, y = address(node[2])
    return (a+b, (x+y) & rounds.U) if op == 'add' else (a-b, (x-y) & rounds.U)


def normalized(node, offset=0):
    if not isinstance(node, tuple):
        return node
    if node[0] == 'mload':
        a, x = address(node[1])
        assert a == 1
        return ('mload', ('address', (x+offset) & rounds.U))
    return (node[0], *(normalized(x, offset) for x in node[1:]))


def check_body(code, masks, stage):
    prefix = ['canary0', 'canary1']+masks
    stack = prefix+['p']
    reads, writes = [], []
    gas = 0
    peak = len(stack)
    for _, op, data in instructions(code):
        gas += 2 if op == 0x5f else 3
        if op == 0x5f:
            stack.append(0)
        elif 0x60 <= op <= 0x7f:
            stack.append(int.from_bytes(data[1:], 'big'))
        elif 0x80 <= op <= 0x8f:
            depth = op-0x7f
            assert len(stack)-depth >= 2
            stack.append(stack[-depth])
        elif 0x90 <= op <= 0x9f:
            depth = op-0x8f
            assert len(stack)-1-depth >= len(prefix)
            stack[-1], stack[-1-depth] = stack[-1-depth], stack[-1]
        elif op == 0x51:
            a = stack.pop()
            reads.append(a)
            stack.append(('mload', a))
        elif op == 0x52:
            a, v = stack.pop(), stack.pop()
            writes.append((a, v))
        else:
            assert op in words.OPS and len(stack) >= len(prefix)+2
            a, b = stack.pop(), stack.pop()
            stack.append((words.OPS[op], a, b))
        peak = max(peak, len(stack))
        assert stack[:len(prefix)] == prefix
    assert stack == prefix+['p'] and len(writes) == 1
    offset = 32*stage
    assert [address(a) for a in reads] == [(1, (offset-d) & rounds.U) for d in [64, 224, 512, 480]]
    assert address(writes[0][0]) == (1, offset)
    original = words.original()
    assert original[:2] == ('mstore', 'p')
    assert words.canonical(normalized(writes[0][1])) == words.canonical(normalized(original[2], offset))
    return dict(gas=gas, max_owned_stack=peak-2, exact_original_word_expression=True,
                ordered_reads=4, stores=1, retained_base_cursor=True, retained_masks=True)


def body(stage):
    assert stage in range(4)
    opcodes = {name.upper():op for op, name in words.OPS.items()} | {'MLOAD':0x51, 'MSTORE':0x52}
    code = bytearray()
    for line in (DATA/f'word-group-{stage}.asm').read_text().splitlines():
        parts = line.split('#', 1)[0].split()
        if not parts:
            continue
        if parts[0] == 'PUSH':
            assert len(parts) == 2
            code += rounds.push(int(parts[1], 16))
        else:
            assert len(parts) == 1
            if parts[0].startswith('DUP') or parts[0].startswith('SWAP'):
                dup = parts[0].startswith('DUP')
                depth = int(parts[0][3 if dup else 4:])
                assert 1 <= depth <= 16
                code.append((0x7f if dup else 0x8f)+depth)
            else:
                code.append(opcodes[parts[0]])
    return bytes(code)


def make():
    retained = masks()
    block = bytearray(b'\x61\x00\x00\x58\x01\x57')
    block += rounds.push(retained[0])+b'\x80\x80'+rounds.push(2)+b'\x1b\x16'
    block += b''.join(rounds.push(m) for m in retained[2:])+rounds.push(0x1c00)
    loop = len(block)
    block.append(0x5b)
    facts = []
    for stage in range(4):
        code = body(stage)
        facts.append(check_body(code, retained, stage))
        block += code
    assert [f['gas'] for f in facts] == [237, 243, 237, 243]
    assert all(f['max_owned_stack'] == 13 for f in facts)
    block += rounds.push(128)+b'\x01\x80'+rounds.push(0x2200)+b'\x11'
    distance = len(block)+3-loop
    block += b'\x61'+distance.to_bytes(2, 'big')+b'\x58\x03\x57'+b'\x50'*7
    end = len(block)
    block.append(0x5b)
    block[1:3] = (end-3).to_bytes(2, 'big')
    assert len(block) == 596 and loop == 179 and end == 595
    return bytes(block)


def load_block():
    import sha_word_loop_check as loop
    loop.load_block(True)  # independently binds original complete loop/Yul body
    code = bytes.fromhex((DATA/'word-group-block.hex').read_text())
    assert len(code) == 596 and hashlib.sha256(code).hexdigest() == BLOCK_HASH
    assert code == make()
    return code


def execute(code, memory, cached):
    """Numeric interpreter knows no construction details, only EVM semantics."""
    assert cached in (0, 1)
    canaries = [rounds.U, 0x987654321]
    stack = canaries+[cached]
    reads, writes, jumps = [], [], []
    pc = steps = gas = 0
    high = len(stack)
    while pc < len(code):
        at = pc
        op = code[pc]
        pc += 1
        steps += 1
        assert steps < 10000
        gas += 10 if op == 0x57 else 1 if op == 0x5b else 2 if op in [0x50, 0x58, 0x5f] else 3
        if op == 0x5f:
            stack.append(0)
        elif 0x60 <= op <= 0x7f:
            n = op-0x5f
            assert pc+n <= len(code)
            stack.append(int.from_bytes(code[pc:pc+n], 'big'))
            pc += n
        elif 0x80 <= op <= 0x8f:
            d = op-0x7f
            assert len(stack)-d >= len(canaries)
            stack.append(stack[-d])
        elif 0x90 <= op <= 0x9f:
            d = op-0x8f
            assert len(stack)-1-d >= len(canaries)
            stack[-1], stack[-1-d] = stack[-1-d], stack[-1]
        elif op == 0x50:
            stack.pop()
        elif op == 0x51:
            address = stack.pop()
            reads.append(address)
            stack.append(memory[address])
        elif op == 0x52:
            address, value = stack.pop(), stack.pop()
            writes.append(address)
            memory[address] = value
        elif op == 0x58:
            stack.append(at)
        elif op == 0x57:
            target, condition = stack.pop(), stack.pop()
            assert 0 <= target < len(code) and code[target] == 0x5b
            if condition:
                pc = target
                jumps.append(target)
        elif op == 0x5b:
            pass
        else:
            assert len(stack) >= len(canaries)+2
            a, b = stack.pop(), stack.pop()
            if op == 1: value = a+b
            elif op == 3: value = a-b
            elif op == 0x11: value = int(a>b)
            elif op == 0x16: value = a & b
            elif op == 0x18: value = a ^ b
            elif op == 0x1b: value = b << a
            else:
                assert op == 0x1c
                value = b >> a
            stack.append(value & rounds.U)
        high = max(high, len(stack))
        assert stack[:len(canaries)] == canaries and len(canaries) <= len(stack) <= len(canaries)+13
    assert stack == canaries
    if cached:
        assert writes == reads == [] and jumps == [len(code)-1]
    else:
        assert writes == list(range(0x1c00, 0x2200, 32))
        assert len(jumps) == 11
        assert reads == [p-d for p in writes for d in [64, 224, 512, 480]]
    return dict(gas=gas, max_owned_stack=high-2, writes=len(writes),
                backward_branches=0 if cached else len(jumps))


def numeric(code):
    rng = random.Random(0x202609174)
    hits = misses = peak = 0
    gas = {}
    for case in range(258):
        inputs = [0]*16 if case == 0 else [rounds.MASK]*16 if case == 1 else [rng.getrandbits(256) & rounds.MASK for _ in range(16)]
        expected = [0]*64
        for lane in range(7):
            schedule, _ = rounds.scalar([(v >> (37*lane)) & 0xffffffff for v in inputs], [0]*8)
            for i, value in enumerate(schedule):
                expected[i] |= value << (37*lane)
        for cached in [0, 1]:
            memory = {0x1a00+32*i:value for i, value in enumerate(inputs)}
            memory.update({0x1a00+32*i:expected[i] if cached else rng.getrandbits(256) for i in range(16, 64)})
            memory.update({0:rounds.U, 0x19e0:0x1234, 0x2200:0x5678, 0x2420:0x9abc})
            before = memory.copy()
            facts = execute(code, memory, cached)
            assert [memory[0x1a00+32*i] for i in range(64)] == expected
            assert all(memory[a] == v for a, v in before.items() if a not in range(0x1c00, 0x2200, 32))
            if cached:
                assert before == memory
                hits += 1
            else:
                misses += 1
            peak = max(peak, facts['max_owned_stack'])
            if cached in gas:
                assert gas[cached] == facts['gas']
            gas[cached] = facts['gas']
    return dict(full_scalar_expansions=258*7, cache_hits=hits, cache_misses=misses,
                miss_gas=gas[0], hit_gas=gas[1], max_owned_stack=peak,
                fixed_48_ordered_stores=True, fixed_192_ordered_reads=True,
                preserved_underlying_stack_and_neighbors=True)


def check():
    code = load_block()
    result = numeric(code)
    assert result['miss_gas'] == 11994 and result['hit_gas'] == 19
    assert result['max_owned_stack'] == 13
    return result | dict(block_bytes=len(code), block_sha256=BLOCK_HASH,
                         exact_original_word_expressions=4, backward_jump_target=179,
                         cached_jump_target=595, groups=12, words_per_group=4)


if __name__ == '__main__':
    print(json.dumps(check(), indent=2))
