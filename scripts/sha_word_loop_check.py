"""A fixed 48-step word expansion loop with an explicit cached-schedule skip.

The input flag is exactly the original usr$cached, an AND of two Boolean
expressions. A hit follows the existing copy and must leave the schedule alone.
A miss expands W16..W63 with the unchanged checked word-step opcodes.
"""
import hashlib
import json
import random

import sha_word_stack_check as words
import sha_stack_check as rounds

def make(double=False):
    body = words.load_block(True)
    assert words.symbolic(body)['gas'] == 237
    # JUMPI consumes the flag and a PC-relative destination. The successful
    # cache path reaches the final JUMPDEST with zero remaining owned words.
    block = bytearray(b'\x61\x00\x00\x58\x01\x57')
    block += rounds.push(0x1c00)
    loop = len(block)
    block += b'\x5b\x80' + body  # preserve the loop cursor below the step input
    if double:
        block += b'\x80' + rounds.push(32) + b'\x01' + body
    block += rounds.push(64 if double else 32) + b'\x01\x80' + rounds.push(0x2200) + b'\x11'
    distance = len(block)+3-loop
    block += b'\x61' + distance.to_bytes(2, 'big') + b'\x58\x03\x57\x50'
    end = len(block)
    block += b'\x5b'
    block[1:3] = (end-3).to_bytes(2, 'big')  # PC of the initial PC instruction is 3
    assert len(block) == (607 if double else 315)
    return bytes(block), loop, end

LOOP_HASH = '6234a2eab2cd341248e9c642e3d588a1f1cfcbfefe8b4af95802a28c0db80a30'
DOUBLE_HASH = '4dd2efd40dc163b484fc7b6526cdba1f1d82bece8845961aa0067939bf0930e9'


def load_block(double=False):
    block = bytes.fromhex((rounds.DATA/('word-double-block.hex' if double else 'word-loop-block.hex')).read_text())
    assert len(block) == (607 if double else 315)
    assert hashlib.sha256(block).hexdigest() == (DOUBLE_HASH if double else LOOP_HASH)
    assert block == make(double)[0]
    # The original loop text must bind the original word equation too.
    original = ('let usr$p := add(mul(usr$cached, 1536), 7168) '
                'for {} lt(usr$p, 0x2200) {usr$p := add(usr$p, 32)} {'
                + (rounds.DATA/'words.yul').read_text() + '}')
    tokens = lambda s: rounds.runtime_tokens('object "C_deployed" {' + s + '}')
    assert tokens(original) == tokens((rounds.DATA/'word-loop.yul').read_text())
    return block


def execute(code, memory, cached, double=False):
    assert cached in (0, 1)
    canaries = [rounds.U, 0x987654321]
    stack = canaries+[cached]
    pc = steps = 0
    writes, reads, jumps = [], [], []
    high = len(stack)
    while pc < len(code):
        at = pc
        op = code[pc]
        pc += 1
        steps += 1
        assert steps < 10000
        if op == 0x5f:
            stack.append(0)
        elif 0x60 <= op <= 0x7f:
            size = op-0x5f
            assert pc+size <= len(code)
            stack.append(int.from_bytes(code[pc:pc+size], 'big'))
            pc += size
        elif 0x80 <= op <= 0x8f:
            depth = op-0x7f
            assert len(stack)-depth >= len(canaries)
            stack.append(stack[-depth])
        elif 0x90 <= op <= 0x9f:
            depth = op-0x8f
            assert len(stack)-1-depth >= len(canaries)
            stack[-1], stack[-1-depth] = stack[-1-depth], stack[-1]
        elif op == 0x50:
            assert len(stack) > len(canaries)
            stack.pop()
        elif op == 0x51:
            assert len(stack) >= len(canaries)+1
            address = stack.pop()
            reads.append(address)
            stack.append(memory[address])
        elif op == 0x52:
            assert len(stack) >= len(canaries)+2
            address, value = stack.pop(), stack.pop()
            memory[address] = value
            writes.append(address)
        elif op == 0x58:
            stack.append(at)
        elif op == 0x57:
            assert len(stack) >= len(canaries)+2
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
        assert stack[:len(canaries)] == canaries and high <= len(canaries)+8
    assert stack == canaries
    if cached:
        assert writes == reads == [] and jumps == [len(code)-1]
    else:
        assert writes == list(range(0x1c00, 0x2200, 32)) and len(jumps) == (23 if double else 47)
        expected = [p-delta for p in writes for delta in [64, 224, 512, 480]]
        assert reads == expected
    return dict(steps=steps, max_owned_stack=high-len(canaries), writes=len(writes), taken_branches=len(jumps))

def check(double=False):
    block = load_block(double)
    _, loop, end = make(double)
    rng = random.Random(0x202609173)
    hits = misses = vectors = 0
    max_stack = 0
    for case in range(258):
        if case == 0: inputs = [0]*16
        elif case == 1: inputs = [rounds.MASK]*16
        else: inputs = [rng.getrandbits(256) & rounds.MASK for _ in range(16)]
        expected = [0]*64
        for lane in range(7):
            w = [(v >> (37*lane)) & 0xffffffff for v in inputs]
            schedule, _ = rounds.scalar(w, [0]*8)
            for i, v in enumerate(schedule):
                expected[i] |= v << (37*lane)
        for cached in (0, 1):
            memory = {0x1a00+32*i:v for i,v in enumerate(inputs)}
            # Dirty uncached words must be overwritten; a cache hit must leave
            # its already-copied canonical schedule exactly unchanged.
            memory.update({0x1a00+32*i:(expected[i] if cached else rng.getrandbits(256)) for i in range(16, 64)})
            memory.update({0:rounds.U, 0x19e0:0x1234, 0x2200:0x5678, 0x2420:0x9abc})
            before = memory.copy()
            facts = execute(block, memory, cached, double)
            assert [memory[0x1a00+32*i] for i in range(64)] == expected
            assert all(memory[p] == v for p,v in before.items() if p not in range(0x1c00, 0x2200, 32))
            if cached:
                assert memory == before
                hits += 1
            else:
                misses += 1
            max_stack = max(max_stack, facts['max_owned_stack'])
        vectors += 7
    result = dict(block_bytes=len(block), block_sha256=hashlib.sha256(block).hexdigest(),
                  exact_original_word_expression=True, full_scalar_expansions=vectors,
                  cache_hits=hits, cache_misses=misses, max_owned_stack=max_stack,
                  fixed_48_stores_on_miss=True, zero_reads_or_writes_on_hit=True,
                  preserved_underlying_stack_and_neighbors=True, backward_jump_target=loop,
                  cached_jump_target=end)
    return result


if __name__ == '__main__':
    print(json.dumps({'single': check(), 'double': check(True)}, indent=2))
