#!/usr/bin/env python3
"""Check scalar SHA continuation through the actual packed expansion/round bytes.

Scalar messages enter with only their low 32-bit lane populated. Upper state
lanes may be arbitrary canonical words, but cannot carry into adjacent lanes:
feed-forward adds two 32-bit values within each 37-bit lane and masks the sum.
The observable scalar digest is therefore exactly the low-lane SHA digest.
"""
import hashlib
import json
import random

import sha_stack_check as rounds
import sha_word_stack_check as words


def check(group=False, word_loop=False, sigma=False, word_group=False, pair=False):
    if pair:
        group = word_loop = sigma = True
    assert not word_loop or group
    assert not sigma or (group and word_loop)
    assert not word_group or sigma
    block = rounds.load_block(retained=True) if pair else rounds.load_block(sigma=True) if sigma else rounds.load_block(group=True) if group else rounds.load_block(four=True)
    word = words.load_block(True)
    if pair:
        import sha_pair_stack_check as loop
        loop_block = loop.load_word()
    elif word_group:
        import sha_word_group_check as loop
        loop_block = loop.load_block()
    elif word_loop:
        import sha_word_loop_check as loop
        loop_block = loop.load_block(sigma)
    rounds.checked_parts(block)
    words.symbolic(word)
    rng = random.Random(0x20260917)
    raw = bytes.fromhex(rounds.KHEX)
    assert len(raw) == 320
    iv = [int.from_bytes(raw[i:i+4], 'big') for i in range(256, 288, 4)]
    assert iv == [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
    lengths = [0, 1, 2, 3, 31, 32, 55, 56, 63, 64, 65, 127, 128, 129,
               255, 256, 513, 4097]
    lengths += [rng.randrange(1025) for _ in range(32)]
    compressions = 0
    for case, length in enumerate(lengths):
        data = rng.randbytes(length)
        padded = data + b'\x80' + b'\x00' * ((55-length) % 64) + (8*length).to_bytes(8, 'big')
        assert len(padded) % 64 == 0
        state = [v | sum(rng.getrandbits(32) << (37*lane) for lane in range(1, 7)) for v in iv]
        memory = {0x1000+32*i: k*rounds.REP for i, k in enumerate(rounds.K)}
        memory.update({0: 0x123456, 0xfe0: rounds.U, 0x2420: 0, 0x2440: 0x98765})
        for offset in range(0, len(padded), 64):
            inputs = [int.from_bytes(padded[offset+i:offset+i+4], 'big') for i in range(0, 64, 4)]
            for i, v in enumerate(inputs):
                memory[0x1a00+32*i] = v
            if pair or word_group:
                loop.execute(loop_block, memory, 0)
            elif word_loop:
                loop.execute(loop_block, memory, 0, sigma)
            else:
                for i in range(16, 64):
                    words.execute(word, memory, 0x1a00+32*i)
            for i, v in enumerate(state):
                memory[0x2300+32*i] = v
            before = memory.copy()
            rounds.execute(block, memory, [rounds.U, 0x123, 0], expected_jumps=15)
            assert all(memory[p] == v for p, v in before.items() if p not in range(0x2300, 0x2400, 32))
            working = [memory[0x2300+32*i] for i in range(8)]
            state = [(a+b) & rounds.MASK for a, b in zip(state, working)]
            assert all(v & ~rounds.MASK == 0 for v in state)
            compressions += 1
        digest = b''.join((v & 0xffffffff).to_bytes(4, 'big') for v in state)
        assert digest == hashlib.sha256(data).digest(), (case, length)
        assert memory[0] == 0x123456 and memory[0xfe0] == rounds.U
        assert memory[0x2420] == 0 and memory[0x2440] == 0x98765
    return dict(messages=len(lengths), compressions=compressions,
                independent_hashlib_sha256=True, arbitrary_canonical_upper_lanes=True,
                actual_word_and_round_opcodes=True, continued_state_canonical=True,
                exact_state_writes=True, preserved_constants_and_neighboring_memory=True)


if __name__ == '__main__':
    print(json.dumps(check(), indent=2))
