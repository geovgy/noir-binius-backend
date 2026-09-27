#!/usr/bin/env python3
"""Check retained round masks and the exact two-predecessor SHA word loop.

No research artifacts are needed. The body models decode actual opcodes and
compare the original value equations. Only affine memory addresses normalize.
The word loop's invariant is [masks,p,W[i-1],W[i-2]] at each body entry, and
[masks,p,W[i],W[i-1]] after its original ordered store.
"""
import hashlib
import json
import random

import sha_stack_check as ref
import sha_word_group_check as groups

ROUND_HASH = 'c42783843e8233d2402c8f174feea2ffd8ae2ade1f503a60aa888ee2bc67c4ad'
WORD_HASH = '997d259dd8aece2235a17177f6422949b27ec974286b968ba83aa0a25ea96071'
DATA = ref.DATA


def asm(name):
    result = bytearray()
    ops = {'ADD':1,'SUB':3,'AND':0x16,'OR':0x17,'XOR':0x18,'SHL':0x1b,'SHR':0x1c,'MLOAD':0x51,'MSTORE':0x52}
    for line in (DATA/name).read_text().splitlines():
        pieces = line.split('#',1)[0].split()
        if not pieces: continue
        op = pieces[0]
        if op=='PUSH':
            assert len(pieces)==2
            result += ref.push(int(pieces[1],16))
        else:
            assert len(pieces)==1
            if op.startswith(('DUP','SWAP')):
                dup = op.startswith('DUP')
                n = int(op[3 if dup else 4:])
                assert 1<=n<=16
                result.append((0x7f if dup else 0x8f)+n)
            else: result.append(ops[op])
    return bytes(result)


def prefix(name, expected):
    code = bytes.fromhex((DATA/name).read_text())
    stack=[]
    for _,op,data in groups.instructions(code):
        if 0x60<=op<=0x7f: stack.append(int.from_bytes(data[1:],'big'))
        elif 0x80<=op<=0x8f:
            n=op-0x7f
            assert n<=len(stack)
            stack.append(stack[-n])
        else:
            assert op in [0x16,0x17,0x1b,0x1c] and len(stack)>=2
            a,b=stack.pop(),stack.pop()
            if op in [0x1b,0x1c]: assert a<256
            if op==0x16: value=a&b
            elif op==0x17: value=a|b
            elif op==0x1b: value=b<<a
            else: value=b>>a
            stack.append(value&ref.U)
        assert len(stack)<=8
    assert stack==expected
    return code


def round_masks():
    actual=[int(v,16) for v in json.loads((DATA/'round-retained-masks.json').read_text())]
    assert actual==[ref.REP*((1<<n)-1) for n in [32,2,13,22,25,11]]
    return actual


def check_round_body(code,before,after,stage,masks):
    frame=['canary0','canary1']+masks
    actual,high=ref.symbolic(code,frame+before)
    assert actual[:len(frame)]==frame and len(actual)==len(frame)+9 and high==22
    value=dict(zip(after,actual[len(frame):]))
    original=ref.group_cursor_reference(ref.absolute_cursor_reference(ref.parse_round((DATA/'rounds.yul').read_text())),stage)
    algebra=ref.Algebra()
    for name in 'abcdefghp': assert algebra.canon(value[name])==algebra.canon(original[name]),(stage,name)
    return dict(outputs=9,max_owned_stack=high-2)


def checked_round_parts(block):
    assert len(block)==705 and hashlib.sha256(block).hexdigest()==ROUND_HASH
    masks=round_masks()
    layout=json.loads((DATA/'round-sigma-orders.json').read_text())
    before=layout['entry']
    p=prefix('round-retained-mask-prefix.hex',masks)
    assert len(p)==136
    code=bytearray(p)
    for name in before:
        code+=ref.push(0x1000) if name=='p' else ref.push(0x2300+32*'abcdefgh'.index(name))+b'\x51'
    loop=len(code)
    code+=b'\x5b'
    bodies=[]
    for stage,after in enumerate(layout['outputs']):
        body=asm(f'round-retained-{stage}.asm')
        check_round_body(body,before,after,stage,masks)
        bodies.append(body);code+=body;before=after
    assert before==layout['entry']
    code+=bytes([0x7f+9-before.index('p')])+ref.push(0x1800)+b'\x11'
    distance=len(code)+3-loop
    code+=b'\x61'+distance.to_bytes(2,'big')+b'\x58\x03\x57'
    for name in reversed(before):
        code+=b'\x50' if name=='p' else ref.push(0x2300+32*'abcdefgh'.index(name))+b'\x52'
    code+=b'\x50'*6
    assert code==block and loop==171
    return bodies,before,dict(group_gas=1245,max_owned_stack=20)


def word_body(stage):
    assert stage in range(8)
    return asm(f'word-pair-{stage}.asm')


def check_word_body(code,stage,masks=None):
    masks=groups.masks() if masks is None else masks
    frame=['canary0','canary1']+masks
    stack=frame+['p','previous','old']
    reads,writes=[],[]
    high=len(stack)
    for _,op,data in groups.instructions(code):
        if 0x60<=op<=0x7f: stack.append(int.from_bytes(data[1:],'big'))
        elif 0x80<=op<=0x8f:
            n=op-0x7f
            assert len(stack)-n>=2
            stack.append(stack[-n])
        elif 0x90<=op<=0x9f:
            n=op-0x8f
            assert len(stack)-1-n>=len(frame)
            stack[-1],stack[-1-n]=stack[-1-n],stack[-1]
        elif op==0x51:
            a=stack.pop();reads.append(a);stack.append(('mload',a))
        elif op==0x52:
            a,v=stack.pop(),stack.pop();writes.append((a,v))
        else:
            assert op in groups.words.OPS
            a,b=stack.pop(),stack.pop();stack.append((groups.words.OPS[op],a,b))
        high=max(high,len(stack))
        assert stack[:len(frame)]==frame
    assert len(writes)==1 and len(stack)==len(frame)+3
    assert stack[len(frame)]=='p' and stack[-1]=='previous' and stack[-2]==writes[0][1]
    assert [groups.address(a) for a in reads]==[(1,(32*stage-d)&ref.U) for d in [224,512,480]]
    assert groups.address(writes[0][0])==(1,32*stage)
    def replace_y(node):
        if isinstance(node,tuple) and node[0]=='mload' and groups.address(node[1])==(1,(-64)&ref.U): return 'old'
        return (node[0],*(replace_y(v) for v in node[1:])) if isinstance(node,tuple) else node
    expected=groups.normalized(replace_y(groups.words.original()[2]),32*stage)
    assert groups.words.canonical(groups.normalized(writes[0][1]))==groups.words.canonical(expected)
    assert high-2==14
    return dict(exact_word_expression=True,preserved_predecessor=True,retained_new_word=True,
                reads=3,writes=1,max_owned_stack=high-2)


def load_word():
    from sha_word_loop_check import load_block
    load_block(True)  # retain the complete original loop/source binding
    p=prefix('word-pair-mask-prefix.hex',groups.masks())
    assert len(p)==86
    code=bytearray(b'\x61\x00\x00\x58\x01\x57'+p)
    code+=ref.push(0x1c00)+ref.push(0x1be0)+b'\x51'+ref.push(0x1bc0)+b'\x51'
    loop=len(code)
    code+=b'\x5b'
    for stage in range(8):
        body=word_body(stage);check_word_body(body,stage);code+=body
    code+=b'\x91'+ref.push(256)+b'\x01\x91\x82'+ref.push(0x2200)+b'\x11'
    distance=len(code)+3-loop
    code+=b'\x61'+distance.to_bytes(2,'big')+b'\x58\x03\x57'+b'\x50'*9
    code[1:3]=(len(code)-3).to_bytes(2,'big');code+=b'\x5b'
    block=bytes.fromhex((DATA/'word-pair-block.hex').read_text())
    assert loop==103 and len(block)==901 and block==code
    assert hashlib.sha256(block).hexdigest()==WORD_HASH
    return block


def _execute(code, memory, sentinel):
    """Independent opcode interpreter, including stack access and PC checks."""
    stack = list(sentinel)
    floor = 2
    canaries = stack[:floor]
    pc = gas = steps = jumps = 0
    peak = len(stack)-floor
    reads, writes = [], []
    while pc < len(code):
        at = pc
        op = code[pc]
        pc += 1
        steps += 1
        assert steps < 20000
        gas += 10 if op == 0x57 else 1 if op == 0x5b else 2 if op in [0x50, 0x58, 0x5f] else 3
        if op == 0x5f:
            stack.append(0)
        elif 0x60 <= op <= 0x7f:
            n = op-0x5f
            assert pc+n <= len(code)
            stack.append(int.from_bytes(code[pc:pc+n], 'big'))
            pc += n
        elif 0x80 <= op <= 0x8f:
            n = op-0x7f
            assert len(stack)-n >= floor
            stack.append(stack[-n])
        elif 0x90 <= op <= 0x9f:
            n = op-0x8f
            assert len(stack)-1-n >= floor
            stack[-1], stack[-1-n] = stack[-1-n], stack[-1]
        elif op == 0x50:
            assert len(stack) > floor
            stack.pop()
        elif op == 0x51:
            a = stack.pop()
            reads.append(a)
            stack.append(memory[a])
        elif op == 0x52:
            a, b = stack.pop(), stack.pop()
            writes.append(a)
            memory[a] = b
        elif op == 0x58:
            stack.append(at)
        elif op == 0x57:
            target, condition = stack.pop(), stack.pop()
            assert 0 <= target < len(code) and code[target] == 0x5b
            if condition:
                pc = target
                jumps += 1
        elif op == 0x5b:
            pass
        else:
            assert len(stack) >= floor+2
            a, b = stack.pop(), stack.pop()
            if op == 1: value = a+b
            elif op == 3: value = a-b
            elif op == 0x11: value = int(a>b)
            elif op == 0x16: value = a & b
            elif op == 0x17: value = a | b
            elif op == 0x18: value = a ^ b
            elif op == 0x1b: value = b << a
            else:
                assert op == 0x1c
                value = b >> a
            stack.append(value & ref.U)
        peak = max(peak, len(stack)-floor)
        assert stack[:floor] == canaries and len(stack) >= floor
    assert stack == canaries
    return dict(gas=gas, max_owned_stack=peak, reads=reads, writes=writes, jumps=jumps)


def execute(code, memory, cached):
    assert cached in (0, 1)
    result = _execute(code, memory, [ref.U, 0x123456, cached])
    if cached:
        assert result['reads'] == result['writes'] == [] and result['jumps'] == 1
    else:
        assert result['reads'] == [0x1be0, 0x1bc0]+[p-d for p in range(0x1c00, 0x2200, 32) for d in [224,512,480]]
        assert result['writes'] == list(range(0x1c00,0x2200,32)) and result['jumps'] == 5
    assert result['max_owned_stack'] <= 14
    return result


def check():
    code, unroll = load_word(), 8
    rng = random.Random(0x202609174)
    gas = {}
    peak = 0
    for case in range(258):
        values = [0]*16 if case==0 else [ref.MASK]*16 if case==1 else [rng.getrandbits(256)&ref.MASK for _ in range(16)]
        expected = [0]*64
        for lane in range(7):
            schedule,_ = ref.scalar([(x>>(37*lane)) & 0xffffffff for x in values],[0]*8)
            for i,x in enumerate(schedule): expected[i] |= x<<(37*lane)
        for cached in [0,1]:
            memory = {0x1a00+32*i:v for i,v in enumerate(values)}
            memory.update({0x1a00+32*i:expected[i] if cached else rng.getrandbits(256) for i in range(16,64)})
            memory.update({0:ref.U,0x19e0:0x1234,0x2200:0x5678,0x2420:0x9abc})
            before = memory.copy()
            run = execute(code,memory,cached)
            assert [memory[0x1a00+32*i] for i in range(64)] == expected
            if cached:
                assert before == memory and run['reads'] == run['writes'] == [] and run['jumps']==1
            else:
                assert run['writes'] == list(range(0x1c00,0x2200,32))
                assert run['reads'] == [0x1be0,0x1bc0]+[p-d for p in run['writes'] for d in [224,512,480]]
                assert run['jumps'] == 48//unroll-1
                assert all(memory[a] == v for a,v in before.items() if a not in run['writes'])
            if cached in gas: assert gas[cached] == run['gas']
            gas[cached] = run['gas']
            peak = max(peak,run['max_owned_stack'])
    return dict(full_scalar_expansions=1806, cache_hits=258, cache_misses=258,
                miss_gas=gas[0],hit_gas=gas[1],max_owned_stack=peak,
                exact_146_reads_and_48_ordered_writes=True, dirty_words_neighbors_and_stack_preserved=True)


if __name__ == '__main__':
    from sha_scalar_stack_check import check as scalar_check
    print(json.dumps(dict(rounds=ref.check(retained=True), words=check(),
                          scalar_continuation=scalar_check(pair=True)), indent=2))
