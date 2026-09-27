#!/usr/bin/env python3
"""Check the production seven-lane SHA block against its exact Yul equations.

Run from any directory: python3 scripts/sha_stack_check.py
No compiler, network, external package, or retained research report is needed.
The symbolic proof keeps integer additions/carries and nonlinear ANDs exact;
only bit-linear maps are normalized. A separate opcode interpreter also checks
all 64 rounds against 2,254 independent scalar SHA-256 compressions, including
zero, dense, basis and deterministic random inputs and underlying-stack canaries.
"""
from pathlib import Path
import hashlib
import json
import random
import re

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / 'src/solidity/sha_stack'
BLOCK_HASH = '25aaa3f04cee1446d5901296eecd247b0dbd9d6d2fca036533802f7485d09fbd'
PLACEMENT_HASH = 'fcb13ca730f9b4f8a65662a14d75ee0731a31d7251addfe3931873f2c67e3717'
CURSOR_HASH = 'b95b04dd62c7769294246ea85f6ae6e5fce78e954ec8e0c0b87b7b88d1bde25f'
FOUR_HASH = '89d86e1aa7d12b47bc53ddd4391018dc61f0b5560e6a5e10aa4ebdc2869f846a'
GROUP_HASH = 'c6b97f9bf6025e0ed5cdb7ecbf46f5b2099dba4f09d28c601edcef6a5d38e741'
SIGMA_HASH = '8747454f3932cbbc93ac3ddaa05fc4d4ffcb30142ef0f88b8d51c1e4bf1ac55b'
RETAINED_HASH = 'c42783843e8233d2402c8f174feea2ffd8ae2ade1f503a60aa888ee2bc67c4ad'
U = (1 << 256) - 1
REP = sum(1 << (37 * i) for i in range(7))
MASK = REP * ((1 << 32) - 1)


def load_block(placement=False, cursor=False, four=False, group=False, sigma=False, retained=False):
    assert sum((placement, cursor, four, group, sigma, retained)) <= 1
    file = 'round-retained-block.hex' if retained else 'round-sigma-block.hex' if sigma else 'round-group-block.hex' if group else 'round-four-block.hex' if four else 'round-cursor-block.hex' if cursor else 'round-placement-block.hex' if placement else 'round-block.hex'
    code = bytes.fromhex((DATA / file).read_text())
    assert len(code) == (705 if retained else 1018 if sigma else 1261 if group else 1290 if four else 485 if cursor else 487 if placement else 488)
    assert hashlib.sha256(code).hexdigest() == (RETAINED_HASH if retained else SIGMA_HASH if sigma else GROUP_HASH if group else FOUR_HASH if four else CURSOR_HASH if cursor else PLACEMENT_HASH if placement else BLOCK_HASH)
    return code


def runtime_tokens(source):
    """Extract only the complete runtime object, ignoring comments safely."""
    lexemes = re.findall(r'/\*[\s\S]*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|'
                         r'[A-Za-z0-9_$.]+|:=|->|[^\s]', source)
    tokens = [s for s in lexemes if not s.startswith(('/*', '//'))]
    starts = [i + 2 for i in range(len(tokens) - 2)
              if tokens[i] == 'object' and tokens[i+1].endswith('_deployed"') and tokens[i+2] == '{']
    assert len(starts) == 1
    start, depth = starts[0], 0
    for i in range(start, len(tokens)):
        depth += (tokens[i] == '{') - (tokens[i] == '}')
        if depth == 0:
            return tokens[start:i+1]
    raise AssertionError('unterminated runtime object')


def validate_source(reference_ir, yul_source, word_block=None, round_block=None, scalar_core=None):
    """The entire emitted runtime must differ by just the proved SHA block."""
    block = load_block() if round_block is None else round_block
    checked_parts(block)
    call = 'verbatim_0i_0o(hex"' + block.hex() + '")'
    assert yul_source.count(call) == 1
    restored = yul_source.replace(call, (DATA / 'rounds.yul').read_text())
    word_loop = False
    if word_block is not None:
        import sha_word_stack_check as words
        import sha_word_loop_check as loop
        import sha_word_group_check as word_groups
        import sha_pair_stack_check as pair
        word_pair = word_block == pair.load_word()
        word_group = word_block == word_groups.load_block()
        double = word_block == loop.load_block(True)
        word_loop = word_pair or word_group or double or word_block == loop.load_block()
        if word_loop:
            assert block == (load_block(retained=True) if word_pair else load_block(sigma=True) if double or word_group else load_block(group=True)) and scalar_core == 'packed'
            reference, argument = 'word-loop.yul', 'usr$cached'
        else:
            assert word_block in (words.load_block(), words.load_block(True))
            words.symbolic(word_block)
            reference, argument = 'words.yul', 'usr$p'
        call = 'verbatim_1i_0o(hex"' + word_block.hex() + '", ' + argument + ')'
        assert restored.count(call) == 1
        restored = restored.replace(call, (DATA / reference).read_text())
    restored_tokens = runtime_tokens(restored)
    if block in (load_block(four=True), load_block(group=True), load_block(sigma=True), load_block(retained=True)):
        assert scalar_core == 'packed' and word_block is not None
        if block == load_block(retained=True):
            assert word_pair
        if block == load_block(sigma=True):
            assert word_group or word_block == loop.load_block(True)
        assert word_loop or word_block == words.load_block(True)
        # The packed callee's complete body must match too, including its
        # schedule cache, state copy, and masked feed-forward. Solc swaps these
        # two specialization names on different circuits.
        bare_tokens = lambda s: runtime_tokens('object "C_deployed" { ' + s + ' }')[1:-1]
        span = lambda ts, needle: [i for i in range(len(ts)-len(needle)+1)
                                  if ts[i:i+len(needle)] == needle]
        matches = []
        for scalar, packed in [('fun_shaRounds', 'fun__shaRounds'), ('fun__shaRounds', 'fun_shaRounds')]:
            callee = bare_tokens((DATA / 'packed-rounds.yul').read_text().replace('fun__shaRounds', packed, 1))
            wrapper = bare_tokens(f'function {scalar}(var_m_mpos) {{ mstore(0x2420, 0) {packed}(var_m_mpos) }}')
            original = bare_tokens((DATA / 'scalar-rounds.yul').read_text().replace('fun_shaRounds', scalar, 1))
            sites = span(restored_tokens, wrapper)
            if sites:
                assert len(sites) == len(span(restored_tokens, callee)) == 1
                matches.append((sites[0], len(wrapper), original))
        assert len(matches) == 1, 'missing or ambiguous scalar core binding'
        i, size, original = matches[0]
        restored_tokens[i:i+size] = original
    else:
        assert scalar_core is None, 'unexpected scalar core binding'
    assert restored_tokens == runtime_tokens(reference_ir), 'unrelated Yul runtime change'


def push(n):
    if n == 0:
        return bytes([0x5f])
    data = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x5f + len(data)]) + data


def checked_parts(block):
    if block == load_block(retained=True):
        from sha_pair_stack_check import checked_round_parts
        bodies, order, _ = checked_round_parts(block)
        return b''.join(bodies), order
    if block in (load_block(group=True), load_block(sigma=True)):
        bodies, order, _ = checked_group_parts(block)
        return b''.join(bodies), order
    if block == load_block(four=True):
        body, order, _ = checked_four_parts(block)
        return body, order
    cursor = False
    if block == load_block():
        assembly = 'round.asm'
    elif block == load_block(True):
        assembly = 'round-placement.asm'
    else:
        assert block == load_block(cursor=True)
        assembly = 'round-cursor.asm'
        cursor = True
    # Decode the prologue to obtain the actual stack ordering, not a scheduler
    # promise about it. Every working state word is loaded once, plus the
    # offset cursor 0 or the absolute constant-table cursor 0x1000.
    pc = 0
    order = []
    while block[pc] != 0x5b:
        op = block[pc]
        pc += 1
        if op == 0x5f:
            assert not cursor
            order.append('p')
        else:
            assert op == 0x61
            address = int.from_bytes(block[pc:pc+2], 'big')
            pc += 2
            if cursor and address == 0x1000:
                order.append('p')
                continue
            assert block[pc] == 0x51 and address in range(0x2300, 0x2400, 32)
            pc += 1
            order.append('abcdefgh'[(address - 0x2300) // 32])
    assert len(order) == 9 and set(order) == set('abcdefghp')
    loop = pc
    # Read the reviewable assembly, then bind it to the ACTUAL embedded body.
    body = bytearray()
    ops = {'ADD':1, 'AND':0x16, 'OR':0x17, 'XOR':0x18,
           'SHL':0x1b, 'SHR':0x1c, 'MLOAD':0x51}
    for line in (DATA / assembly).read_text().splitlines():
        parts = line.split()
        if parts[0] == 'PUSH':
            body.extend(push(int(parts[1], 16)))
        elif parts[0].startswith('DUP'):
            body.append(0x7f + int(parts[0][3:]))
        elif parts[0].startswith('SWAP'):
            body.append(0x8f + int(parts[0][4:]))
        else:
            body.append(ops[parts[0]])
    assert block[pc+1:pc+1+len(body)] == body
    # Construct the complete suffix, verifying the loop's test, internal branch
    # and all eight stores; cursor is discarded and no underlying stack is read.
    rebuilt = bytearray(block[:pc+1]) + body
    rebuilt.append(0x7f + 9 - order.index('p'))
    rebuilt.extend(push(0x1800 if cursor else 2048) + b'\x11')
    distance = len(rebuilt) + 3 - loop
    rebuilt.extend(b'\x61' + distance.to_bytes(2, 'big') + b'\x58\x03\x57')
    for name in reversed(order):
        if name == 'p':
            rebuilt.append(0x50)
        else:
            rebuilt.extend(push(0x2300 + 32 * 'abcdefgh'.index(name)) + b'\x52')
    assert rebuilt == block
    return bytes(body), order


def checked_four_parts(block):
    """Prove the actual four-round block by composition of exact single rounds.

    Three retained constants replace four PUSH32s with DUPs. Their stack
    depths are decoded symbolically, and all other body bytes stay identical.
    The full reconstruction binds all four copies, 16 loops, and eight stores.
    """
    assert block == load_block(four=True)
    previous, order = checked_parts(load_block(cursor=True))
    masks = [
        0x3fffffffc1fffffffe0ffffffff07fffffff83fffffffc1fffffffe0ffffffff,
        0xfffff8003fffffc001fffffe000ffffff0007fffff8003fffffc001fffffe000,
        0xfff000003fff800001fffc00000fffe000007fff000003fff800001fffc00000,
    ]
    patches = {119: (masks[1], 12), 194: (masks[2], 12),
               322: (masks[0], 13), 362: (masks[0], 12)}
    body = bytearray()
    pc = 0
    while pc < len(previous):
        if pc in patches:
            value, depth = patches[pc]
            assert previous[pc:pc+33] == push(value)
            body.append(0x7f + depth)
            pc += 33
        else:
            op = previous[pc]
            size = 1 + (op-0x5f if 0x60 <= op <= 0x7f else 0)
            body.extend(previous[pc:pc+size])
            pc += size
    assert len(previous) == 405 and len(body) == 277
    left, high = symbolic(body, ['canary0', 'canary1'] + masks + order)
    right, old_high = symbolic(previous, ['canary0', 'canary1'] + order)
    assert left[:5] == ['canary0', 'canary1'] + masks and left[5:] == right[2:]
    assert high == old_high + 3 == 18  # 16 owned stack words + two canaries
    prefix = b''.join(push(value) for value in masks)
    for name in order:
        prefix += push(0x1000) if name == 'p' else push(0x2300 + 32 * 'abcdefgh'.index(name)) + b'\x51'
    loop = len(prefix)
    rebuilt = bytearray(prefix) + b'\x5b' + body * 4
    rebuilt.append(0x7f + 9 - order.index('p'))
    rebuilt.extend(push(0x1800) + b'\x11')
    distance = len(rebuilt) + 3 - loop
    rebuilt.extend(b'\x61' + distance.to_bytes(2, 'big') + b'\x58\x03\x57')
    for name in reversed(order):
        rebuilt += b'\x50' if name == 'p' else push(0x2300 + 32 * 'abcdefgh'.index(name)) + b'\x52'
    rebuilt += b'\x50' * 3
    assert rebuilt == block
    return bytes(body), order, masks


def symbolic(code, initial):
    stack=list(initial);pc=0; high=len(stack)
    names={1:'add',0x16:'and',0x17:'or',0x18:'xor',0x1b:'shl',0x1c:'shr',0x51:'mload'}
    while pc<len(code):
        op=code[pc];pc+=1
        if op==0x5f:stack.append(0)
        elif 0x60<=op<=0x7f:
            n=op-0x5f;stack.append(int.from_bytes(code[pc:pc+n],'big'));pc+=n
        elif 0x80<=op<=0x8f:stack.append(stack[-(op-0x7f)])
        elif 0x90<=op<=0x9f:
            d=op-0x8f;stack[-1],stack[-1-d]=stack[-1-d],stack[-1]
        elif op in names:
            a=stack.pop()
            if op==0x51:stack.append(('mload',a))
            else:stack.append((names[op],a,stack.pop()))
        else:raise AssertionError(hex(op))
        high=max(high,len(stack))
    return stack,high

def parse_round(source):
    match=re.search(r'for\s*\{\s*\}\s*lt\(([^,]+),\s*2048\)\s*\{([^}]*)\}\s*\{',source)
    assert match
    cursor=match[1].strip()
    assert re.sub(r'\s+','',match[2])==cursor+':=add('+cursor+',32)'
    lo=match.end();depth=1;end=lo
    while depth:
        depth+=(source[end]=='{')-(source[end]=='}');end+=1
    tokens=re.findall(r'0x[0-9a-f]+|[0-9]+|[A-Za-z_$][A-Za-z0-9_$]*|:=|[(),]',source[lo:end-1])
    env={'usr$'+name:name for name in 'abcdefgh'};env[cursor]='p';at=0;statements=[]
    def expression():
        nonlocal at
        token=tokens[at];at+=1
        if token[0].isdigit():return int(token,16 if token.startswith('0x') else 10)
        if at<len(tokens) and tokens[at]=='(':
            at+=1;args=[]
            while tokens[at]!=')':
                args.append(expression())
                if tokens[at]!=')':assert tokens[at]==',';at+=1
            at+=1;return (token,*args)
        assert token in env,token
        return env[token]
    while at<len(tokens):
        if tokens[at]=='let':at+=1
        name=tokens[at];assert tokens[at+1]==':=';at+=2
        env[name]=expression();statements.append(name)
    assert len(statements)==11,statements
    return {name:env['usr$'+name] for name in 'abcdefgh'} | {'p':('add','p',32)}

class Algebra:
    def __init__(self):self.leaves={};self.next=1;self.cache={}
    def leaf(self,key,mask=U):
        if key not in self.leaves:
            self.leaves[key]=tuple(1<<(self.next+i) if (mask>>i)&1 else 0 for i in range(256))
            self.next+=256
        return self.leaves[key]
    def address(self,n):
        if not isinstance(n,tuple):return n
        args=[self.address(a) for a in n[1:]]
        if n[0]=='add':args.sort(key=repr)
        return (n[0],*args)
    def canon(self,n):
        if n in self.cache:return self.cache[n]
        if isinstance(n,int):v=tuple((n>>i)&1 for i in range(256))
        elif isinstance(n,str):v=self.leaf(('parameter',n),MASK if n in 'abcdefgh' else U)
        elif n[0]=='mload':v=self.leaf(('memory',self.address(n[1])),MASK)
        elif n[0] in ['shr','shl']:
            shift=n[1];assert isinstance(shift,int) and 0<=shift<256
            a=self.canon(n[2])
            v=tuple((a[i+shift] if i+shift<256 else 0) if n[0]=='shr' else (a[i-shift] if i>=shift else 0) for i in range(256))
        elif n[0]=='xor':v=tuple(a^b for a,b in zip(self.canon(n[1]),self.canon(n[2])))
        elif n[0]=='or':
            a,b=self.canon(n[1]),self.canon(n[2])
            assert all(x==0 or y==0 or x==y for x,y in zip(a,b)),'OR is not linear on these operands'
            v=tuple(x or y for x,y in zip(a,b))
        elif n[0]=='and':
            if isinstance(n[1],int):mask,a=n[1],self.canon(n[2]);v=tuple(x if (mask>>i)&1 else 0 for i,x in enumerate(a))
            elif isinstance(n[2],int):mask,a=n[2],self.canon(n[1]);v=tuple(x if (mask>>i)&1 else 0 for i,x in enumerate(a))
            else:v=self.leaf(('and',*sorted([self.canon(n[1]),self.canon(n[2])])) )
        elif n[0]=='add':
            terms=[]
            def collect(x):
                if isinstance(x,tuple) and x[0]=='add':
                    collect(x[1]);collect(x[2])
                else:terms.append(self.canon(x))
            collect(n)
            v=self.leaf(('add',*sorted(terms)))
        else:raise AssertionError(n[0])
        self.cache[n]=v;return v

def execute(code, memory, sentinel, expected_jumps=63):
    # Numeric interpreter intentionally decodes the retained bytes, not DAGs.
    stack=list(sentinel);pc=0;steps=0;jumps=0;writes=[]
    while pc<len(code):
        at=pc;op=code[pc];pc+=1;steps+=1
        assert steps<20000
        if op==0x5f:stack.append(0)
        elif 0x60<=op<=0x7f:
            n=op-0x5f;stack.append(int.from_bytes(code[pc:pc+n],'big'));pc+=n
        elif 0x80<=op<=0x8f:stack.append(stack[-(op-0x7f)])
        elif 0x90<=op<=0x9f:
            d=op-0x8f;stack[-1],stack[-1-d]=stack[-1-d],stack[-1]
        elif op in [1,3,0x11,0x16,0x17,0x18,0x1b,0x1c]:
            a,b=stack.pop(),stack.pop()
            if op==1:z=a+b
            elif op==3:z=a-b
            elif op==0x11:z=int(a>b)
            elif op==0x16:z=a&b
            elif op==0x17:z=a|b
            elif op==0x18:z=a^b
            elif op==0x1b:z=b<<a
            else:z=b>>a
            stack.append(z&U)
        elif op==0x51:stack.append(memory[stack.pop()])
        elif op==0x52:
            a,b=stack.pop(),stack.pop();memory[a]=b;writes.append(a)
        elif op==0x50:stack.pop()
        elif op==0x58:stack.append(at)
        elif op==0x57:
            dest,condition=stack.pop(),stack.pop()
            assert 0<=dest<len(code) and code[dest]==0x5b
            if condition:pc=dest;jumps+=1
        else:assert op==0x5b,hex(op)
    assert stack==sentinel and jumps==expected_jumps
    assert sorted(writes)==list(range(0x2300,0x2400,32))
    return steps

source = (ROOT / 'src/solidity/runtime.sol').read_text()
KHEX = re.search(r'bytes memory rawConstants\s*=\s*hex"([0-9a-f]+)"', source)[1]
K = [int.from_bytes(bytes.fromhex(KHEX)[i:i+4], 'big') for i in range(0, 256, 4)]
assert len(K) == 64 and K[0] == 0x428a2f98 and K[-1] == 0xc67178f2

def scalar(w,state):
    m=(1<<32)-1
    def rot(x,n):return ((x>>n)|(x<<(32-n)))&m
    w=list(w)
    for i in range(16,64):
        x,y=w[i-15],w[i-2]
        w.append((w[i-16]+(rot(x,7)^rot(x,18)^(x>>3))+w[i-7]+(rot(y,17)^rot(y,19)^(y>>10)))&m)
    a,b,c,d,e,f,g,h=state
    for i in range(64):
        t=(h+(rot(e,6)^rot(e,11)^rot(e,25))+((e&f)^((~e)&g))+K[i]+w[i])&m
        z=((rot(a,2)^rot(a,13)^rot(a,22))+((a&b)^(a&c)^(b&c)))&m
        a,b,c,d,e,f,g,h=(t+z)&m,a,b,c,(d+t)&m,e,f,g
    return w,[a,b,c,d,e,f,g,h]

def validate_runtime(code, source_map, block, word_block=None):
    assert 0 < len(code) <= 24576
    assert code[:1] == b'\x61' and code[3:6] == b'\x60\x40\x52'
    free = int.from_bytes(code[1:3], 'big')
    assert 128 <= free <= 4096 and free % 32 == 0
    assert code.count(block) == 1
    checked_parts(block)
    start = code.index(block)
    blocks = {start: block}
    if word_block is not None:
        import sha_word_stack_check as words
        import sha_word_loop_check as loop
        import sha_word_group_check as word_groups
        import sha_pair_stack_check as pair
        assert code.count(word_block) == 1
        if word_block == pair.load_word():
            assert block == load_block(retained=True)
        elif word_block in (word_groups.load_block(), loop.load_block(True)):
            assert block == load_block(sigma=True)
        elif word_block == loop.load_block():
            assert block == load_block(group=True)
        else:
            assert word_block in (words.load_block(), words.load_block(True))
            words.symbolic(word_block)
        blocks[code.index(word_block)] = word_block
        assert len(blocks) == 2
    metadata = len(code) - 2 - int.from_bytes(code[-2:], 'big')
    pc = seen = 0
    for _ in source_map.split(';'):
        assert pc < metadata
        if pc in blocks:
            pc += len(blocks[pc])
            seen += 1
        else:
            op = code[pc]
            assert op not in (0x55, 0x5d, 0xf0, 0xf1, 0xf2, 0xf4, 0xf5, 0xfa, 0xff)
            pc += 1 + (op - 0x5f if 0x60 <= op <= 0x7f else 0)
    assert seen == len(blocks) and pc <= metadata
    if pc < metadata:
        assert code[pc] == 0xfe and 0x5b not in code[pc:metadata]
    result = dict(free_pointer=free, kernel_pc=start, mapped_end=pc, metadata_start=metadata)
    if word_block is not None:
        result['word_kernel_pc'] = code.index(word_block)
    return result


def absolute_cursor_reference(reference):
    """Rebase only the two reads: p_absolute = 0x1000 + p_offset.

    The decoded prologue/loop suffix establish the initial cursor and bound.
    The symbolic body below preserves p += 32. These address equalities thus
    cover every iteration; no state value or round equation is rewritten.
    """
    addresses = {
        ('add', 0x1000, 'p'): 'p',
        ('add', 0x1a00, 'p'): ('add', 0xa00, 'p'),
    }
    seen = set()
    def rewrite(n):
        if not isinstance(n, tuple):
            return n
        if n[0] == 'mload':
            assert n[1] in addresses, 'unexpected round memory read'
            seen.add(n[1])
            return ('mload', addresses[n[1]])
        return (n[0], *(rewrite(a) for a in n[1:]))
    rebased = {name: rewrite(n) for name, n in reference.items()}
    assert seen == set(addresses)
    for offset in range(0, 2048, 32):
        absolute = 0x1000 + offset
        assert (absolute, absolute + 0xa00) == (0x1000 + offset, 0x1a00 + offset)
    return rebased


def group_cursor_reference(reference, stage):
    """Rebase a round's two reads against the group's unchanged base cursor.

    Only the fourth body advances the cursor. The independently decoded loop
    initializes p=0x1000 and ends at p=0x1800, hence 16 groups cover 64 rounds.
    """
    assert stage in range(4) and reference['p'] == ('add', 'p', 32)
    addresses = {'p': ('add', 32*stage, 'p') if stage else 'p',
                 ('add', 0xa00, 'p'): ('add', 0xa00+32*stage, 'p')}
    seen = set()
    def rewrite(n):
        if not isinstance(n, tuple):
            return n
        if n[0] == 'mload':
            assert n[1] in addresses, 'unexpected group round memory read'
            seen.add(n[1])
            return ('mload', addresses[n[1]])
        return (n[0], *(rewrite(a) for a in n[1:]))
    result = {name:rewrite(reference[name]) for name in 'abcdefgh'}
    result['p'] = ('add', 'p', 128) if stage == 3 else 'p'
    assert seen == set(addresses)
    for group in range(16):
        p = 0x1000+128*group
        original_round = 4*group+stage
        assert (p+32*stage, p+0xa00+32*stage) == (0x1000+32*original_round, 0x1a00+32*original_round)
    return result


def group_body(stage, sigma=False):
    """Assemble the reviewable body; checked_group_parts binds it to the bytes."""
    assert stage in range(4)
    ops = {'ADD':1, 'AND':0x16, 'OR':0x17, 'XOR':0x18, 'SHL':0x1b, 'SHR':0x1c, 'MLOAD':0x51}
    body = bytearray()
    family = 'sigma' if sigma else 'group'
    for line in (DATA / f'round-{family}-{stage}.asm').read_text().splitlines():
        parts = line.split('#', 1)[0].split()
        if not parts:
            continue
        if parts[0] == 'PUSH':
            assert len(parts) == 2
            body.extend(push(int(parts[1], 16)))
        else:
            assert len(parts) == 1
            if parts[0].startswith('DUP'):
                depth = int(parts[0][3:])
                assert 1 <= depth <= 16
                body.append(0x7f+depth)
            elif parts[0].startswith('SWAP'):
                depth = int(parts[0][4:])
                assert 1 <= depth <= 16
                body.append(0x8f+depth)
            else:
                body.append(ops[parts[0]])
    return bytes(body)


def group_masks(sigma=False):
    # Shared ROTR13/22 correction retains their wrap-input masks; the exact
    # symbolic comparison below proves the original strict rotations including
    # every guard bit. The unchanged ROTR2 expression remains part of that proof.
    return [MASK, REP*((1 << 13)-1), REP*((1 << 22)-1)] if sigma else checked_four_parts(load_block(four=True))[2]


def check_group_body(body, before, after, stage, sigma=False):
    assert len(before) == len(after) == 9 and set(before) == set(after) == set('abcdefghp')
    masks = group_masks(sigma)
    prefix = ['canary0', 'canary1'] + masks
    actual, high = symbolic(body, prefix + before)
    assert actual[:len(prefix)] == prefix and len(actual) == len(prefix)+9 and high <= (19 if sigma else 18)
    actual = dict(zip(after, actual[len(prefix):]))
    reference = group_cursor_reference(absolute_cursor_reference(parse_round((DATA / 'rounds.yul').read_text())), stage)
    algebra = Algebra()
    for name in 'abcdefghp':
        assert algebra.canon(actual[name]) == algebra.canon(reference[name]), (stage, name)
    pc = gas = 0
    while pc < len(body):
        op = body[pc]
        pc += 1+(op-0x5f if 0x60 <= op <= 0x7f else 0)
        assert op in (1, 0x16, 0x17, 0x18, 0x1b, 0x1c, 0x51, 0x5f) or 0x60 <= op <= 0x9f
        gas += 2 if op == 0x5f else 3
    assert pc == len(body)
    return dict(gas=gas, max_owned_stack=high-2)


def checked_group_parts(block):
    sigma = block == load_block(sigma=True)
    assert sigma or block == load_block(group=True)
    layout = json.loads((DATA / ('round-sigma-orders.json' if sigma else 'round-group-orders.json')).read_text())
    assert set(layout) == {'entry', 'outputs'} and len(layout['outputs']) == 4
    masks = group_masks(sigma)
    order = layout['entry']
    bodies, facts = [], []
    for stage, after in enumerate(layout['outputs']):
        body = group_body(stage, sigma)
        facts.append(check_group_body(body, order, after, stage, sigma))
        bodies.append(body)
        order = after
    assert order == layout['entry']
    prefix = b''.join(push(value) for value in masks)
    for name in order:
        prefix += push(0x1000) if name == 'p' else push(0x2300+32*'abcdefgh'.index(name)) + b'\x51'
    loop = len(prefix)
    rebuilt = bytearray(prefix) + b'\x5b' + b''.join(bodies)
    rebuilt.append(0x7f+9-order.index('p'))
    rebuilt.extend(push(0x1800) + b'\x11')
    distance = len(rebuilt)+3-loop
    rebuilt.extend(b'\x61'+distance.to_bytes(2, 'big')+b'\x58\x03\x57')
    for name in reversed(order):
        rebuilt += b'\x50' if name == 'p' else push(0x2300+32*'abcdefgh'.index(name)) + b'\x52'
    rebuilt += b'\x50'*3
    assert rebuilt == block
    facts = dict(group_gas=sum(row['gas'] for row in facts), max_owned_stack=max(row['max_owned_stack'] for row in facts))
    assert facts == dict(group_gas=1245, max_owned_stack=17 if sigma else 16)
    return bodies, order, facts


def check(placement=False, cursor=False, four=False, group=False, sigma=False, retained=False):
    block = load_block(placement, cursor, four, group, sigma, retained)
    if retained:
        from sha_pair_stack_check import checked_round_parts
        checked_round_parts(block)
    elif group or sigma:
        checked_group_parts(block)
    else:
        body, order = checked_parts(block)
        masks = checked_four_parts(block)[2] if four else []
        prefix = ['canary0', 'canary1'] + masks
        actual, high = symbolic(body, prefix + order)
        assert actual[:len(prefix)] == prefix and len(actual) == len(prefix) + 9 and high == len(prefix) + 13
        actual = dict(zip(order, actual[len(prefix):]))
        reference = parse_round((DATA / 'rounds.yul').read_text())
        if cursor or four:
            reference = absolute_cursor_reference(reference)
        algebra = Algebra()
        for name in 'abcdefghp':
            assert algebra.canon(actual[name]) == algebra.canon(reference[name]), name
    rng = random.Random(0x312901)
    for mode in range(322):
        if mode == 0:
            values = [0] * 24
        elif mode == 1:
            values = [MASK] * 24
        elif mode < 226:
            values = [0] * 24
            values[(mode - 2) % 24] = 1 << (((mode - 2) // 32) * 37 + (mode - 2) % 32)
        else:
            values = [rng.getrandbits(256) & MASK for _ in range(24)]
        schedule, expected = [0] * 64, [0] * 8
        for lane in range(7):
            words = [(n >> (37 * lane)) & 0xffffffff for n in values[:16]]
            state = [(n >> (37 * lane)) & 0xffffffff for n in values[16:]]
            ws, result = scalar(words, state)
            for i, n in enumerate(ws):
                schedule[i] |= n << (37 * lane)
            for i, n in enumerate(result):
                expected[i] |= n << (37 * lane)
        memory = {0x1000 + 32 * i: k * REP for i, k in enumerate(K)}
        memory.update({0x1a00 + 32 * i: w for i, w in enumerate(schedule)})
        memory.update({0x2300 + 32 * i: v for i, v in enumerate(values[16:])})
        memory.update({0: 0x1234, 0x2420: 0x5678})
        before = dict(memory)
        execute(block, memory, [0x123456, U, 0], 15 if four or group or sigma or retained else 63)
        assert [memory[0x2300 + 32 * i] for i in range(8)] == expected
        assert all(memory[p] == value for p, value in before.items() if p not in range(0x2300, 0x2400, 32))
    return dict(block_sha256=hashlib.sha256(block).hexdigest(), symbolic_outputs=36 if group or sigma or retained else 9, canonical_state_bits=1792,
                integer_carries_not_linearized=True, rounds_per_compression=64,
                vectors=322, scalar_compressions=2254, exact_state_writes=True,
                underlying_stack_preserved=True)


if __name__ == '__main__':
    from sha_scalar_stack_check import check as scalar_check
    print(json.dumps({'legacy': check(), 'placement': check(True), 'cursor': check(cursor=True),
                      'four': check(four=True), 'group': check(group=True), 'sigma': check(sigma=True), 'retained': check(retained=True),
                      'scalar_core': scalar_check(), 'group_scalar_core': scalar_check(group=True),
                      'word_loop_scalar_core': scalar_check(group=True, word_loop=True),
                      'double_word_scalar_core': scalar_check(group=True, word_loop=True, sigma=True),
                      'group_word_scalar_core': scalar_check(group=True, word_loop=True, sigma=True, word_group=True),
                      'pair_word_scalar_core': scalar_check(pair=True)}, indent=2))
