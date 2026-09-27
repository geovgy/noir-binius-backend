"""Independently decode the W-step opcodes and check the original equations."""
from pathlib import Path
import hashlib,json,random,re
DATA=Path(__file__).resolve().parents[1]/'src/solidity/sha_stack'
BLOCK_HASH='4c6cc06c6965224f123533b5ad7b855828b107042ebde9993c31516bd1e11bda'
ORDER_HASH='4e56b829a8c054a5388a18673f804cfc74f71ce617feb5b788fcb78747b02776'
U=(1<<256)-1;W=(1<<32)-1
OPS={1:'add',3:'sub',0x16:'and',0x18:'xor',0x1b:'shl',0x1c:'shr'}

def original():
    tokens=re.findall(r'0x[0-9a-f]+|[0-9]+|[A-Za-z_$][A-Za-z0-9_$]*|:=|[(),]',(DATA/'words.yul').read_text())
    i=0;variables={'usr$p':'p'}
    def expr():
        nonlocal i
        name=tokens[i];i+=1
        if name[0].isdigit():return int(name,16 if name.startswith('0x') else 10)
        if i<len(tokens) and tokens[i]=='(':
            i+=1;args=[]
            while tokens[i]!=')':
                args.append(expr())
                if tokens[i]!=')':assert tokens[i]==',';i+=1
            i+=1;return (name,*args)
        return variables[name]
    while i<len(tokens):
        if tokens[i]=='let':
            i+=1;name=tokens[i];assert tokens[i+1]==':=';i+=2;variables[name]=expr()
        else:
            result=expr();assert i==len(tokens) and result[0]=='mstore';return result
    raise AssertionError('missing store')

def canonical(node):
    if not isinstance(node,tuple):return node
    op=node[0];args=[canonical(a) for a in node[1:]]
    if op=='not':assert len(args)==1 and isinstance(args[0],int);return U^args[0]
    if op=='sub':assert isinstance(args[1],int);op='add';args[1]=(-args[1])&U
    if op in ['add','and','xor']:args.sort(key=repr)
    return (op,*args)

def symbolic(code):
    stack=['canary0','canary1','p'];pc=0;gas=0;peak=3;loads=[];stores=[]
    while pc<len(code):
        op=code[pc];pc+=1;gas+=2 if op in [0x50,0x5f] else 3
        if op==0x5f:stack.append(0)
        elif 0x60<=op<=0x7f:
            size=op-0x5f;assert pc+size<=len(code);stack.append(int.from_bytes(code[pc:pc+size],'big'));pc+=size
        elif 0x80<=op<=0x8f:
            depth=op-0x7f;assert len(stack)-depth>=2;stack.append(stack[-depth])
        elif 0x90<=op<=0x9f:
            depth=op-0x8f;assert len(stack)-1-depth>=2;stack[-1],stack[-1-depth]=stack[-1-depth],stack[-1]
        elif op==0x51:
            assert len(stack)>=3 and not stores;address=stack.pop();loads.append(address);stack.append(('mload',address))
        elif op==0x52:
            assert len(stack)>=4;address,value=stack.pop(),stack.pop();stores.append(('mstore',address,value))
        else:
            assert op in OPS and len(stack)>=4;left,right=stack.pop(),stack.pop();stack.append((OPS[op],left,right))
        peak=max(peak,len(stack))
    assert stack==['canary0','canary1'] and len(stores)==1
    assert canonical(stores[0])==canonical(original())
    expected=[('sub','p',c) for c in [480,64,512,224]]
    assert sorted(map(canonical,loads),key=repr)==sorted(map(canonical,expected),key=repr)
    assert stores[0][1]=='p'
    return dict(gas=gas,bytes=len(code),max_stack=peak-2,loads=4,stores=1,exact_opcode_dag_equivalence=True,underlying_stack_preserved=True)

def execute(code,memory,p):
    stack=[0xfedcba987,0x123456,p];pc=0;writes=[];reads=[]
    while pc<len(code):
        op=code[pc];pc+=1
        if op==0x5f:stack.append(0)
        elif 0x60<=op<=0x7f:
            n=op-0x5f;stack.append(int.from_bytes(code[pc:pc+n],'big'));pc+=n
        elif 0x80<=op<=0x8f:stack.append(stack[-(op-0x7f)])
        elif 0x90<=op<=0x9f:
            n=op-0x8f;stack[-1],stack[-1-n]=stack[-1-n],stack[-1]
        elif op==0x51:
            address=stack.pop();reads.append(address);stack.append(memory[address])
        elif op==0x52:
            address,value=stack.pop(),stack.pop();memory[address]=value;writes.append(address)
        else:
            a,b=stack.pop(),stack.pop()
            if op==1:v=a+b
            elif op==3:v=a-b
            elif op==0x16:v=a&b
            elif op==0x18:v=a^b
            elif op==0x1b:v=b<<a
            else:assert op==0x1c;v=b>>a
            stack.append(v&U)
    assert stack==[0xfedcba987,0x123456] and writes==[p]
    assert sorted(reads)==sorted([p-480,p-64,p-512,p-224])

def pack(words):return sum((x&W)<<(37*i) for i,x in enumerate(words))
def ror(x,n):return ((x>>n)|(x<<(32-n)))&W
def step(x,y,z,t):return (z+t+(ror(x,7)^ror(x,18)^(x>>3))+(ror(y,17)^ror(y,19)^(y>>10)))&W

def load_block(order=False):
    code=bytes.fromhex((DATA/('word-order-block.hex' if order else 'word-block.hex')).read_text())
    assert len(code)==(288 if order else 292) and hashlib.sha256(code).hexdigest()==(ORDER_HASH if order else BLOCK_HASH)
    assembled=bytearray()
    opcodes={name.upper():op for op,name in OPS.items()} | {'MLOAD':0x51,'MSTORE':0x52}
    for line in (DATA/('word-order.asm' if order else 'word.asm')).read_text().splitlines():
        parts=line.split();op=parts[0]
        if op=='PUSH':
            value=int(parts[1],16)
            if value==0:assembled.append(0x5f)
            else:
                data=value.to_bytes((value.bit_length()+7)//8,'big');assembled.append(0x5f+len(data));assembled.extend(data)
        elif op.startswith('DUP'):assembled.append(0x7f+int(op[3:]))
        elif op.startswith('SWAP'):assembled.append(0x8f+int(op[4:]))
        else:assembled.append(opcodes[op])
    assert assembled==code
    return code

def check(order=False):
    code=load_block(order);facts=symbolic(code)
    assert facts['gas']==(237 if order else 249) and facts['max_stack']==7
    rng=random.Random(0x51260917);cases=[]
    for operand in range(4):
        for lane in range(7):
            for bit in range(32):
                words=[[0]*7 for _ in range(4)];words[operand][lane]=1<<bit;cases.append(words)
    for pattern in [0,1,W,0x55555555,0xaaaaaaaa,0x80000000,0x7fffffff]:
        cases.append([[pattern]*7 for _ in range(4)])
    for _ in range(2000):cases.append([[rng.getrandbits(32) for _ in range(7)] for _ in range(4)])
    for i,words in enumerate(cases):
        p=7168+(i%48)*32;memory={p-480:pack(words[0]),p-64:pack(words[1]),p-512:pack(words[2]),p-224:pack(words[3]),p:0xfedcba987,0:0x123456789}
        before=memory.copy();execute(code,memory,p)
        expected=pack([step(*(words[j][k] for j in range(4))) for k in range(7)])
        assert memory[p]==expected,(i,hex(memory[p]),hex(expected))
        assert all(memory[a]==v for a,v in before.items() if a!=p)
    # Recurrence dependencies are exercised for all 48 generated words, not
    # only isolated steps. The first 16 words are arbitrary in each lane.
    for case in range(128):
        lanes=[[rng.getrandbits(32) for _ in range(16)] for _ in range(7)]
        memory={0:0x123456789,0x2200:0xfedcba987}
        for i in range(16):memory[0x1a00+32*i]=pack([lane[i] for lane in lanes])
        for i in range(16,64):
            execute(code,memory,0x1a00+32*i)
            for lane in lanes:lane.append(step(lane[i-15],lane[i-2],lane[i-16],lane[i-7]))
            assert memory[0x1a00+32*i]==pack([lane[i] for lane in lanes])
        assert memory[0]==0x123456789 and memory[0x2200]==0xfedcba987
    result=facts|dict(scalar_step_batches=len(cases),scalar_steps=len(cases)*7,full_expansion_batches=128,full_lane_expansions=896,code_sha256=hashlib.sha256(code).hexdigest())
    return result
if __name__=='__main__':print(json.dumps({'legacy':check(),'constant_order':check(True)},indent=2))
