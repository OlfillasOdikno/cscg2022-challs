"""
design: r0-r7

OPCODES

LOAD # loads from memory into register
MOV # loads contant or register into register
ADD # add two registers
STORE # store register value into memory

MEMORY LAYOUT (subject to change)
0x00-0x10: scratch (initialized to zero)
0x10-0xf8: INPUT
0x0f8-0x100: registers
0x100-0x200: constants
0x200-0x400: memory

r0 is return value

example:

MOV r1, 0x41 #loads constant into register
MOV r2, 0x01

ADD r1, r2 #adds r2 to r1

STORE r1, 0x1 # store r1 into memory[1]


BREQUAL r1, r2, asdf# 
:loop
JMP loop

asdf:
ADD r1, r2

"""

"""
primitives:
# mov content from memory 1 into memory 4
1, 5, PC+1
5, 4, PC+1

# sub content from memory 2 of memory 1 and store in memory 6
1, 7, PC+1
7, 6, PC+1
2, 6, PC+1
"""


from dataclasses import dataclass
import struct


FLAG = b"m3110N!!"

KEY = [0x4198F302]*len(FLAG) #TODO make better

example_program = ""
for idx in range(1+len(FLAG)//4):
    c = FLAG[idx*4:][:4]
    if not c:
        break
    example_program+=f"""
    # loads constant into register
    MOV r1, {(int.from_bytes(c,"little")+KEY[idx])&0xFFFFFFFF}
    MOV r3, {KEY[idx]}
    INPUT r2, {idx}
    ADD r2, r3
    SUB r2, r1
    JZ r2, next_{idx}
    MOV r0, 1
    next_{idx}:"""
example_program+="""
SUB r1, r1
SUB r2, r2
SUB r3, r3
"""

@dataclass
class Register:
    idx: int 
    pass

gl = globals()
for i in range(8):
    gl[f"r{i}"] = Register(idx=i)

memory = [
    0x00 #scratch
]*0x10+[
    0x00 #INPUT
]*(0xf8-0x10)+[
    0x00 #REGISTER
]*8+[
    0x00 #CONSTANT
]*0x100+[
    0x00 #MEMORY
]*0x200


cidx = 1 #zero is zero :)
def get_or_add_constant(constant):
    global cidx
    constants = memory[0x100:0x200]
    if constant in constants:
        return 0x100+constants.index(constant)
    memory[0x100+cidx] = constant
    cidx += 1
    assert cidx < 0x200-0x100
    return 0x100+cidx-1

PC = 0
REGISTER_OFFSET = 0x0f8
LABELS = {}
CODE = []

for line in example_program.splitlines():
    line = line.strip()
    if ":" in line:
        line = line.split("#")[0]
        label = line.split(":")[0]
        gl[label] = label

for line in example_program.splitlines():
    line = line.strip()
    if ":" in line:
        line = line.split("#")[0]
        label = line.split(":")[0]
        LABELS[label] = PC

    if " " in line and not line.startswith("#"):
        opc, operands = line.split(" ", 1)
        opc = opc.strip().upper()
        operands = eval(operands)
        CODE.append(lambda: "\n# ----"+line+"----")
        if opc == "MOV":
            assert len(operands) == 2
            assert type(operands[0]) == Register
            assert type(operands[1]) == int or type(operands[1]) == Register
            dst = REGISTER_OFFSET+operands[0].idx
            if type(operands[1]) == int:
                src =  get_or_add_constant(operands[1])
            else:
                src = REGISTER_OFFSET+operands[1].idx
            CODE.append(lambda PC=PC, dst=dst, src=src: f"""
            # zero out register
            {dst}, {dst}, {PC+1}
            # load -src into scratch
            {src}, 0, {PC+2}
            # load src into dst register
            0, {dst}, {PC+3}
            # reset scratch
            0, 0, {PC+4}
            """)
            PC+=4
        if opc == "SUB":
            assert len(operands) == 2
            assert type(operands[0]) == Register
            assert type(operands[1]) == int or type(operands[1]) == Register
            dst = REGISTER_OFFSET+operands[0].idx
            if type(operands[1]) == int:
                src = get_or_add_constant(operands[1])
            else:
                src = REGISTER_OFFSET+operands[1].idx
            CODE.append(lambda PC=PC, dst=dst, src=src: f"""
            {src}, {dst}, {PC+1}
            """)
            PC+=1
        if opc == "ADD":
            assert len(operands) == 2
            assert type(operands[0]) == Register
            assert type(operands[1]) == int or type(operands[1]) == Register
            dst = REGISTER_OFFSET+operands[0].idx
            if type(operands[1]) == int:
                src = get_or_add_constant(operands[1])
            else:
                src = REGISTER_OFFSET+operands[1].idx
            CODE.append(lambda PC=PC, dst=dst, src=src: f"""
            #store -src in scratch
            {src}, 0, {PC+1}
            #sub -src from dst (add src to dst)
            0, {dst}, {PC+2}
            # reset scratch
            0, 0, {PC+3}
            """)
            PC+=3
        
        if opc == "LOAD":
            assert len(operands) == 2
            assert type(operands[0]) == Register
            assert type(operands[1]) == int
            dst = REGISTER_OFFSET+operands[0].idx
            src = 0x200+operands[1]
            CODE.append(lambda PC=PC, dst=dst, src=src: f"""
            # zero out register
            {dst}, {dst}, {PC+1}
            # load -src into scratch
            {src}, 0, {PC+2}
            # load src into dst register
            0, {dst}, {PC+3}
            # reset scratch
            0, 0, {PC+4}
            """)
            PC+=4
        if opc == "STORE":
            assert len(operands) == 2
            assert type(operands[0]) == Register
            assert type(operands[1]) == int
            src = REGISTER_OFFSET+operands[0].idx
            dst = 0x200+operands[1]
            CODE.append(lambda PC=PC, dst=dst, src=src: f"""
            # zero out memory
            {dst}, {dst}, {PC+1}
            # load -src into scratch
            {src}, 0, {PC+2}
            # load src into dst memory
            0, {dst}, {PC+3}
            # reset scratch
            0, 0, {PC+4}
            """)
            PC+=4
        
        if opc == "JMP":
            assert type(operands) == str
            dst = operands
            CODE.append(lambda PC=PC, dst=dst: f"""
            0, 0, {LABELS[dst]}
            """)
            PC+=1
        
        if opc == "JZ":
            assert len(operands) == 2
            assert type(operands[0]) == Register
            assert type(operands[1]) == str
            dst = operands[1]
            src = REGISTER_OFFSET+operands[0].idx
            CODE.append(lambda PC=PC, src=src, dst=dst: f"""
            # if src == 0 jmp
            {src}, 0, {PC+2}
            #nz
            0, 0, {PC+3}
            #z
            0, 0, {LABELS[dst]}
            """)
            PC += 3

        if opc == "INPUT":
            assert len(operands) == 2
            assert type(operands[0]) == Register
            assert type(operands[1]) == int
            dst = REGISTER_OFFSET+operands[0].idx
            src = 0x10+operands[1]
            CODE.append(lambda PC=PC, dst=dst, src=src: f"""
            # zero out register
            {dst}, {dst}, {PC+1}
            # load -src into scratch
            {src}, 0, {PC+2}
            # load src into dst register
            0, {dst}, {PC+3}
            # reset scratch
            0, 0, {PC+4}
            """)
            PC+=4     

code_ = ""
for c in CODE:
    code_+=c()

CODE = "\n".join([x.strip() for x in code_.splitlines()])

with open("code.sq", "wb") as f:
    f.write(CODE.encode())
with open("mem.sq", "wb") as f:
    f.write(b"".join([struct.pack("<I", x) for x in memory]))

def subeq(a,b,c):
    temp = (memory[b]-memory[a])
    memory[b] = temp&0xFFFFFFFF
    if temp==0:
        return c
    return -1
run_code = True
if not run_code:
    exit(0)

test_input = FLAG
test_input = [int.from_bytes(test_input[idx*4:][:4],"little") for idx in range(1+len(test_input)//4) if test_input[idx*4:][:4]]
memory[0x10:0x10+len(test_input)] = test_input

code = list(filter(lambda x: x and "#" not in x,CODE.splitlines()))
try:
    PC = 0
    while True:
        line = code[PC]
        r = subeq(*eval(line))
        if r >= 0:
            PC = r
        else:
            PC = PC+1
except:
    pass

for idx in range(8):
    print(f"r{idx}: {hex(memory[REGISTER_OFFSET+idx])}")
