import struct
from qiling import *
from qiling.const import QL_VERBOSE
from keystone import *
from chaingen import subeq, strcpy
ql = Qiling(["rootfs/x8664_linux/bin/ping"], "rootfs/x8664_linux", verbose=QL_VERBOSE.DISABLED)
CODE = b"""
mov rsp, 0x15555558c000; ret
"""
ks = Ks(KS_ARCH_X86, KS_MODE_64)
encoding, count = ks.asm(CODE)

def cb(ql):
    print("CB")
    ql.save(reg=True, cpu_context=True, snapshot="/tmp/snapshot.bin")
    ql.emu_stop()


ql.hook_address(cb, 0x0000555555558800)
ql.run()
print("SAVED")


ql = Qiling(["rootfs/x8664_linux/bin/ping"], "rootfs/x8664_linux", verbose=QL_VERBOSE.DISASM)
ql.restore(snapshot="/tmp/snapshot.bin")

def dbg(ql):
    print(hex(ql.reg.al))
    #ql.emu_stop()

ql.mem.unmap_all()
ql.mem.map(0x155555500000, 0x1000)
ql.mem.map(0x155555510000, 0x1000)
with open("mem.sq", "rb") as f:
    ql.mem.write(0x155555510000, f.read())


ql.mem.map(0x155555520000, 0x1000) #scratch


ql.mem.map(0x0000555555558000, 0x0000555555563000-0x0000555555558000)
ql.mem.map(0x155555580000, 0x1000)#this would be our input argv[1]
ql.mem.write(0x155555580000, b"C")

ql.mem.write(0x155555500000, b"".join([bytes([x]) for x in encoding]))

with open("code.sq", "rb") as f:
    CODE = f.read().decode()
code = list(filter(lambda x: x and "#" not in x,CODE.splitlines()))

chain=strcpy(0x155555580000,0x155555510000+0x10*0x4,0x15555558c000)
#chain = b""
offset = len(chain)
clen = len(subeq(0x155555510000,0x155555510000, 0x155555510000))

for line in code:
    (a,b,c) = eval(line)
    print(line)
    chain+=subeq(0x155555510000+a*4,0x155555510000+b*4, 0x15555558c000+offset+c*clen)

chain+=struct.pack("Q",(0x555555555000+0x000000000000301a))#nop
chain+=struct.pack("Q",(0x555555555000+0x000000000000a518))#end
print("ROP chain length is: ",len(chain))
ql.mem.map(0x15555558c000, 0x1000*((len(chain)+0x1000)//0x1000))
ql.mem.write(0x15555558c000, chain)

with open("result.bin", "rb") as f:
    ql.mem.write(0x0000555555558000, f.read())

def instr(ql):
    print("NEXT SUBLEQ INSTRUCTION")

ql.hook_address(dbg, 0x000055555555b2d7)
ql.hook_address(instr, 0x00005555555580cf)

ql.run(begin = 0x155555500000, end=0x555555555000+0x000000000000a518)#, end=0x000055555555ae68)
print(ql.reg.rbx)
for idx in range(8):
    print(f'r{idx} = {hex(struct.unpack("I",ql.mem.read(0x155555510000+(0x0f8+idx)*4,4))[0])}')
print(ql.mem.read(0x155555510000+0x10*0x4, 16))
