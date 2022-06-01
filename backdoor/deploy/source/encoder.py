import lief
from keystone import *
import struct
from chaingen import save_stack, strcpy, subeq, jmp_if_correct, add_libc_aslr
RELOCS = []


CODE = b"""
lea r9, [0x555555558052]
"""

ks = Ks(KS_ARCH_X86, KS_MODE_64)
encoding, count = ks.asm(CODE, addr = 0x55555555a090)
elf = lief.ELF.parse("ping")
osg = elf.segment_from_virtual_address(0x4000)
modified = [x for x in osg.content[:0xa090-0x8000]]+encoding+[ x for x in osg.content[0xa090-0x8000+len(encoding):]]

CODE = b"""
mov rax, 0x555555594000
xchg rsp, rax
ret
"""
encoding, count = ks.asm(CODE, addr = 0x555555558052)
modified[0x52:0x52+len(encoding)] = encoding

#replace getuid with prctl
offset = bytes(modified).find(int.to_bytes(0x1569fb,3, "big"), 0)
modified[offset+1:offset+3] = [0x5f-6, 0xfc]

offset = bytes(modified).find(int.to_bytes(0x1539fc,3, "big"), 0)
modified[offset+1:offset+3] = [0x4f-6, 0xfb]

reloc_offset = bytes(modified).find(int.to_bytes(0x555555594000,8, "little"))

relocation = lief.ELF.Relocation(0x0000555555557000+reloc_offset-0x0000555555554000, type=lief.ELF.RELOCATION_X86_64.RELATIVE64, is_rela=True)
relocation.addend = 0x555555594000-0x0000555555554000
elf.add_dynamic_relocation(relocation)

segment = lief.ELF.Segment()
segment           = lief.ELF.Segment()
segment.type      = lief.ELF.SEGMENT_TYPES.LOAD
segment.content   = modified
segment.alignment = 8
segment.flags = lief.ELF.SEGMENT_FLAGS(3)
segment           = elf.add(segment, base=(-0x0000000000015000+0x4000)&0xFFFFFFFFFFFFFFFF)


ropchain = save_stack(0x0000555555568000,0x0000555555594000, 0x00 )
reloc_offset = ropchain.find(int.to_bytes(0xaabbaabbaabb,8, "little"))

symbol = lief.ELF.Symbol() 
symbol.name = "__libc_stack_end" 
symbol.size = 0
symbol.value = 0
symbol.binding = lief.ELF.SYMBOL_BINDINGS.GLOBAL

relocation = lief.ELF.Relocation(0x0000555555594000+reloc_offset-0x0000555555554000, type=lief.ELF.RELOCATION_X86_64.R64, is_rela=True)
relocation.addend = 0x3d
relocation.symbol = symbol 

elf.add_dynamic_relocation(relocation)

reloc_offset = ropchain.find(int.to_bytes(0xaabbaabbaacc,8, "little"))

symbol = lief.ELF.Symbol() 
symbol.name = "__libc_stack_end" 
symbol.size = 0
symbol.value = 0
symbol.binding = lief.ELF.SYMBOL_BINDINGS.GLOBAL

relocation = lief.ELF.Relocation(0x0000555555594000+reloc_offset-0x0000555555554000, type=lief.ELF.RELOCATION_X86_64.R64, is_rela=True)
relocation.addend = 0x3d+4
relocation.symbol = symbol 

elf.add_dynamic_relocation(relocation)

with open("mem.sq", "rb") as f:
    sqmem_data = f.read()

sqmem_loc = 0x0000555555633000 #this changes depending on code size ;/

ropchain += strcpy(0x0000555555568000,sqmem_loc+0x10*0x4,0x0000555555594000+len(ropchain))

with open("code.sq", "rb") as f:
    CODE = f.read().decode()
code = list(filter(lambda x: x and "#" not in x,CODE.splitlines()))

offset = len(ropchain)
clen = len(subeq(sqmem_loc,sqmem_loc, 0x0000555555594000))

for line in code:
    (a,b,c) = eval(line)
    ropchain+=subeq(sqmem_loc+a*4,sqmem_loc+b*4, 0x0000555555594000+offset+c*clen)

ropchain+=struct.pack("Q",(0x555555555000+0x000000000000301a))#nop
ropchain+=add_libc_aslr(0x0000555555568048, 0x0000555555567f80)
ropchain+=struct.pack("Q",(0x555555555000+0x000000000000301a))#nop
ropchain+=jmp_if_correct(sqmem_loc+0x0f8*4, 0x0000555555568048, 0x0000555555594000+len(ropchain), 0x0000555555567f80)
ropchain+=struct.pack("Q",(0x555555555000+0x000000000000a518))#end

chain = lief.ELF.Segment()
chain           = lief.ELF.Segment()
chain.type      = lief.ELF.SEGMENT_TYPES.LOAD
chain.content   = [x for x in ropchain]
chain.alignment = 8
chain.flags = lief.ELF.SEGMENT_FLAGS.W
chain           = elf.add(chain)

sqmem = lief.ELF.Segment()
sqmem           = lief.ELF.Segment()
sqmem.type      = lief.ELF.SEGMENT_TYPES.LOAD
sqmem.content   = [x for x in sqmem_data]
sqmem.alignment = 8
sqmem.flags = lief.ELF.SEGMENT_FLAGS.W
sqmem           = elf.add(sqmem)
relocs = set()
for i in range(len(ropchain)//8):
    maybe_reloc = struct.unpack("Q",ropchain[i*8:][:8])[0]
    if maybe_reloc  & 0xffffff000000 == 0x555555000000:
        relocs.add(maybe_reloc)
        relocation = lief.ELF.Relocation(0x0000555555594000+i*8-0x0000555555554000, type=lief.ELF.RELOCATION_X86_64.RELATIVE64, is_rela=True)
        relocation.addend = maybe_reloc-0x0000555555554000
        elf.add_dynamic_relocation(relocation)


#elf.header.file_type = lief.ELF.E_TYPE.EXECUTABLE

elf[lief.ELF.DYNAMIC_TAGS.FLAGS_1].remove(lief.ELF.DYNAMIC_FLAGS_1.PIE)

elf.write("pong")
