from os import fdopen
from socket import timeout
from pwn import *
import tempfile, subprocess

with open("../pwn/dumped_bootloader", "rb") as f:
    sbox = bytearray(f.read()[:256])

key = bytes.fromhex("4100410041004100")

def encrypt(text, key, sbox):
    v = text[:]
    t = v[0]
    for i in range(32 * 8):
        t = (t + key[i & 0b111]) & 0xFF
        t = (sbox[t] + v[(i + 1) & 0b111]) & 0xFF
        t = ((t << 1) | (t >> 7)) & 0xFF
        v[(i + 1) & 0b111] = t
    return v


def hash(data, sbox):
    text = [0] * 8
    keys = [data[i * 8:][:8] for i in range(len(data) // 8)]
    keys[-1] += bytes([0] * (8 - len(keys[-1])))
    for k in keys:
        enc = encrypt(text, k, sbox)
        text = [a ^ b for a, b in zip(text, enc)]
    return text


def sign(data, key, sbox):
    signature = hash(data, sbox)
    return encrypt(signature, key, sbox)


print("signing custom mbr..")


asm = '''
.intel_syntax noprefix
.code16
.section .text
.global _start
_start:
    //read flag
    mov ax, 0x0201
    mov bx, 0x600
    mov dl, 0x82
    mov cx, 0x0001
    mov dh, 0
    int 0x13

    mov si, 0x600
    mov ah, 0x0e
print_loop:
    lodsb
    cmp al, 0x00
    je wait
    int 0x10
    jmp print_loop
wait:
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
'''

fd, path = tempfile.mkstemp(suffix =".S")
fd1, path1 = tempfile.mkstemp()
with fdopen(fd, "w") as f:
    f.write(asm)

cmd = f'clang {path} -nostdlib -target i386-none-elf -static -Ttext 0x7c00 -o {path} && objcopy --only-section=.text --output-target binary {path} {path1}'

subprocess.check_output(["sh", "-c", cmd])
with fdopen(fd1, "rb") as f:
    data = f.read()
data = data.ljust(512, b"\xcc")

signature = bytes(sign(data, key, sbox))

r = process("ncat --ssl 7b000000b7bee61ef2433944-secureboot.challenge.master.cscg.live 31337", shell=True)
#r = remote('localhost', 1024)

r.sendlineafter(b"[1] PRODUCTION", b"0")
r.sendlineafter(b"[1] NOGRAPHIC", b"0")

r.sendlineafter(b"[*] End your input with \"EOF\"",((data+signature).hex()+"EOF").encode())
data = r.recvall(timeout=1)
flag = data.split(b"CSCG")[1]
print("FLAG:","CSCG"+flag.decode())
