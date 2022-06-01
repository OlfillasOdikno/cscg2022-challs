import sys

if len(sys.argv) != 5:
    print(f"usage: {sys.argv[0]} <bootloader_location> <image_location> <key> <output_location>")
    exit(1)

bootloader_location = sys.argv[1]
image_location = sys.argv[2]
key = bytes.fromhex(sys.argv[3].replace('0x', '').replace(',', '').replace(' ','').replace('\\',''))
output_location = sys.argv[4]

with open(bootloader_location, "rb") as f:
    sbox = bytearray(f.read()[:256])

def encrypt(text, key):
    t = text[0]
    for i in range(32 * 8):
        t = (t + key[i & 0b111]) & 0xFF
        t = (sbox[t] + text[(i+1) & 0b111]) & 0xFF
        t = ((t << 1) | (t >> 7)) & 0xFF
        text[(i + 1) & 0b111] = t

def hash(data):
    text = [0]*8
    keys = [data[i*8:][:8] for i in range(len(data)//8)]
    keys[-1] = keys[-1]+bytearray([0]*(8-len(keys[-1])))
    for k in keys:
        cloned = text.copy()
        encrypt(text, k)
        text = [a^b for a,b in zip(text, cloned)]
    return text

def sign(data, key):
    signature = hash(data)
    encrypt(signature, key)
    return bytes(signature)

with open(image_location, "rb") as f:
    plain = f.read()

with open(output_location,"wb") as f:
    f.write(plain+sign(plain, key))
