
with open("../pwn/dumped_bootloader", "rb") as f:
    sbox = bytearray(f.read()[:256])
all = []
key = bytes.fromhex("4100410041004100")
offset = sbox.index(key)

example_key = bytes.fromhex("1234567812873465")

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

    sbox[offset : offset + 8] = example_key
    valid = hash(my_input, sbox)

    
    sbox[offset : offset + 8] = [0] * 8
    while hash(my_input, sbox) != valid:
        sbox[offset + byte] += 1
        print(f"{100*sbox[offset+byte]/256:.02f}%", end="\r")

    print(f"key byte {byte}: {hex(sbox[offset+byte])}")
    return sbox[offset + byte]


leaked_key = []
for i in range(8):
    leaked_key.append(brute_force(i))
assert example_key == bytes(leaked_key)
print(f"key: {bytes(leaked_key).hex()}")