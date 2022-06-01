from z3 import *


def get_n(n):
    # solve
    a = BitVec('a', 8)
    b = BitVec('b', 8)
    c = BitVec('c', 8)
    v = BitVecVal(n, 8)

    # solve v = (a & b) ^ c
    # a,b,c > A < Z
    s = Solver()
    s.add(a >= ord(' '), a <= ord('~'))
    s.add(b >= ord(' '), b <= ord('~'))
    s.add(c >= ord(' '), c <= ord('~'))
    for i in "0123456789":
        s.add(a != ord(i))
        s.add(b != ord(i))
        s.add(c != ord(i))
    s.add(v == a-b-c)
    assert str(s.check()) == "sat", n
    a = eval(str(s.model()[a]))
    b = eval(str(s.model()[b]))
    c = eval(str(s.model()[c]))
    assert ((a-b)-c) & 0xFF == n
    return a, b, c


lookup = {}
for i in range(0x00, 0x100):
    if i >= ord('A') and i <= ord('Z') and i not in [ord(n) for n in "0123456789"]:
        continue
    lookup[i] = get_n(i)
print("lookup = "+str(lookup))
