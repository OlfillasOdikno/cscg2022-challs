import struct
import random
random.seed(0x31337)
scratch = 0x0000555555568100 #TODO adjust

scratch2 = 0x0000555555568200 #TODO adjust

scratch3 = 0x0000555555568400 #TODO adjust

scratch4 = 0x000055555556845d #TODO adjust

used_gadgets = [
    0x555555568200,
    0x555555568000,
    0x5555556e9000,
    0x5555555b5a00,
    0x555555600400,
    0x5555555b2208,
    0x5555555aea10,
    0x5555555f9410,
    0x5555555ab218,
    0x5555555f5c18,
    0x55555555801a,
    0x5555556e941d,
    0x5555555a7a20,
    0x5555556e9421,
    0x5555555f2420,
    0x5555556e9425,
    0x555555594228,
    0x5555556e9429,
    0x5555555a4228,
    0x55555555b62b,
    0x55555559422c,
    0x5555555eec28,
    0x5555555a0a30,
    0x5555555eb430,
    0x55555559d238,
    0x5555555e7c38,
    0x555555568038,
    0x555555561c3b,
    0x55555556823d,
    0x55555556803d,
    0x5555556e903d,
    0x555555599a40,
    0x5555556e9441,
    0x5555555e4440,
    0x5555556e9445,
    0x5555555e0c48,
    0x5555556e9449,
    0x555555568048,
    0x5555556e944d,
    0x555555595450,
    0x5555556e9451,
    0x5555555dd450,
    0x5555556e9455,
    0x5555555d9c58,
    0x5555555d6460,
    0x5555555d2c68,
    0x555555562270,
    0x5555555cf470,
    0x5555555cbc78,
    0x555555562279,
    0x5555556e907d,
    0x555555595480,
    0x5555556e9081,
    0x5555555c8480,
    0x5555556e9085,
    0x5555555c4c88,
    0x5555556e9089,
    0x5555555c1490,
    0x5555555bdc98,
    0x5555555ba4a0,
    0x555555604ea0,
    0x55555555b0a5,
    0x55555555b0a7,
    0x55555555b0a8,
    0x5555555954a8,
    0x5555555680a8,
    0x5555555b6ca8,
    0x5555556016a8,
    0x5555555b34b0,
    0x5555555fdeb0,
    0x5555556084b0,
    0x5555555afcb8,
    0x5555555fa6b8,
    0x5555555f6ec0,
    0x5555555a8cc8,
    0x5555555f36c8,
    0x5555555580cf,
    0x5555555a54d0,
    0x5555555efed0,
    0x55555555b6d2,
    0x55555555b6d4,
    0x55555555b2d5,
    0x5555555a1cd8,
    0x55555555b6d9,
    0x5555555ec6d8,
    0x55555559e4e0,
    0x5555555e8ee0,
    0x55555559ace8,
    0x5555555e56e8,
    0x5555555952f8,
    0x5555555de6f8,
    0x5555555952fc,
    0x5555555682ff,
    0x555555568100,
    0x555555568101,
    0x555555568102,
    0x555555568103,
    0x5555555daf00,
    0x5555555d7708,
    0x5555555d3f10,
    0x555555567d18,
    0x5555555d0718,
    0x55555555f518,
    0x5555555ccf20,
    0x5555555c9728,
    0x5555555c5f30,
    0x5555555c2738,
    0x55555556813d,
    0x5555555bef40,
    0x55555555ab46,
    0x5555555bb748,
    0x555555606148,
    0x55555555f548,
    0x5555555b7f50,
    0x555555602950,
    0x555555558358,
    0x5555555b4758,
    0x5555555ff158,
    0x55555555a95f,
    0x55555555a960,
    0x55555555b961,
    0x5555555b0f60,
    0x5555555fb960,
    0x5555555ad768,
    0x5555555f8168,
    0x555555560570,
    0x5555555a9f70,
    0x5555555f4970,
    0x5555555a6778,
    0x5555555f1178,
    0x5555555a2f80,
    0x5555555ed980,
    0x555555567f80,
    0x555555594188,
    0x55555559f788,
    0x5555556e9388,
    0x5555555ea188,
    0x55555559418c,
    0x5555556e938c,
    0x55555559bf90,
    0x5555556e9390,
    0x55555555b792,
    0x5555555e6990,
    0x5555556e9394,
    0x5555555e3198,
    0x5555555df9a0,
    0x5555556e8fa8,
    0x5555555dc1a8,
    0x5555555621aa,
    0x5555555d89b0,
    0x55555555abb1,
    0x5555555d51b8,
    0x555555603bf8,
    0x5555555d19c0,
    0x5555555ce1c8,
    0x5555555953d0,
    0x5555555ca9d0,
    0x5555556e93e0,
    0x5555555c39e0,
    0x5555556e93e4,
    0x5555556e93e8,
    0x5555555c01e8,
    0x5555556e93ec,
    0x5555555bc9f0,
    0x5555556073f0,
    0x5555555b91f8,
]

BASE = 0x555555555000 #adjust qiling?xD
gadget = lambda x: BASE+x

"""
Instruction subeqa a, b, c
    Mem[b] = Mem[b] - Mem[a]
    if (Mem[b] >= 0)
        goto c
"""

rnd = lambda x:  random.choice(used_gadgets)

def save_stack(arg_dst,selfref, offset_to_argv):
    chain = [
        gadget(0x00000000000060a8), # : pop rax ; ret
        0xaabbaabbaabb, # this will be relocated to libc argv
        gadget(0x0000000000006792), # : pop rbx ; pop rbp ; ret
        0x0,
        rnd(0x0),
        gadget(0x00000000000060a7), # : add ebx, dword ptr [rax - 0x3d] ; ret

        gadget(0x00000000000066d9), # : pop rsi ; ret
        0x4d,

        #move to esi
        gadget(0x0000000000005960), # : pop rdi ; ret
        scratch,
        gadget(0x000000000000662b), # : add esi, ebx ; stosq qword ptr [rdi], rax ; pop rbx ; pop rbp ; pop r12 ; ret
        rnd(0x00),
        rnd(0x00),
        rnd(0x00),

        gadget(0x00000000000060a8), # : pop rax ; ret
        0x00,
        gadget(0x0000000000006792), # : pop rbx ; pop rbp ; ret
        selfref+60*0x8-0x58,
        rnd(0x00),
        gadget(0x00000000000060a5), # : add dword ptr [rbx + rax + 0x58], esi ; ret


        gadget(0x0000000000006792), # : pop rbx ; pop rbp ; ret
        0x4,
        rnd(0x0),

        #move to esi
        gadget(0x0000000000005960), # : pop rdi ; ret
        scratch,
        gadget(0x000000000000662b), # : add esi, ebx ; stosq qword ptr [rdi], rax ; pop rbx ; pop rbp ; pop r12 ; ret
        rnd(0x00),
        rnd(0x00),
        rnd(0x00),

        gadget(0x0000000000006792), # : pop rbx ; pop rbp ; ret
        selfref+80*0x8-0x58,
        rnd(0x00),
        gadget(0x00000000000060a5), # : add dword ptr [rbx + rax + 0x58], esi ; ret
    ]+[
        gadget(0x00000000000060a8), # : pop rax ; ret
        0xaabbaabbaacc, # this will be relocated to libc argv
        gadget(0x0000000000006792), # : pop rbx ; pop rbp ; ret
        0x0,
        rnd(0x0),
        gadget(0x00000000000060a7), # : add ebx, dword ptr [rax - 0x3d] ; ret

        #zero esi
        gadget(0x00000000000066d9), # : pop rsi ; ret
        0x00,

        #move to esi
        gadget(0x0000000000005960), # : pop rdi ; ret
        scratch,
        gadget(0x000000000000662b), # : add esi, ebx ; stosq qword ptr [rdi], rax ; pop rbx ; pop rbp ; pop r12 ; ret
        rnd(0x00),
        rnd(0x00),
        rnd(0x00),

        gadget(0x00000000000060a8), # : pop rax ; ret
        0x00,
        gadget(0x0000000000006792), # : pop rbx ; pop rbp ; ret
        selfref+60*0x8+4-0x58,
        rnd(0x00),
        gadget(0x00000000000060a5), # : add dword ptr [rbx + rax + 0x58], esi ; ret

        gadget(0x00000000000060a8), # : pop rax ; ret
        0x00,
        gadget(0x0000000000006792), # : pop rbx ; pop rbp ; ret
        selfref+80*0x8+4-0x58,
        rnd(0x00),
        gadget(0x00000000000060a5), # : add dword ptr [rbx + rax + 0x58], esi ; ret
    ]
    #print(len(chain)+1)
    chain += [
        gadget(0x00000000000060a8), # : pop rax ; ret
        0x00, # this will be relocated to [libc stac_end]
        gadget(0x0000000000006792), # : pop rbx ; pop rbp ; ret
        0x0,
        rnd(0x0),
        gadget(0x00000000000060a7), # : add ebx, dword ptr [rax - 0x3d] ; ret

        gadget(0x00000000000066d9), # : pop rsi ; ret
        0x00, #point to first arg

        #move to esi
        gadget(0x0000000000005960), # : pop rdi ; ret
        scratch,
        gadget(0x000000000000662b), # : add esi, ebx ; stosq qword ptr [rdi], rax ; pop rbx ; pop rbp ; pop r12 ; ret
        rnd(0x00),
        rnd(0x00),
        rnd(0x00),

        gadget(0x00000000000060a8), # : pop rax ; ret
        0x00,
        gadget(0x0000000000006792), # : pop rbx ; pop rbp ; ret
        selfref+618*0x8-0x58,
        rnd(0x00),
        gadget(0x00000000000060a5), # : add dword ptr [rbx + rax + 0x58], esi ; ret
    ]
    #print(len(chain)+1)
    chain+=[
        gadget(0x00000000000060a8), # : pop rax ; ret
        0x00, #  this will be relocated to [libc stac_end+4]
        gadget(0x0000000000006792), # : pop rbx ; pop rbp ; ret
        0x0,
        rnd(0x0),
        gadget(0x00000000000060a7), # : add ebx, dword ptr [rax - 0x3d] ; ret

        #zero esi
        gadget(0x00000000000066d9), # : pop rsi ; ret
        0x00,

        #move to esi
        gadget(0x0000000000005960), # : pop rdi ; ret
        scratch,
        gadget(0x000000000000662b), # : add esi, ebx ; stosq qword ptr [rdi], rax ; pop rbx ; pop rbp ; pop r12 ; ret
        rnd(0x00),
        rnd(0x00),
        rnd(0x00),

        gadget(0x00000000000060a8), # : pop rax ; ret
        0x00,
        gadget(0x0000000000006792), # : pop rbx ; pop rbp ; ret
        selfref+618*0x8+4-0x58,
        rnd(0x00),
        gadget(0x00000000000060a5), # : add dword ptr [rbx + rax + 0x58], esi ; ret
    ]
    chain += [
        gadget(0x00000000000030cf), # ret 0 identifier
        
        #is zero (if not carry)
        gadget(0x0000000000006792), # : pop rbx ; pop rbp ; ret
        0xFFFFFFFFFFFFFFFF,
        rnd(0x00),
        gadget(0x0000000000005960), # : pop rdi ; ret
        scratch,
        gadget(0x000000000000662b), # : add esi, ebx ; stosq qword ptr [rdi], rax ; pop rbx ; pop rbp ; pop r12 ; ret
        rnd(0x00),
        rnd(0x00),
        rnd(0x00),

        gadget(0x00000000000062d5), #: adc al, 1 ; ret 0xf40
        gadget(0x000000000000301a), # nop
    ]+[
        rnd(0x00) for _ in range(0xf40//8)#has probably to be moved behind next instruction :(
    ]+[
        
       #move eax somewhere else
        gadget(0x0000000000005960), # : pop rdi ; ret
        scratch2,
        gadget(0x0000000000006961), # : stosd dword ptr [rdi], eax ; ret
    ]+[
        #load carry
        gadget(0x0000000000006792), # : pop rbx ; pop rbp ; ret
        0x0,
        rnd(0x0),
        gadget(0x00000000000060a8), #: pop rax ; ret
        scratch2+0x3d,
        gadget(0x00000000000060a7), #: add ebx, dword ptr [rax - 0x3d] ; ret        


        gadget(0x00000000000060a8), #: pop rax ; ret
        gadget(0x00000000000066d5-0x1), # : pop rsp ; pop r13 ; pop r14 ; ret  ; ret 
        #if no carry rax=rax, if carry rax=rax+1
        gadget(0x0000000000003358), #: add rax, rbx ; jmp rax
        selfref+650*8, #jump to round begin
        gadget(0x000000000000301a), # ret sled
        gadget(0x000000000000301a), # ret sled
    ]
    #print(len(chain)+4)
    #print(len(chain)+20)
    chain += [
        gadget(0x0000000000005960), # : pop rdi ; ret
        arg_dst,
        gadget(0x00000000000066d4), # : pop r12 ; pop r13 ; pop r14 ; ret
        arg_dst,
        0x00, #store here
        0x50,
        gadget(0x000000000000595f), # pop r15 ; ret
        selfref+634*8,
        gadget(0x0000000000006792), # : pop rbx ; pop rbp ; ret
        0x0,
        0x1,
        gadget(0x000000000000d270), # mov rdx, r14, rsi, r13, edi, r12d CALL   qword ptr [R15 + RBX*0x8]; pops 8
        rnd(0x0),
        rnd(0x0),
        rnd(0x0),
        rnd(0x0),
        rnd(0x0),
        rnd(0x0),
        rnd(0x0),
        gadget(0x000000000000595f), # pop r15 ; ret
        gadget(0x000000000000301a), # ret sled
        gadget(0x0000000000005960), # : pop rdi ; ret
        arg_dst,
        gadget(0x000000000000595f), # pop r15 ; ret
        gadget(0x12d18), #address to strncpy got
        gadget(0x0000000000006792), # : pop rbx ; pop rbp ; ret
        0x0,
        0x1,
        gadget(0x000000000000d279), # CALL   qword ptr [R15 + RBX*0x8]; pops 8
        rnd(0x0),
        rnd(0x0),
        rnd(0x0),
        rnd(0x0),
        rnd(0x0),
        rnd(0x0),
        rnd(0x0),
        gadget(0x000000000000301a), # ret sled
        gadget(0x000000000000301a), # ret sled
        gadget(0x000000000000301a), # ret sled
    ]
    #print(len(chain)-3)


    return b"".join([struct.pack("<Q", x) for x in chain])

def strcpy(src, dst, selfref):
    chain = [
        gadget(0x0000000000005960), # : pop rdi ; ret
        scratch,
        gadget(0x00000000000060a8), # : pop rax ; ret
        0x0,
        gadget(0x0000000000006961), # : stosd dword ptr [rdi], eax ; ret

        #round_begin
        gadget(0x000000000000301a), # ret sled
        gadget(0x00000000000030cf), # ret 0 identifier
        gadget(0x00000000000060a8), # : pop rax ; ret
        src+0x3d,
        gadget(0x0000000000006792), # : pop rbx ; pop rbp ; ret
        0x0,
        rnd(0x0),
        gadget(0x00000000000060a7), # : add ebx, dword ptr [rax - 0x3d] ; ret

        #zero esi
        gadget(0x00000000000066d9), # : pop rsi ; ret
        0x00,

        #move to esi
        gadget(0x0000000000005960), # : pop rdi ; ret
        scratch,
        gadget(0x000000000000662b), # : add esi, ebx ; stosq qword ptr [rdi], rax ; pop rbx ; pop rbp ; pop r12 ; ret
        rnd(0x00),
        rnd(0x00),
        rnd(0x00),

        #store at dst+i
        gadget(0x0000000000006792), # : pop rbx ; pop rbp ; ret
        (dst-src-0x58-0x3d)&0xFFFFFFFFFFFFFFFF,
        rnd(0x00),
        gadget(0x00000000000060a5), # : add dword ptr [rbx + rax + 0x58], esi ; ret


        #inc pointer by 4
    ]+[
        gadget(0x000000000000cc3b), # : add al, 0x89 ; ret
    ]*(114)+[
        gadget(0x00000000000062d5), #: adc al, 1 ; ret 0xf40
        gadget(0x000000000000301a), # nop
    ]+[
        rnd(0x00) for _ in range(0xf40//8)#has probably to be moved behind next instruction :(
    ]+[

        #update location
        gadget(0x0000000000005960), # : pop rdi ; ret
        selfref+8*8,
        gadget(0x0000000000006961), # : stosd dword ptr [rdi], eax ; ret

        #we can now use rax :) polymorphic rop :checkmark:

        #has overflowed?
        gadget(0x00000000000060a8), # : pop rax ; ret
        0x00,
        gadget(0x00000000000062d5), #: adc al, 1 ; ret 0xf40
        gadget(0x000000000000301a), # nop
    ]+[
        rnd(0x00) for _ in range(0xf40//8)#has probably to be moved behind next instruction :(
    ]+[
        
   

        #is zero (if not carry)
        gadget(0x0000000000006792), # : pop rbx ; pop rbp ; ret
        0xFFFFFFFFFFFFFFFF,
        rnd(0x00),
        gadget(0x0000000000005960), # : pop rdi ; ret
        scratch,
        gadget(0x000000000000662b), # : add esi, ebx ; stosq qword ptr [rdi], rax ; pop rbx ; pop rbp ; pop r12 ; ret
        rnd(0x00),
        rnd(0x00),
        rnd(0x00),

        gadget(0x00000000000062d5), #: adc al, 1 ; ret 0xf40
        gadget(0x000000000000301a), # nop
    ]+[
        rnd(0x00) for _ in range(0xf40//8)#has probably to be moved behind next instruction :(
    ]+[
        
       #move eax somewhere else
        gadget(0x0000000000005960), # : pop rdi ; ret
        scratch2,
        gadget(0x0000000000006961), # : stosd dword ptr [rdi], eax ; ret
    ]+[
        #load carry
        gadget(0x0000000000006792), # : pop rbx ; pop rbp ; ret
        0x0,
        rnd(0x0),
        gadget(0x00000000000060a8), #: pop rax ; ret
        scratch2+0x3d,
        gadget(0x00000000000060a7), #: add ebx, dword ptr [rax - 0x3d] ; ret        


        gadget(0x00000000000060a8), #: pop rax ; ret
        gadget(0x00000000000066d5-0x3), # : pop rsp ; pop r13 ; pop r14 ; ret  ; ret #compensate for adc 2 (ebx is either )
        #if no carry rax=rax, if carry rax=rax+1
        gadget(0x0000000000003358), #: add rax, rbx ; jmp rax
        selfref+3*8, #jump to round begin
        gadget(0x000000000000301a), # ret sled
        gadget(0x000000000000301a), # ret sled
    ]
    return b"".join([struct.pack("<Q", x) for x in chain])

def subeq(a,b,c):
    chain = [
        gadget(0x000000000000301a), # ret sled
        gadget(0x00000000000030cf), # ret 0 identifier
        #load deref a into ebx
        gadget(0x0000000000006792), # : pop rbx ; pop rbp ; ret
        0x0,
        rnd(0x0),
        gadget(0x00000000000060a8), # : pop rax ; ret
        a+0x3d,
        gadget(0x00000000000060a7), # : add ebx, dword ptr [rax - 0x3d] ; ret

        #move into eax

        #zero esi
        gadget(0x0000000000005960), # : pop rdi ; ret
        0xFFFFFFFF, #add one for neg
        gadget(0x00000000000060a8), # : pop rax ; ret
        gadget(0x0000000000005960), # : pop nop ; ret
        gadget(0x000000000000b570), # : mov esi, edi ; mov rdi, rbp ; call rax

        #move to esi
        gadget(0x0000000000005960), # : pop rdi ; ret
        scratch,
        gadget(0x000000000000662b), # : add esi, ebx ; stosq qword ptr [rdi], rax ; pop rbx ; pop rbp ; pop r12 ; ret
        rnd(0x00),
        rnd(0x00),
        rnd(0x00),

        #zero scratch
        gadget(0x00000000000060a8), # : pop rax ; ret
        0x0,
        gadget(0x0000000000005960), # : pop rdi ; ret
        scratch,
        gadget(0x0000000000006961), #  : stosd dword ptr [rdi], eax ; ret

        #store into scratch(currently 0)
        gadget(0x0000000000006792), # : pop rbx ; pop rbp ; ret
        0x00,
        rnd(0x00),
        gadget(0x00000000000060a8), # : pop rax ; ret
        scratch-0x58,
        gadget(0x00000000000060a5), # : add dword ptr [rbx + rax + 0x58], esi ; ret


        #negate value in scratch
        gadget(0x00000000000060a8), # : pop rax ; ret
        ((scratch+0x100)&0xFFFFFFFFFFFFFF00)|0xFF,
        gadget(0x000000000000d1aa), # : mov rdx, rax ; deref rdx, add rsp, 8 pop rbx, pop rbp, pop r12, pop r13; ret
        rnd(0x00),
        rnd(0x00),
        rnd(0x00),
        rnd(0x00),
        rnd(0x00),

        gadget(0x0000000000005960), # : pop rdi ; ret
        scratch,
        gadget(0x00000000000060a8), # : pop rax ; ret
        scratch,
        gadget(0x0000000000005bb1), # : xor byte ptr [rax], dl ; or dword ptr [rdi + 4], eax ; xor eax, eax ; ret
        gadget(0x00000000000060a8), # : pop rax ; ret
        scratch+1,
        gadget(0x0000000000005bb1), # : xor byte ptr [rax], dl ; or dword ptr [rdi + 4], eax ; xor eax, eax ; ret
        gadget(0x00000000000060a8), # : pop rax ; ret
        scratch+2,
        gadget(0x0000000000005bb1), # : xor byte ptr [rax], dl ; or dword ptr [rdi + 4], eax ; xor eax, eax ; ret
        gadget(0x00000000000060a8), # : pop rax ; ret
        scratch+3,
        gadget(0x0000000000005bb1), # : xor byte ptr [rax], dl ; or dword ptr [rdi + 4], eax ; xor eax, eax ; ret


        #load memory in b
        gadget(0x0000000000006792), # : pop rbx ; pop rbp ; ret
        0x0,
        rnd(0x0),
        gadget(0x00000000000060a8), #: pop rax ; ret
        b+0x3d,
        gadget(0x00000000000060a7), #: add ebx, dword ptr [rax - 0x3d] ; ret
        
        #add (sub b,a)
        gadget(0x00000000000060a8), #: pop rax ; ret
        scratch+0x3d,
        gadget(0x00000000000060a7), #: add ebx, dword ptr [rax - 0x3d] ; ret

        #store into b
        #zero esi
        gadget(0x0000000000005960), # : pop rdi ; ret
        0x0,
        gadget(0x00000000000060a8), # : pop rax ; ret
        gadget(0x00000000000060a8), # : nop ; ret
        gadget(0x000000000000b570), # : mov esi, edi ; mov rdi, rbp ; call rax

        #zero b mem
        gadget(0x00000000000060a8), # : pop rax ; ret
        0x0,
        gadget(0x0000000000005960), # : pop rdi ; ret
        b,
        gadget(0x0000000000006961), #  : stosd dword ptr [rdi], eax ; ret


        #move ebx to esi
        gadget(0x0000000000005960), # : pop rdi ; ret
        scratch,
        gadget(0x000000000000662b), # : add esi, ebx ; stosq qword ptr [rdi], rax ; pop rbx ; pop rbp ; pop r12 ; ret
        rnd(0x00),
        rnd(0x00),
        rnd(0x00),

        #store into b mem(currently 0)
        gadget(0x0000000000006792), # : pop rbx ; pop rbp ; ret
        0x00,
        rnd(0x00),
        gadget(0x00000000000060a8), # : pop rax ; ret
        b-0x58,
        gadget(0x00000000000060a5), # : add dword ptr [rbx + rax + 0x58], esi ; ret

        #add 0xFFFFFFFF to test if != 0

        gadget(0x0000000000006792), # : pop rbx ; pop rbp ; ret
        0xFFFFFFFF,
        rnd(0x00),
        gadget(0x0000000000005960), # : pop rdi ; ret
        scratch,
        gadget(0x000000000000662b), # : add esi, ebx ; stosq qword ptr [rdi], rax ; pop rbx ; pop rbp ; pop r12 ; ret
        rnd(0x00),
        rnd(0x00),
        rnd(0x00),

        #save overflow bit (<0)
        gadget(0x00000000000060a8), # : pop rax ; ret
        0x00,
        gadget(0x00000000000062d5), #: adc al, 1 ; ret 0xf40
        gadget(0x000000000000301a), # nop
    ]+[
        rnd(0x00) for _ in range(0xf40//8)#has probably to be moved behind next instruction :(
    ]+[

        #move eax somewhere else
        gadget(0x0000000000005960), # : pop rdi ; ret
        scratch2,
        gadget(0x0000000000006961), # : stosd dword ptr [rdi], eax ; ret
    ]+[
        #load carry
        gadget(0x0000000000006792), # : pop rbx ; pop rbp ; ret
        0x0,
        rnd(0x0),
        gadget(0x00000000000060a8), #: pop rax ; ret
        scratch2+0x3d,
        gadget(0x00000000000060a7), #: add ebx, dword ptr [rax - 0x3d] ; ret        


        gadget(0x00000000000060a8), #: pop rax ; ret
        gadget(0x0000000000005b47-0x1), #:  : pop rsp ; pop r13  ; ret #compensate for adc 1
        #if no carry rax=rax, if carry rax=rax+1
        gadget(0x0000000000003358), #: add rax, rbx ; jmp rax
        c,
    ]

    return b"".join([struct.pack("<Q", x) for x in chain])

def add_libc_aslr(jump_ptr_addr, exit):
    chain = [
        gadget(0x00000000000060a8), # : pop rax ; ret
        exit+0x3d, # this will be relocated to libc argv
        gadget(0x0000000000006792), # : pop rbx ; pop rbp ; ret
        0x0,
        rnd(0x0),
        gadget(0x00000000000060a7), # : add ebx, dword ptr [rax - 0x3d] ; ret

        gadget(0x00000000000066d9), # : pop rsi ; ret
        0x0,

        #move to esi
        gadget(0x0000000000005960), # : pop rdi ; ret
        scratch,
        gadget(0x000000000000662b), # : add esi, ebx ; stosq qword ptr [rdi], rax ; pop rbx ; pop rbp ; pop r12 ; ret
        rnd(0x00),
        rnd(0x00),
        rnd(0x00),

        gadget(0x00000000000060a8), # : pop rax ; ret
        0x00,
        gadget(0x0000000000006792), # : pop rbx ; pop rbp ; ret
        jump_ptr_addr-0x58,
        rnd(0x00),
        gadget(0x00000000000060a5), # : add dword ptr [rbx + rax + 0x58], esi ; ret
    ]+[
        gadget(0x00000000000060a8), # : pop rax ; ret
        exit+0x3d+0x4, # this will be relocated to libc argv
        gadget(0x0000000000006792), # : pop rbx ; pop rbp ; ret
        0x0,
        rnd(0x0),
        gadget(0x00000000000060a7), # : add ebx, dword ptr [rax - 0x3d] ; ret

        #zero esi
        gadget(0x00000000000066d9), # : pop rsi ; ret
        0x00,

        #move to esi
        gadget(0x0000000000005960), # : pop rdi ; ret
        scratch,
        gadget(0x000000000000662b), # : add esi, ebx ; stosq qword ptr [rdi], rax ; pop rbx ; pop rbp ; pop r12 ; ret
        rnd(0x00),
        rnd(0x00),
        rnd(0x00),

        gadget(0x00000000000060a8), # : pop rax ; ret
        0x00,
        gadget(0x0000000000006792), # : pop rbx ; pop rbp ; ret
        jump_ptr_addr-0x58+4,
        rnd(0x00),
        gadget(0x00000000000060a5), # : add dword ptr [rbx + rax + 0x58], esi ; ret
        gadget(0x00000000000060a8), # : pop rax ; ret
        jump_ptr_addr-0x1,
        gadget(0x0000000000006dcf), #  mov byte ptr [rax], 0 ; pop r12 ; ret
        rnd(0x00),
    ]
    return b"".join([struct.pack("<Q", x) for x in chain])

def jmp_if_correct(check_addr,jump_ptr_addr, self_ref, exit):
    chain = [
        gadget(0x000000000000a548),# :  or eax, 0x89000000 ; ret

        gadget(0x0000000000006792), # : pop rbx ; pop rbp ; ret
        0x0,
        rnd(0x0),
        gadget(0x00000000000060a8), # : pop rax ; ret
        check_addr+0x3d,
        gadget(0x00000000000060a7), # : add ebx, dword ptr [rax - 0x3d] ; ret

        gadget(0x00000000000066d9), # : pop rsi ; ret
        0x00,

        gadget(0x0000000000005960), # : pop rdi ; ret
        scratch,
        gadget(0x000000000000662b), # : add esi, ebx ; stosq qword ptr [rdi], rax ; pop rbx ; pop rbp ; pop r12 ; ret
        rnd(0x00),
        rnd(0x00),
        rnd(0x00),

        gadget(0x0000000000006792), # : pop rbx ; pop rbp ; ret
        0xFFFFFFFF,
        rnd(0x00),
        gadget(0x0000000000005960), # : pop rdi ; ret
        scratch,
        gadget(0x000000000000662b), # : add esi, ebx ; stosq qword ptr [rdi], rax ; pop rbx ; pop rbp ; pop r12 ; ret
        rnd(0x00),
        rnd(0x00),
        rnd(0x00),

        gadget(0x00000000000060a8), # : pop rax ; ret
        0x00,
        gadget(0x00000000000062d5), #: adc al, 1 ; ret 0xf40
        gadget(0x000000000000301a), # nop
    ]+[
        rnd(0x00) for _ in range(0xf40//8)#has probably to be moved behind next instruction :(
    ]+[
        gadget(0x0000000000005960), # : pop rdi ; ret
        scratch2,
        gadget(0x0000000000006961), # : stosd dword ptr [rdi], eax ; ret
        gadget(0x0000000000006792), # : pop rbx ; pop rbp ; ret
        0x0,
        rnd(0x0),
        gadget(0x00000000000060a8), #: pop rax ; ret
        scratch2+0x3d,
        gadget(0x00000000000060a7), #: add ebx, dword ptr [rax - 0x3d] ; ret        
        gadget(0x0000000000005960), # : pop rdi ; ret
        0x0,
        gadget(0x00000000000060a8), #: pop rax ; ret
        gadget(0x0000000000005b47-0x1), #:  : pop rsp ; pop r13  ; ret #compensate for adc 1
        #if no carry rax=rax, if carry rax=rax+1
        gadget(0x0000000000003358), #: add rax, rbx ; jmp rax
    ]
    chain += [
        self_ref+0x8*len(chain)+3*8,
        #TODO exit gracefully
        gadget(0x000000000000595f), # pop r15 ; ret
        exit,
        gadget(0x00000000000066d3),# : pop rbp ; pop r12 ; pop r13 ; pop r14 ; ret
        gadget(0x000000000000595f), # pop r15 ; ret
        jump_ptr_addr,
        gadget(0x0000000000005960), # : pop rdi ; ret
        jump_ptr_addr-0x10,

        gadget(0x0000000000006792), # : pop rbx ; pop rbp ; ret
        0x0,
        0x1,
        gadget(0x000000000000d279), # CALL   qword ptr [R15 + RBX*0x8]; pops 8
        rnd(0x0),
        rnd(0x0),
        rnd(0x0),
        rnd(0x0),
        rnd(0x0),
        rnd(0x0),
        rnd(0x0),
    ]
    return b"".join([struct.pack("<Q", x) for x in chain])
