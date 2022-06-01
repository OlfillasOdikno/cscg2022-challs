.intel_syntax noprefix
.code16


.section .sbox
.global Sbox
.global _start
Sbox:
_start:
    cli
    mov sp, 0x7c00
    
    mov si, 0x7c00
    mov di, 0x600
    mov cx, 0x80
    cld
    rep movsd
.att_syntax prefix
    jmpl $0x00, $_next
.intel_syntax noprefix

_next:
    sti
    mov ax, 0x0202
    mov bx, 0x7c00
    mov dl, 0x81
    mov cx, 0x0001 //read first sector
    mov dh, 0
    int 0x13

check_valid:
    mov di, 0x7c00
    lea si, state
_hash_loop:
    mov ax, di
    lea di, state2
    mov cx, 2
    rep movsd
    mov di, ax
    sub si, 8
    call treyfer_encrypt

    mov bx, di
    lea di, state2
    mov cx, 8
_xor_loop:
    mov ah, byte ptr [si]
    mov al, byte ptr [di]
    xor al, ah
    mov byte ptr [si], al
    inc si
    inc di
    loop _xor_loop
    mov di, bx
    sub si, 8

    add di, 8
    mov ax, di
    sub ax, 0x7e00
    jnz _hash_loop
    
    mov si, 0x7e00 
    lea di, key
    call treyfer_decrypt
check_state:
    mov si, 0x7e00 
    lea di, state
    mov cx, 8
    rep cmpsb
    jnz failed
    mov ax, 0x7c00
    jmp ax
failed:
    lea si, msg_failed
    mov ah, 0x0e
print_loop:
    lodsb
    cmp al, 0x00
    je print_hex
    int 0x10
    jmp print_loop

//text: si
//key: di
//sbox: .text
treyfer_encrypt:
    mov cx, 256
    lodsb //t
    dec si
    xor dx, dx
_loop:
    push si
    push di
    add di, dx
    
    mov ah, byte ptr [di] //key[i%8]
    add al, ah

    // load from sbox
    mov bx, 0x600 
    xlatb


    //load from text
    inc dx
    and dx, 0b111

    add si, dx
    mov ah, byte ptr [si]
    add al, ah
    rol al

    mov byte ptr [si], al


    pop di
    pop si
    loop _loop
    .byte 0xc3

//text: si
//key: di
//sbox: .text
treyfer_decrypt:
    mov cx, 256
_inner_loop:
    push si

    mov dx, cx
    dec dx
    and dx, 0b111

    mov ah, byte ptr [esi+edx]
    mov al, byte ptr [edi+edx]

    aad 1
    
    // load from sbox
    mov bx, 0x600
    xlatb 

    inc dx
    and dx, 0b111

    
    add esi, edx
    mov ah, byte ptr [si]

    ror ah

    sub ah, al

    mov byte ptr [si], ah
    pop si


    loop _inner_loop
    .byte 0xc3

key:
.byte secret_key

.align 0x100

msg_failed:
.asciz "Invalid signature!\n"
hex:
.ascii "0123456789ABCDEF"


print_hex:

    lea si, state
    mov cx, 8
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
    jmp sleep

sleep:
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

state:
.byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
state2:
.byte 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00