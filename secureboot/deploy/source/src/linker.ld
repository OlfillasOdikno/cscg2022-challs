OUTPUT_FORMAT("binary")
ENTRY(_start)
SECTIONS {
    . = 0x600;
    .text :
    {
        *(.sbox*)
        *(.text*)
        . = 0x1FE;
        SHORT(0xAA55)
    }
}