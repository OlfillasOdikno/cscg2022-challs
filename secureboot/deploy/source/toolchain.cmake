set(CMAKE_ASM_COMPILER clang)
set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang++)

SET(CMAKE_ASM_FLAGS "-target i386-none-elf ${CMAKE_ASM_FLAGS}" CACHE STRING "" FORCE)
SET(CMAKE_C_FLAGS "-target i386-none-elf -ffreestanding ${CMAKE_C_FLAGS}" CACHE STRING "" FORCE)
SET(CMAKE_CXX_FLAGS "-target i386-none-elf -ffreestanding -fno-exceptions -fno-rtti ${CMAKE_CXX_FLAGS}" CACHE STRING "" FORCE)
SET(CMAKE_EXE_LINKER_FLAGS_INIT "-target i386-linux-elf -nostdlib")