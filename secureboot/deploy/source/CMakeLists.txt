cmake_minimum_required(VERSION 3.0.0)
set(CMAKE_TOOLCHAIN_FILE toolchain.cmake)

find_program(
    PYTHON_EXECUTABLE
    NAMES
        python python3 python36
    DOC "Python executable location"
)

project(bootloader ASM C)

set(TEST_KEY "0x41, 0x00, 0x41, 0x00, 0x41, 0x00, 0x41, 0x00")
set(PROD_KEY "0x37, 0xf1, 0x88, 0x7a, 0xcc, 0x35, 0x1b, 0x92")

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Debug")
endif()
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(KEY ${TEST_KEY})
    set(TARGET "test")
else()
    set(KEY ${PROD_KEY})
    set(TARGET "prod")
endif()
set(CMAKE_ASM_FLAGS "-Dsecret_key='${KEY}' ${CMAKE_ASM_FLAGS}")

add_executable( bootloader-${TARGET} )

get_filename_component(SCRIPT "src/linker.ld" ABSOLUTE)

file(GLOB images images/*)

target_link_options(bootloader-${TARGET} PRIVATE  -T "${SCRIPT}")
set_target_properties(bootloader-${TARGET} PROPERTIES LINK_DEPENDS ${SCRIPT})

target_sources(
    bootloader-${TARGET}
    PRIVATE
    src/boot.S
)
set(signed_images "")

foreach(image ${images})
    get_filename_component(NAME ${image} NAME_WE)
    list(APPEND signed_images sign_${NAME})
    add_custom_target(sign_${NAME}
        DEPENDS
            "${CMAKE_CURRENT_BINARY_DIR}/bootloader-${TARGET}"
        COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/sign.py
        ${CMAKE_CURRENT_BINARY_DIR}/"bootloader-${TARGET}" 
        "${image}"
        '${KEY}'
        ${CMAKE_CURRENT_BINARY_DIR}/"${NAME}-${TARGET}_signed"
    )
endforeach()
add_custom_target(sign_all
        DEPENDS
        ${signed_images}
)