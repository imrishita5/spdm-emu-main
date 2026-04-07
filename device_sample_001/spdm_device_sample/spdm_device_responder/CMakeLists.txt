cmake_minimum_required(VERSION 3.5)

set(SPDM_DEVICE_RESPONDER_FIRMWARE_LINK_FLAGS "")

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    if(ARCH STREQUAL "x64")
        set(SPDM_DEVICE_RESPONDER_FIRMWARE_LINK_FLAGS "-nostdlib -flto -Wl,--entry,ModuleEntryPoint")
    elseif(ARCH STREQUAL "aarch64")
        if(TOOLCHAIN STREQUAL "ARM_DS2022")
            set(SPDM_DEVICE_RESPONDER_FIRMWARE_LINK_FLAGS "--target=aarch64-arm-none-eabi -nostdlib -flto -Wl,--entry,ModuleEntryPoint,--undefined=__udivti3")
        elseif(TOOLCHAIN STREQUAL "ARM_GNU")
            set(SPDM_DEVICE_RESPONDER_FIRMWARE_LINK_FLAGS "-nostdlib -flto -Wl,--entry,ModuleEntryPoint,--undefined=__udivti3")
        elseif(TOOLCHAIN STREQUAL "AARCH64_GCC")
            set(SPDM_DEVICE_RESPONDER_FIRMWARE_LINK_FLAGS "-nostdlib -flto -Wl,--entry,ModuleEntryPoint")
        endif()
    endif()
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    set(SPDM_DEVICE_RESPONDER_FIRMWARE_LINK_FLAGS "/DLL /ENTRY:ModuleEntryPoint /NOLOGO /SUBSYSTEM:EFI_BOOT_SERVICE_DRIVER /NODEFAULTLIB /IGNORE:4086 /MAP /OPT:REF")
endif()

# Propagate parent CMake variables to this subdirectory
if(NOT DEFINED LIBSPDM_DIR)
    get_filename_component(LIBSPDM_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../libspdm ABSOLUTE)
endif()
if(NOT DEFINED SPDM_EMU_DIR)
    get_filename_component(SPDM_EMU_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../.. ABSOLUTE)
endif()
if(NOT DEFINED SPDM_DEVICE_DIR)
    get_filename_component(SPDM_DEVICE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/.. ABSOLUTE)
endif()

include_directories(${SPDM_DEVICE_DIR}/include
                    ${SPDM_DEVICE_DIR}/spdm_device_responder
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/os_stub
                    ${LIBSPDM_DIR}/os_stub/include
                    ${SPDM_EMU_DIR}/include
                    ${PROJECT_SOURCE_DIR}/library
)

set(src_spdm_device_responder
    spdm_responder_init.c
    spdm_responder_main.c
    compiler_stub.c
    support.c
    spdm_responder_pci_doe.c
    pci.c
)

set(src_spdm_device_responder_host_emu
    spdm_responder_host_main.c
    spdm_responder_init.c
    spdm_responder_main.c
    compiler_stub.c
    support.c
    spdm_responder_pci_doe.c
    pci.c
)

set(spdm_device_responder_LIBRARY
    memlib
    debuglib
    spdm_responder_lib
    spdm_common_lib
    cryptstublib
    ${CRYPTO_LIB_PATHS}
    cryptlib_${CRYPTO}
    rnglib
    malloclib_simple
    spdm_crypt_lib
    spdm_secured_message_lib
    spdm_transport_pcidoe_lib
    spdm_device_secret_lib
    spdm_crypt_ext_lib
    intrinsiclib
    platform_lib
    pci_doe_responder_lib
    pci_ide_km_responder_lib
    pci_ide_km_device_lib
    pci_tdisp_responder_lib
    pci_tdisp_device_lib
)

if(TOOLCHAIN STREQUAL "ARM_DS2022" OR TOOLCHAIN STREQUAL "ARM_GNU")
    set(spdm_device_responder_LIBRARY ${spdm_device_responder_LIBRARY} armbuild_lib)
endif()

add_executable(spdm_device_responder ${src_spdm_device_responder})
if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    target_link_libraries(spdm_device_responder ${spdm_device_responder_LIBRARY} -lgcc)
else()
    target_link_libraries(spdm_device_responder ${spdm_device_responder_LIBRARY})
endif()
set_target_properties(spdm_device_responder PROPERTIES
    LINK_FLAGS "${SPDM_DEVICE_RESPONDER_FIRMWARE_LINK_FLAGS}")

add_executable(spdm_device_responder_host_emu ${src_spdm_device_responder_host_emu})
target_compile_definitions(spdm_device_responder_host_emu PRIVATE LIBSPDM_HOST_EMU=1)
if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    target_link_libraries(spdm_device_responder_host_emu
        ${spdm_device_responder_LIBRARY}
        spdm_transport_tcp_lib)
else()
    target_link_libraries(spdm_device_responder_host_emu
        ${spdm_device_responder_LIBRARY}
        spdm_transport_tcp_lib
        ws2_32)
endif()


