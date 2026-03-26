# spdm_emu/spdm_nic_device/CMakeLists.txt

cmake_minimum_required(VERSION 3.14)

include_directories(
    ${LIBSPDM_DIR}/include
    ${PROJECT_SOURCE_DIR}/spdm_emu/spdm_emu_common
    ${PROJECT_SOURCE_DIR}/include
)

set(SRCS
    device_main.c     
    device_secret_lib.c    
    measurements.c         
)
add_executable(io-device-sim ${SRCS})

target_link_libraries(spdm_nic_device
    spdm_emu_common            
    spdm_responder_lib
    spdm_transport_pcidoe_lib 
    spdm_crypt_lib
    spdm_secured_message_lib
    platform_lib
    ${CRYPTO_LIB_PATHS}
)





