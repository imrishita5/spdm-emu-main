/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_responder.h"

#define SOCKET_SPDM_COMMAND_NORMAL   0x0001
#define SOCKET_SPDM_COMMAND_TEST     0xDEAD
#define SOCKET_SPDM_COMMAND_SHUTDOWN 0xFFFE

/* Disable optimization to avoid code removal with VS2019.*/

#if defined(_MSC_EXTENSIONS)
#pragma optimize("", off)
#elif defined (__clang__)
#pragma clang optimize off
#endif

void spdm_dispatch(void)
{
    void *spdm_context;
    libspdm_return_t status;
#if defined(LIBSPDM_HOST_EMU)
    static const char m_test_response[] = "Server Hello!";
#endif

    spdm_context = spdm_server_init();
    if (spdm_context == NULL) {
        return;
    }

#if !defined(LIBSPDM_HOST_EMU)
    status = pci_doe_init_responder ();
    if (status != LIBSPDM_STATUS_SUCCESS) {
        return;
    }
#endif

    while (true) {
        status = libspdm_responder_dispatch_message(spdm_context);
        if (status == LIBSPDM_STATUS_SUCCESS) {
            continue;
        }

#if defined(LIBSPDM_HOST_EMU)
        if (status == LIBSPDM_STATUS_UNSUPPORTED_CAP) {
            if (m_command == SOCKET_SPDM_COMMAND_TEST) {
                (void)spdm_responder_send_platform_message(SOCKET_SPDM_COMMAND_TEST,
                                                           sizeof(m_test_response),
                                                           m_test_response);
                continue;
            }

            if (m_command == SOCKET_SPDM_COMMAND_SHUTDOWN) {
                (void)spdm_responder_send_platform_message(SOCKET_SPDM_COMMAND_SHUTDOWN,
                                                           0,
                                                           NULL);
                break;
            }
        }
#endif

        if (status == LIBSPDM_STATUS_SEND_FAIL ||
            status == LIBSPDM_STATUS_RECEIVE_FAIL) {
            break;
        }
    }
    return;
}

/**
 * Main entry point.
 *
 * @return This function should never return.
 *
 **/
void ModuleEntryPoint(void)
{
    spdm_dispatch();

    return;
}
