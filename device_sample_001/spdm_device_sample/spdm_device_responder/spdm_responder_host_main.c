/**
 *  Copyright Notice:
 *  Copyright 2026 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_responder.h"

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

#ifndef TCP_SPDM_PLATFORM_PORT
#define TCP_SPDM_PLATFORM_PORT 4194
#endif

extern int m_host_emu_socket;

static int spdm_host_emu_create_listen_socket(uint16_t port)
{
    int listen_fd;
    int opt = 1;
    struct sockaddr_in addr;

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        return -1;
    }

    (void)setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));

    libspdm_zero_mem(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
#if !defined(_WIN32)
        close(listen_fd);
#endif
        return -1;
    }

    if (listen(listen_fd, 1) != 0) {
#if !defined(_WIN32)
        close(listen_fd);
#endif
        return -1;
    }

    return listen_fd;
}

int main(void)
{
    int listen_fd;
    struct sockaddr_in peer_addr;
    socklen_t peer_len;

    listen_fd = spdm_host_emu_create_listen_socket(TCP_SPDM_PLATFORM_PORT);
    if (listen_fd < 0) {
        return 1;
    }

    peer_len = (socklen_t)sizeof(peer_addr);
    m_host_emu_socket = accept(listen_fd, (struct sockaddr *)&peer_addr, &peer_len);
    if (m_host_emu_socket < 0) {
#if !defined(_WIN32)
        close(listen_fd);
#endif
        return 1;
    }

    spdm_dispatch();

#if !defined(_WIN32)
    close(m_host_emu_socket);
    close(listen_fd);
#endif
    return 0;
}
