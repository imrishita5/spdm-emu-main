/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

#include "spdm_responder.h"
#include "spdm_device_secret_lib/spdm_device_secret_lib_internal.h"
#include "library/spdm_transport_tcp_lib.h"

/* TCP transport uses a 4-byte header and no tail (per spdm_transport_tcp_lib.h) */
#define LIBSPDM_TCP_TRANSPORT_HEADER_SIZE 4
#define LIBSPDM_TCP_TRANSPORT_TAIL_SIZE   0

#if defined(LIBSPDM_HOST_EMU)
#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

int m_host_emu_socket = -1;

static bool spdm_host_emu_read_n(void *buffer, size_t size)
{
    size_t done;
    ssize_t ret;
    uint8_t *ptr;

    done = 0;
    ptr = (uint8_t *)buffer;
    while (done < size) {
        ret = recv(m_host_emu_socket, (char *)ptr + done, size - done, 0);
        if (ret <= 0) {
            return false;
        }
        done += (size_t)ret;
    }
    return true;
}

static bool spdm_host_emu_write_n(const void *buffer, size_t size)
{
    size_t done;
    ssize_t ret;
    const uint8_t *ptr;

    done = 0;
    ptr = (const uint8_t *)buffer;
    while (done < size) {
        ret = send(m_host_emu_socket, (const char *)ptr + done, size - done, 0);
        if (ret <= 0) {
            return false;
        }
        done += (size_t)ret;
    }
    return true;
}
#endif

uint8_t m_scratch_buffer[LIBSPDM_SCRATCH_BUFFER_SIZE];

bool m_send_receive_buffer_acquired = false;
uint8_t m_send_receive_buffer[LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE];
size_t m_send_receive_buffer_size;

libspdm_return_t spdm_responder_send_message(void *spdm_context,
                                             size_t message_size, const void *message,
                                             uint64_t timeout)
{
#if defined(LIBSPDM_HOST_EMU)
    (void)spdm_context;
    (void)timeout;

    if (m_host_emu_socket < 0) {
        return LIBSPDM_STATUS_SEND_FAIL;
    }

    /* TCP framing is handled by libspdm_transport_tcp_encode_message().
     * This function just sends the already-encoded message to the socket.
     */
    if (!spdm_host_emu_write_n(message, message_size)) {
        return LIBSPDM_STATUS_SEND_FAIL;
    }

    return LIBSPDM_STATUS_SUCCESS;
#else
    size_t index;
    const uint32_t *msg;
    uint32_t data32;

    LIBSPDM_ASSERT((message_size % 3) == 0);
    msg = message;

    while (true) {
        data32 = spdm_dev_pci_cfg_doe_read_32(PCI_EXPRESS_REG_DOE_STATUS_OFFSET);
        if ((data32 & PCI_EXPRESS_REG_DOE_STATUS_BIT_BUSY) == 0) {
            break;
        }
    }

    for (index = 0; index < message_size / 4; index++) {
        spdm_dev_pci_cfg_doe_write_32 (PCI_EXPRESS_REG_DOE_READ_DATA_MAILBOX_OFFSET, msg[index]);
    }

    spdm_dev_pci_cfg_doe_write_32 (PCI_EXPRESS_REG_DOE_STATUS_OFFSET,
                                   PCI_EXPRESS_REG_DOE_STATUS_BIT_DATA_READY);
    return LIBSPDM_STATUS_SUCCESS;
#endif
}

libspdm_return_t spdm_responder_receive_message(void *spdm_context,
                                                size_t *message_size,
                                                void **message,
                                                uint64_t timeout)
{
#if defined(LIBSPDM_HOST_EMU)
    uint8_t header[2];
    uint16_t payload_length;

    (void)spdm_context;
    (void)timeout;

    LIBSPDM_ASSERT (*message == m_send_receive_buffer);

    if (m_host_emu_socket < 0) {
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }

    /* Read the 2-byte TCP binding header with payload length */
    if (!spdm_host_emu_read_n(header, sizeof(header))) {
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }

    /* Extract payload_length in big-endian format */
    payload_length = ((uint16_t)header[0] << 8) | (uint16_t)header[1];
    
    /* payload_length includes version (1 byte) + type (1 byte) + SPDM message
     * Total bytes in buffer = 2 (header) + payload_length
     */
    if (payload_length < 2 || (2 + payload_length) > sizeof(m_send_receive_buffer)) {
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }

    /* Copy the 2-byte header into the receive buffer */
    libspdm_copy_mem(m_send_receive_buffer, sizeof(m_send_receive_buffer),
                     header, sizeof(header));

    /* Read the remaining payload_length bytes */
    if (!spdm_host_emu_read_n((uint8_t*)m_send_receive_buffer + sizeof(header), 
                              payload_length)) {
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }

    *message = m_send_receive_buffer;
    *message_size = sizeof(header) + payload_length;
    return LIBSPDM_STATUS_SUCCESS;
#else
    size_t index;
    uint32_t *msg;
    uint32_t data32;

    LIBSPDM_ASSERT (*message == m_send_receive_buffer);
    LIBSPDM_ASSERT((m_send_receive_buffer_size % 3) == 0);
    msg = *message;

    while (true) {
        data32 = spdm_dev_pci_cfg_doe_read_32(PCI_EXPRESS_REG_DOE_STATUS_OFFSET);
        if ((data32 & PCI_EXPRESS_REG_DOE_STATUS_BIT_BUSY) == 0) {
            break;
        } else {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
    }

    while (true) {
        data32 = spdm_dev_pci_cfg_doe_read_32(PCI_EXPRESS_REG_DOE_CONTROL_OFFSET);
        if ((data32 & PCI_EXPRESS_REG_DOE_CONTROL_BIT_GO) != 0) {
            break;
        } else {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
    }

    for (index = 0; index < m_send_receive_buffer_size / 4; index++) {
        msg[index] = spdm_dev_pci_cfg_doe_read_32 (PCI_EXPRESS_REG_DOE_WRITE_DATA_MAILBOX_OFFSET);
    }
    *message_size = m_send_receive_buffer_size;

    spdm_dev_pci_cfg_doe_write_32 (PCI_EXPRESS_REG_DOE_CONTROL_OFFSET, 0);
    return LIBSPDM_STATUS_SUCCESS;
#endif
}

libspdm_return_t spdm_device_acquire_sender_buffer (
    void *context, void **msg_buf_ptr)
{
    LIBSPDM_ASSERT (!m_send_receive_buffer_acquired);
    *msg_buf_ptr = m_send_receive_buffer;
    libspdm_zero_mem (m_send_receive_buffer, sizeof(m_send_receive_buffer));
    m_send_receive_buffer_acquired = true;
    return LIBSPDM_STATUS_SUCCESS;
}

void spdm_device_release_sender_buffer (
    void *context, const void *msg_buf_ptr)
{
    LIBSPDM_ASSERT (m_send_receive_buffer_acquired);
    LIBSPDM_ASSERT (msg_buf_ptr == m_send_receive_buffer);
    m_send_receive_buffer_acquired = false;
    return;
}

libspdm_return_t spdm_device_acquire_receiver_buffer (
    void *context, void **msg_buf_ptr)
{
    LIBSPDM_ASSERT (!m_send_receive_buffer_acquired);
    *msg_buf_ptr = m_send_receive_buffer;
    libspdm_zero_mem (m_send_receive_buffer, sizeof(m_send_receive_buffer));
    m_send_receive_buffer_acquired = true;
    return LIBSPDM_STATUS_SUCCESS;
}

void spdm_device_release_receiver_buffer (
    void *context, const void *msg_buf_ptr)
{
    LIBSPDM_ASSERT (m_send_receive_buffer_acquired);
    LIBSPDM_ASSERT (msg_buf_ptr == m_send_receive_buffer);
    m_send_receive_buffer_acquired = false;
    return;
}

void *spdm_server_init(void)
{
    void *spdm_context;
    libspdm_data_parameter_t parameter;
    uint8_t data8;
    uint16_t data16;
    uint32_t data32;
    void *data;
    size_t data_size;

    spdm_context = (void *)allocate_pool(libspdm_get_context_size());
    if (spdm_context == NULL) {
        return NULL;
    }
    libspdm_init_context(spdm_context);

    libspdm_register_device_io_func(spdm_context, spdm_responder_send_message,
                                    spdm_responder_receive_message);
#if defined(LIBSPDM_HOST_EMU)
    libspdm_register_transport_layer_func(spdm_context,
                                          LIBSPDM_MAX_SPDM_MSG_SIZE,
                                          LIBSPDM_TCP_TRANSPORT_HEADER_SIZE,
                                          LIBSPDM_TCP_TRANSPORT_TAIL_SIZE,
                                          libspdm_transport_tcp_encode_message,
                                          libspdm_transport_tcp_decode_message);
#else
    libspdm_register_transport_layer_func(spdm_context,
                                          LIBSPDM_MAX_SPDM_MSG_SIZE,
                                          LIBSPDM_PCI_DOE_TRANSPORT_HEADER_SIZE,
                                          LIBSPDM_PCI_DOE_TRANSPORT_TAIL_SIZE,
                                          libspdm_transport_pci_doe_encode_message,
                                          libspdm_transport_pci_doe_decode_message);
#endif
    libspdm_register_device_buffer_func(spdm_context,
                                        LIBSPDM_SENDER_BUFFER_SIZE,
                                        LIBSPDM_RECEIVER_BUFFER_SIZE,
                                        spdm_device_acquire_sender_buffer,
                                        spdm_device_release_sender_buffer,
                                        spdm_device_acquire_receiver_buffer,
                                        spdm_device_release_receiver_buffer);

    /* io function callback */
    libspdm_set_scratch_buffer (spdm_context, m_scratch_buffer, sizeof(m_scratch_buffer));

    /* version */
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
    data16 = SPDM_MESSAGE_VERSION_12 << SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_SPDM_VERSION, &parameter,
                     &data16, sizeof(data16));

    /* capabilities */
    data8 = 0;
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_CAPABILITY_CT_EXPONENT,
                     &parameter, &data8, sizeof(data8));

        /* Smart Card capabilities: core attestation and measurements only */
        data32 =
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP |
            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG
        ;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter,
                     &data32, sizeof(data32));

    /* algorithm */
    data8 = SPDM_MEASUREMENT_SPECIFICATION_DMTF;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_MEASUREMENT_SPEC, &parameter,
                     &data8, sizeof(data8));
    data32 = SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_MEASUREMENT_HASH_ALGO, &parameter,
                     &data32, sizeof(data32));
    data32 = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter,
                     &data32, sizeof(data32));
    data32 = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_BASE_HASH_ALGO, &parameter,
                     &data32, sizeof(data32));
    data16 = SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_DHE_NAME_GROUP, &parameter,
                     &data16, sizeof(data16));
    data16 = SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_AEAD_CIPHER_SUITE, &parameter,
                     &data16, sizeof(data16));
    data16 = 0;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &parameter,
                     &data16, sizeof(data16));
    data16 = SPDM_ALGORITHMS_KEY_SCHEDULE_SPDM;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_KEY_SCHEDULE, &parameter, &data16,
                     sizeof(data16));
    data8 = SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_OTHER_PARAMS_SUPPORT, &parameter,
                     &data8, sizeof(data8));

    data8 = 0xF0;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_HEARTBEAT_PERIOD, &parameter,
                     &data8, sizeof(data8));

    /* certificate */
    libspdm_read_responder_public_certificate_chain(
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384,
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384,
        &data, &data_size,
        NULL, NULL);
    parameter.additional_data[0] = 0;
    libspdm_set_data(spdm_context,
                     LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN,
                     &parameter, data, data_size);

    /* spdm function callback */
    libspdm_register_get_response_func(
        spdm_context, spdm_get_response_vendor_defined_request);

    return spdm_context;
}
