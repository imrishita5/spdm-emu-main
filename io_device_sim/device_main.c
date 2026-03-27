// nic_device_main.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "library/spdm_responder_lib.h"
#include "library/spdm_transport_pcidoe_lib.h"   // or mctp_lib
#include "./spdm_emu/spdm_emu_common/spdm_emu.h"             // TCP helpers from spdm-emu

// ── Transport send/receive wrappers (TCP for now) ──────────────────────────
// These are the two function pointers libspdm calls to move bytes.
// On a real NIC you'd replace these with your PCIe DOE MMIO reads/writes.

libspdm_return_t nic_send_message(void *spdm_context, size_t message_size,
                                   const void *message, uint64_t timeout)
{
    return spdm_device_send_message(spdm_context, message_size, message, timeout);
    // spdm_device_send_message = TCP send helper from spdm-emu
}

libspdm_return_t nic_receive_message(void *spdm_context, size_t *message_size,
                                      void **message, uint64_t timeout)
{
    return spdm_device_receive_message(spdm_context, message_size, message, timeout);
}

// ── NIC device state (whatever you want to simulate) ──────────────────────
typedef struct {
    uint8_t  mac_addr[6];
    uint32_t link_speed_mbps;
    uint8_t  fw_version[4];     // measured into SPDM measurement block
    bool     tls_offload_enabled;
} nic_state_t;

static nic_state_t g_nic = {
    .mac_addr          = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01},
    .link_speed_mbps   = 25000,
    .fw_version        = {1, 2, 3, 4},
    .tls_offload_enabled = true,
};

// ── Main ──────────────────────────────────────────────────────────────────
int main(int argc, char *argv[])
{
    void    *spdm_context;
    void    *scratch_buffer;
    size_t   scratch_size;
    libspdm_return_t status;

    printf("[NIC-SIM] Starting simulated 25G NIC SPDM responder\n");

    // 1. Allocate and initialise the libspdm context
    spdm_context = malloc(libspdm_get_context_size());
    if (!spdm_context) { perror("malloc context"); return 1; }
    libspdm_init_context(spdm_context);

    // 2. Scratch buffer (libspdm uses this for in-flight message crypto)
    scratch_size = libspdm_get_sizeof_required_scratch_buffer(spdm_context);
    scratch_buffer = malloc(scratch_size);
    if (!scratch_buffer) { perror("malloc scratch"); return 1; }
    libspdm_set_scratch_buffer(spdm_context, scratch_buffer, scratch_size);

    // 3. Register YOUR send/receive transport hooks
    libspdm_register_device_io_func(spdm_context,
                                    nic_send_message,
                                    nic_receive_message);

    // 4. Register the transport framing (PCI DOE for a PCIe NIC)
    libspdm_register_transport_layer_func(
        spdm_context,
        LIBSPDM_MAX_SPDM_MSG_SIZE,
        LIBSPDM_TRANSPORT_HEADER_SIZE,
        LIBSPDM_TRANSPORT_TAIL_SIZE,
        libspdm_transport_pcidoe_encode_message,
        libspdm_transport_pcidoe_decode_message);

    // 5. Register the device buffer (where libspdm DMA's messages)
    libspdm_register_device_buffer_func(
        spdm_context,
        LIBSPDM_MAX_SPDM_MSG_SIZE + LIBSPDM_TRANSPORT_ADDITIONAL_SIZE,
        LIBSPDM_MAX_SPDM_MSG_SIZE + LIBSPDM_TRANSPORT_ADDITIONAL_SIZE,
        spdm_device_acquire_sender_buffer,    // from spdm-emu helpers
        spdm_device_release_sender_buffer,
        spdm_device_acquire_receiver_buffer,
        spdm_device_release_receiver_buffer);

    // 6. Load certificates + set capabilities
    //    spdm_emu_load_device_cert_chain() reads the PEM files from
    //    make copy_sample_key output — same certs you already generated
    status = spdm_emu_load_device_cert_chain(spdm_context);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        fprintf(stderr, "[NIC-SIM] Failed to load certs: 0x%x\n", status);
        return 1;
    }

    // 7. Set responder capabilities
    libspdm_data_parameter_t param = { .location = LIBSPDM_DATA_LOCATION_LOCAL };
    uint32_t capabilities = SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP     |
                            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG |
                            SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS,
                     &param, &capabilities, sizeof(capabilities));

    // 8. Open TCP listener (same port as spdm-emu by default: 2323)
    spdm_server_connection_state_t connection_state;
    status = spdm_emu_platform_server_routine_start(spdm_context,
                                                     &connection_state);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
        fprintf(stderr, "[NIC-SIM] Server start failed: 0x%x\n", status);
        return 1;
    }

    // 9. Responder dispatch loop — this is the "missing main" body
    printf("[NIC-SIM] Waiting for SPDM requester on port 2323...\n");
    while (true) {
        // Block until a full SPDM request arrives over TCP
        // libspdm reads it via nic_receive_message, processes it,
        // sends the response via nic_send_message — all inside here
        status = libspdm_responder_dispatch_message(spdm_context);

        if (status == LIBSPDM_STATUS_SUCCESS) {
            printf("[NIC-SIM] Request handled OK\n");
        } else if (status == LIBSPDM_STATUS_RESYNCH_PEER) {
            // Requester triggered re-authentication — reset session, keep going
            printf("[NIC-SIM] Re-sync requested, resetting session\n");
            libspdm_init_connection(spdm_context, false);
        } else {
            fprintf(stderr, "[NIC-SIM] Dispatch error: 0x%x — reconnecting\n",
                    status);
            // For TCP: close and re-accept; for a real device: reset DOE mailbox
            spdm_emu_platform_server_routine_stop(spdm_context);
            spdm_emu_platform_server_routine_start(spdm_context,
                                                    &connection_state);
        }
    }

    return 0;
}