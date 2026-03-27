// nic_measurements.c

#include <string.h>
#include "library/spdm_common_lib.h"
#include "internal/libspdm_common_lib.h"

// Simulated NIC measurement indices (match whatever your security policy expects)
#define NIC_MEAS_IDX_FW_VERSION    1   // firmware version hash
#define NIC_MEAS_IDX_CONFIG        2   // NIC config hash (link speed, offloads)
#define NIC_MEAS_IDX_PCIE_CONFIG   3   // PCIe capability register snapshot

// Raw values that will be SHA-384'd into measurement blocks
static const uint8_t g_fw_version_blob[16] = {
    0x01, 0x02, 0x03, 0x04,   // major.minor.patch.build
    'N',  'I',  'C', '-',
    'S',  'I',  'M', 0x00,
    0x00, 0x00, 0x00, 0x00
};

static const uint8_t g_nic_config_blob[32] = {
    0xC4, 0x61, 0x00, 0x00,   // link_speed = 25000 Mbps (little-endian)
    0x01,                      // tls_offload = enabled
    0x00,                      // reserved
    // ... rest zeroed
};

// Helper: hash a blob and wrap it in a DMTF measurement block
static libspdm_return_t build_one_block(
    uint32_t hash_algo, uint8_t index,
    const void *raw, size_t raw_size,
    spdm_measurement_block_dmtf_t *out_block, size_t *out_size)
{
    size_t hash_size = libspdm_get_hash_size(hash_algo);
    size_t block_size = sizeof(spdm_measurement_block_dmtf_t) + hash_size;

    out_block->measurement_block_common_header.index = index;
    out_block->measurement_block_common_header.measurement_specification =
        SPDM_MEASUREMENT_SPECIFICATION_DMTF;
    out_block->measurement_block_common_header.measurement_size =
        (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) + hash_size);
    out_block->measurement_block_dmtf_header.dmtf_spec_measurement_value_type =
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_IMMUTABLE_ROM |   // or MUTABLE_FIRMWARE
        SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM;   // raw digest
    out_block->measurement_block_dmtf_header.dmtf_spec_measurement_value_size =
        (uint16_t)hash_size;

    // Hash the raw blob into the block
    bool ok = libspdm_hash_all(hash_algo, raw, raw_size,
                                (uint8_t *)out_block + sizeof(spdm_measurement_block_dmtf_t));
    *out_size = block_size;
    return ok ? LIBSPDM_STATUS_SUCCESS : LIBSPDM_STATUS_CRYPTO_ERROR;
}

libspdm_return_t nic_build_measurement_record(
    uint32_t  hash_algo,
    uint8_t   requested_index,    // 0xFF = all
    uint8_t  *count,
    void     *out_buf,
    size_t   *out_size)
{
    uint8_t *ptr = (uint8_t *)out_buf;
    size_t   used = 0;
    *count = 0;

    struct { uint8_t idx; const void *blob; size_t sz; } blocks[] = {
        { NIC_MEAS_IDX_FW_VERSION,  g_fw_version_blob,  sizeof(g_fw_version_blob)  },
        { NIC_MEAS_IDX_CONFIG,      g_nic_config_blob,  sizeof(g_nic_config_blob)  },
    };

    for (int i = 0; i < 2; i++) {
        if (requested_index != 0xFF && requested_index != blocks[i].idx)
            continue;

        size_t block_sz;
        libspdm_return_t ret = build_one_block(
            hash_algo, blocks[i].idx,
            blocks[i].blob, blocks[i].sz,
            (spdm_measurement_block_dmtf_t *)(ptr + used), &block_sz);
        if (LIBSPDM_STATUS_IS_ERROR(ret)) return ret;

        used += block_sz;
        (*count)++;
    }

    *out_size = used;
    return LIBSPDM_STATUS_SUCCESS;
}