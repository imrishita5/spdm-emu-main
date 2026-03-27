/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-emu/blob/main/LICENSE.md
 **/

/** @file
 * SPDM common library.
 * It follows the SPDM Specification.
 **/

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <base.h>
#include "library/memlib.h"
#include "spdm_device_secret_lib_internal.h"

#define RESPONDER_CERT_CHAIN_PATH  "./io-device-certs/bundle.certchain.der"
#define RESPONDER_ROOT_CERT_PATH   "./io-device-certs/ca.cert.der"

static bool read_file_to_buffer(
    const char *file,
    uint8_t **buffer,
    size_t *buffer_size
)
{
    FILE *fp;
    long size;

    fp = fopen(file, "rb");
    if (fp == NULL) {
        return false;
    }

    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    rewind(fp);

    *buffer = malloc(size);
    if (*buffer == NULL) {
        fclose(fp);
        return false;
    }

    if (fread(*buffer, 1, size, fp) != (size_t)size) {
        fclose(fp);
        free(*buffer);
        return false;
    }

    fclose(fp);
    *buffer_size = (size_t)size;
    return true;
}

bool libspdm_read_responder_public_certificate_chain(
    uint32_t base_hash_algo, uint32_t base_asym_algo, void **data,
    size_t *size, void **hash, size_t *hash_size)
{
    bool res;
    spdm_cert_chain_t *cert_chain;
    size_t cert_chain_size;
    const uint8_t *root_cert;
    size_t root_cert_len;
    size_t digest_size;

    *data = NULL;
    *size = 0;
    if (hash != NULL) {
        *hash = NULL;
    }
    if (hash_size != NULL) {
        *hash_size = 0;
    }

    if (base_asym_algo == 0) {
        return false;
    }

    digest_size = libspdm_get_hash_size(base_hash_algo);
#if LIBSPDM_SHA384_SUPPORT
    LIBSPDM_ASSERT(digest_size == LIBSPDM_SHA384_DIGEST_SIZE);
#endif

    switch (base_asym_algo) {
#if LIBSPDM_ECDSA_SUPPORT
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
        uint8_t *cert_chain_buffer;
        uint8_t *root_cert_buffer;
        size_t cert_chain_buffer_size;
        size_t root_cert_buffer_size;

        if (!read_file_to_buffer(
                RESPONDER_CERT_CHAIN_PATH,
                &cert_chain_buffer,
                &cert_chain_buffer_size)) {
            return false;
        }

        if (!read_file_to_buffer(
                RESPONDER_ROOT_CERT_PATH,
                &root_cert_buffer,
                &root_cert_buffer_size)) {
            free(cert_chain_buffer);
            return false;
        }

        cert_chain = (spdm_cert_chain_t *)cert_chain_buffer;
        cert_chain_size = cert_chain_buffer_size;
        break;
#endif
    default:
        LIBSPDM_ASSERT(false);
        return false;
    }

    /* patch */
    cert_chain->length = (uint32_t)cert_chain_size;

    /* Get Root Certificate and calculate hash value*/

    root_cert = root_cert_buffer;
    root_cert_len = root_cert_buffer_size;

    res = libspdm_hash_all(base_hash_algo, root_cert, root_cert_len,
                           (uint8_t *)(cert_chain + 1));
    if (!res) {
        return res;
    }
    *data = cert_chain;
    *size = cert_chain_size;
    if (hash != NULL) {
        *hash = (cert_chain + 1);
    }
    if (hash_size != NULL) {
        *hash_size = digest_size;
    }

    return true;
}
