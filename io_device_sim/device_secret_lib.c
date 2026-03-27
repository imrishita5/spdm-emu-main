// nic_device_secret_lib.c

#include "library/spdm_responder_lib.h"

// Called by libspdm when it needs to sign a challenge or measurement
// with the device's private key.
// In a real device this would go to a secure enclave or TPM.
// Here we use the sample key from make copy_sample_key.
libspdm_return_t spdm_responder_data_sign(
    spdm_version_number_t  spdm_version,
    uint8_t                op_code,           // CHALLENGE_AUTH or MEASUREMENTS
    uint16_t               req_base_asym_alg,
    uint32_t               base_hash_algo,
    bool                   is_requester,
    const uint8_t         *message,
    size_t                 message_size,
    uint8_t               *signature,
    size_t                *sig_size)
{
    // Delegate to the sample key helper — reads rsa3072_Priv.pem
    // (the key you generated with make copy_sample_key)
    return spdm_emu_sign_with_private_key(req_base_asym_alg, base_hash_algo,
                                           message, message_size,
                                           signature, sig_size);
}

// Called by libspdm when the requester asks GET_MEASUREMENTS
// This is where you put the NIC's actual firmware digest, config hash, etc.
libspdm_return_t spdm_measurement_collection(
    spdm_version_number_t  spdm_version,
    uint8_t                measurement_specification,
    uint32_t               measurement_hash_algo,
    uint8_t                measurements_index,   // which block (0xFF = all)
    uint8_t                request_attribute,
    uint8_t               *measurements_count,
    void                  *measurements,
    size_t                *measurements_size)
{
    return nic_build_measurement_record(
        measurement_hash_algo,
        measurements_index,
        measurements_count,
        measurements,
        measurements_size);
}