#include "enterprise/enterprise_driver_entrypoints.h"

#include <string.h>
#include <psa/crypto.h>

static void add(const uint8_t *augend, const uint8_t *addend, uint8_t *sum, size_t byte_count);

psa_status_t enterprise_transparent_generate_key(
    const psa_key_attributes_t *attributes,
    uint8_t *key_buffer,
    size_t key_buffer_size,
    size_t *key_buffer_length) {
    if (attributes == NULL || key_buffer == NULL || key_buffer_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_key_type_t key_type = psa_get_key_type(attributes);
    if (key_type != PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    size_t key_bits = psa_get_key_bits(attributes);
    if (key_bits != 256) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (key_buffer_size < 32) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    // TODO: Determine if this should be stored in LSB.
    // Min = 0x01
    //
    // Max = n - 1
    //     = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632550
    //
    // Range = Max - Min
    //       = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254F
    const uint8_t range[32] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xBC, 0xE6,
        0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x4F
    };

    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    uint8_t key_payload[32] = {0};
    uint8_t index = 0;
    while (index < 32) {
        status = psa_generate_random(key_payload + index, 1);
        if (status != PSA_SUCCESS) {
            return status;
        }

        if (key_payload[index] > range[index]) {
            continue;
        }

        if (key_payload[index] < range[index]) {
            break;
        }

        index++;
    }

    if (index < 32) {
        status = psa_generate_random(key_payload + index + 1, 32 - (index + 1));
        if (status != PSA_SUCCESS) {
            return status;
        }
    }

    index = 0;
    while (index < 32) {
        uint8_t *itr = key_payload + index;
        if (*itr != 0xFF) {
            *itr += 1;
            break;
        }

        *itr = 0x00;
        index++;
    }

    (void) memcpy(key_buffer, key_payload, 32);
    *key_buffer_length = 32;

    return PSA_SUCCESS;
}

psa_status_t enterprise_transparent_import_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *data,
    size_t data_length,
    uint8_t *key_buffer,
    size_t key_buffer_size,
    size_t *key_buffer_length,
    size_t *bits) {
    if (attributes == NULL || data == NULL || key_buffer == NULL || key_buffer_length == NULL || bits == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_key_type_t key_type = psa_get_key_type(attributes);
    if (key_type == PSA_KEY_TYPE_HMAC || key_type == PSA_KEY_TYPE_DERIVE) {
        if (*bits == 0) {
            *bits = data_length * 8;
        }
    } else if (key_type == PSA_KEY_TYPE_AES) {
        if (*bits == 0) {
            *bits = 256;
        } else if (*bits != 256) {
            return PSA_ERROR_NOT_SUPPORTED;
        }
    } else {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (key_buffer_size < data_length || key_buffer_size < *bits / 8) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    memcpy(key_buffer, data, data_length);
    *key_buffer_length = data_length;

    return PSA_SUCCESS;
}

// TODO: Test.
psa_status_t enterprise_transparent_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    uint8_t *data,
    size_t data_size,
    size_t *data_length) {
    // TODO: Reinstate.
    // if (attributes == NULL || key_buffer == NULL || data == NULL || data_length == NULL) {
    //     return PSA_ERROR_INVALID_ARGUMENT;
    // }
    //
    // psa_key_type_t key_type = psa_get_key_type(attributes);
    // size_t key_bits = psa_get_key_bits(attributes);
    // if (key_type != PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1) || key_bits != 256) {
    //     return PSA_ERROR_NOT_SUPPORTED;
    // }
    //
    // if (key_buffer_size != 32) {
    //     return PSA_ERROR_INVALID_ARGUMENT;
    // }
    //
    // if (data_size < 65) {
    //     return PSA_ERROR_BUFFER_TOO_SMALL;
    // }

    // TODO: Determine if this should be stored in LSB.
    const uint8_t g_x[32] = {
        0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03,
        0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96
    };
    const uint8_t g_y[32] = {
        0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce,
        0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5
    };

    uint8_t r_x[32] = {0};
    uint8_t r_y[32] = {0};

    (void)memcpy(r_x, g_x, 32);
    (void)memcpy(r_y, g_y, 32);

    uint8_t bit_exp = 6;
    for (size_t byte_index = 0; byte_index < 32; byte_index++) {
        while (bit_exp < 8) {
            add(r_x, r_x, r_x, 32);
            add(r_y, r_y, r_y, 32);

            if (((key_buffer[byte_index] >> bit_exp) & 1) == 1) {
                add(r_x, g_x, r_x, 32);
                add(r_y, g_y, r_y, 32);
            }

            bit_exp--;
        }

        bit_exp = 8;
    }

    data[0] = 0x04;
    (void)memcpy(data + 1, r_x, 32);
    (void)memcpy(data + 33, r_y, 32);
    *data_length = 65;

    return PSA_SUCCESS;
}

psa_status_t enterprise_transparent_mac_compute(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *mac,
    size_t mac_size,
    size_t *mac_length) {
    return PSA_ERROR_GENERIC_ERROR;
}

psa_status_t enterprise_transparent_aead_encrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *nonce,
    size_t nonce_length,
    const uint8_t *additional_data,
    size_t additional_data_length,
    const uint8_t *plaintext,
    size_t plaintext_length,
    uint8_t *ciphertext,
    size_t ciphertext_size,
    size_t *ciphertext_length) {
    return PSA_ERROR_GENERIC_ERROR;
}

psa_status_t enterprise_transparent_aead_decrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *nonce,
    size_t nonce_length,
    const uint8_t *additional_data,
    size_t additional_data_length,
    const uint8_t *ciphertext,
    size_t ciphertext_length,
    uint8_t *plaintext,
    size_t plaintext_size,
    size_t *plaintext_length) {
    return PSA_ERROR_GENERIC_ERROR;
}

psa_status_t enterprise_transparent_key_agreement(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *peer_key,
    size_t peer_key_length,
    uint8_t *shared_secret,
    size_t shared_secret_size,
    size_t *shared_secret_length) {
    return PSA_ERROR_GENERIC_ERROR;
}

static void add(const uint8_t *augend, const uint8_t *addend, uint8_t *sum, size_t byte_count) {
    uint8_t carry = 0;
    for (size_t byte_index = byte_count - 1; byte_index < byte_count; byte_index--) {
        uint8_t augend_byte = augend[byte_index];
        uint8_t addend_byte = addend[byte_index];
        uint8_t sum_byte = 0;
        for (uint8_t bit_exp = 0; bit_exp < 8; bit_exp++) {
            uint8_t augend_bit = (augend_byte >> bit_exp) & 1;
            uint8_t addend_bit = (addend_byte >> bit_exp) & 1;
            sum_byte |= (augend_bit ^ addend_bit ^ carry) << bit_exp;
            carry = (augend_bit & addend_bit) | (augend_bit & carry) | (addend_bit & carry);
        }

        sum[byte_index] = sum_byte;
    }
}
