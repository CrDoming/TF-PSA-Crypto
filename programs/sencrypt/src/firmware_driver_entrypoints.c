#include "../include/firmware_driver_entrypoints.h"

#include <psa/crypto.h>

psa_status_t firmware_transparent_generate_key(
    const psa_key_attributes_t *attributes,
    uint8_t *key_buffer,
    size_t key_buffer_size,
    size_t *key_buffer_length) {
    if (attributes == NULL || key_buffer == NULL || key_buffer_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    const psa_key_type_t key_type = psa_get_key_type(attributes);
    if (key_type != PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    const size_t key_bits = psa_get_key_bits(attributes);
    if (key_bits != 256) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (key_buffer_size < 32) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    // TODO: In a later PR, add logic.

    *key_buffer_length = 32;

    return PSA_SUCCESS;
}

psa_status_t firmware_transparent_import_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *data,
    size_t data_length,
    uint8_t *key_buffer,
    size_t key_buffer_size,
    size_t *key_buffer_length,
    size_t *bits) {
    if (attributes == NULL || data == NULL || key_buffer == NULL ||
        key_buffer_length == NULL || bits == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    const psa_key_type_t key_type = psa_get_key_type(attributes);
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

    // TODO: In a later PR, add logic to copy contents of data to key_buffer.

    *key_buffer_length = data_length;

    return PSA_SUCCESS;
}

psa_status_t firmware_transparent_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    uint8_t *data,
    size_t data_size,
    size_t *data_length) {
    if (attributes == NULL || key_buffer == NULL || data == NULL ||
        data_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    const psa_key_type_t key_type = psa_get_key_type(attributes);
    if (key_type != PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    const size_t key_bits = psa_get_key_bits(attributes);
    if (key_bits != 256 || key_buffer_size != 32) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (data_size < 65) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    // TODO: In a later PR, add logic.

    *data_length = 65;

    return PSA_SUCCESS;
}

psa_status_t firmware_transparent_mac_compute(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *mac,
    size_t mac_size,
    size_t *mac_length) {
    if (attributes == NULL || key_buffer == NULL || key_buffer_size <= 0 ||
        input == NULL || input_length <= 0 || mac == NULL ||
        mac_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    const psa_key_type_t key_type = psa_get_key_type(attributes);
    if (key_type != PSA_KEY_TYPE_HMAC) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    const psa_key_usage_t key_usage = psa_get_key_usage_flags(attributes);
    if ((key_usage & PSA_KEY_USAGE_SIGN_MESSAGE) == 0) {
        return PSA_ERROR_NOT_PERMITTED;
    }

    if (alg != PSA_ALG_HMAC(PSA_ALG_SHA_256)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (mac_size < 32) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    // TODO: In a later PR, add logic.

    *mac_length = 32;

    return PSA_SUCCESS;
}

psa_status_t firmware_transparent_aead_encrypt(
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
    if (attributes == NULL || key_buffer == NULL || nonce == NULL ||
        nonce_length < 7 || nonce_length > 13 || plaintext == NULL ||
        plaintext_length <= 0 || ciphertext == NULL ||
        ciphertext_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    const psa_key_type_t key_type = psa_get_key_type(attributes);
    if (key_type != PSA_KEY_TYPE_AES) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    const psa_key_usage_t key_usage = psa_get_key_usage_flags(attributes);
    if ((key_usage & PSA_KEY_USAGE_ENCRYPT) == 0) {
        return PSA_ERROR_NOT_PERMITTED;
    }

    if (key_buffer_size != 32) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (alg != PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, 8)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (ciphertext_size < plaintext_length + 8) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    // TODO: In a later PR, add logic.

    *ciphertext_length = plaintext_length + 8;

    return PSA_SUCCESS;
}

psa_status_t firmware_transparent_aead_decrypt(
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
    if (attributes == NULL || key_buffer == NULL || nonce == NULL ||
        nonce_length < 7 || nonce_length > 13 || ciphertext == NULL ||
        ciphertext_length <= 0 || plaintext == NULL ||
        plaintext_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    const psa_key_type_t key_type = psa_get_key_type(attributes);
    if (key_type != PSA_KEY_TYPE_AES) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    const psa_key_usage_t key_usage = psa_get_key_usage_flags(attributes);
    if ((key_usage & PSA_KEY_USAGE_DECRYPT) == 0) {
        return PSA_ERROR_NOT_PERMITTED;
    }

    if (key_buffer_size != 32) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (alg != PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, 8)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (plaintext_size < ciphertext_length - 8) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    // TODO: In a later PR, add logic.

    *plaintext_length = ciphertext_length - 8;

    return PSA_SUCCESS;
}

psa_status_t firmware_transparent_key_agreement(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *peer_key,
    size_t peer_key_length,
    uint8_t *shared_secret,
    size_t shared_secret_size,
    size_t *shared_secret_length) {
    if (attributes == NULL || key_buffer == NULL || peer_key == NULL ||
        shared_secret == NULL || shared_secret_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    const psa_key_type_t key_type = psa_get_key_type(attributes);
    if (key_type != PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    const psa_key_usage_t key_usage = psa_get_key_usage_flags(attributes);
    if ((key_usage & PSA_KEY_USAGE_DERIVE) == 0) {
        return PSA_ERROR_NOT_PERMITTED;
    }

    if (key_buffer_size != 32 || peer_key_length != 65) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (alg != PSA_ALG_ECDH) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (shared_secret_size < 32) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    // TODO: In a later PR, add logic.

    *shared_secret_length = 32;

    return PSA_SUCCESS;
}
