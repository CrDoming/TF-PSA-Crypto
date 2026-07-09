#ifndef ENTERPRISE_DRIVER_ENTRYPOINTS_H
#define ENTERPRISE_DRIVER_ENTRYPOINTS_H

#ifdef ENTERPRISE_DRIVER_ENABLED
#ifndef PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT
#define PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT
#endif /* PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT */
#endif /* ENTERPRISE_DRIVER_ENABLED */

#include "psa/crypto_types.h"

psa_status_t enterprise_transparent_generate_key(
    const psa_key_attributes_t* attributes,
    uint8_t* key_buffer,
    size_t key_buffer_size,
    size_t* key_buffer_length);

psa_status_t enterprise_transparent_import_key(
    const psa_key_attributes_t* attributes,
    const uint8_t* data,
    size_t data_length,
    uint8_t* key_buffer,
    size_t key_buffer_size,
    size_t* key_buffer_length,
    size_t* bits);

psa_status_t enterprise_transparent_export_public_key(
    const psa_key_attributes_t* attributes,
    const uint8_t* key_buffer,
    size_t key_buffer_size,
    uint8_t* data,
    size_t data_size,
    size_t* data_length);

psa_status_t enterprise_transparent_mac_compute(
    const psa_key_attributes_t* attributes,
    const uint8_t* key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t* input,
    size_t input_length,
    uint8_t* mac,
    size_t mac_size,
    size_t* mac_length);

psa_status_t enterprise_transparent_aead_encrypt(
    const psa_key_attributes_t* attributes,
    const uint8_t* key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t* nonce,
    size_t nonce_length,
    const uint8_t* additional_data,
    size_t additional_data_length,
    const uint8_t* plaintext,
    size_t plaintext_length,
    uint8_t* ciphertext,
    size_t ciphertext_size,
    size_t* ciphertext_length);

psa_status_t enterprise_transparent_aead_decrypt(
    const psa_key_attributes_t* attributes,
    const uint8_t* key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t* nonce,
    size_t nonce_length,
    const uint8_t* additional_data,
    size_t additional_data_length,
    const uint8_t* ciphertext,
    size_t ciphertext_length,
    uint8_t* plaintext,
    size_t plaintext_size,
    size_t* plaintext_length);

psa_status_t enterprise_transparent_key_agreement(
    const psa_key_attributes_t* attributes,
    const uint8_t* key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t* peer_key,
    size_t peer_key_length,
    uint8_t* shared_secret,
    size_t shared_secret_size,
    size_t* shared_secret_length);

#endif /* ENTERPRISE_DRIVER_ENTRYPOINTS_H */
