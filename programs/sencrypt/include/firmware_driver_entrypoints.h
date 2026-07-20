#ifndef FIRMWARE_DRIVER_ENTRYPOINTS_H
#define FIRMWARE_DRIVER_ENTRYPOINTS_H

#ifdef FIRMWARE_DRIVER_ENABLED
#ifndef PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT
#define PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT
#endif // PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT
#endif // FIRMWARE_DRIVER_ENABLED

#include "psa/crypto_types.h"

/**
 * @brief Generates a key.
 * @param attributes The attributes for the new key.
 * @param key_buffer The buffer to receive the new key material.
 * @param key_buffer_size The size of @code key_buffer@endcode in bytes.
 * @param key_buffer_length The count of bytes written to @code key_buffer@endcode.
 * @return PSA_SUCCESS on success; otherwise, a different value.
 */
psa_status_t firmware_transparent_generate_key(
    const psa_key_attributes_t *attributes,
    uint8_t *key_buffer,
    size_t key_buffer_size,
    size_t *key_buffer_length);

/**
 * @brief Imports a key in binary format.
 * @param attributes The attributes for the new key.
 * @param data The buffer containing the key data.
 * @param data_length The count of bytes to read from @code data@endcode.
 * @param key_buffer The buffer to receive the new key material.
 * @param key_buffer_size The size of @code key_buffer@endcode in bytes.
 * @param key_buffer_length The count of bytes written to @code key_buffer@endcode.
 * @param bits The expected size of the new key in bits. If set to 0, then this function will set it to another value.
 * @return PSA_SUCCESS on success; otherwise, a different value.
 */
psa_status_t firmware_transparent_import_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *data,
    size_t data_length,
    uint8_t *key_buffer,
    size_t key_buffer_size,
    size_t *key_buffer_length,
    size_t *bits);

/**
 * @brief Exports a public key in binary format.
 * @param attributes The attributes of the key to export.
 * @param key_buffer The buffer containing the key material.
 * @param key_buffer_size The size of @code key_buffer@endcode in bytes.
 * @param data The buffer to receive the key data.
 * @param data_size The size of the @code data@endcode in bytes.
 * @param data_length The count of bytes written to @code data@endcode.
 * @return PSA_SUCCESS on success; otherwise, a different value.
 */
psa_status_t firmware_transparent_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    uint8_t *data,
    size_t data_size,
    size_t *data_length);

/**
 * @brief Computes the message authentication code (MAC) of a message.
 * @param attributes The attributes of the key to use.
 * @param key_buffer The buffer containing the key material.
 * @param key_buffer_size The size of @code key_buffer@endcode in bytes.
 * @param alg The MAC algorithm to use.
 * @param input The input message.
 * @param input_length The count of bytes to read from @code input@endcode.
 * @param mac The buffer to receive the MAC.
 * @param mac_size The size of @code mac@endcode in bytes.
 * @param mac_length The count of bytes written to @code mac@endcode.
 * @return PSA_SUCCESS on success; otherwise, a different value.
 */
psa_status_t firmware_transparent_mac_compute(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *mac,
    size_t mac_size,
    size_t *mac_length);

/**
 * @brief Encrypts a message via authenticated encryption with associated data (AEAD).
 * @param attributes The attributes of the key to use.
 * @param key_buffer The buffer containing the key material.
 * @param key_buffer_size The size of @code key_buffer@endcode in bytes.
 * @param alg The MAC algorithm to use.
 * @param nonce The nonce.
 * @param nonce_length The count of bytes to read from @code nonce@endcode.
 * @param additional_data The additional data that will be authenticated, but not encrypted.
 * @param additional_data_length The count of bytes to read from @code additional_data@endcode.
 * @param plaintext The data that will be authenticated and encrypted.
 * @param plaintext_length The count of bytes to read from @code plaintext@endcode.
 * @param ciphertext The buffer to receive the authenticated and encrypted data.
 * @param ciphertext_size The size of @code ciphertext@endcode in bytes.
 * @param ciphertext_length The count of bytes written to @code ciphertext@endcode.
 * @return PSA_SUCCESS on success; otherwise, a different value.
 */
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
    size_t *ciphertext_length);

/**
 * @brief Decrypts a message via authenticated encryption with associated data (AEAD).
 * @param attributes The attributes of the key to use.
 * @param key_buffer The buffer containing the key material.
 * @param key_buffer_size The size of @code key_buffer@endcode in bytes.
 * @param alg The MAC algorithm to use.
 * @param nonce The nonce.
 * @param nonce_length The count of bytes to read from @code nonce@endcode.
 * @param additional_data The additional data that will be authenticated, but not encrypted.
 * @param additional_data_length The count of bytes to read from @code additional_data@endcode.
 * @param ciphertext The data that has been authenticated and encrypted.
 * @param ciphertext_length The count of bytes to read from @code ciphertext@endcode.
 * @param plaintext The buffer to receive the decrypted data.
 * @param plaintext_size The size of @code plaintext@endcode in bytes.
 * @param plaintext_length The count of bytes written to @code plaintext@endcode.
 * @return PSA_SUCCESS on success; otherwise, a different value.
 */
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
    size_t *plaintext_length);

/**
 * @brief Performs a key agreement operation to derive a shared secret.
 * @param attributes The attributes of the key to use.
 * @param key_buffer The buffer containing the key material.
 * @param key_buffer_size The size of @code key_buffer@endcode in bytes.
 * @param alg The MAC algorithm to use.
 * @param peer_key The buffer containing the public key data.
 * @param peer_key_length The count of bytes written to @code peer_key@endcode.
 * @param shared_secret The buffer to receive the shared secret.
 * @param shared_secret_size The size of @code shared_secret@endcode in bytes.
 * @param shared_secret_length The count of bytes written to @code shared_secret@endcode.
 * @return PSA_SUCCESS on success; otherwise, a different value.
 */
psa_status_t firmware_transparent_key_agreement(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *peer_key,
    size_t peer_key_length,
    uint8_t *shared_secret,
    size_t shared_secret_size,
    size_t *shared_secret_length);

#endif // FIRMWARE_DRIVER_ENTRYPOINTS_H
