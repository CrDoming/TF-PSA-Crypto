#ifndef FIRMWARE_DRIVER_ENTRYPOINTS_H
#define FIRMWARE_DRIVER_ENTRYPOINTS_H
#include "psa/crypto.h"

#ifdef FIRMWARE_DRIVER_ENABLED
#ifndef PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT
#define PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT
#endif  // PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT
#endif  // FIRMWARE_DRIVER_ENABLED

#include "psa/crypto_types.h"

/**
 * @brief Generates a key.
 * @param[in] attributes The attributes for the new key.
 * @param[out] key_buffer The buffer to receive the new key material.
 * @param[in] key_buffer_size The size of @code key_buffer@endcode in bytes.
 * @param[out] key_buffer_length The count of bytes written to @code key_buffer@endcode.
 * @return PSA_SUCCESS on success; otherwise, a different value.
 */
psa_status_t firmware_transparent_generate_key(
    const psa_key_attributes_t *attributes,
    uint8_t *key_buffer,
    size_t key_buffer_size,
    size_t *key_buffer_length);

/**
 * @brief Imports a key in binary format.
 * @param[in] attributes The attributes for the new key.
 * @param[in] data The buffer containing the key data.
 * @param[in] data_length The count of bytes to read from @code data@endcode.
 * @param[out] key_buffer The buffer to receive the new key material.
 * @param[in] key_buffer_size The size of @code key_buffer@endcode in bytes.
 * @param[out] key_buffer_length The count of bytes written to @code key_buffer@endcode.
 * @param[in,out] bits The expected size of the new key in bits. If set to 0,
 * then this function will set it to another value.
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
 * @param[in] attributes The attributes of the key to export.
 * @param[in] key_buffer The buffer containing the key material.
 * @param[in] key_buffer_size The size of @code key_buffer@endcode in bytes.
 * @param[out] data The buffer to receive the key data.
 * @param[in] data_size The size of @code data@endcode in bytes.
 * @param[out] data_length The count of bytes written to @code data@endcode.
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
 * @brief Encrypts a message using a symmetric cipher.
 * @param attributes[in] The attributes of the key to use.
 * @param key_buffer[in] The buffer containing the key material.
 * @param key_buffer_size[in] The size of @code key_buffer@endcode in bytes.
 * @param alg[in] The algorithm to use.
 * @param iv[in] The buffer containing the IV.
 * @param iv_length[in] The count of bytes to read from @code iv@endcode.
 * @param input[in] The buffer containing the plaintext.
 * @param input_length[in] The count of bytes to read from @code input@endcode.
 * @param output[out] The buffer to receive the ciphertext.
 * @param output_size[in] The size of @code output@endcode in bytes.
 * @param output_length[out] The count of bytes written to @code output@endcode.
 * @return PSA_SUCCESS on success; otherwise, a different value.
 */
psa_status_t firmware_transparent_cipher_encrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *iv,
    size_t iv_length,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length);

/**
 * @brief Sets up a multipart hash operation.
 * @param operation[in] The hash operation to set up.
 * @param alg[in] The hash algorithm to use.
 * @return PSA_SUCCESS on success; otherwise, a different value.
 */
psa_status_t firmware_transparent_hash_setup(
    psa_hash_operation_t *operation,
    psa_algorithm_t alg);

/**
 * @brief Updates a multipart hash operation with a message fragment.
 * @param operation[in] The active hash operation.
 * @param input[in] The buffer containing the message fragment.
 * @param input_length[in] The count of bytes to read from @code input@endcode.
 * @return PSA_SUCCESS on success; otherwise, a different value.
 */
psa_status_t firmware_transparent_hash_update(
    psa_hash_operation_t *operation,
    const uint8_t *input,
    size_t input_length);

/**
 * @brief Finishes the calculation of a hash.
 * @param operation[in] The active hash operation.
 * @param hash[out] The buffer to receive the hash.
 * @param hash_size[in] The size of @code hash@endcode in bytes.
 * @param hash_length[out] The count of bytes written to @code hash@endcode.
 * @return PSA_SUCCESS on success; otherwise, a different value.
 */
psa_status_t firmware_transparent_hash_finish(
    psa_hash_operation_t *operation,
    uint8_t *hash,
    size_t hash_size,
    size_t *hash_length);

/**
 * @brief Performs a key agreement operation to derive a shared secret.
 * @param[in] attributes The attributes of the key to use.
 * @param[in] key_buffer The buffer containing the key material.
 * @param[in] key_buffer_size The size of @code key_buffer@endcode in bytes.
 * @param[in] alg The algorithm to use.
 * @param[in] peer_key The buffer containing the public key data.
 * @param[in] peer_key_length The count of bytes written to @code peer_key@endcode.
 * @param[out] shared_secret The buffer to receive the shared secret.
 * @param[in] shared_secret_size The size of @code shared_secret@endcode in bytes.
 * @param[out] shared_secret_length The count of bytes written to @code shared_secret@endcode.
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

#endif  // FIRMWARE_DRIVER_ENTRYPOINTS_H
