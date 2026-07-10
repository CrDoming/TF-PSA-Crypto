#include <stdlib.h>
#include <psa/crypto.h>
#include <string.h>

#include "enterprise/enterprise_driver_entrypoints.h"

static uint8_t l_AuditLogKey[] = {
    0x02, 0xde, 0xea, 0x61, 0x87, 0x88, 0x4a, 0xb1, 0xfc, 0xe1, 0x7a,
    0xee, 0xb7, 0x5d, 0xf0, 0x1d, 0xe4, 0x82, 0x16, 0xf6, 0xc4, 0x6f,
    0x7d, 0xc5, 0xa5, 0x49, 0x3a, 0x7b, 0x78, 0xbf, 0x89, 0x40
};

static uint8_t l_MasterDerivationKey[] = {
    0x01, 0xde, 0xea, 0x61, 0x87, 0x88, 0x4a, 0xb1, 0xfc, 0xe1, 0x7a,
    0xee, 0xb7, 0x5d, 0xf0, 0x1d, 0xe4, 0x82, 0x16, 0xf6, 0xc4, 0x6f,
    0x7d, 0xc5, 0xa5, 0x49, 0x3a, 0x7b, 0x78, 0xbf, 0x89, 0x40
};

static uint8_t l_Plaintext[] = "Salutations.";

void CLI_PrintBytes(const uint8_t *pBytes, size_t byteCount);

void CLI_PrintKey(psa_key_id_t keyId);

psa_status_t CLI_CreateHmacKey(
    psa_key_id_t keyId,
    const uint8_t *pKey,
    size_t keyByteCount);

psa_status_t CLI_CreateDerivationKey(
    psa_key_id_t keyId,
    const uint8_t *pKey,
    size_t keyByteCount);

psa_status_t CLI_CreateEccPrivateKey(psa_key_id_t keyId);

psa_status_t CLI_GetPublicKey(
    psa_key_id_t privateKeyId,
    uint8_t *pPublicKey,
    size_t publicKeyByteSize,
    size_t *pPublicKeyWrittenByteCount);

psa_status_t CLI_CreateSharedSecret(
    psa_key_id_t privateKeyId,
    const uint8_t *pPeerPublicKey,
    size_t peerPublicKeyByteCount,
    uint8_t *pSharedSecret,
    size_t sharedSecretByteSize,
    size_t *pSharedSecretWrittenByteCount);

// psa_status_t CLI_CreateSessionKeyAndSalt(
//     psa_key_id_t privateKeyId,
//     const uint8_t *pInputSalt,
//     size_t inputSaltByteCount,
//     const uint8_t *pInfo,
//     size_t infoByteCount,
//     psa_key_id_t sessionKeyId,
//     uint64_t *pOutputSalt);

psa_status_t CLI_CreateSessionKeyAndSalt(
    const uint8_t *pPrivateKey,
    size_t privateKeyByteCount,
    const uint8_t *pInputSalt,
    size_t inputSaltByteCount,
    const uint8_t *pInfo,
    size_t infoByteCount,
    psa_key_id_t sessionKeyId,
    uint64_t *pOutputSalt);

psa_status_t CLI_Sign(
    psa_key_id_t keyId,
    const uint8_t *pInput,
    size_t inputByteCount,
    uint8_t *pMac,
    size_t macByteSize,
    size_t *pMacWrittenByteCount);

psa_status_t CLI_Encrypt(
    psa_key_id_t keyId,
    uint64_t salt,
    uint32_t counter,
    const uint8_t *pPlaintext,
    size_t plaintextByteCount,
    uint8_t *pAuthCiphertext,
    size_t authCiphertextByteSize,
    size_t *pAuthCiphertextWrittenByteCount);

psa_status_t CLI_Decrypt(
    psa_key_id_t keyId,
    uint64_t salt,
    uint32_t counter,
    const uint8_t *pAuthCiphertext,
    size_t authCiphertextByteCount,
    uint8_t *pPlaintext,
    size_t plaintextByteSize,
    size_t *pPlaintextWrittenByteCount);

// TODO: Discard.
static void add(const uint8_t* augend, const uint8_t* addend, uint8_t* sum, size_t byte_count) {
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

int main(int argc, char **argv) {
    // TODO: Discard.
    uint8_t augend[] = {0x00, 0x00, 0xFF, 0xFF};
    uint8_t addend[] = {0x00, 0x00, 0x00, 0x02};
    uint8_t sum[] = {0x00, 0x00, 0x00, 0x00};
    add(augend, addend, sum, sizeof(sum));

    printf("Sum = 0x");
    for (size_t i = 0; i < sizeof(sum); i++) {
        printf("%02x", sum[i]);
    }
    printf("\n");

    int exitCode = 1;
    psa_key_id_t auditLogKeyId = PSA_KEY_ID_USER_MIN + 0;
    psa_key_id_t masterDerivationKeyId = PSA_KEY_ID_USER_MIN + 1;
    psa_key_id_t hostKeyId = PSA_KEY_ID_USER_MIN + 2;
    psa_key_id_t smibKeyId = PSA_KEY_ID_USER_MIN + 3;
    psa_key_id_t sessionKeyId = PSA_KEY_ID_USER_MIN + 4;
    psa_key_id_t keyIds[] = {
        auditLogKeyId,
        masterDerivationKeyId,
        hostKeyId,
        smibKeyId,
        sessionKeyId
    };

    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf(
            "Failed to initialize the PSA Crypto library. Status = %d\n",
            status);
        goto CLEAN_UP;
    }

    status =
            CLI_CreateHmacKey(auditLogKeyId, l_AuditLogKey, sizeof(l_AuditLogKey));
    if (status != PSA_SUCCESS) {
        printf(
            "Failed to create a key with ID %d. Status = %d\n",
            auditLogKeyId,
            status);
        goto CLEAN_UP;
    }

    CLI_PrintKey(auditLogKeyId);

    status = CLI_CreateDerivationKey(
        masterDerivationKeyId,
        l_MasterDerivationKey,
        sizeof(l_MasterDerivationKey));
    if (status != PSA_SUCCESS) {
        printf(
            "Failed to create a key with ID %d. Status = %d\n",
            masterDerivationKeyId,
            status);
        goto CLEAN_UP;
    }

    CLI_PrintKey(masterDerivationKeyId);

    status = CLI_CreateEccPrivateKey(hostKeyId);
    if (status != PSA_SUCCESS) {
        printf(
            "Failed to create a key with ID %d. Status = %d\n",
            hostKeyId,
            status);
        goto CLEAN_UP;
    }

    CLI_PrintKey(hostKeyId);

    status = CLI_CreateEccPrivateKey(smibKeyId);
    if (status != PSA_SUCCESS) {
        printf(
            "Failed to create a key with ID %d. Status = %d\n",
            smibKeyId,
            status);
        goto CLEAN_UP;
    }

    CLI_PrintKey(smibKeyId);

    size_t writtenByteCount = 0;

    uint8_t hostPublicKey[65] = {0};
    status = CLI_GetPublicKey(
        hostKeyId,
        hostPublicKey,
        sizeof(hostPublicKey),
        &writtenByteCount);
    if (status != PSA_SUCCESS) {
        printf(
            "Failed to get the public key for a key with ID %d. Status = %d\n",
            hostKeyId,
            status);
        goto CLEAN_UP;
    }

    // TODO: Discard.
    printf("HOST Public Key = 0x");
    CLI_PrintBytes(hostPublicKey, writtenByteCount);
    uint8_t hostPrivateKey[32] = {0};
    (void)psa_export_key(
        hostKeyId,
        hostPrivateKey,
        sizeof(hostPrivateKey),
        &writtenByteCount);
    uint8_t somePublicKey[65] = {0};
    (void)enterprise_transparent_export_public_key(
        NULL,
        hostPrivateKey,
        sizeof(hostPrivateKey),
        somePublicKey,
        sizeof(somePublicKey),
        &writtenByteCount);
    printf("Some Public Key = 0x");
    CLI_PrintBytes(somePublicKey, writtenByteCount);

    uint8_t smibPublicKey[65] = {0};
    status = CLI_GetPublicKey(
        smibKeyId,
        smibPublicKey,
        sizeof(smibPublicKey),
        &writtenByteCount);
    if (status != PSA_SUCCESS) {
        printf(
            "Failed to get the public key for a key with ID %d. Status = %d\n",
            smibKeyId,
            status);
        goto CLEAN_UP;
    }

    uint8_t hostSharedSecret[32] = {0};
    status = CLI_CreateSharedSecret(
        hostKeyId,
        smibPublicKey,
        sizeof(smibPublicKey),
        hostSharedSecret,
        sizeof(hostSharedSecret),
        &writtenByteCount);
    if (status != PSA_SUCCESS) {
        printf(
            "Failed to create the shared secret for a key with ID %d. Status = "
            "%d\n",
            hostKeyId,
            status);
        goto CLEAN_UP;
    }

    printf("HOST Shared Secret = ");
    CLI_PrintBytes(hostSharedSecret, writtenByteCount);

    uint8_t smibSharedSecret[32] = {0};
    status = CLI_CreateSharedSecret(
        smibKeyId,
        hostPublicKey,
        sizeof(hostPublicKey),
        smibSharedSecret,
        sizeof(smibSharedSecret),
        &writtenByteCount);
    if (status != PSA_SUCCESS) {
        printf(
            "Failed to create the shared secret for a key with ID %d. Status = "
            "%d\n",
            smibKeyId,
            status);
        goto CLEAN_UP;
    }

    printf("SMIB Shared Secret = ");
    CLI_PrintBytes(smibSharedSecret, writtenByteCount);

    if (memcmp(hostSharedSecret, smibSharedSecret, sizeof(hostSharedSecret)) !=
        0) {
        printf("Created 2 shared secrets that do not match.\n");
        goto CLEAN_UP;
    }

    // HOST Session Seed + SMIB Session Seed
    uint8_t sessionInputSalt[16] = {
        0xa1,
        0xa2,
        0xa3,
        0xa4,
        0xa5,
        0xa6,
        0xa7,
        0xa8,
        0xb1,
        0xb2,
        0xb3,
        0xb4,
        0xb5,
        0xb6,
        0xb7,
        0xb8,
    };

    // Session UID + Shared Secret
    uint8_t sessionInfo[35] = {0xc1, 0xc2, 0xc3};
    for (size_t i = 0; i < sizeof(hostSharedSecret); i++) {
        sessionInfo[i + 3] = hostSharedSecret[i];
    }

    uint64_t sessionOutputSalt = 0;
    status = CLI_CreateSessionKeyAndSalt(
        l_MasterDerivationKey,
        sizeof(l_MasterDerivationKey),
        sessionInputSalt,
        sizeof(sessionInputSalt),
        sessionInfo,
        sizeof(sessionInfo),
        sessionKeyId,
        &sessionOutputSalt);
    if (status != PSA_SUCCESS) {
        printf(
            "Failed to create a key with ID %d. Status = %d\n",
            sessionKeyId,
            status);
        goto CLEAN_UP;
    }

    CLI_PrintKey(sessionKeyId);

    uint8_t mac[32] = {0};
    size_t macWrittenByteCount = 0;
    status = CLI_Sign(
        auditLogKeyId,
        l_Plaintext,
        sizeof(l_Plaintext),
        mac,
        sizeof(mac),
        &macWrittenByteCount);
    if (status != PSA_SUCCESS) {
        printf(
            "Failed to sign data with a key with ID %d. Status = %d\n",
            sessionKeyId,
            status);
        goto CLEAN_UP;
    }

    printf("MAC for Plaintext = ");
    CLI_PrintBytes(mac, macWrittenByteCount);

    uint32_t counter = 4;
    uint8_t plaintext[128] = {0};
    uint8_t authCiphertext[128] = {0};

    size_t ciphertextWrittenByteCount = 0;
    status = CLI_Encrypt(
        sessionKeyId,
        sessionOutputSalt,
        counter,
        l_Plaintext,
        sizeof(l_Plaintext),
        authCiphertext,
        sizeof(authCiphertext),
        &ciphertextWrittenByteCount);
    if (status != PSA_SUCCESS) {
        printf(
            "Failed to encrypt data with a key with ID %d. Status = %d\n",
            sessionKeyId,
            status);
        goto CLEAN_UP;
    }

    printf("Ciphertext = ");
    CLI_PrintBytes(authCiphertext, ciphertextWrittenByteCount - 8);
    printf("Auth Tag = ");
    CLI_PrintBytes(authCiphertext + ciphertextWrittenByteCount - 8, 8);

    status = CLI_Decrypt(
        sessionKeyId,
        sessionOutputSalt,
        counter,
        authCiphertext,
        ciphertextWrittenByteCount,
        plaintext,
        sizeof(plaintext),
        &writtenByteCount);
    if (status != PSA_SUCCESS) {
        printf(
            "Failed to decrypt data with a key with ID %d. Status = %d\n",
            sessionKeyId,
            status);
        goto CLEAN_UP;
    }

    printf("Decrypted Plaintext = '");
    for (size_t i = 0; i < writtenByteCount; i++) {
        if (plaintext[i] == 0) {
            continue;
        }

        printf("%c", plaintext[i]);
    }
    printf("'\n");

    exitCode = 0;

CLEAN_UP:
    uint8_t keyIdCount = sizeof(keyIds) / sizeof(keyIds[0]);
    for (uint8_t i = 0; i < keyIdCount; i++) {
        (void) psa_destroy_key(keyIds[i]);
    }

    return exitCode;
}

void CLI_PrintBytes(const uint8_t *pBytes, size_t byteCount) {
    if (pBytes == NULL || byteCount == 0) {
        return;
    }

    printf("0x");
    for (size_t i = 0; i < byteCount; i++) {
        printf("%02x", pBytes[i]);
    }
    printf("\n");
}

void CLI_PrintKey(psa_key_id_t keyId) {
    uint8_t keyBuffer[128] = {0};
    size_t writtenByteCount = 0;
    psa_status_t status =
            psa_export_key(keyId, keyBuffer, sizeof(keyBuffer), &writtenByteCount);
    if (status != PSA_SUCCESS) {
        printf(
            "Failed to print a key with ID %d. Status = %d\n",
            keyId,
            status);
        return;
    }

    printf("Key with ID %d = 0x", keyId);
    for (size_t i = 0; i < writtenByteCount; i++) {
        printf("%02x", keyBuffer[i]);
    }
    printf("\n");
}

psa_status_t CLI_CreateHmacKey(
    psa_key_id_t keyId,
    const uint8_t *pKey,
    size_t keyByteCount) {
    psa_key_attributes_t keyAttributes = psa_key_attributes_init();
    psa_set_key_id(&keyAttributes, keyId);
    psa_set_key_lifetime(&keyAttributes, PSA_KEY_LIFETIME_PERSISTENT);
    psa_set_key_type(&keyAttributes, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&keyAttributes, 256);
    psa_set_key_usage_flags(
        &keyAttributes,
        PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&keyAttributes, PSA_ALG_HMAC(PSA_ALG_SHA_256));

    psa_key_id_t generatedKeyId = 0;
    return psa_import_key(&keyAttributes, pKey, keyByteCount, &generatedKeyId);
}

psa_status_t CLI_CreateDerivationKey(
    psa_key_id_t keyId,
    const uint8_t *pKey,
    size_t keyByteCount) {
    psa_key_attributes_t keyAttributes = psa_key_attributes_init();
    psa_set_key_id(&keyAttributes, keyId);
    psa_set_key_lifetime(&keyAttributes, PSA_KEY_LIFETIME_PERSISTENT);
    psa_set_key_type(&keyAttributes, PSA_KEY_TYPE_DERIVE);
    psa_set_key_bits(&keyAttributes, keyByteCount * 8);
    psa_set_key_usage_flags(
        &keyAttributes,
        PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&keyAttributes, PSA_ALG_HKDF(PSA_ALG_SHA_256));

    psa_key_id_t generatedKeyId = 0;
    return psa_import_key(&keyAttributes, pKey, keyByteCount, &generatedKeyId);
}

psa_status_t CLI_CreateEccPrivateKey(psa_key_id_t keyId) {
    psa_key_attributes_t keyAttributes = psa_key_attributes_init();
    psa_set_key_id(&keyAttributes, keyId);
    psa_set_key_lifetime(&keyAttributes, PSA_KEY_LIFETIME_PERSISTENT);
    psa_set_key_type(
        &keyAttributes,
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&keyAttributes, 256);
    psa_set_key_usage_flags(
        &keyAttributes,
        PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&keyAttributes, PSA_ALG_ECDH);

    psa_key_id_t generatedKeyId = 0;
    return psa_generate_key(&keyAttributes, &generatedKeyId);
}

psa_status_t CLI_GetPublicKey(
    psa_key_id_t privateKeyId,
    uint8_t *pPublicKey,
    size_t publicKeyByteSize,
    size_t *pPublicKeyWrittenByteCount) {
    if (pPublicKey == NULL || pPublicKeyWrittenByteCount == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    return psa_export_public_key(
        privateKeyId,
        pPublicKey,
        publicKeyByteSize,
        pPublicKeyWrittenByteCount);
}

psa_status_t CLI_CreateSharedSecret(
    psa_key_id_t privateKeyId,
    const uint8_t *pPeerPublicKey,
    size_t peerPublicKeyByteCount,
    uint8_t *pSharedSecret,
    size_t sharedSecretByteSize,
    size_t *pSharedSecretWrittenByteCount) {
    if (pPeerPublicKey == NULL || pSharedSecret == NULL ||
        pSharedSecretWrittenByteCount == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    return psa_raw_key_agreement(
        PSA_ALG_ECDH,
        privateKeyId,
        pPeerPublicKey,
        peerPublicKeyByteCount,
        pSharedSecret,
        sharedSecretByteSize,
        pSharedSecretWrittenByteCount);
}

// psa_status_t CLI_CreateSessionKeyAndSalt(psa_key_id_t privateKeyId,
//                                          const uint8_t* pInputSalt,
//                                          size_t inputSaltByteCount,
//                                          const uint8_t* pInfo,
//                                          size_t infoByteCount,
//                                          psa_key_id_t sessionKeyId,
//                                          uint64_t* pOutputSalt) {
//     if (pInputSalt == NULL || pInfo == NULL || pOutputSalt == NULL) {
//         return PSA_ERROR_INVALID_ARGUMENT;
//     }
//
//     psa_status_t status = PSA_ERROR_GENERIC_ERROR;
//     psa_key_derivation_operation_t operation =
//         psa_key_derivation_operation_init();
//
//     status =
//         psa_key_derivation_setup(&operation, PSA_ALG_HKDF(PSA_ALG_SHA_256));
//     if (status != PSA_SUCCESS) {
//         printf("Failed to set up a key derivation operation. Status = %d\n",
//                status);
//         goto CLEAN_UP;
//     }
//
//     status = psa_key_derivation_input_bytes(&operation,
//                                             PSA_KEY_DERIVATION_INPUT_SALT,
//                                             pInputSalt,
//                                             inputSaltByteCount);
//     if (status != PSA_SUCCESS) {
//         printf(
//             "Failed to input the salt into the key derivation operation. "
//             "Status = "
//             "%d\n",
//             status);
//         goto CLEAN_UP;
//     }
//
//     status = psa_key_derivation_input_key(
//         &operation, PSA_KEY_DERIVATION_INPUT_SECRET, privateKeyId);
//     if (status != PSA_SUCCESS) {
//         printf(
//             "Failed to input the private key into the key derivation "
//             "operation. "
//             "Status = %d\n",
//             status);
//         goto CLEAN_UP;
//     }
//
//     status = psa_key_derivation_input_bytes(
//         &operation, PSA_KEY_DERIVATION_INPUT_INFO, pInfo, infoByteCount);
//     if (status != PSA_SUCCESS) {
//         printf(
//             "Failed to input the info into the key derivation operation. "
//             "Status = "
//             "%d\n",
//             status);
//         goto CLEAN_UP;
//     }
//
//     uint8_t sessionPrivateKey[32] = {0};
//     status = psa_key_derivation_output_bytes(
//         &operation, sessionPrivateKey, sizeof(sessionPrivateKey));
//     if (status != PSA_SUCCESS) {
//         printf(
//             "Failed to output a session private key from the key derivation "
//             "operation. Status = %d\n",
//             status);
//         goto CLEAN_UP;
//     }
//
//     uint8_t outputSalt[8] = {0};
//     status = psa_key_derivation_output_bytes(
//         &operation, outputSalt, sizeof(outputSalt));
//     if (status != PSA_SUCCESS) {
//         printf(
//             "Failed to output a session salt from the key derivation "
//             "operation. "
//             "Status = %d\n",
//             status);
//         goto CLEAN_UP;
//     }
//
//     psa_key_attributes_t sessionKeyAttributes = psa_key_attributes_init();
//     psa_set_key_id(&sessionKeyAttributes, sessionKeyId);
//     psa_set_key_lifetime(&sessionKeyAttributes, PSA_KEY_LIFETIME_PERSISTENT);
//     psa_set_key_type(&sessionKeyAttributes, PSA_KEY_TYPE_AES);
//     psa_set_key_bits(&sessionKeyAttributes, 256);
//     psa_set_key_usage_flags(
//         &sessionKeyAttributes,
//         PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
//     psa_set_key_algorithm(&sessionKeyAttributes,
//                           PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, 8));
//
//     psa_key_id_t generatedKeyId = 0;
//     status = psa_import_key(&sessionKeyAttributes,
//                             sessionPrivateKey,
//                             sizeof(sessionPrivateKey),
//                             &generatedKeyId);
//     if (status != PSA_SUCCESS) {
//         printf("Failed to create a session key via import. Status = %d\n",
//                status);
//         goto CLEAN_UP;
//     }
//
//     (void)memcpy_s(
//         pOutputSalt, sizeof(uint64_t), outputSalt, sizeof(outputSalt));
//
// CLEAN_UP:
//     (void)psa_key_derivation_abort(&operation);
//     return status;
// }

psa_status_t CLI_CreateSessionKeyAndSalt(
    const uint8_t *pPrivateKey,
    size_t privateKeyByteCount,
    const uint8_t *pInputSalt,
    size_t inputSaltByteCount,
    const uint8_t *pInfo,
    size_t infoByteCount,
    psa_key_id_t sessionKeyId,
    uint64_t *pOutputSalt) {
    if (pOutputSalt == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    psa_key_id_t generatedKeyId = 0;
    uint8_t *payload = malloc(32 + infoByteCount + 1);
    if (payload == NULL) {
        status = PSA_ERROR_GENERIC_ERROR;
        goto CLEAN_UP;
    }

    // ================
    // Extract Phase
    // ================

    psa_key_attributes_t keyAttributes = psa_key_attributes_init();
    psa_set_key_type(&keyAttributes, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&keyAttributes, inputSaltByteCount * 8);
    psa_set_key_usage_flags(
        &keyAttributes,
        PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&keyAttributes, PSA_ALG_HMAC(PSA_ALG_SHA_256));

    status = psa_import_key(&keyAttributes, pInputSalt, inputSaltByteCount, &generatedKeyId);
    if (status != PSA_SUCCESS) {
        printf(
            "Failed to create a key based on the input salt for the extract phrase. Status = %d",
            status);
        goto CLEAN_UP;
    }

    uint8_t prk[32] = {0};
    size_t writtenByteCount = 0;
    status = psa_mac_compute(
        generatedKeyId,
        PSA_ALG_HMAC(PSA_ALG_SHA_256),
        pPrivateKey,
        privateKeyByteCount,
        prk,
        sizeof(prk),
        &writtenByteCount);
    if (status != PSA_SUCCESS) {
        printf(
            "Failed to compute a MAC for the extract phrase. Status = %d",
            status);
        goto CLEAN_UP;
    }

    // ================
    // Expand Phase
    // ================

    (void) psa_destroy_key(generatedKeyId);

    keyAttributes = psa_key_attributes_init();
    psa_set_key_type(&keyAttributes, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&keyAttributes, sizeof(prk) * 8);
    psa_set_key_usage_flags(
        &keyAttributes,
        PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&keyAttributes, PSA_ALG_HMAC(PSA_ALG_SHA_256));

    status = psa_import_key(&keyAttributes, prk, sizeof(prk), &generatedKeyId);
    if (status != PSA_SUCCESS) {
        printf(
            "Failed to create a key based on the PRK for the expand phrase. Status = %d",
            status);
        goto CLEAN_UP;
    }

    uint8_t okm[40] = {0};
    size_t okmByteCount = 0;
    uint8_t t[32] = {0};
    uint8_t counter = 0;
    writtenByteCount = 0;

    while (okmByteCount < sizeof(okm)) {
        size_t payloadByteCount = 0;

        if (counter > 1) {
            memcpy(payload, t, 32);
            payloadByteCount += 32;
        }

        if (pInfo != NULL && infoByteCount > 0) {
            memcpy(payload + payloadByteCount, pInfo, infoByteCount);
            payloadByteCount += infoByteCount;
        }

        payload[payloadByteCount] = counter;
        payloadByteCount += 1;

        status = psa_mac_compute(
            generatedKeyId,
            PSA_ALG_HMAC(PSA_ALG_SHA_256),
            payload,
            payloadByteCount,
            t,
            sizeof(t),
            &writtenByteCount);
        if (status != PSA_SUCCESS) {
            printf(
                "Failed to compute a MAC for the expand phrase. Status = %d",
                status);
            goto CLEAN_UP;
        }

        size_t transferableByteCount = sizeof(okm) - writtenByteCount;
        if (transferableByteCount > 32) {
            transferableByteCount = 32;
        }

        memcpy(okm + okmByteCount, t, transferableByteCount);
        okmByteCount += transferableByteCount;
        counter++;
    }

    (void) psa_destroy_key(generatedKeyId);

    psa_key_attributes_t sessionKeyAttributes = psa_key_attributes_init();
    psa_set_key_id(&sessionKeyAttributes, sessionKeyId);
    psa_set_key_lifetime(&sessionKeyAttributes, PSA_KEY_LIFETIME_PERSISTENT);
    psa_set_key_type(&sessionKeyAttributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&sessionKeyAttributes, 256);
    psa_set_key_usage_flags(
        &sessionKeyAttributes,
        PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(
        &sessionKeyAttributes,
        PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, 8));

    status = psa_import_key(
        &sessionKeyAttributes,
        okm,
        32,
        &generatedKeyId);
    if (status != PSA_SUCCESS) {
        printf(
            "Failed to create a session key from the OKM. Status = %d\n",
            status);
        goto CLEAN_UP;
    }

    generatedKeyId = 0;

    (void) memcpy_s(
        pOutputSalt,
        sizeof(uint64_t),
        okm + 32,
        8);

CLEAN_UP:
    (void) psa_destroy_key(generatedKeyId);
    if (payload != NULL) {
        free(payload);
    }

    return status;
}

psa_status_t CLI_Sign(
    psa_key_id_t keyId,
    const uint8_t *pInput,
    size_t inputByteCount,
    uint8_t *pMac,
    size_t macByteSize,
    size_t *pMacWrittenByteCount) {
    if (pInput == NULL || pMac == NULL || pMacWrittenByteCount == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    return psa_mac_compute(
        keyId,
        PSA_ALG_HMAC(PSA_ALG_SHA_256),
        pInput,
        inputByteCount,
        pMac,
        macByteSize,
        pMacWrittenByteCount);
}

psa_status_t CLI_Encrypt(
    psa_key_id_t keyId,
    uint64_t salt,
    uint32_t counter,
    const uint8_t *pPlaintext,
    size_t plaintextByteCount,
    uint8_t *pAuthCiphertext,
    size_t authCiphertextByteSize,
    size_t *pAuthCiphertextWrittenByteCount) {
    if (pPlaintext == NULL || pAuthCiphertext == NULL ||
        pAuthCiphertextWrittenByteCount == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    uint8_t nonce[12] = {0};
    nonce[0] = (uint8_t) (salt << 56);
    nonce[1] = (uint8_t) (salt << 48);
    nonce[2] = (uint8_t) (salt << 40);
    nonce[3] = (uint8_t) (salt << 32);
    nonce[4] = (uint8_t) (salt << 24);
    nonce[5] = (uint8_t) (salt << 16);
    nonce[6] = (uint8_t) (salt << 8);
    nonce[7] = (uint8_t) (salt);
    nonce[8] = (uint8_t) (counter << 24);
    nonce[9] = (uint8_t) (counter << 16);
    nonce[10] = (uint8_t) (counter << 8);
    nonce[11] = (uint8_t) counter;
    return psa_aead_encrypt(
        keyId,
        PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, 8),
        nonce,
        sizeof(nonce),
        NULL,
        0,
        pPlaintext,
        plaintextByteCount,
        pAuthCiphertext,
        authCiphertextByteSize,
        pAuthCiphertextWrittenByteCount);
}

psa_status_t CLI_Decrypt(
    psa_key_id_t keyId,
    uint64_t salt,
    uint32_t counter,
    const uint8_t *pAuthCiphertext,
    size_t authCiphertextByteCount,
    uint8_t *pPlaintext,
    size_t plaintextByteSize,
    size_t *pPlaintextWrittenByteCount) {
    if (pAuthCiphertext == NULL || pPlaintext == NULL ||
        pPlaintextWrittenByteCount == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    uint8_t nonce[12] = {0};
    nonce[0] = (uint8_t) (salt << 56);
    nonce[1] = (uint8_t) (salt << 48);
    nonce[2] = (uint8_t) (salt << 40);
    nonce[3] = (uint8_t) (salt << 32);
    nonce[4] = (uint8_t) (salt << 24);
    nonce[5] = (uint8_t) (salt << 16);
    nonce[6] = (uint8_t) (salt << 8);
    nonce[7] = (uint8_t) (salt);
    nonce[8] = (uint8_t) (counter << 24);
    nonce[9] = (uint8_t) (counter << 16);
    nonce[10] = (uint8_t) (counter << 8);
    nonce[11] = (uint8_t) counter;
    return psa_aead_decrypt(
        keyId,
        PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, 8),
        nonce,
        sizeof(nonce),
        NULL,
        0,
        pAuthCiphertext,
        authCiphertextByteCount,
        pPlaintext,
        plaintextByteSize,
        pPlaintextWrittenByteCount);
}
