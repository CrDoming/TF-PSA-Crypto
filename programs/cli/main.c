#include <psa/crypto.h>
#include <string.h>

static uint8_t l_Plaintext[] = "Salutations.";

void CLI_PrintBytes(const uint8_t *pBytes, size_t byteCount);

void CLI_PrintKey(psa_key_id_t keyId);

psa_status_t CLI_CreatePrivateKey(psa_key_id_t keyId, uint8_t *pPrivateKey, size_t privateKeyByteCount);

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

psa_status_t CLI_CreateSessionKeyAndSalt(
        psa_key_id_t privateKeyId,
        const uint8_t *pInputSalt,
        size_t inputSaltByteCount,
        const uint8_t *pInfo,
        size_t infoByteCount,
        psa_key_id_t sessionKeyId,
        uint64_t *pOutputSalt);

psa_status_t CLI_Encrypt(
        psa_key_id_t keyId,
        uint64_t salt,
        uint32_t counter,
        const uint8_t *pPlaintext,
        size_t plaintextByteCount,
        uint8_t *pCiphertext,
        size_t ciphertextByteSize,
        size_t *pCiphertextWrittenByteCount,
        uint8_t *pMac,
        size_t macByteSize,
        size_t *pMacWrittenByteCount);

psa_status_t CLI_Decrypt(
        psa_key_id_t keyId,
        uint64_t salt,
        uint32_t counter,
        const uint8_t *pCiphertext,
        size_t ciphertextByteCount,
        const uint8_t *pMac,
        size_t macByteCount,
        uint8_t *pPlaintext,
        size_t plaintextByteSize,
        size_t *pPlaintextWrittenByteCount);

int main(int argc, char **argv) {
    int exitCode = 1;
    psa_key_id_t masterKeyId = PSA_KEY_ID_USER_MIN + 0;
    psa_key_id_t hostKeyId = PSA_KEY_ID_USER_MIN + 1;
    psa_key_id_t smibKeyId = PSA_KEY_ID_USER_MIN + 2;
    psa_key_id_t sessionKeyId = PSA_KEY_ID_USER_MIN + 3;
    psa_key_id_t sourceKeyIds[3] = {masterKeyId, hostKeyId, smibKeyId};
    uint8_t sourceKeyIdCount = sizeof(sourceKeyIds) / sizeof(sourceKeyIds[0]);
    psa_key_id_t derivedKeyIds[1] = {sessionKeyId};
    uint8_t derivedKeyIdCount = sizeof(derivedKeyIds) / sizeof(derivedKeyIds[0]);

    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("Failed to initialize the PSA Crypto library. Status = %d\n", status);
        goto CLEAN_UP;
    }

    uint8_t masterPrivateKey[32] = {0};
    status = psa_generate_random(masterPrivateKey, sizeof(masterPrivateKey));
    if (status != PSA_SUCCESS) {
        printf("Failed to generate a random private key. Status = %d\n", status);
        goto CLEAN_UP;
    }

    status = CLI_CreatePrivateKey(masterKeyId, masterPrivateKey, sizeof(masterPrivateKey));
    if (status != PSA_SUCCESS) {
        printf("Failed to create a random private key with ID %d. Status = %d\n", masterKeyId, status);
        goto CLEAN_UP;
    }

    CLI_PrintKey(masterKeyId);

    status = CLI_CreateEccPrivateKey(hostKeyId);
    if (status != PSA_SUCCESS) {
        printf("Failed to create an ECC private key with ID %d. Status = %d\n", hostKeyId, status);
        goto CLEAN_UP;
    }

    CLI_PrintKey(hostKeyId);

    status = CLI_CreateEccPrivateKey(smibKeyId);
    if (status != PSA_SUCCESS) {
        printf("Failed to create an ECC private key with ID %d. Status = %d\n", smibKeyId, status);
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
                "Failed to create the shared secret for a key with ID %d. Status = %d\n",
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
                "Failed to create the shared secret for a key with ID %d. Status = %d\n",
                smibKeyId,
                status);
        goto CLEAN_UP;
    }

    printf("SMIB Shared Secret = ");
    CLI_PrintBytes(smibSharedSecret, writtenByteCount);

    if (memcmp(hostSharedSecret, smibSharedSecret, sizeof(hostSharedSecret)) != 0) {
        printf("Created 2 shared secrets that do not match.\n");
        goto CLEAN_UP;
    }

    uint8_t sessionInputSalt[16] = {
            // HOST Session Seed
            0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
            // SMIB Session Seed
            0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
    };

    uint8_t sessionInfo[35] = {
            // Session UID
            0xc1, 0xc2, 0xc3
    };
    for (size_t i = 0; i < sizeof(hostSharedSecret); i++) {
        sessionInfo[i + 3] = hostSharedSecret[i];
    }

    uint64_t sessionOutputSalt = 0;
    status = CLI_CreateSessionKeyAndSalt(
            masterKeyId,
            sessionInputSalt,
            sizeof(sessionInputSalt),
            sessionInfo,
            sizeof(sessionInfo),
            sessionKeyId,
            &sessionOutputSalt);
    if (status != PSA_SUCCESS) {
        printf("Failed to create a key with ID %d. Status = %d\n", sessionKeyId, status);
        goto CLEAN_UP;
    }

    CLI_PrintKey(sessionKeyId);

    uint32_t counter = 4;
    uint8_t plaintext[128] = {0};
    uint8_t ciphertext[128] = {0};
    uint8_t mac[8] = {0};

    size_t ciphertextWrittenByteCount = 0;
    size_t macWrittenByteCount = 0;
    status = CLI_Encrypt(
            sessionKeyId,
            sessionOutputSalt,
            counter,
            l_Plaintext,
            sizeof(l_Plaintext),
            ciphertext,
            sizeof(ciphertext),
            &ciphertextWrittenByteCount,
            mac,
            sizeof(mac),
            &macWrittenByteCount);
    if (status != PSA_SUCCESS) {
        printf("Failed to encrypt data with a key with ID %d. Status = %d\n", sessionKeyId, status);
        goto CLEAN_UP;
    }

    status = CLI_Decrypt(
            sessionKeyId,
            sessionOutputSalt,
            counter,
            ciphertext,
            ciphertextWrittenByteCount,
            mac,
            macWrittenByteCount,
            plaintext,
            sizeof(plaintext),
            &writtenByteCount);
    if (status != PSA_SUCCESS) {
        printf("Failed to decrypt data with a key with ID %d. Status = %d\n", sessionKeyId, status);
        goto CLEAN_UP;
    }

    printf("Plaintext Decrypted = '");
    for (size_t i = 0; i < writtenByteCount; i++) {
        if (plaintext[i] == 0) {
            continue;
        }

        printf("%c", plaintext[i]);
    }
    printf("'\n");

    exitCode = 0;

    CLEAN_UP:
    for (uint8_t i = 0; i < sourceKeyIdCount; i++) {
        (void) psa_destroy_key(sourceKeyIds[i]);
    }

    for (uint8_t i = 0; i < derivedKeyIdCount; i++) {
        (void) psa_destroy_key(derivedKeyIds[i]);
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
    psa_status_t status = psa_export_key(
            keyId,
            keyBuffer,
            sizeof(keyBuffer),
            &writtenByteCount);
    if (status != PSA_SUCCESS) {
        printf("Failed to print a key with ID %d. Status = %d\n", keyId, status);
        return;
    }

    printf("Key with ID %d = 0x", keyId);
    for (size_t i = 0; i < writtenByteCount; i++) {
        printf("%02x", keyBuffer[i]);
    }
    printf("\n");
}

psa_status_t CLI_CreatePrivateKey(psa_key_id_t keyId, uint8_t *pPrivateKey, size_t privateKeyByteCount) {
    psa_key_attributes_t keyAttributes = psa_key_attributes_init();
    psa_set_key_id(&keyAttributes, keyId);
    psa_set_key_lifetime(&keyAttributes, PSA_KEY_LIFETIME_PERSISTENT);
    psa_set_key_type(&keyAttributes, PSA_KEY_TYPE_DERIVE);
    psa_set_key_bits(&keyAttributes, privateKeyByteCount * 8);
    psa_set_key_usage_flags(&keyAttributes, PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&keyAttributes, PSA_ALG_HKDF(PSA_ALG_SHA_256));

    psa_key_id_t generatedKeyId = 0;
    return psa_import_key(&keyAttributes, pPrivateKey, privateKeyByteCount, &generatedKeyId);
}

psa_status_t CLI_CreateEccPrivateKey(psa_key_id_t keyId) {
    psa_key_attributes_t keyAttributes = psa_key_attributes_init();
    psa_set_key_id(&keyAttributes, keyId);
    psa_set_key_lifetime(&keyAttributes, PSA_KEY_LIFETIME_PERSISTENT);
    psa_set_key_type(&keyAttributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&keyAttributes, 256);
    psa_set_key_usage_flags(&keyAttributes, PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_DERIVE);
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
    if (pPeerPublicKey == NULL || pSharedSecret == NULL || pSharedSecretWrittenByteCount == NULL) {
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

psa_status_t CLI_CreateSessionKeyAndSalt(
        psa_key_id_t privateKeyId,
        const uint8_t *pInputSalt,
        size_t inputSaltByteCount,
        const uint8_t *pInfo,
        size_t infoByteCount,
        psa_key_id_t sessionKeyId,
        uint64_t *pOutputSalt) {
    if (pInputSalt == NULL || pInfo == NULL || pOutputSalt == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    psa_key_derivation_operation_t operation = psa_key_derivation_operation_init();

    status = psa_key_derivation_setup(&operation, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (status != PSA_SUCCESS) {
        printf("Failed to set up a key derivation operation. Status = %d\n", status);
        goto CLEAN_UP;
    }

    status = psa_key_derivation_input_bytes(
            &operation,
            PSA_KEY_DERIVATION_INPUT_SALT,
            pInputSalt,
            inputSaltByteCount);
    if (status != PSA_SUCCESS) {
        printf("Failed to input the salt into the key derivation operation. Status = %d\n", status);
        goto CLEAN_UP;
    }

    status = psa_key_derivation_input_key(
            &operation,
            PSA_KEY_DERIVATION_INPUT_SECRET,
            privateKeyId);
    if (status != PSA_SUCCESS) {
        printf("Failed to input the private key into the key derivation operation. Status = %d\n", status);
        goto CLEAN_UP;
    }

    status = psa_key_derivation_input_bytes(
            &operation,
            PSA_KEY_DERIVATION_INPUT_INFO,
            pInfo,
            infoByteCount);
    if (status != PSA_SUCCESS) {
        printf("Failed to input the info into the key derivation operation. Status = %d\n", status);
        goto CLEAN_UP;
    }

    uint8_t sessionPrivateKey[32] = {0};
    status = psa_key_derivation_output_bytes(
            &operation,
            sessionPrivateKey,
            sizeof(sessionPrivateKey));
    if (status != PSA_SUCCESS) {
        printf("Failed to output a session private key from the key derivation operation. Status = %d\n", status);
        goto CLEAN_UP;
    }

    uint8_t outputSalt[8] = {0};
    status = psa_key_derivation_output_bytes(
            &operation,
            outputSalt,
            sizeof(outputSalt));
    if (status != PSA_SUCCESS) {
        printf("Failed to output a session salt from the key derivation operation. Status = %d\n", status);
        goto CLEAN_UP;
    }

    psa_key_attributes_t sessionKeyAttributes = psa_key_attributes_init();
    psa_set_key_id(&sessionKeyAttributes, sessionKeyId);
    psa_set_key_lifetime(&sessionKeyAttributes, PSA_KEY_LIFETIME_PERSISTENT);
    psa_set_key_type(&sessionKeyAttributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&sessionKeyAttributes, 256);
    psa_set_key_usage_flags(
            &sessionKeyAttributes,
            PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&sessionKeyAttributes, PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, 8));

    psa_key_id_t generatedKeyId = 0;
    status = psa_import_key(
            &sessionKeyAttributes,
            sessionPrivateKey,
            sizeof(sessionPrivateKey),
            &generatedKeyId);
    if (status != PSA_SUCCESS) {
        printf("Failed to create a session key via import. Status = %d\n", status);
        goto CLEAN_UP;
    }

    (void) memcpy_s(pOutputSalt, sizeof(uint64_t), outputSalt, sizeof(outputSalt));

    CLEAN_UP:
    (void) psa_key_derivation_abort(&operation);
    return status;
}

psa_status_t CLI_Encrypt(
        psa_key_id_t keyId,
        uint64_t salt,
        uint32_t counter,
        const uint8_t *pPlaintext,
        size_t plaintextByteCount,
        uint8_t *pCiphertext,
        size_t ciphertextByteSize,
        size_t *pCiphertextWrittenByteCount,
        uint8_t *pMac,
        size_t macByteSize,
        size_t *pMacWrittenByteCount) {
    if (pPlaintext == NULL ||
        pCiphertext == NULL ||
        pCiphertextWrittenByteCount == NULL ||
        pMac == NULL ||
        pMacWrittenByteCount == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    psa_aead_operation_t operation = psa_aead_operation_init();
    status = psa_aead_encrypt_setup(&operation, keyId, PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, 8));
    if (status != PSA_SUCCESS) {
        printf("Failed to set up an AEAD encryption operation. Status = %d\n", status);
        goto CLEAN_UP;
    }

    status = psa_aead_set_lengths(&operation, 0, plaintextByteCount);
    if (status != PSA_SUCCESS) {
        printf("Failed to set the lengths of the AEAD encryption operation. Status = %d\n", status);
        goto CLEAN_UP;
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
    nonce[11] = (uint8_t) (counter);
    status = psa_aead_set_nonce(&operation, nonce, sizeof(nonce));
    if (status != PSA_SUCCESS) {
        printf("Failed to set the nonce for an AEAD encryption operation. Status = %d\n", status);
        goto CLEAN_UP;
    }

    uint8_t *pCiphertextItr = pCiphertext;
    size_t ciphertextUpdateByteCount = 0;
    status = psa_aead_update(
            &operation,
            pPlaintext,
            plaintextByteCount,
            pCiphertextItr,
            ciphertextByteSize,
            &ciphertextUpdateByteCount);
    if (status != PSA_SUCCESS) {
        printf("Failed to update an AEAD encryption operation. Status = %d\n", status);
        goto CLEAN_UP;
    }

    pCiphertextItr += ciphertextUpdateByteCount;
    status = psa_aead_finish(
            &operation,
            pCiphertextItr,
            ciphertextByteSize - ciphertextUpdateByteCount,
            pCiphertextWrittenByteCount,
            pMac,
            macByteSize,
            pMacWrittenByteCount);
    if (status != PSA_SUCCESS) {
        printf("Failed to finish an AEAD encryption operation. Status = %d\n", status);
        goto CLEAN_UP;
    }

    *pCiphertextWrittenByteCount += ciphertextUpdateByteCount;
    status = PSA_SUCCESS;

    CLEAN_UP:
    (void) psa_aead_abort(&operation);
    return status;
}

psa_status_t CLI_Decrypt(
        psa_key_id_t keyId,
        uint64_t salt,
        uint32_t counter,
        const uint8_t *pCiphertext,
        size_t ciphertextByteCount,
        const uint8_t *pMac,
        size_t macByteCount,
        uint8_t *pPlaintext,
        size_t plaintextByteSize,
        size_t *pPlaintextWrittenByteCount) {
    if (pCiphertext == NULL ||
        pMac == NULL ||
        pPlaintext == NULL ||
        pPlaintextWrittenByteCount == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    psa_aead_operation_t operation = psa_aead_operation_init();
    status = psa_aead_decrypt_setup(&operation, keyId, PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, 8));
    if (status != PSA_SUCCESS) {
        printf("Failed to set up an AEAD decryption operation. Status = %d\n", status);
        goto CLEAN_UP;
    }

    status = psa_aead_set_lengths(&operation, 0, ciphertextByteCount);
    if (status != PSA_SUCCESS) {
        printf("Failed to set the lengths of the AEAD decryption operation. Status = %d\n", status);
        goto CLEAN_UP;
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
    nonce[11] = (uint8_t) (counter);
    status = psa_aead_set_nonce(&operation, nonce, sizeof(nonce));
    if (status != PSA_SUCCESS) {
        printf("Failed to set the nonce for an AEAD decryption operation. Status = %d\n", status);
        goto CLEAN_UP;
    }

    uint8_t *pPlaintextItr = pPlaintext;
    size_t plaintextUpdateByteCount = 0;
    status = psa_aead_update(
            &operation,
            pCiphertext,
            ciphertextByteCount,
            pPlaintextItr,
            plaintextByteSize,
            &plaintextUpdateByteCount);
    if (status != PSA_SUCCESS) {
        printf("Failed to update an AEAD decryption operation. Status = %d\n", status);
        goto CLEAN_UP;
    }

    pPlaintextItr += plaintextUpdateByteCount;
    status = psa_aead_verify(
            &operation,
            pPlaintextItr,
            plaintextByteSize - plaintextUpdateByteCount,
            pPlaintextWrittenByteCount,
            pMac,
            macByteCount);
    if (status != PSA_SUCCESS) {
        printf("Failed to verify an AEAD decryption operation. Status = %d\n", status);
        goto CLEAN_UP;
    }

    *pPlaintextWrittenByteCount += plaintextUpdateByteCount;
    status = PSA_SUCCESS;

    CLEAN_UP:
    (void) psa_aead_abort(&operation);
    return status;
}