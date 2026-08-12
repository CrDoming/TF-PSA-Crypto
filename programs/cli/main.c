#if defined(_MSC_VER) && !defined(_Noreturn)
#define _Noreturn __declspec(noreturn)
#endif

#include "mbedtls/platform.h"
#include "mbedtls/threading.h"
#include "psa/crypto.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "threads.h"

static uint8_t l_AuditLogKey[] = {
    0x01, 0xde, 0xea, 0x61, 0x87, 0x88, 0x4a, 0xb1, 0xfc, 0xe1, 0x7a,
    0xee, 0xb7, 0x5d, 0xf0, 0x1d, 0xe4, 0x82, 0x16, 0xf6, 0xc4, 0x6f,
    0x7d, 0xc5, 0xa5, 0x49, 0x3a, 0x7b, 0x78, 0xbf, 0x89, 0x40
};

static uint8_t l_MasterDerivationKey[] = {
    0x02, 0xde, 0xea, 0x61, 0x87, 0x88, 0x4a, 0xb1, 0xfc, 0xe1, 0x7a,
    0xee, 0xb7, 0x5d, 0xf0, 0x1d, 0xe4, 0x82, 0x16, 0xf6, 0xc4, 0x6f,
    0x7d, 0xc5, 0xa5, 0x49, 0x3a, 0x7b, 0x78, 0xbf, 0x89, 0x40
};

static char l_Plaintext[] = "Salutations.";

int CLI_InitializeMutex(mbedtls_platform_mutex_t *pMutex);

void CLI_DestroyMutex(mbedtls_platform_mutex_t *pMutex);

int CLI_LockMutex(mbedtls_platform_mutex_t *pMutex);

int CLI_UnlockMutex(mbedtls_platform_mutex_t *pMutex);

void CLI_PrintBytes(const uint8_t *pBytes, size_t byteCount);

void CLI_PrintKey(psa_key_id_t keyId, const char *pKeyName);

psa_status_t CLI_CreateHmacKey(
    const uint8_t *pKey,
    size_t keyByteCount,
    psa_key_id_t *keyId);

psa_status_t CLI_CreateDerivationKey(
    const uint8_t *pKey,
    size_t keyByteCount,
    psa_key_id_t *keyId);

psa_status_t CLI_CreateEccPrivateKey(psa_key_id_t *keyId);

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
    const uint8_t *pPrivateKey,
    size_t privateKeyByteCount,
    const uint8_t *pInputSalt,
    size_t inputSaltByteCount,
    const uint8_t *pInfo,
    size_t infoByteCount,
    psa_key_id_t *sessionKeyId,
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

// TODO: Redefine.
static size_t l_MaxBlockSize = 0;
static size_t l_TotalSize = 0;

typedef struct {
    size_t size;
    uint8_t* ptr;
} memory_block_t;

void* CLI_Calloc(size_t n, size_t size) {
    size_t len = n * size;
    if (len > l_MaxBlockSize) {
        l_MaxBlockSize = len;
    }

    l_TotalSize += len;

    memory_block_t* block = malloc(sizeof(memory_block_t) + len);
    if (block == NULL) {
        return NULL;
    }

    block->size = len;
    block->ptr = (uint8_t*)block + sizeof(size_t);
    return block->ptr;
}

void CLI_Free(void* ptr) {
    if (ptr == NULL) {
        return;
    }

    memory_block_t* block = (memory_block_t*)((uint8_t*)ptr - sizeof(size_t));
    l_TotalSize -= block->size;
    free(block);
}

int main(int argc, char **argv) {
    int exitCode = 1;
    uint8_t memory_buffer[7000];
    psa_key_id_t auditLogKeyId = 0;
    char auditLogKeyName[] = "Audit Log";
    psa_key_id_t masterDerivationKeyId = 0;
    char masterDerivationKeyName[] = "Master Derivation";
    psa_key_id_t hostKeyId = 0;
    char hostKeyName[] = "HOST";
    psa_key_id_t smibKeyId = 0;
    char smibKeyName[] = "SMIB";
    psa_key_id_t sessionKeyId = 0;
    char sessionKeyName[] = "Session";
    psa_key_id_t keyIds[] = {
        auditLogKeyId,
        masterDerivationKeyId,
        hostKeyId,
        smibKeyId,
        sessionKeyId
    };

    mbedtls_threading_set_alt(
        CLI_InitializeMutex,
        CLI_DestroyMutex,
        CLI_LockMutex,
        CLI_UnlockMutex,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL);

    mbedtls_platform_set_calloc_free(
        CLI_Calloc,
        CLI_Free);

    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf(
            "Failed to initialize the PSA Crypto library. Status = %d\n",
            status);
        goto CLEAN_UP;
    }

    status = CLI_CreateHmacKey(l_AuditLogKey, sizeof(l_AuditLogKey), &auditLogKeyId);
    if (status != PSA_SUCCESS) {
        printf(
            "Failed to create the %s Key. Status = %d\n",
            auditLogKeyName,
            status);
        goto CLEAN_UP;
    }

    CLI_PrintKey(auditLogKeyId, auditLogKeyName);

    status = CLI_CreateDerivationKey(
        l_MasterDerivationKey,
        sizeof(l_MasterDerivationKey),
        &masterDerivationKeyId);
    if (status != PSA_SUCCESS) {
        printf(
            "Failed to create the %s Key. Status = %d\n",
            masterDerivationKeyName,
            status);
        goto CLEAN_UP;
    }

    CLI_PrintKey(masterDerivationKeyId, masterDerivationKeyName);

    status = CLI_CreateEccPrivateKey(&hostKeyId);
    if (status != PSA_SUCCESS) {
        printf(
            "Failed to create the %s Key. Status = %d\n",
            hostKeyName,
            status);
        goto CLEAN_UP;
    }

    CLI_PrintKey(hostKeyId, hostKeyName);

    status = CLI_CreateEccPrivateKey(&smibKeyId);
    if (status != PSA_SUCCESS) {
        printf(
            "Failed to create the %s Key. Status = %d\n",
            smibKeyName,
            status);
        goto CLEAN_UP;
    }

    CLI_PrintKey(smibKeyId, smibKeyName);

    size_t writtenByteCount = 0;

    uint8_t hostPublicKey[65] = {0};
    status = CLI_GetPublicKey(
        hostKeyId,
        hostPublicKey,
        sizeof(hostPublicKey),
        &writtenByteCount);
    if (status != PSA_SUCCESS) {
        printf(
            "Failed to get the public key for the %s Key. Status = %d\n",
            hostKeyName,
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
            "Failed to get the public key for the %s Key. Status = %d\n",
            smibKeyName,
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
            "Failed to create the shared secret for the %s Key. Status = %d\n",
            hostKeyName,
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
            "Failed to create the shared secret for the %s Key. Status = %d\n",
            smibKeyName,
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
        &sessionKeyId,
        &sessionOutputSalt);
    if (status != PSA_SUCCESS) {
        printf(
            "Failed to create the %s Key. Status = %d\n",
            sessionKeyName,
            status);
        goto CLEAN_UP;
    }

    CLI_PrintKey(sessionKeyId, sessionKeyName);
    printf("Session Output Salt = 0x%016llx\n", sessionOutputSalt);

    uint8_t mac[32] = {0};
    size_t macWrittenByteCount = 0;
    status = CLI_Sign(
        auditLogKeyId,
        (const uint8_t *) l_Plaintext,
        sizeof(l_Plaintext),
        mac,
        sizeof(mac),
        &macWrittenByteCount);
    if (status != PSA_SUCCESS) {
        printf(
            "Failed to sign data with the %s Key. Status = %d\n",
            sessionKeyName,
            status);
        goto CLEAN_UP;
    }

    printf("MAC for Plaintext = ");
    CLI_PrintBytes(mac, macWrittenByteCount);

    const uint32_t counter = 4;
    uint8_t authCiphertext[128] = {0};
    size_t authCiphertextWrittenByteCount = 0;
    status = CLI_Encrypt(
        sessionKeyId,
        sessionOutputSalt,
        counter,
        (const uint8_t *) l_Plaintext,
        sizeof(l_Plaintext),
        authCiphertext,
        sizeof(authCiphertext),
        &authCiphertextWrittenByteCount);
    if (status != PSA_SUCCESS) {
        printf(
            "Failed to encrypt data with the %s Key. Status = %d\n",
            sessionKeyName,
            status);
        goto CLEAN_UP;
    }

    printf("Ciphertext = ");
    CLI_PrintBytes(authCiphertext, authCiphertextWrittenByteCount - 8);
    printf("Auth Tag = ");
    CLI_PrintBytes(authCiphertext + authCiphertextWrittenByteCount - 8, 8);

    uint8_t plaintext[128] = {0};
    status = CLI_Decrypt(
        sessionKeyId,
        sessionOutputSalt,
        counter,
        authCiphertext,
        authCiphertextWrittenByteCount,
        plaintext,
        sizeof(plaintext),
        &writtenByteCount);
    if (status != PSA_SUCCESS) {
        printf(
            "Failed to decrypt data with the %s Key. Status = %d\n",
            sessionKeyName,
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

    mbedtls_psa_crypto_free();
    mbedtls_threading_free_alt();
    return exitCode;
}

int CLI_InitializeMutex(mbedtls_platform_mutex_t *pMutex) {
    if (pMutex == NULL) {
        return MBEDTLS_ERR_THREADING_USAGE_ERROR;
    }

    pMutex->data = malloc(sizeof(mtx_t));
    if (pMutex->data == NULL) {
        return MBEDTLS_ERR_THREADING_USAGE_ERROR;
    }

    if (mtx_init(pMutex->data, mtx_plain) != thrd_success) {
        free(pMutex->data);
        pMutex->data = NULL;
        return MBEDTLS_ERR_THREADING_USAGE_ERROR;
    }

    return MBEDTLS_EXIT_SUCCESS;
}

void CLI_DestroyMutex(mbedtls_platform_mutex_t *pMutex) {
    if (pMutex == NULL || pMutex->data == NULL) {
        return;
    }

    free(pMutex->data);
    pMutex->data = NULL;
}

int CLI_LockMutex(mbedtls_platform_mutex_t *pMutex) {
    if (pMutex == NULL || pMutex->data == NULL) {
        return MBEDTLS_ERR_THREADING_USAGE_ERROR;
    }

    mtx_t *pMtx = pMutex->data;
    if (mtx_lock(pMtx) != thrd_success) {
        return MBEDTLS_ERR_THREADING_USAGE_ERROR;
    }

    return MBEDTLS_EXIT_SUCCESS;
}

int CLI_UnlockMutex(mbedtls_platform_mutex_t *pMutex) {
    if (pMutex == NULL || pMutex->data == NULL) {
        return MBEDTLS_ERR_THREADING_USAGE_ERROR;
    }

    mtx_t *pMtx = pMutex->data;
    if (mtx_unlock(pMtx) != thrd_success) {
        return MBEDTLS_ERR_THREADING_USAGE_ERROR;
    }

    return MBEDTLS_EXIT_SUCCESS;
}

void CLI_PrintBytes(const uint8_t *pBytes, const size_t byteCount) {
    if (pBytes == NULL || byteCount == 0) {
        return;
    }

    printf("0x");
    for (size_t i = 0; i < byteCount; i++) {
        printf("%02x", pBytes[i]);
    }
    printf("\n");
}

void CLI_PrintKey(const psa_key_id_t keyId, const char *keyName) {
    uint8_t keyBuffer[128] = {0};
    size_t writtenByteCount = 0;
    psa_status_t status =
            psa_export_key(keyId, keyBuffer, sizeof(keyBuffer), &writtenByteCount);
    if (status != PSA_SUCCESS) {
        printf(
            "Failed to print the %s Key. Status = %d\n",
            keyName,
            status);
        return;
    }

    printf("%s Key = 0x", keyName);
    for (size_t i = 0; i < writtenByteCount; i++) {
        printf("%02x", keyBuffer[i]);
    }
    printf("\n");
}

psa_status_t CLI_CreateHmacKey(
    const uint8_t *pKey,
    const size_t keyByteCount,
    psa_key_id_t *keyId) {
    psa_key_attributes_t keyAttributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&keyAttributes, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&keyAttributes, 256);
    psa_set_key_usage_flags(
        &keyAttributes,
        PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&keyAttributes, PSA_ALG_HMAC(PSA_ALG_SHA_256));

    return psa_import_key(&keyAttributes, pKey, keyByteCount, keyId);
}

psa_status_t CLI_CreateDerivationKey(
    const uint8_t *pKey,
    const size_t keyByteCount,
    psa_key_id_t *keyId) {
    psa_key_attributes_t keyAttributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&keyAttributes, PSA_KEY_TYPE_DERIVE);
    psa_set_key_bits(&keyAttributes, keyByteCount * 8);
    psa_set_key_usage_flags(
        &keyAttributes,
        PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&keyAttributes, PSA_ALG_HKDF(PSA_ALG_SHA_256));

    return psa_import_key(&keyAttributes, pKey, keyByteCount, keyId);
}

psa_status_t CLI_CreateEccPrivateKey(psa_key_id_t *keyId) {
    psa_key_attributes_t keyAttributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(
        &keyAttributes,
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&keyAttributes, 256);
    psa_set_key_usage_flags(
        &keyAttributes,
        PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&keyAttributes, PSA_ALG_ECDH);

    return psa_generate_key(&keyAttributes, keyId);
}

psa_status_t CLI_GetPublicKey(
    const psa_key_id_t privateKeyId,
    uint8_t *pPublicKey,
    const size_t publicKeyByteSize,
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
    const psa_key_id_t privateKeyId,
    const uint8_t *pPeerPublicKey,
    const size_t peerPublicKeyByteCount,
    uint8_t *pSharedSecret,
    const size_t sharedSecretByteSize,
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

psa_status_t CLI_CreateSessionKeyAndSalt(
    const uint8_t *pPrivateKey,
    const size_t privateKeyByteCount,
    const uint8_t *pInputSalt,
    const size_t inputSaltByteCount,
    const uint8_t *pInfo,
    const size_t infoByteCount,
    psa_key_id_t *sessionKeyId,
    uint64_t *pOutputSalt) {
    if (sessionKeyId == NULL || pOutputSalt == NULL) {
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

    psa_key_attributes_t keyAttributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&keyAttributes, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&keyAttributes, inputSaltByteCount * 8);
    psa_set_key_usage_flags(
        &keyAttributes,
        PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&keyAttributes, PSA_ALG_HMAC(PSA_ALG_SHA_256));

    status = psa_import_key(
        &keyAttributes,
        pInputSalt,
        inputSaltByteCount,
        &generatedKeyId);
    if (status != PSA_SUCCESS) {
        printf(
            "Failed to create a key based on the input salt for the extract "
            "phrase. Status = %d",
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

    keyAttributes = (psa_key_attributes_t) PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&keyAttributes, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&keyAttributes, sizeof(prk) * 8);
    psa_set_key_usage_flags(
        &keyAttributes,
        PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&keyAttributes, PSA_ALG_HMAC(PSA_ALG_SHA_256));

    status = psa_import_key(&keyAttributes, prk, sizeof(prk), &generatedKeyId);
    if (status != PSA_SUCCESS) {
        printf(
            "Failed to create a key based on the PRK for the expand phrase. "
            "Status = %d",
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

    psa_key_attributes_t sessionKeyAttributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&sessionKeyAttributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&sessionKeyAttributes, 256);
    psa_set_key_usage_flags(
        &sessionKeyAttributes,
        PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(
        &sessionKeyAttributes,
        PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, 8));

    status = psa_import_key(&sessionKeyAttributes, okm, 32, &generatedKeyId);
    if (status != PSA_SUCCESS) {
        printf(
            "Failed to create a session key from the OKM. Status = %d\n",
            status);
        goto CLEAN_UP;
    }

    *sessionKeyId = generatedKeyId;
    generatedKeyId = 0;

    (void) memcpy_s(pOutputSalt, sizeof(uint64_t), okm + 32, 8);

CLEAN_UP:
    (void) psa_destroy_key(generatedKeyId);
    if (payload != NULL) {
        free(payload);
    }

    return status;
}

psa_status_t CLI_Sign(
    const psa_key_id_t keyId,
    const uint8_t *pInput,
    const size_t inputByteCount,
    uint8_t *pMac,
    const size_t macByteSize,
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
    const psa_key_id_t keyId,
    const uint64_t salt,
    const uint32_t counter,
    const uint8_t *pPlaintext,
    const size_t plaintextByteCount,
    uint8_t *pAuthCiphertext,
    const size_t authCiphertextByteSize,
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
    const psa_key_id_t keyId,
    const uint64_t salt,
    const uint32_t counter,
    const uint8_t *pAuthCiphertext,
    const size_t authCiphertextByteCount,
    uint8_t *pPlaintext,
    const size_t plaintextByteSize,
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
