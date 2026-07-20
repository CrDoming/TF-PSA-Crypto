#include "psa/internal_trusted_storage.h"

#include "psa/crypto_values.h"

psa_status_t psa_its_set(
    psa_storage_uid_t uid,
    uint32_t data_length,
    const void *p_data,
    psa_storage_create_flags_t create_flags) {
    (void) uid;
    (void) data_length;
    (void) p_data;
    (void) create_flags;

    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_its_get(
    psa_storage_uid_t uid,
    uint32_t data_offset,
    uint32_t data_length,
    void *p_data,
    size_t *p_data_length) {
    (void) uid;
    (void) data_offset;
    (void) data_length;
    (void) p_data;
    (void) p_data_length;

    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_its_get_info(
    psa_storage_uid_t uid,
    struct psa_storage_info_t *p_info) {
    (void) uid;
    (void) p_info;

    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_its_remove(psa_storage_uid_t uid) {
    (void) uid;

    return PSA_ERROR_NOT_SUPPORTED;
}
