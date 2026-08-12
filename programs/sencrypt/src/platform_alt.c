#include "mbedtls/platform.h"

#ifdef _MSC_VER
#include "stdarg.h"
#include "stdlib.h"
#include "time.h"
#endif

// The declaration is in TF-PSA-Crypto/include/mbedtls/platform.h
int mbedtls_platform_get_entropy(
    psa_driver_get_entropy_flags_t flags,
    size_t *estimate_bits,
    unsigned char *output,
    size_t output_size) {
    (void) flags;
    if (estimate_bits == NULL) {
        return PSA_ERROR_INSUFFICIENT_ENTROPY;
    }

#ifdef _MSC_VER
    srand((unsigned int) time(NULL));
    for (size_t i = 0; i < output_size; i++) {
        output[i] = rand() % 256;
    }
#else
    // TODO: Add logic.
#endif

    *estimate_bits = 8 * output_size;
    return PSA_SUCCESS;
}
