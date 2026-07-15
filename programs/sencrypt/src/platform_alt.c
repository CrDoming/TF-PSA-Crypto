#include "mbedtls/platform.h"

#ifndef ENTERPRISE_DRIVER_ENABLED
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#endif

int mbedtls_platform_get_entropy(
    psa_driver_get_entropy_flags_t flags,
    size_t *estimate_bits,
    unsigned char *output,
    size_t output_size) {
    (void) flags;
    if (estimate_bits == NULL) {
        return PSA_ERROR_INSUFFICIENT_ENTROPY;
    }

#ifdef ENTERPRISE_DRIVER_ENABLED
    // TODO: In a later PR, add logic here.
#else
    srand((unsigned int) time(NULL));
    for (size_t i = 0; i < output_size; i++) {
        output[i] = rand() % 256;
    }
#endif

    *estimate_bits = 8 * output_size;
    return PSA_SUCCESS;
}
