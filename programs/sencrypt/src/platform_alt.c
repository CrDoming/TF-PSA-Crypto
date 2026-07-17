#include "../include/public/platform_alt.h"

#include "mbedtls/platform.h"

#ifdef _MSC_VER
#include "stdarg.h"
#include "stdio.h"
#include "stdlib.h"
#include "time.h"
#endif

void firmware_exit(int status) {
#ifdef _MSC_VER
    exit(status);
#else
    // TODO: In a later PR, add logic.
#endif
}

void *firmware_calloc(size_t n, size_t size) {
#ifdef _MSC_VER
    return calloc(n, size);
#else
    // TODO: In a later PR, add logic.
#endif
}

void firmware_free(void *ptr) {
#ifdef _MSC_VER
    free(ptr);
#else
    // TODO: In a later PR, add logic.
#endif
}

void firmware_setbuf(void *stream, char *buf) {
#ifdef _MSC_VER
    if (buf == NULL) {
        (void) setvbuf(stream, NULL, _IONBF, 0);
    } else {
        (void) setvbuf(stream, buf, _IOFBF, BUFSIZ);
    }
#else
    // TODO: In a later PR, add logic.
#endif
}

int firmware_printf(const char *format, ...) {
#ifdef _MSC_VER
    va_list args = {0};
    va_start(args, format);
    const int result = vprintf(format, args);
    va_end(args);
    return result;
#else
    // TODO: In a later PR, add logic.
#endif
}

int firmware_fprintf(void *stream, const char *format, ...) {
#ifdef _MSC_VER
    va_list args = {0};
    va_start(args, format);
    const int result = vfprintf(stream, format, args);
    va_end(args);
    return result;
#else
    // TODO: In a later PR, add logic.
#endif
}

int firmware_snprintf(char *s, size_t n, const char *format, ...) {
#ifdef _MSC_VER
    va_list args = {0};
    va_start(args, format);
    const int result = vsnprintf(s, n, format, args);
    va_end(args);
    return result;
#else
    // TODO: In a later PR, add logic.
#endif
}

int firmware_vsnprintf(char *s, size_t n, const char *format, va_list args) {
#ifdef _MSC_VER
    return vsnprintf(s, n, format, args);
#else
    // TODO: In a later PR, add logic.
#endif
}

time_t firmware_time(time_t *ptr) {
#ifdef _MSC_VER
    return time(ptr);
#else
    // TODO: In a later PR, add logic.
#endif
}

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
    // TODO: In a later PR, add logic.
#endif

    *estimate_bits = 8 * output_size;
    return PSA_SUCCESS;
}
