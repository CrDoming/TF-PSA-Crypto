#ifndef THREADING_ALT_H
#define THREADING_ALT_H

/**
 * A handle to some mutex.
 */
typedef struct {
    void *data;
} mbedtls_platform_mutex_t;

/**
 * A handle to some conditional variable.
 */
typedef struct {
    void *data;
} mbedtls_platform_condition_variable_t;

#endif // THREADING_ALT_H
