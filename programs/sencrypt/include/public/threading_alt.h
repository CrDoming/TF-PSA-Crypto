#ifndef THREADING_ALT_H
#define THREADING_ALT_H

typedef struct {
    void *handle;
} mbedtls_platform_mutex_t;

typedef struct {
    void *handle;
} mbedtls_platform_condition_variable_t;

#endif // THREADING_ALT_H
