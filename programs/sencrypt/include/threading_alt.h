#pragma once

typedef struct {
    void* handle;
} mbedtls_platform_mutex_t;

typedef struct {
    void* handle;
} mbedtls_platform_condition_variable_t;