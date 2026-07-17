#ifndef PLATFORM_ALT_H
#define PLATFORM_ALT_H

#ifdef _MSC_VER
#include "stddef.h"
#else
// TODO: In a later PR, determine if these are already defined.
typedef unsigned long long size_t;

typedef long long int64_t;

typedef long long time_t;
#endif

void firmware_exit(int status);

void *firmware_calloc(size_t n, size_t size);

void firmware_free(void *ptr);

void firmware_setbuf(void *stream, char *buf);

int firmware_printf(const char *format, ...);

int firmware_fprintf(void *stream, const char *format, ...);

int firmware_snprintf(char *s, size_t n, const char *format, ...);

int firmware_vsnprintf(char *s, size_t n, const char *format, va_list args);

time_t firmware_time(time_t *ptr);

#endif // PLATFORM_ALT_H
