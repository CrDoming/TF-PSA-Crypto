#ifndef PLATFORM_ALT_H
#define PLATFORM_ALT_H

#include "stdint.h"

/**
 * @brief Allocates memory for an array of objects and sets each byte to 0.
 * @param[in] n The count of objects.
 * @param[in] size The size of each object in bytes.
 * @returns The pointer to the allocated memory on success; otherwise, a null pointer.
 */
void *firmware_calloc(size_t n, size_t size);

/**
 * @brief Deallocates memory.
 * @param[in] ptr The pointer to the memory to deallocate.
 */
void firmware_free(void *ptr);

#endif // PLATFORM_ALT_H
