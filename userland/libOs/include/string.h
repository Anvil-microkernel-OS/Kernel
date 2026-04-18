#pragma once

#include "types.h"

int memcmp(const char *s1, const char *s2, size_t n);
void* memcpy(void *restrict destination, const void *restrict source, size_t n);
void* memset(void* ptr, int value, size_t num);
void* memmove(void *dest, void *src, size_t count);