#pragma once

#include "types.h"

static inline int memcmp(const char *s1, const char *s2, size_t n) {
    unsigned char u1, u2;

    for (; n--; s1++, s2++){
        u1 = *(unsigned char *)s1;
        u2 = *(unsigned char *)s2;

        if (u1 != u2){
            return (u1 - u2);
        }
    }

    return 0;
}

static inline void* memcpy(void *restrict destination, const void *restrict source, size_t n) {
    size_t *tmp_dest = (size_t *)destination;
    size_t *tmp_src = (size_t *)source;
    size_t len = n / sizeof(size_t);
    size_t i = 0;
    size_t tail = n & (sizeof(size_t) - 1);

    for (; i < len; i++) {
        *tmp_dest++ = *tmp_src++;
    }

    if(tail) {
        char *dest = (char *)destination;
        const char *src = (const char *)source;

        for(i = n - tail; i < n; i++) {
            dest[i] = src[i];
        }
    }

	return destination;
}

static inline void* memset(void* ptr, int value, size_t num) {
    uint8_t* bytes = ptr;

    while(num--) {
        *bytes++ = (uint8_t)value;
    }
}

static inline void* memmove(void *dest, void *src, size_t count) {
    void* ret = dest;

	if (dest <= src || (char*)dest >= ((char*)src + count)) {
		while (count--) {
			*(char*)dest = *(char*)src;
			dest = (char*)dest + 1;
			src = (char*)src + 1;
		}
	} else {
		dest = (char*)dest + count - 1;
		src = (char*)src + count - 1;
		while (count--) {
			*(char*)dest = *(char*)src;
			dest = (char*)dest - 1;
			src = (char*)src - 1;
		}
	}

	return ret;
}