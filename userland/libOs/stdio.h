#pragma once

#include "types.h"
#include "stdlib.h"

#define SYS_PRINT          0x10

static inline int64_t sys_print(const char *str, uint64_t len) {
    if ((uint64_t)str < 0x1000 || (uint64_t)str > 0x00007FFFFFFFFFFF) {
        return 1;
    }
    if (len > 4096) {
        return 1;
    }
    
    return syscall2(SYS_PRINT, (uint64_t)str, len);
}

static inline void printf(const char *fmt, ...) {
    char buf[1024];
    __builtin_va_list ap;
    __builtin_va_start(ap, fmt);

    int len = vsnprintf_simple(buf, sizeof(buf), fmt, ap);
    
    __builtin_va_end(ap);

    sys_print(buf, len);
}