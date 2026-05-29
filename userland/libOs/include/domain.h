#pragma once
#include "syscalls.h"
#include "types.h"

#define SYS_DOMAIN_CREATE 70

static int64_t create_domain(uint64_t cap, const char* name) {
    if (name == NULL) {
        return -1;
    }

    return syscall3(SYS_DOMAIN_CREATE, cap, (uint64_t)name, sizeof(name));
}