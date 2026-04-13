#pragma once

#include "syscalls.h"
#include "types.h"

#define SYS_VMA_MAP     0x2
#define SYS_VMA_UNMAP   0x3
#define SYS_MPROTECT    0x4
#define SYS_VMO_CREATE  0x5

#define MAP_READ  (1 << 0)
#define MAP_WRITE (1 << 1)
#define MAP_EXEC  (1 << 2)
#define MAP_USER  (1 << 3)

static inline int64_t vma_map(uint64_t vspace_cap_idx, uint64_t vmo_cap_idx, uint64_t vaddr, uint64_t flags) {
    return syscall4(SYS_VMA_MAP, vspace_cap_idx, vmo_cap_idx, vaddr, flags);
}

static inline int64_t vma_unmap(uint64_t vspace_cap_idx, uint64_t vaddr) {
    return syscall2(SYS_VMA_UNMAP, vspace_cap_idx, vaddr);
}

static inline int64_t mprotect(uint64_t vspace_cap_idx, uint64_t vaddr, uint64_t flags) {
    return syscall3(SYS_MPROTECT, vspace_cap_idx, vaddr, flags);
}

static inline int64_t vmo_create(uint64_t size) {
    return syscall1(SYS_VMO_CREATE, size);
}
