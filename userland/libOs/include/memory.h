#pragma once

#include "syscalls.h"
#include "types.h"

#define SYS_VMA_MAP     11
#define SYS_VMA_UNMAP   12
#define SYS_MPROTECT    13
#define SYS_VMO_CREATE  14
#define SYS_VMO_WRITE   16

#define MAP_READ  (1 << 0)
#define MAP_WRITE (1 << 1)
#define MAP_EXEC  (1 << 2)
#define MAP_USER  (1 << 3)

enum vmo_type_e {
    VmoContigious = 0,
    VmoAnonymous = 1,
    VmoPhysical = 2
};

typedef struct {
    uint64_t vscape_cap;
    uint64_t vmo_cap;
    uint64_t vaddr;
    uint64_t size;
    uint64_t vmo_offset;
    uint64_t flags;
} mmap_args_t;

static inline int64_t vma_map(mmap_args_t* args) {
    if (args == NULL) {
        return -1;
    }

    return syscall1(SYS_VMA_MAP, (uint64_t)args);
}

static inline int64_t vma_unmap(uint64_t vspace_cap_idx, uint64_t vaddr) {
    return syscall2(SYS_VMA_UNMAP, vspace_cap_idx, vaddr);
}

static inline int64_t mprotect(uint64_t vspace_cap_idx, uint64_t vaddr, uint64_t flags) {
    return syscall3(SYS_MPROTECT, vspace_cap_idx, vaddr, flags);
}

static inline int64_t vmo_create(uint64_t size, enum vmo_type_e type) {
    return syscall2(SYS_VMO_CREATE, size, type);
}

static inline int64_t vmo_write(uint64_t vmo_cap, void* data_ptr, size_t offset, size_t len) {
    return syscall4(SYS_VMO_WRITE, vmo_cap, (uint64_t)data_ptr, (uint64_t)offset, (uint64_t)len);
}