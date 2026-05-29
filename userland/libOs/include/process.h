#pragma once

#include "types.h"
#include "syscalls.h"

#define SYS_PROC_GET_PID 4
#define SYS_PROC_GET_THREADS_TID 5
#define SYS_PROC_GET_NAME 6

#define SYS_PROC_CREATE 60
#define SYS_PROC_RUN 61

typedef struct {
    uint32_t* tids;
    size_t    count;
} proc_threads_list_t;

static inline int64_t get_pid(uint64_t capability) {
    return syscall1(SYS_PROC_GET_PID, capability);
}

static inline int64_t _proc_get_threads_raw(
    uint64_t capability,
    uint32_t* buf,
    size_t buf_count,
    size_t* out_count
) {
    return syscall4(SYS_PROC_GET_THREADS_TID, capability, 
                    (uint64_t)buf, (uint64_t)buf_count, (uint64_t)out_count);
}

static inline int64_t get_proc_name(uint64_t capability, char* buffer, uint64_t buff_len) {
    return syscall3(SYS_PROC_GET_NAME, capability, (uint64_t)buffer, buff_len);
}

typedef struct
{
    uint64_t proc_cap;
    uint64_t cnode_cap;
    uint64_t vspce_cap;
} initial_capabilities_t;


static inline int64_t create_proc(uint64_t capability, uint64_t domain_capability, const char* name, initial_capabilities_t* initial_caps) {
    return syscall5(SYS_PROC_CREATE, capability, domain_capability, (uint64_t)name, sizeof(name), (uint64_t)initial_caps);
}