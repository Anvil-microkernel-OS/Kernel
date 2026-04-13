#pragma once

#include "syscalls.h"
#include "types.h"

#define SYS_TCB_CREATE    0x70
#define SYS_TCB_RESUME    0x71
#define SYS_TCB_SET_REGS  0x72
#define SYS_TCB_CONFIGURE 0x73

static inline int64_t tcb_create() {
    return syscall0(SYS_TCB_CREATE);
}

static inline int64_t tcb_resume(uint64_t tcb_cap) {
    return syscall1(SYS_TCB_RESUME, tcb_cap);
}

static inline int64_t tcb_set_regs(uint64_t tcb_cap) {
    return syscall1(SYS_TCB_SET_REGS, tcb_cap);
}

static inline int64_t tcb_configure(uint64_t tcb_cap, uint64_t vspace_cap, uint64_t ipc_buff_vaddr, uint64_t vmo_cap_idx) {
    return syscall4(SYS_TCB_CONFIGURE, tcb_cap, vspace_cap, ipc_buff_vaddr, vmo_cap_idx);
}