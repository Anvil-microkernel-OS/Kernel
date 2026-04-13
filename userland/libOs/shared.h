#pragma once

#include "types.h"
#include "syscalls.h"
#include "stdlib.h"
#include "stdio.h"
#include "ipc.h"
#include "memory.h"
#include "tcb.h"

#define SYS_CAP_COPY 0x80

#define SYS_THREAD_SLEEP 0x99

static inline void spin_pause(void) {
    asm volatile("pause");
}

static inline int64_t cap_copy(uint64_t src_cnode_cap, uint64_t dst_cnode_cap, uint64_t src_cnode_copy_idx) {
    return syscall3(SYS_CAP_COPY, src_cnode_cap, dst_cnode_cap, src_cnode_copy_idx);
}

static inline int64_t sleep(uint64_t ns) {
    return syscall1(SYS_THREAD_SLEEP, ns);
}


__attribute__((noreturn))
static inline void kill_sleep(void) {
    for (;;) { spin_pause(); }
}
