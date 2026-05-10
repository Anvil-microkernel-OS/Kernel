#pragma once

#include "port.h"
#include "channel.h"
#include "memory.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "syscalls.h"
#include "types.h"
#include "io_ports.h"
#include "interrupts.h"
#include "thread.h"
#include "process.h"

#define SYS_CAP_COPY 17

static inline void spin_pause(void) {
    asm volatile("pause");
}

static inline int64_t cap_copy(uint64_t src_cnode_cap, uint64_t dst_cnode_cap, uint64_t src_cnode_copy_idx) {
    return syscall3(SYS_CAP_COPY, src_cnode_cap, dst_cnode_cap, src_cnode_copy_idx);
}


__attribute__((noreturn))
static inline void kill_sleep(void) {
    for (;;) { spin_pause(); }
}
