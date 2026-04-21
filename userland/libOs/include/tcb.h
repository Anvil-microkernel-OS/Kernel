#pragma once

#include "syscalls.h"
#include "types.h"

#define SYS_TCB_CREATE    1
#define SYS_TCB_RESUME    2
#define SYS_TCB_SET_REGS  3

#define TCB_GENERAL_REGISTERS 1
typedef struct {
    uint64_t rax;
    uint64_t rbx;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t rbp;
    uint64_t rsp;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rip;
    uint64_t rflags;
} general_registers_t;

typedef struct {
    uint64_t tcb_slot;
    uint64_t vspace_slot;
    uint64_t cnode_slot;
} child_cap_slots_t;

static inline int64_t tcb_create(child_cap_slots_t* child_slots) {
    if (child_slots == NULL) {
        return -1;
    }

    return syscall1(SYS_TCB_CREATE, (uint64_t)child_slots);
}

static inline int64_t tcb_resume(uint64_t tcb_cap) {
    return syscall1(SYS_TCB_RESUME, tcb_cap);
}

static inline int64_t tcb_set_regs(uint64_t tcb_cap, uint64_t type, void* buffer) {
    return syscall3(SYS_TCB_SET_REGS, tcb_cap, type, (uint64_t)buffer);
}