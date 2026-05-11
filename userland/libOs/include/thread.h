#pragma once

#include "types.h"
#include "syscalls.h"

#define SYS_THREAD_INFO_GET_TID 1
#define SYS_THREAD_INFO_GET_STATE 2
#define SYS_THREAD_INFO_GET_REGS 3

#define SYS_THREAD_ACTION_CREATE 7
#define SYS_THREAD_ACTION_WRITE_REGS 8
#define SYS_THREAD_ACTION_RUN 9
#define SYS_THREAD_ACTION_SLEEP 19

#define NSEC(n) (1LL * (n))
#define USEC(n) (1000LL * (n))
#define MSEC(n) (1000000LL * (n))
#define SEC(n)  (1000000000LL * (n))
#define MIN(n)  (SEC(n) * 60LL)
#define HOUR(n) (MIN(n) * 60LL)

typedef enum {
    THREAD_STATE_RUNNING     = 0,
    THREAD_STATE_READY       = 1,
    THREAD_STATE_EXITING     = 2,
    THREAD_STATE_SLEEPING    = 3,
} thread_state_t;

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
} general_purpose_registers_t;

static inline int64_t get_tid(uint64_t capability) {
    return syscall1(SYS_THREAD_INFO_GET_TID, capability);
}

static inline int64_t get_tstate(uint64_t capability) {
    return syscall1(SYS_THREAD_INFO_GET_STATE, capability);
}

static inline int64_t get_tregs(uint64_t capability, general_purpose_registers_t* regs) {
    if (regs == NULL) {
        return -1;
    }

    return syscall2(SYS_THREAD_INFO_GET_REGS, capability, (uint64_t)regs);
}

static inline int64_t create_thread(uint64_t capability) {
    return syscall1(SYS_THREAD_ACTION_CREATE, capability);
}

static inline int64_t write_tregs(uint64_t capability, general_purpose_registers_t* regs) {
    if (regs == NULL) {
        return -1;
    }

    
    return syscall2(SYS_THREAD_ACTION_WRITE_REGS, capability, (uint64_t)regs);
}

static inline int64_t start_thread(uint64_t capability) {
    return syscall1(SYS_THREAD_ACTION_RUN, capability);
}

static inline int64_t sleep(uint64_t ns) {
    return syscall1(SYS_THREAD_ACTION_SLEEP, ns);
}

static inline const char* thread_state_to_str(thread_state_t state) {
    switch (state) {
        case THREAD_STATE_RUNNING:     return "running";
        case THREAD_STATE_READY:       return "ready";
        case THREAD_STATE_EXITING:     return "exiting";
        case THREAD_STATE_SLEEPING:    return "sleeping";
        default:                       return "unknown";
    }
}