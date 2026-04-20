#pragma once

#include "types.h"

static inline int64_t syscall0(uint64_t number) {
    int64_t ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(number)
        : "rcx", "r11", "rdi", "rsi", "rdx", "r10", "r8", "r9", "memory"
    );
    return ret;
}

static inline int64_t syscall1(uint64_t number, uint64_t arg1) {
    int64_t ret;
    register uint64_t r_rdi asm("rdi") = arg1;
    __asm__ volatile (
        "syscall"
        : "=a"(ret), "+r"(r_rdi)
        : "a"(number)
        : "rcx", "r11", "rsi", "rdx", "r10", "r8", "r9", "memory"
    );
    return ret;
}

static inline int64_t syscall2(uint64_t number, uint64_t arg1, uint64_t arg2) {
    int64_t ret;
    register uint64_t r_rdi asm("rdi") = arg1;
    register uint64_t r_rsi asm("rsi") = arg2;
    __asm__ volatile (
        "syscall"
        : "=a"(ret), "+r"(r_rdi), "+r"(r_rsi)
        : "a"(number)
        : "rcx", "r11", "rdx", "r10", "r8", "r9", "memory"
    );
    return ret;
}

static inline int64_t syscall3(uint64_t number, uint64_t arg1, uint64_t arg2,
                                uint64_t arg3) {
    int64_t ret;
    register uint64_t r_rdi asm("rdi") = arg1;
    register uint64_t r_rsi asm("rsi") = arg2;
    register uint64_t r_rdx asm("rdx") = arg3;
    __asm__ volatile (
        "syscall"
        : "=a"(ret), "+r"(r_rdi), "+r"(r_rsi), "+r"(r_rdx)
        : "a"(number)
        : "rcx", "r11", "r10", "r8", "r9", "memory"
    );
    return ret;
}

static inline int64_t syscall4(uint64_t number, uint64_t arg1, uint64_t arg2,
                                uint64_t arg3, uint64_t arg4) {
    int64_t ret;
    register uint64_t r_rdi asm("rdi") = arg1;
    register uint64_t r_rsi asm("rsi") = arg2;
    register uint64_t r_rdx asm("rdx") = arg3;
    register uint64_t r_r10 asm("r10") = arg4;
    __asm__ volatile (
        "syscall"
        : "=a"(ret), "+r"(r_rdi), "+r"(r_rsi), "+r"(r_rdx), "+r"(r_r10)
        : "a"(number)
        : "rcx", "r11", "r8", "r9", "memory"
    );
    return ret;
}

static inline int64_t syscall5(uint64_t number, uint64_t arg1, uint64_t arg2,
                                uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    int64_t ret;
    register uint64_t r_rdi asm("rdi") = arg1;
    register uint64_t r_rsi asm("rsi") = arg2;
    register uint64_t r_rdx asm("rdx") = arg3;
    register uint64_t r_r10 asm("r10") = arg4;
    register uint64_t r_r8  asm("r8")  = arg5;
    __asm__ volatile (
        "syscall"
        : "=a"(ret), "+r"(r_rdi), "+r"(r_rsi), "+r"(r_rdx),
          "+r"(r_r10), "+r"(r_r8)
        : "a"(number)
        : "rcx", "r11", "r9", "memory"
    );
    return ret;
}
