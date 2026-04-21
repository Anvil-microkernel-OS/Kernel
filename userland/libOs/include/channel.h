#pragma once

#include "syscalls.h"
#include "types.h"

#define SYS_CH_OPEN 12
#define SYS_CH_CLOSE 13
#define SYS_CH_WRITE 14
#define SYS_CH_READ 15
#define SYS_CH_WAIT 16
#define SYS_CH_CALL 17
#define SYS_CH_STATUS 18
#define SYS_CH_EXC_OPEN 4

typedef struct {
    uint64_t src_cap;
    uint64_t dst_cap;
} channel_h_pair_t;

static inline int64_t channel_open(channel_h_pair_t* pair) {
    if (pair == NULL) {
        return -1;
    }
    
    return syscall1(SYS_CH_OPEN, (uint64_t)pair);
}

static inline int64_t channel_close(uint64_t cap) {
    return syscall1(SYS_CH_CLOSE, cap);
}

typedef struct {
    uint64_t label;
    uint64_t data[5];
} channel_message_t;

static inline int64_t channel_write(uint64_t cap, channel_message_t* out) {
    if (out == NULL) {
        return -1;
    }

    return syscall2(SYS_CH_WRITE, cap, (uint64_t)out);
}

static inline int64_t channel_read(uint64_t cap, channel_message_t* out) {
    if (out == NULL) return -1;

    int64_t ret;
    register uint64_t r_rdi asm("rdi") = cap;
    register uint64_t r_rsi asm("rsi");
    register uint64_t r_rdx asm("rdx");
    register uint64_t r_r10 asm("r10");
    register uint64_t r_r8  asm("r8");
    register uint64_t r_r9  asm("r9");

    __asm__ volatile (
        "syscall"
        : "=a"(ret),
          "+r"(r_rdi),
          "=r"(r_rsi),
          "=r"(r_rdx),
          "=r"(r_r10),
          "=r"(r_r8),
          "=r"(r_r9)
        : "a"((uint64_t)SYS_CH_READ)
        : "rcx", "r11", "memory"
    );

    if (out) {
        out->label   = r_rdi;
        out->data[0] = r_rsi;
        out->data[1] = r_rdx;
        out->data[2] = r_r10;
        out->data[3] = r_r8;
        out->data[4] = r_r9;
    }
    return ret;
}

static inline int64_t channel_wait(uint64_t cap, uint64_t timeout, channel_message_t* out) {
    int64_t ret;
    register uint64_t r_rdi asm("rdi") = cap;
    register uint64_t r_rsi asm("rsi") = timeout;
    register uint64_t r_rdx asm("rdx");
    register uint64_t r_r10 asm("r10");
    register uint64_t r_r8  asm("r8");
    register uint64_t r_r9  asm("r9");

    __asm__ volatile (
        "syscall"
        : "=a"(ret),
          "+r"(r_rdi),
          "+r"(r_rsi),
          "=r"(r_rdx),
          "=r"(r_r10),
          "=r"(r_r8),
          "=r"(r_r9)
        : "a"((uint64_t)SYS_CH_WAIT)
        : "rcx", "r11", "memory"
    );

    if (out) {
        out->label   = r_rdi;
        out->data[0] = r_rsi;
        out->data[1] = r_rdx;
        out->data[2] = r_r10;
        out->data[3] = r_r8;
        out->data[4] = r_r9;
    }
    return ret;
}

static inline int64_t channel_call(uint64_t cap, channel_message_t* args, channel_message_t* result) {
    if (args == NULL || result == NULL) return -1;

    int64_t ret;
    register uint64_t r_rdi asm("rdi") = cap;
    register uint64_t r_rsi asm("rsi") = (uint64_t)args;
    register uint64_t r_rdx asm("rdx");
    register uint64_t r_r10 asm("r10");
    register uint64_t r_r8  asm("r8");
    register uint64_t r_r9  asm("r9");

    __asm__ volatile (
        "syscall"
        : "=a"(ret),
          "+r"(r_rdi),
          "+r"(r_rsi),
          "=r"(r_rdx),
          "=r"(r_r10),
          "=r"(r_r8),
          "=r"(r_r9)
        : "a"((uint64_t)SYS_CH_CALL)
        : "rcx", "r11", "memory"
    );

    if (result) {
        result->label   = r_rdi;
        result->data[0] = r_rsi;
        result->data[1] = r_rdx;
        result->data[2] = r_r10;
        result->data[3] = r_r8;
        result->data[4] = r_r9;
    }
    return ret;
}

typedef struct {
    uint64_t readable;
    uint64_t peer_alive;
    uint64_t queue_len;
} channel_status_t;

static inline int64_t channel_status(uint64_t cap, channel_status_t* status) {
    if (status == NULL) {
        return -1;
    }

    return syscall2(SYS_CH_STATUS, cap, (uint64_t)status);
}

static inline int64_t exception_channel_open(uint64_t flags, uint64_t* descriptor) {
    return 0;
}
