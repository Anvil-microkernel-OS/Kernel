#pragma once
#include "syscalls.h"
#include "types.h"

#define SYS_PORT_CREATE 40
#define SYS_PORT_CLOSE 41
#define SYS_PORT_BIND 42
#define SYS_PORT_UNBIND 43
#define SYS_PORT_WAIT 44
#define SYS_PORT_POLL 45

#define PORT_EVENT_READABLE 0
#define PORT_EVENT_PEER_CLOSED 1

typedef struct {
    uint64_t key;
    uint64_t event;
    uint64_t irq_vector;
} port_packet_t;

static inline int64_t port_create() {
    return syscall0(SYS_PORT_CREATE);
}

static inline int64_t port_close(uint64_t cap) {
    return syscall1(SYS_PORT_CLOSE, cap);
}

static inline int64_t port_bind(uint64_t cap, uint64_t ch_cap, uint64_t key) {
    return syscall3(SYS_PORT_BIND, cap, ch_cap, key);
}

static inline int64_t port_unbind(uint64_t cap, uint64_t ch_cap) {
    return syscall2(SYS_PORT_UNBIND, cap, ch_cap);
}

static inline int64_t port_wait(uint64_t port, uint64_t timeout, port_packet_t* out) {
    int64_t ret;
    register uint64_t r_rdi asm("rdi") = port;
    register uint64_t r_rsi asm("rsi") = timeout;
    register uint64_t r_rdx asm("rdx");

    __asm__ volatile (
        "syscall"
        : "=a"(ret), "+r"(r_rdi), "+r"(r_rsi), "=r"(r_rdx)
        : "a"((uint64_t)SYS_PORT_WAIT)
        : "rcx", "r11", "r10", "r8", "r9", "memory"
    );

    if (out) {
        out->key        = r_rdi;  
        out->event      = r_rsi;   
        out->irq_vector = r_rdx;   
    }
    return ret;
}

static inline int64_t port_poll(uint64_t cap) {
    return syscall1(SYS_PORT_POLL, cap);
}