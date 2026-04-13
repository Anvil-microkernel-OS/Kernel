#pragma once

#include "syscalls.h"
#include "types.h"

#define SYS_IPC_EP_CREATE  0x64
#define SYS_IPC_EP_DESTROY 0x65
#define SYS_IPC_SEND       0x60
#define SYS_IPC_RECV       0x61
#define SYS_IPC_CALL       0x62
#define SYS_IPC_REPLY      0x63

typedef struct {
    uint64_t ep_id;
    uint64_t msg[4];
} ipc_syscall_args_t;

typedef struct {
    uint64_t label;
    uint64_t data[4];
} ipc_msg_t;

static inline int64_t ipc_recv_msg(uint64_t ep_id, ipc_msg_t *out) {
    int64_t ret;
    register uint64_t rdi asm("rdi") = ep_id;
    register uint64_t rsi asm("rsi");
    register uint64_t rdx asm("rdx");
    register uint64_t r10 asm("r10");
    register uint64_t r8  asm("r8");

    __asm__ volatile (
        "syscall"
        : "=a"(ret), "+r"(rdi), "=r"(rsi), "=r"(rdx), "=r"(r10), "=r"(r8)
        : "a"((uint64_t)SYS_IPC_RECV)
        : "rcx", "r11", "r9", "r12", "r13", "r14", "r15", "memory"
    );

    if (out) {
        out->label   = rdi;
        out->data[0] = rsi;
        out->data[1] = rdx;
        out->data[2] = r10;
        out->data[3] = r8;
    }

    return ret;
}

static inline int64_t ipc_ep_create(void) {
    return syscall1(SYS_IPC_EP_CREATE, 0);
}

static inline int64_t ipc_ep_destroy(uint64_t ep_id) {
    return syscall1(SYS_IPC_EP_DESTROY, ep_id);
}

static inline int64_t ipc_send(uint64_t ep_id, uint64_t msg0, uint64_t msg1, 
                                uint64_t msg2, uint64_t msg3) {
    return syscall5(SYS_IPC_SEND, ep_id, msg0, msg1, msg2, msg3);
}

static inline int64_t ipc_try_recv(uint64_t ep_id) {

    uint64_t ret = syscall1(SYS_IPC_RECV, ep_id);
    
    return ret;
}

static inline int64_t ipc_call(uint64_t ep_id, uint64_t req0, uint64_t req1,
                                uint64_t req2, uint64_t req3,
                                uint64_t *resp0, uint64_t *resp1,
                                uint64_t *resp2, uint64_t *resp3) {
    return syscall5(SYS_IPC_CALL, ep_id, req0, req1, req2, req3);
}

static inline int64_t ipc_reply(uint64_t ep_id, uint64_t resp0, uint64_t resp1,
                                 uint64_t resp2, uint64_t resp3) {
    return syscall5(SYS_IPC_REPLY, ep_id, resp0, resp1, resp2, resp3);
}