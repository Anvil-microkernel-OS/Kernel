#pragma once

#include "types.h"
#include "syscalls.h"

#define SYS_IPC_EP_CREATE  0x64
#define SYS_IPC_EP_DESTROY 0x65
#define SYS_IPC_SEND       0x60
#define SYS_IPC_RECV       0x61
#define SYS_IPC_CALL       0x62
#define SYS_IPC_REPLY      0x63
#define SYS_PRINT          0x10

#define SYS_VMA_MAP     0x2
#define SYS_VMA_UNMAP   0x3
#define SYS_MPROTECT    0x4
#define SYS_VMO_CREATE  0x5

#define MAP_READ  (1 << 0)
#define MAP_WRITE (1 << 1)
#define MAP_EXEC  (1 << 2)
#define MAP_USER  (1 << 3)

#define SYS_TCB_CREATE    0x70
#define SYS_TCB_RESUME    0x71
#define SYS_TCB_SET_REGS  0x72
#define SYS_TCB_CONFIGURE 0x73

#define SYS_CAP_COPY 0x80

#define SYS_THREAD_SLEEP 0x99

typedef struct {
    uint64_t ep_id;
    uint64_t msg[4];
} ipc_syscall_args_t;


static inline void spin_pause(void) {
    asm volatile("pause");
}

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

static inline int64_t vma_map(uint64_t vspace_cap_idx, uint64_t vmo_cap_idx, uint64_t vaddr, uint64_t flags) {
    return syscall4(SYS_VMA_MAP, vspace_cap_idx, vmo_cap_idx, vaddr, flags);
}

static inline int64_t vma_unmap(uint64_t vspace_cap_idx, uint64_t vaddr) {
    return syscall2(SYS_VMA_UNMAP, vspace_cap_idx, vaddr);
}

static inline int64_t mprotect(uint64_t vspace_cap_idx, uint64_t vaddr, uint64_t flags) {
    return syscall3(SYS_MPROTECT, vspace_cap_idx, vaddr, flags);
}

static inline int64_t vmo_create(uint64_t size) {
    return syscall1(SYS_VMO_CREATE, size);
}

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

static inline int64_t cap_copy(uint64_t src_cnode_cap, uint64_t dst_cnode_cap, uint64_t src_cnode_copy_idx) {
    return syscall3(SYS_CAP_COPY, src_cnode_cap, dst_cnode_cap, src_cnode_copy_idx);
}

static inline int64_t sleep(uint64_t ns) {
    return syscall1(SYS_THREAD_SLEEP, ns);
}

static inline int64_t sys_print(const char *str, uint64_t len) {
    if ((uint64_t)str < 0x1000 || (uint64_t)str > 0x00007FFFFFFFFFFF) {
        return 1;
    }
    if (len > 4096) {
        return 1;
    }
    
    return syscall2(SYS_PRINT, (uint64_t)str, len);
}

static inline int vsnprintf_simple(char *buf, int size, const char *fmt, __builtin_va_list ap) {
    int pos = 0;

#define PUT(c) do { if (pos < size - 1) buf[pos++] = (c); } while(0)

    while (*fmt) {
        if (*fmt != '%') {
            PUT(*fmt++);
            continue;
        }
        fmt++; // skip '%'

        // флаги
        int zero_pad = 0;
        int width = 0;
        if (*fmt == '0') { zero_pad = 1; fmt++; }
        while (*fmt >= '0' && *fmt <= '9') {
            width = width * 10 + (*fmt++ - '0');
        }

        switch (*fmt++) {
            case 'd': case 'i': {
                long val = __builtin_va_arg(ap, long);
                char tmp[32];
                int neg = 0, i = 30;
                tmp[31] = '\0';
                if (val < 0) { neg = 1; val = -val; }
                if (val == 0) tmp[i--] = '0';
                while (val > 0) { tmp[i--] = '0' + (val % 10); val /= 10; }
                if (neg) tmp[i--] = '-';
                const char *s = &tmp[i + 1];
                int len = 30 - i;
                for (int p = len; p < width; p++) PUT(zero_pad ? '0' : ' ');
                while (*s) PUT(*s++);
                break;
            }
            case 'u': {
                unsigned long val = __builtin_va_arg(ap, unsigned long);
                char tmp[32];
                int i = 30;
                tmp[31] = '\0';
                if (val == 0) tmp[i--] = '0';
                while (val > 0) { tmp[i--] = '0' + (val % 10); val /= 10; }
                const char *s = &tmp[i + 1];
                int len = 30 - i;
                for (int p = len; p < width; p++) PUT(zero_pad ? '0' : ' ');
                while (*s) PUT(*s++);
                break;
            }
            case 'x': case 'X': {
                unsigned long val = __builtin_va_arg(ap, unsigned long);
                const char *hex = (*( fmt - 1) == 'X') ? "0123456789ABCDEF" : "0123456789abcdef";
                char tmp[32];
                int i = 30;
                tmp[31] = '\0';
                if (val == 0) tmp[i--] = '0';
                while (val > 0) { tmp[i--] = hex[val & 0xf]; val >>= 4; }
                const char *s = &tmp[i + 1];
                int len = 30 - i;
                for (int p = len; p < width; p++) PUT(zero_pad ? '0' : ' ');
                while (*s) PUT(*s++);
                break;
            }
            case 's': {
                const char *s = __builtin_va_arg(ap, const char *);
                if (!s) s = "(null)";
                int len = 0;
                const char *t = s;
                while (*t++) len++;
                for (int p = len; p < width; p++) PUT(' ');
                while (*s) PUT(*s++);
                break;
            }
            case 'c': {
                char c = (char)__builtin_va_arg(ap, int);
                PUT(c);
                break;
            }
            case 'p': {
                unsigned long val = __builtin_va_arg(ap, unsigned long);
                PUT('0'); PUT('x');
                char tmp[32];
                int i = 30;
                tmp[31] = '\0';
                if (val == 0) tmp[i--] = '0';
                while (val > 0) { tmp[i--] = "0123456789abcdef"[val & 0xf]; val >>= 4; }
                const char *s = &tmp[i + 1];
                while (*s) PUT(*s++);
                break;
            }
            case '%': PUT('%'); break;
            default:  PUT('?'); break;
        }
    }

#undef PUT
    buf[pos] = '\0';
    return pos;
}

static inline void printf(const char *fmt, ...) {
    char buf[1024];
    __builtin_va_list ap;
    __builtin_va_start(ap, fmt);
    int len = vsnprintf_simple(buf, sizeof(buf), fmt, ap);
    __builtin_va_end(ap);
    sys_print(buf, len);
}

__attribute__((noreturn))
static inline void kill_sleep(void) {
    for (;;) { spin_pause(); }
}
