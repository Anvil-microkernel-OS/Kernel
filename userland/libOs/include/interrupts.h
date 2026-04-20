#pragma once

#include "syscalls.h"
#include "types.h"

#define SYS_BIND_IRQ_TO_PORT 35
#define SYS_UNBIND_IRQ_FROM_PORT 36
#define SYS_ACK_IRQ 37

static int64_t irq_bind_to_port(uint64_t port, uint64_t vector, uint64_t key) {
    return syscall3(SYS_BIND_IRQ_TO_PORT, port, vector, key);
}

static int64_t irq_unbind_irq_from_port(uint64_t port, uint64_t vector) {
    return syscall2(SYS_UNBIND_IRQ_FROM_PORT, port, vector);
}

static void irq_ack(uint64_t vector) {
    (void)syscall1(SYS_ACK_IRQ, vector);
}