#pragma once

#include "syscalls.h"
#include "types.h"


#define SYS_IO_PORT_ENABLE 31
#define SYS_IO_PORT_DISABLE 32

static inline int64_t io_port_enable(uint64_t port) {
    return syscall1(SYS_IO_PORT_ENABLE, port);
}

static inline int64_t io_port_disable(uint64_t port) {
    return syscall1(SYS_IO_PORT_DISABLE, port);
}

static inline uint8_t inb(uint16_t port) {
    uint8_t val;
    __asm__ volatile("inb %1, %0" : "=a"(val) : "d"(port));
    return val;
}

static inline uint16_t inw(uint16_t port) {
    uint16_t val;
    __asm__ volatile("inw %1, %0" : "=a"(val) : "d"(port));
    return val;
}

static inline uint32_t inl(uint16_t port) {
    uint32_t val;
    __asm__ volatile("inl %1, %0" : "=a"(val) : "d"(port));
    return val;
}

static inline void outb(uint16_t port, uint8_t val) {
    __asm__ volatile("outb %0, %1" : : "a"(val), "d"(port));
}

static inline void outw(uint16_t port, uint16_t val) {
    __asm__ volatile("outw %0, %1" : : "a"(val), "d"(port));
}

static inline void outl(uint16_t port, uint32_t val) {
    __asm__ volatile("outl %0, %1" : : "a"(val), "d"(port));
}