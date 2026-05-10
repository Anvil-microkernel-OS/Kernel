#include "../libOs/include/shared.h"

typedef struct {
    uint64_t self_tcb_cap;
    uint64_t self_vspace_cap;
    uint64_t self_cnode_cap;

    uint64_t test_cap_messaging;
} UserBootInfo;

__attribute__((noreturn, section(".text._start")))
void _start(UserBootInfo* boot_info) {
    printf("\nName server process started!\n");

    printf("Got capabilities from master! self_tcb_cap: %d, self_vspace_cap: %d, self_cnode_cap: %d\n", boot_info->self_tcb_cap, boot_info->self_vspace_cap, boot_info->self_cnode_cap);

    kill_sleep();
}
