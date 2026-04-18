#include "../libOs/include/shared.h"

typedef struct {
    uint64_t self_tcb_cap;
    uint64_t self_vspace_cap;
    uint64_t self_cnode_cap;
} UserBootInfo;

__attribute__((noreturn, section(".text._start")))
void _start(UserBootInfo* boot_info) {
    printf("\nName server process started!\n");

    printf("Got capabilities from master! self_tcb_cap: %d, self_vspace_cap: %d, self_cnode_cap: %d\n", boot_info->self_tcb_cap, boot_info->self_vspace_cap, boot_info->self_cnode_cap);

    int vmo_idx = vmo_create(4096);

    int64_t ret = vma_map(boot_info->self_vspace_cap, vmo_idx, 0x0, MAP_READ | MAP_WRITE); 

    if (ret < 0) {
        printf("Failed to allocate memory!\n");
        kill_sleep();
    }

    printf("Allocated memory at addr: 0x%x!\n", (uint64_t)ret);

    uint64_t* start = (uint64_t*)ret;

    (*start) = 0xCAFEBABE;

    printf("Wrote data: 0x%x\n", (*start));

    vma_unmap(boot_info->self_vspace_cap, ret);

    kill_sleep();
}
