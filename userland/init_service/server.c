#include "../libOs/include/shared.h"
#include "cpio_parser.h"
#include "minimal_elf.h"

typedef struct {
    uint64_t self_vspace_cap;
    uint64_t self_cnode_cap;
    uint64_t self_thread_cap;
    uint64_t self_proc_cap;
    uint64_t cpio_base_addr;
    uint64_t cpio_size;
} BootInfo_t;

typedef struct {
    uint64_t self_tcb_cap;
    uint64_t self_vspace_cap;
    uint64_t self_cnode_cap;

    uint64_t test_cap_messaging;
} UserBootInfo;

#define USER_STACK_TOP  0x7FFFFFFFC000
#define USER_STACK_SIZE 0x4000

uint64_t allocate_user_stack() {
    return 0;
}

uint64_t create_root_thread() {
    return 0;
}

int bootstrap_service(BootInfo_t* boot_info, const char* name) {
    uint64_t elf_size = 0;

    const uint8_t *elf_data = cpio_find(
        (const uint8_t *)boot_info->cpio_base_addr,
        boot_info->cpio_size,
        name,
        &elf_size
    );
    if (!elf_data) {
        printf("%s not found in CPIO!\n", name);
        return -1;
    }

    printf("Found %s: %d bytes at 0x%x\n", name, (int)elf_size, (uint64_t)elf_data);

    int64_t thread_cap = create_thread();

    if (thread_cap < 0) {
        printf("Can not create root thread for service: %s\n", name);
        return -1;
    }
    uint64_t slave_cnode = 0;

    /*int64_t proc_cap = create_proc(boot_info->self_proc_cap, thread_cap, name, sizeof(name), &slave_cnode);

    if (proc_cap < 0) {
        printf("Can not create process: %s\n", name);
        return -1;
    }

    printf("Got slave cnode cap: %d\n", slave_cnode);

    uint64_t slave_proc_slot = cap_copy(boot_info->self_cnode_cap, slave_cnode, boot_info->self_proc_cap);
    uint64_t slave_thread_slot = cap_copy(boot_info->self_cnode_cap, slave_cnode, boot_info->self_thread_cap);
    int64_t slave_vspace_slot = cap_copy(boot_info->self_cnode_cap, slave_cnode, boot_info->self_vspace_cap);

    printf("Capability copied!\n");

    uint64_t entry = load_elf(elf_data, elf_size,
                              boot_info->self_vspace_cap,
                              slave_vspace_slot);
    
    printf("ELF loaded!\n");*/

    return 0;
}

const int servies_size = 1;
const char* bootstrap_services[1] = {
    "name_server/server.elf"
};

__attribute__((noreturn, section(".text._start")))
void _start(BootInfo_t* boot_info) {
    int64_t ret;

    printf("Init process started!\n");

    printf("Validating cpio info...\n");
    if (boot_info->cpio_base_addr == 0 || boot_info->cpio_size == 0) {
        printf("No CPIO found!\n");
        kill_sleep();
    }
    printf("CPIO found at 0x%x, size %d bytes\n",
           (uint64_t)boot_info->cpio_base_addr, (int)boot_info->cpio_size);
    
    for(int i = 0; i < servies_size; ++i) {
        if (!bootstrap_service(boot_info, bootstrap_services[i])) {
            kill_sleep();
        }
    }

    printf("All services booted. Halting...\n");

    kill_sleep();
}
