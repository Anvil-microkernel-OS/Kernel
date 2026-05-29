#include "../libOs/include/shared.h"
#include "cpio_parser.h"
#include "minimal_elf.h"

typedef struct {
    uint64_t self_vspace_cap;
    uint64_t self_cnode_cap;
    uint64_t self_thread_cap;
    uint64_t self_proc_cap;
    uint64_t self_domain_cap;
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

uint64_t allocate_user_stack(uint64_t slave_vspace_cap) {
    int64_t vmo = vmo_create(USER_STACK_SIZE, VmoPhysical);
    if (vmo < 0) {
        printf("Can not create VMO for stack\n");
        return -1;
    }

    mmap_args_t mmap_args = {
        .vscape_cap = slave_vspace_cap,
        .vmo_cap = (uint64_t)vmo,
        .vaddr = USER_STACK_TOP,              
        .size = USER_STACK_SIZE,
        .vmo_offset = 0,
        .flags = MAP_READ | MAP_WRITE
    };

    int64_t mapped = vma_map(&mmap_args);

    if (mapped < 0) {
        printf("Can not map user stack!\n");
        return -1;
    }

    return mapped;
}

int bootstrap_service(BootInfo_t* boot_info, const char* name, uint64_t init_domain_cap) {
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

    initial_capabilities_t caps;

    int64_t proc_cap = create_proc(boot_info->self_proc_cap, init_domain_cap, name, &caps);
    printf("Got process capability: %d\n", caps.proc_cap);
    printf("Got vspace capability: %d\n", caps.vspce_cap);

    if (proc_cap < 0) {
        printf("Can not create process for service: %s\n", name);
        return -1;
    }
    printf("Created new process for service: %s\n", name);

    int64_t thread_cap = create_thread(caps.proc_cap);
    if (thread_cap < 0) {
        printf("Can not create root thread for service: %s\n", name);
        return -1;
    }
    printf("Created new root thread for service: %s\n", name);

    int64_t elf_result = load_elf(elf_data, elf_size, boot_info->self_vspace_cap, caps.vspce_cap);

    if(elf_result < 0) {
        printf("Can not load elf to service: %s\n", name);
        return -1;
    }

    printf("Mapped elf for service: %s\n", name);

    int64_t stack_bottom_result = 0;//allocate_user_stack(caps.vspce_cap);

    if(stack_bottom_result < 0) {
        printf("Can not allocate stack for service: %s\n", name);
        return -1;
    }

    uint64_t entry_point = elf_result;
    general_purpose_registers_t regs;
    regs.rip = entry_point;
    regs.rsp = stack_bottom_result + USER_STACK_SIZE;

    if (write_tregs(thread_cap, &regs)) {
        printf("Can not write registers for service: %s\n", name);
        return -1;
    }

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
    
    int64_t domain_cap = create_domain(boot_info->self_domain_cap, "initial_env");
    if (domain_cap < 0) {
        printf("Can not create domain for init services\n");
        kill_sleep();
    }
    printf("Created domain for initial services group\n");

    for(int i = 0; i < servies_size; ++i) {
        if (!bootstrap_service(boot_info, bootstrap_services[i], domain_cap)) {
            kill_sleep();
        }
    }

    printf("All services booted. Halting...\n");

    kill_sleep();
}
