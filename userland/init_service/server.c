#include "../libOs/include/shared.h"
#include "cpio_parser.h"
#include "minimal_elf.h"

typedef struct {
    uint64_t self_tcb_cap;
    uint64_t self_vspace_cap;
    uint64_t self_cnode_cap;
    uint64_t ipc_buff_addr;
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

static int64_t allocate_user_stack(int slave_vspace, uint64_t stack_top, uint64_t stack_size) {
    int vmo = vmo_create(stack_size);
    if (vmo < 0) return -1;

    uint64_t stack_bottom = stack_top - stack_size;
    uint64_t ret = vma_map(slave_vspace, vmo, stack_bottom, MAP_READ | MAP_WRITE | MAP_USER);
    if (ret < 0) return -1;

    return stack_top; 
}

#define KEY_CLIENT 1

__attribute__((noreturn, section(".text._start")))
void _start(BootInfo_t* boot_info) {
    int64_t ret;

    printf("Init process started!\n");

    printf("Detecting cpio...\n");
    if (boot_info->cpio_base_addr == 0 || boot_info->cpio_size == 0) {
        printf("No CPIO found!\n");
        kill_sleep();
    }
    printf("CPIO found at 0x%x, size %d bytes\n",
           (uint64_t)boot_info->cpio_base_addr, (int)boot_info->cpio_size);

    uint64_t elf_size = 0;
    const uint8_t *elf_data = cpio_find(
        (const uint8_t *)boot_info->cpio_base_addr,
        boot_info->cpio_size,
        "name_server/server.elf",
        &elf_size
    );
    if (!elf_data) {
        printf("server.elf not found in CPIO!\n");
        kill_sleep();
    }
    printf("Found server.elf: %d bytes at 0x%x\n", (int)elf_size, (uint64_t)elf_data);

    ret = tcb_create();
    if (ret < 0) {
        printf("Failed to create TCB: %d\n", ret);
        kill_sleep();
    }

    uint64_t *slots = (uint64_t *)boot_info->ipc_buff_addr;
    int tcb_slave_slot    = slots[0];
    int vspace_slave_slot = slots[1];
    int cnode_slave_slot  = slots[2];
    printf("Slave caps: tcb=%d vspace=%d cnode=%d\n",
           tcb_slave_slot, vspace_slave_slot, cnode_slave_slot);

    int ipc_vmo = vmo_create(0x1000);
    if (ipc_vmo < 0) {
        printf("Failed to create IPC VMO: %d\n", ipc_vmo);
        kill_sleep();
    }

    ret = vma_map(vspace_slave_slot, ipc_vmo, 0x0000, MAP_READ | MAP_WRITE | MAP_USER);
    if (ret < 0) {
        printf("Failed to map slave ipc_buff: %d\n", ret);
        kill_sleep();
    }
    uint64_t slave_ipc_vaddr = (uint64_t)ret;
    printf("Slave ipc_buff mapped at 0x%x\n", slave_ipc_vaddr);

    ret = tcb_configure(tcb_slave_slot, vspace_slave_slot, slave_ipc_vaddr, ipc_vmo);
    if (ret < 0) {
        printf("Failed to configure TCB: %d\n", ret);
        kill_sleep();
    }

    uint64_t entry = load_elf(elf_data, elf_size,
                              boot_info->self_vspace_cap,
                              vspace_slave_slot);
    if (entry < 0) {
        printf("Failed to load ELF\n");
        kill_sleep();
    }
    printf("ELF loaded, entry=0x%x\n", entry);

    int stack_vmo = vmo_create(USER_STACK_SIZE);
    if (stack_vmo < 0) {
        printf("Failed to create stack VMO\n");
        kill_sleep();
    }

    uint64_t stack_bottom = USER_STACK_TOP - USER_STACK_SIZE;
    ret = vma_map(vspace_slave_slot, stack_vmo, stack_bottom, MAP_READ | MAP_WRITE | MAP_USER);
    if (ret < 0) {
        printf("Failed to map slave stack\n");
        kill_sleep();
    }
    printf("Slave stack mapped at 0x%x (size 0x%x)\n", stack_bottom, USER_STACK_SIZE);

    int64_t init_stack_map = vma_map(boot_info->self_vspace_cap, stack_vmo, 0,
                                     MAP_READ | MAP_WRITE | MAP_USER);
    if (init_stack_map < 0) {
        printf("Failed to map slave stack into init vspace\n");
        kill_sleep();
    }

    uint64_t slave_tcb_slot = cap_copy(boot_info->self_cnode_cap, cnode_slave_slot, tcb_slave_slot);
    uint64_t slave_vspace_slot = cap_copy(boot_info->self_cnode_cap, cnode_slave_slot, vspace_slave_slot);
    uint64_t slave_cnode_slot = cap_copy(boot_info->self_cnode_cap, cnode_slave_slot, cnode_slave_slot);

    printf("slave_tcb_slot: %d, slave_vspace_slot: %d, slave_cnode_slot: %d\n", slave_tcb_slot, slave_vspace_slot, slave_cnode_slot);

    channel_h_pair_t pair;

    if (channel_open(&pair) < 0) {
        printf("Failed to open channel\n");
        kill_sleep();
    }

    printf("Server end: %d | client end: %d\n", pair.src_cap, pair.dst_cap);

    int64_t port = port_create();

    if (port < 0) {
        printf("Failed to create port\n");
        kill_sleep();
    }

    int64_t res = port_bind(port, pair.src_cap, KEY_CLIENT);

    if (res < 0) {
        port_close(port);
        printf("Failed to bind port to server_end\n");
        kill_sleep();
    }

    uint64_t slave_channel_cap = cap_copy(boot_info->self_cnode_cap, cnode_slave_slot, pair.dst_cap);

    UserBootInfo slave_boot = {
        .self_tcb_cap    = slave_tcb_slot,
        .self_vspace_cap = slave_vspace_slot,
        .self_cnode_cap  = slave_cnode_slot,
        .test_cap_messaging = slave_channel_cap
    };

    uint64_t slave_rsp = USER_STACK_TOP;
    slave_rsp -= sizeof(UserBootInfo);
    slave_rsp &= ~0xF;
    uint64_t boot_info_addr = slave_rsp;  

    uint64_t offset_from_top = USER_STACK_TOP - slave_rsp;
    uint64_t init_write_addr = (uint64_t)init_stack_map + USER_STACK_SIZE - offset_from_top;
    memcpy((void *)init_write_addr, &slave_boot, sizeof(UserBootInfo));

    ret = vma_unmap(boot_info->self_vspace_cap, init_stack_map);
    if (ret < 0) {
        printf("Failed to unmap slave stack from init\n");
        kill_sleep();
    }

    slave_rsp -= 8;

    printf("Pushed boot info to slave proc\n");

    uint64_t *regs = (uint64_t *)boot_info->ipc_buff_addr;
    regs[0] = slave_rsp;        
    regs[1] = entry;             
    regs[2] = boot_info_addr;   

    ret = tcb_set_regs(tcb_slave_slot);
    if (ret < 0) {
        printf("Failed to set TCB registers: %d\n", ret);
        kill_sleep();
    }

    ret = tcb_resume(tcb_slave_slot);
    if (ret < 0) {
        printf("Failed to resume TCB: %d\n", ret);
        kill_sleep();
    }

    printf("Slave process started, init going message handling...\n");

    while(1) {
        port_packet_t packet;

        int64_t res = port_wait(port, 0, &packet);

        if (res < 0) {
            port_unbind(port, pair.src_cap);
            printf("Somethig was wrong, when woke up\n");
            spin_pause();
        }

        if (packet.key == KEY_CLIENT) {
            switch (packet.event) {
                case PORT_EVENT_READABLE: {
                    channel_message_t msg;
                    channel_read(pair.src_cap, &msg);

                    printf("Handled message with label: 0x%x\n", msg.label);
                    printf("Messase: [0]: %d [1]: %d [2]: %d [3]: %d [4]: %d\n", msg.data[0], msg.data[1], msg.data[2], msg.data[3], msg.data[4]);
                    if (msg.label == 0x900) {
                        uint64_t reply_cap = msg.data[0];
                        channel_message_t reply = {
                            .label = 0x100,
                            .data  = { 0, 0, 0, 0, 0 },
                        };
                        channel_write(reply_cap, &reply);
                    }
                break;
                    break;
                }
                case PORT_EVENT_PEER_CLOSED: {
                    printf("Client closed his port. Going dead idle...\n");
                    spin_pause();
                    break;
                }
            }
        }
    }
}
