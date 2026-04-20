#include "../libOs/include/shared.h"
#include "keyboard_handler.h"

typedef struct {
    uint64_t self_tcb_cap;
    uint64_t self_vspace_cap;
    uint64_t self_cnode_cap;

    uint64_t test_cap_messaging;
} UserBootInfo;

static Ps2KeyboardState kbd;

void on_key(KeyEvent ev, void *userdata) {
    if (ev.type != KEY_EVENT_PRESS) return;
    char c = ps2_key_to_ascii(ev);
    if (c == 0) return; 

    putchar(c);
}

__attribute__((noreturn, section(".text._start")))
void _start(UserBootInfo* boot_info) {
    printf("\nName server process started!\n");

    printf("Got capabilities from master! self_tcb_cap: %d, self_vspace_cap: %d, self_cnode_cap: %d\n", boot_info->self_tcb_cap, boot_info->self_vspace_cap, boot_info->self_cnode_cap);

    /*int vmo_idx = vmo_create(4096);

    int64_t ret = vma_map(boot_info->self_vspace_cap, vmo_idx, 0x0, MAP_READ | MAP_WRITE); 

    if (ret < 0) {
        printf("Failed to allocate memory!\n");
        kill_sleep();
    }

    printf("Allocated memory at addr: 0x%x!\n", (uint64_t)ret);

    uint64_t* start = (uint64_t*)ret;

    (*start) = 0xCAFEBABE;

    printf("Wrote data: 0x%x\n", (*start));

    vma_unmap(boot_info->self_vspace_cap, ret);*/

    printf("Testing channel messaging...\n");

    channel_message_t msg = {
        .label   = 0x1337,
        .data    = { 67, 68, 69, 70, 71 },
    };
    sleep(1000000000); 
    int64_t res = channel_write(boot_info->test_cap_messaging, &msg);
    if (res < 0) {
        printf("Failed to write to channel\n");
        kill_sleep();
    }

    ps2_keyboard_init(&kbd, on_key, NULL);

    int64_t port = port_create();

    if (irq_bind_to_port(port, 150, 0x1337) < 0) {
        port_close(port);
        printf("Failed to bind port to irq 150\n");
        kill_sleep();
    }

    res = io_port_enable(0x60);
    if (res < 0) {
        printf("Somethig was wrong, when enabling port\n");
        spin_pause();
    }

    while(1) {  
        port_packet_t packet;

        int64_t res = port_wait(port, 0, &packet);

        if (res < 0) {
            //unbind
            printf("Somethig was wrong, when woke up\n");
            spin_pause();
        }

        if (packet.key == 0x1337) {
            uint8_t val = inb(0x60);

            if (val < 0) {
                printf("Somethig was wrong, when read port\n");
                spin_pause();
            }

            ps2_keyboard_handle_byte(&kbd, val);
        }
    }

    kill_sleep();
}
