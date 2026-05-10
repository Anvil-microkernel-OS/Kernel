/*
int64_t curr_pid = get_pid(boot_info->self_proc_cap);
    size_t count = 0;
    int64_t result = _proc_get_threads_raw(boot_info->self_proc_cap, NULL, 0, &count);

    if (result < 0 || count == 0) {
        kill_sleep();
    }

    char proc_name[10];
    get_proc_name(boot_info->self_proc_cap, proc_name, 10);
    printf("Current PID: %d\n", curr_pid);
    printf("Process name: %s\n", proc_name);
    printf("Active threads for PID %d: %d\n", curr_pid, count);
    printf("ROOT THREAD id: %d\n", get_tid(boot_info->self_thread_cap));
    printf("ROOT THREAD state: %s\n", thread_state_to_str(get_tstate(boot_info->self_thread_cap)));

    int64_t thread_cap = create_thread();

    if (thread_cap < 0) {
        kill_sleep();
    }

    printf("new thread created! Capability: %d\n", thread_cap);

    int64_t stack_vmo = vmo_create(USER_STACK_SIZE, VmoPhysical);

    if (stack_vmo < 0) {
        printf("Failed to create stack VMO\n");
        kill_sleep();
    }
    
    printf("Created stack vmo\n");

    uint64_t stack_bottom = USER_STACK_TOP - USER_STACK_SIZE;

    mmap_args_t args = {
        .vscape_cap = boot_info->self_vspace_cap,
        .vmo_cap = stack_vmo,
        .vaddr = stack_bottom,
        .size = USER_STACK_SIZE,
        .vmo_offset = 0,
        .flags = MAP_WRITE | MAP_READ | MAP_USER
    };

    ret = vma_map(&args);
    if (ret < 0) {
        printf("Failed to map slave stack\n");
        kill_sleep();
    }

    printf("Mapped stack vmo\n");

    general_purpose_registers_t regs;
    regs.rsp = USER_STACK_TOP;
    regs.rip = (uint64_t)&another_thread;
    regs.rdi = thread_cap;
    regs.rflags = 0x202;
    result = write_tregs(thread_cap, &regs);

    printf("Regs wrote to stack vmo\n");

    if (result < 0) {
        printf("Failed to write thread regs: %d\n", result);
        kill_sleep();
    }

    int r2 = start_thread(thread_cap);

    if (r2 < 0) {
        printf("Failed to start new thread\n");
    }
*/