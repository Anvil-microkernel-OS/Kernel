use core::arch::naked_asm;

#[derive(Debug, Default)]
#[repr(C)]
#[allow(dead_code)]
pub struct ThreadRegisters {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,

    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,

    pub syscall_number_or_irq_or_error_code: u64,

    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

impl ThreadRegisters {
    pub fn get_stack_ptr(&self) -> u64 {
        self.rsp
    }

    pub fn get_instr_ptr(&self) -> u64 {
        self.rip
    }

    pub fn set_stack_ptr(&mut self, val: u64) {
        self.rsp = val;
    }

    pub fn set_instr_ptr(&mut self, val: u64) {
        self.rip = val;
    }
}

#[unsafe(naked)]
pub unsafe extern "C" fn switch_to_task(
    previous_task_stack_pointer: *const u64,
    next_task_stack_pointer: u64,
    next_page_table: u64,
) {
    naked_asm!(
        "push rax", "push rbx", "push rcx", "push rdx",
        "push rbp", "push rsi", "push rdi",
        "push r8",  "push r9",  "push r10", "push r11",
        "push r12", "push r13", "push r14", "push r15",
        "mov [rdi], rsp",
        "mov rsp, rsi",
        "mov cr3, rdx",
        "pop r15", "pop r14", "pop r13", "pop r12",
        "pop r11", "pop r10", "pop r9",  "pop r8",
        "pop rdi", "pop rsi", "pop rbp", "pop rdx",
        "pop rcx", "pop rbx", "pop rax",
        "ret",
    );
}