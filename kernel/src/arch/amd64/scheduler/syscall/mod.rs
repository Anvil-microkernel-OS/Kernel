use core::arch::naked_asm;

use alloc::{format, sync::Arc};
use spin::Mutex;
use x86_64::{VirtAddr, registers::{control::{Efer, EferFlags}, model_specific::{LStar, SFMask}, rflags::RFlags}};

use crate::{arch::amd64::{gdt::{USER_CODE_SELECTOR, USER_DATA_SELECTOR}, scheduler::{PerCpuSchedulerData, syscall::{capability::action::CapabilityActionSyscalls, interrupts::action::IrqSyscallNumbers, io::IoPortSyscalls, memory::{vma::MemorySyscallNumbers, vmo::MemoryVmoSyscalls}, messaging::{channel::ChannelSyscallNumbers, port::PortSyscallNumbers}, processes::{action::ProcessActionSyscalls, info::ProcessInfoSyscalls}, threads::{actions::ThreadActionSyscalls, info::ThreadInfoSyscalls}}, task::{Process, Thread, ThreadRegisters}, task_storage::{get_process, get_thread}}}, define_per_cpu_u64, early_print, early_println, register_syscall_groups};

pub mod syscall_groups;
pub mod messaging;
mod interrupts;
mod threads;
mod processes;
mod memory;
mod capability;
mod io;

use threads::info::_SYSCALL_GROUP as THREAD_INFO_SYSCALL_GROUP;
use threads::actions::_SYSCALL_GROUP as THREAD_ACTIONS_SYSCALL_GROUP;

use processes::info::_SYSCALL_GROUP as PROC_INFO_SYSCALL_GROUP;
use processes::action::_SYSCALL_GROUP as PROC_ACTION_SYSCALL_GROUP;

use memory::vma::_SYSCALL_GROUP as MEMORY_VMA_SYSCALL_GROUP;
use memory::vmo::_SYSCALL_GROUP as MEMORY_VMO_SYSCALL_GROUP;

use capability::action::_SYSCALL_GROUP as CAPABILITY_ACTION_SYSCALL_GROUP;

use interrupts::action::_SYSCALL_GROUP as IRQ_SYSCALL_GROUP;

use io::_SYSCALL_GROUP as IO_PORTS_SYSCALL_GROUP;

use messaging::channel::_SYSCALL_GROUP as MESSAGING_CHNL_SYSCALL_GROUP;
use messaging::port::_SYSCALL_GROUP as MESSAGING_PORT_SYSCALL_GROUP;

#[repr(i64)]
pub (crate) enum SyscallError {
    InvalidHandle = -1,
    PermissionDenied = -2,
    OutOfMemory = -3,
    InvalidArgument = -4,
    BufferTooSmall = -5,
    AlreadyExists = -6,
    NotFound = -7,
    ResourceExhausted = -8,
    Timeout = -9,
    Fault = -10,
}

struct IpcSyscallArguments {
    ep_id: u64,
    msg: [u64; 4],
}

#[derive(Debug)]
struct SyscallArguments {
    syscall_number: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
}

register_syscall_groups! {
    THREAD_INFO_SYSCALL_GROUP,
    PROC_INFO_SYSCALL_GROUP,
    THREAD_ACTIONS_SYSCALL_GROUP,
    MEMORY_VMA_SYSCALL_GROUP,
    MEMORY_VMO_SYSCALL_GROUP,
    CAPABILITY_ACTION_SYSCALL_GROUP,
    IRQ_SYSCALL_GROUP,
    IO_PORTS_SYSCALL_GROUP,
    MESSAGING_CHNL_SYSCALL_GROUP,
    MESSAGING_PORT_SYSCALL_GROUP,
    PROC_ACTION_SYSCALL_GROUP,
    &[25] // debug printf
}

pub trait IntoSyscallReturn {
    fn into_syscall_return(self) -> u64;
}

impl<T: Into<u64>> IntoSyscallReturn for Result<T, SyscallError> {
    fn into_syscall_return(self) -> u64 {
        match self {
            Ok(val) => val.into(),
            Err(err) => (err as i64) as u64,
        }
    }
}

static LOCK: Mutex<()> = Mutex::new(());

fn handle_debug_print(ptr: u64, len: u64) -> Result<u64, SyscallError> {
    let _guard = LOCK.lock();
    
    if ptr < 0x1000 || ptr > 0x0000_7FFF_FFFF_FFFF {
        return Err(SyscallError::InvalidArgument);
    }
    if len > 4096 {
        return Err(SyscallError::InvalidArgument);
    }

    let slice = unsafe { core::slice::from_raw_parts(ptr as *const u8, len as usize) };

    for &byte in slice {
        if byte == 0 { break; }
        early_print!("{}", byte as char);
    }
    Ok(0)
}

pub (crate) fn get_curr_exec_ctx() -> (Arc<Thread>, Arc<Process>) {
    let curr_tid = PerCpuSchedulerData::get().curr_thread_id;
    let curr_thread = get_thread(curr_tid).expect(format!("FATAL ERROR: NO THREAD FOUND FOR TID: {}", curr_tid).as_str());
    let curr_proc = curr_thread.parent_proc.read().upgrade().expect(format!("FATAL ERROR: NO PROCESS FOUND FROM TID: {}", curr_tid).as_str());

    return (curr_thread, curr_proc)
}

fn syscall_dispatcher(registers: &mut ThreadRegisters, args: &SyscallArguments) -> u64 {
    if let Ok(syscall) = ThreadInfoSyscalls::try_from(args.syscall_number) {
        return threads::info::dispatch_thread_info_syscall_group(syscall, args)
            .into_syscall_return();
    }

    if let Ok(syscall) = ThreadActionSyscalls::try_from(args.syscall_number) {
        return threads::actions::dispatch_thread_actions_syscall_group(syscall, args)
            .into_syscall_return();
    }

    if let Ok(syscall) = ProcessInfoSyscalls::try_from(args.syscall_number) {
        return processes::info::dispatch_process_info_syscall_group(syscall, args)
            .into_syscall_return();
    }

    if let Ok(syscall) = ProcessActionSyscalls::try_from(args.syscall_number) {
        return processes::action::dispatch_process_action_syscalls(syscall, args)
            .into_syscall_return();
    }

    if let Ok(syscall) = MemorySyscallNumbers::try_from(args.syscall_number) {
        return memory::vma::dispatch_vma_memory_syscall_group(syscall, args)
            .into_syscall_return();
    }

    if let Ok(syscall) = MemoryVmoSyscalls::try_from(args.syscall_number) {
        return memory::vmo::dispatch_vmo_memory_syscall_group(syscall, args)
            .into_syscall_return();
    }

    if let Ok(syscall) = CapabilityActionSyscalls::try_from(args.syscall_number) {
        return capability::action::dispatch_capability_action_syscalls(syscall, args)
            .into_syscall_return();
    }

    if let Ok(syscall) = IrqSyscallNumbers::try_from(args.syscall_number) {
        return interrupts::action::dispatch_irq_syscall_group(syscall, args)
            .into_syscall_return();
    }

    if let Ok(syscall) = IoPortSyscalls::try_from(args.syscall_number) {
        return io::dispatch_port_syscall_group(syscall, args)
            .into_syscall_return();
    }

    if let Ok(syscall) = PortSyscallNumbers::try_from(args.syscall_number) {
        return messaging::port::dispatch_port_syscall_group(syscall, args, registers)
            .into_syscall_return();
    }

    if let Ok(syscall) = ChannelSyscallNumbers::try_from(args.syscall_number) {
        return messaging::channel::dispatch_channel_syscall_group(syscall, args, registers)
            .into_syscall_return();
    }

    if args.syscall_number == 25 {
        return handle_debug_print(args.arg1, args.arg2).into_syscall_return();
    }

    let ctx = get_curr_exec_ctx();

    early_println!("Unknown syscall: {} tid={} pid={}", args.syscall_number, ctx.0.tid, ctx.1.pid);
    (SyscallError::InvalidHandle as i64) as u64
}

pub fn init_syscall_subsystem() {
    set_per_cpu_USER_STACK_SCRATCH(0);
    unsafe {
        Efer::update(|efer| {
            *efer |= EferFlags::SYSTEM_CALL_EXTENSIONS;
        });
    }

    SFMask::write(RFlags::INTERRUPT_FLAG);

    let syscall_handler_addr = VirtAddr::new(syscall_handler as u64);
    LStar::write(syscall_handler_addr);
}

define_per_cpu_u64!(
    pub(super) TOP_OF_KERNEL_STACK
);

define_per_cpu_u64!(
    pub(super) USER_STACK_SCRATCH
);

#[unsafe(naked)]
pub(super) unsafe extern "C" fn syscall_handler() {
    naked_asm!(
        "swapgs",
        "mov gs:{user_stack_scratch}, rsp",
        "mov rsp, gs:{kernel_stack}",

        // iret frame
        "push {user_data_selector}",    // SS
        "push gs:{user_stack_scratch}", // RSP
        "push r11",                     // RFLAGS
        "push {user_code_selector}",    // CS
        "push rcx",                     // RIP

        "push rax",                     

        "push rdi",
        "push rsi",
        "push rdx",
        "push rcx",
        "push rax",
        "push r8",
        "push r9",
        "push r10",
        "push r11",
        "push rbx",
        "push rbp",
        "push r12",
        "push r13",
        "push r14",
        "push r15",

        "mov rdi, rsp",
        "call {syscall_handler_inner}",

        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rax",
        "pop rcx",
        "pop rdx",
        "pop rsi",
        "pop rdi",

        "pop rax",

        "pop rcx",                     
        "add rsp, 8",                   
        "pop r11",                      
        "pop rsp",                      

        "swapgs",
        "sysretq",

        kernel_stack = sym TOP_OF_KERNEL_STACK,
        user_data_selector = const USER_DATA_SELECTOR.0,
        user_code_selector = const USER_CODE_SELECTOR.0,
        user_stack_scratch = sym USER_STACK_SCRATCH,
        syscall_handler_inner = sym syscall_handler_inner,
    )
}

extern "C" fn syscall_handler_inner(registers: &mut ThreadRegisters) {
    let args = SyscallArguments {
        syscall_number: registers.syscall_number_or_irq_or_error_code,
        arg1: registers.rdi,
        arg2: registers.rsi,
        arg3: registers.rdx,
        arg4: registers.r10,
        arg5: registers.r8,
    };

    registers.syscall_number_or_irq_or_error_code = syscall_dispatcher(registers, &args);
}