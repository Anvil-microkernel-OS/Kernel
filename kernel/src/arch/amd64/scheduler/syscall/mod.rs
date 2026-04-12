use core::arch::naked_asm;

use spin::Mutex;
use x86_64::{VirtAddr, registers::{control::{Efer, EferFlags}, model_specific::{LStar, SFMask}, rflags::RFlags}};

use crate::{arch::amd64::{gdt::{USER_CODE_SELECTOR, USER_DATA_SELECTOR}, scheduler::{PerCpuSchedulerData, syscall::{cap_handler::CapSyscallNumbers, ipc_handlers::IpcSyscallNumbers, memory_handler::MemorySyscallNumbers, tcb::TcbSyscallNumbers, thread_handler::ThreadSyscallNums}, task::TaskRegisters}}, define_per_cpu_u64, early_print, early_println, register_syscall_groups};

mod ipc_handlers;
mod memory_handler;
mod thread_handler;
mod cap_check;
mod tcb;
mod cap_handler;
mod syscall_groups;

use cap_handler::_SYSCALL_GROUP as CAP_SYSCALL_GROUP;
use ipc_handlers::_SYSCALL_GROUP as IPC_SYSCALL_GROUP;
use memory_handler::_SYSCALL_GROUP as MEMORY_SYSCALL_GROUP;
use tcb::_SYSCALL_GROUP as TCB_SYSCALL_GROUP;
use thread_handler::_SYSCALL_GROUP as THREAD_SYSCALL_GROUP;

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
    CAP_SYSCALL_GROUP,
    IPC_SYSCALL_GROUP,
    MEMORY_SYSCALL_GROUP,
    TCB_SYSCALL_GROUP,
    THREAD_SYSCALL_GROUP,
    &[0x10] // debug printf
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

fn syscall_dispatcher(registers: &mut TaskRegisters, args: &SyscallArguments) -> u64 {
    let curr_task_id = PerCpuSchedulerData::get().curr_task_id.id();

    if let Ok(syscall) = MemorySyscallNumbers::try_from(args.syscall_number) {
        return memory_handler::dispatch_memory_syscall_group(syscall, curr_task_id, args)
            .into_syscall_return();
    }

    if let Ok(syscall) = IpcSyscallNumbers::try_from(args.syscall_number) {
        return ipc_handlers::dispatch_ipc_syscall_group(syscall, curr_task_id, args, registers)
            .into_syscall_return();
    }

    if let Ok(syscall) = ThreadSyscallNums::try_from(args.syscall_number) {
        return thread_handler::dispatch_thread_syscall_group(syscall, curr_task_id, args)
            .into_syscall_return();
    }

    if let Ok(syscall) = TcbSyscallNumbers::try_from(args.syscall_number) {
        return tcb::dispatch_tcb_syscall_group(syscall, curr_task_id, args)
            .into_syscall_return();
    }

    if let Ok(syscall) = CapSyscallNumbers::try_from(args.syscall_number) {
        return cap_handler::dispatch_cap_syscall_group(syscall, curr_task_id, args)
            .into_syscall_return();
    }

    if args.syscall_number == 0x10 {
        return handle_debug_print(args.arg1, args.arg2).into_syscall_return();
    }

    early_println!("Unknown syscall: {} task={}", args.syscall_number, curr_task_id);
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

extern "C" fn syscall_handler_inner(registers: &mut TaskRegisters) {
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