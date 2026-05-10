use core::sync::atomic::Ordering;

use crate::{arch::amd64::{capability_sys::{cap_resolver::resolve_thread, capability::Rights, cnode::CapIdx}, memory::u_k_boundary::uaccsess::copy_to_user, scheduler::{syscall::{SyscallArguments, SyscallError, get_curr_exec_ctx}}}, define_syscall_group};

define_syscall_group! {
    pub enum ThreadInfoSyscalls {
        ThreadGetTid = 1,
        ThreadGetState = 2,
        ThreadGetRegisters = 3
    }
}

fn handle_get_tid(capability: CapIdx) -> Result<u64, SyscallError> {
    let ctx = get_curr_exec_ctx();

    let target_obj = resolve_thread(&ctx.1.cnode, capability, Rights::READ).map_err(|err| err.to_syscall_error())?;

    Ok(target_obj.0.tid as u64)
}

fn handle_get_state(capability: CapIdx) -> Result<u64, SyscallError> {
    let ctx = get_curr_exec_ctx();

    let target_obj = resolve_thread(&ctx.1.cnode, capability, Rights::READ).map_err(|err| err.to_syscall_error())?;

    Ok(target_obj.0.state.load(Ordering::Acquire) as u64)
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct GeneralGroupRegisters {
    pub rax:    u64, 
    pub rbx:    u64,
    pub rcx:    u64,
    pub rdx:    u64,
    pub rsi:    u64,
    pub rdi:    u64,
    pub rbp:    u64,
    pub rsp:    u64,
    pub r8:     u64,
    pub r9:     u64,
    pub r10:    u64,
    pub r11:    u64,
    pub r12:    u64,
    pub r13:    u64,
    pub r14:    u64,
    pub r15:    u64,
    pub rip:    u64,
    pub rflags: u64,
}

fn handle_get_registers(capability: CapIdx, struct_ptr: u64) -> Result<u64, SyscallError> {
    let ctx = get_curr_exec_ctx();

    let target_obj = resolve_thread(&ctx.1.cnode, capability, Rights::READ).map_err(|err| err.to_syscall_error())?;

    let curr_registers = unsafe{ &*target_obj.0.registers.get() };

    let result = copy_to_user::<GeneralGroupRegisters>(struct_ptr as usize, GeneralGroupRegisters {
        rax:    curr_registers.rax, 
        rbx:    curr_registers.rbx,
        rcx:    curr_registers.rcx,
        rdx:    curr_registers.rdx,
        rsi:    curr_registers.rsi,
        rdi:    curr_registers.rdi,
        rbp:    curr_registers.rbp,
        rsp:    curr_registers.rsp,
        r8:     curr_registers.r8,
        r9:     curr_registers.r9,
        r10:    curr_registers.r10,
        r11:    curr_registers.r11,
        r12:    curr_registers.r12,
        r13:    curr_registers.r13,
        r14:    curr_registers.r14,
        r15:    curr_registers.r15,
        rip:    curr_registers.rip,
        rflags: curr_registers.rflags,
    });

    if result != true {
        return Err(SyscallError::Fault);
    }

    Ok(0)
}

pub fn dispatch_thread_info_syscall_group(syscall: ThreadInfoSyscalls, args: &SyscallArguments) -> Result<u64, SyscallError> {
    match syscall {
        ThreadInfoSyscalls::ThreadGetRegisters => handle_get_registers(args.arg1 as u32, args.arg2),
        ThreadInfoSyscalls::ThreadGetState     => handle_get_state(args.arg1 as u32),
        ThreadInfoSyscalls::ThreadGetTid       => handle_get_tid(args.arg1 as u32)
    }
}