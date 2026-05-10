use core::{cell::UnsafeCell, sync::atomic::{AtomicU32, AtomicU64, Ordering}};

use alloc::sync::Arc;
use spin::rwlock::RwLock;

use crate::{arch::amd64::{capability_sys::{cap_resolver::{resolve_process, resolve_thread}, capability::{CapType, Capability, Rights}, cnode::CapIdx}, memory::u_k_boundary::uaccsess::copy_from_user, scheduler::{exec_loader::prepare_new_thread, sleep, stack::{DEFAULT_KERNEL_STACK_SIZE, allocate_kernel_stack}, syscall::{SyscallArguments, SyscallError, get_curr_exec_ctx, threads::info::GeneralGroupRegisters}, task::{AtomicThreadState, Thread, ThreadRegisters, ThreadState}, task_storage::{register_thread, spawn_thread}}}, define_syscall_group};

define_syscall_group! {
    pub enum ThreadActionSyscalls {
        ThreadCreate = 7,
        ThreadWriteRegs = 8,
        ThreadRun = 9,
        ThreadExit = 10,
        ThreadSleep = 19
    }
}

static NEXT_TID: AtomicU32 = AtomicU32::new(1);

fn handle_thread_create(proc_cap: CapIdx) -> Result<u64, SyscallError> {
    let ctx = get_curr_exec_ctx();

    let target_obj = resolve_process(&ctx.1.cnode, proc_cap, Rights::WRITE).map_err(|err| err.to_syscall_error())?;

    let kernel_stack  = allocate_kernel_stack(DEFAULT_KERNEL_STACK_SIZE);

    let new_thread = Arc::new(Thread {
        parent_proc: RwLock::new(Arc::downgrade(&target_obj.0)),
        tid: NEXT_TID.fetch_add(1, Ordering::Relaxed),
        wake_at_tick: AtomicU64::new(0),
        kernel_stack,
        registers: UnsafeCell::new(ThreadRegisters {
            ..ThreadRegisters::default()
        }),
        state: AtomicThreadState::new(ThreadState::Configuring)
    });

    target_obj.0.threads.lock().push(Arc::downgrade(&new_thread));

    register_thread(&new_thread);

    let slot = target_obj.0.cnode.alloc(Capability::new(CapType::Thread(new_thread), Rights::MANAGE));

    Ok(slot as u64)
}

fn handle_thread_write_registers(proc_cap: CapIdx, regs_ptr: u64) -> Result<u64, SyscallError> {
    let ctx = get_curr_exec_ctx();

    let target_obj = resolve_thread(&ctx.1.cnode, proc_cap, Rights::WRITE).map_err(|err| err.to_syscall_error())?;

    if target_obj.0.state.load(Ordering::Acquire) != ThreadState::Configuring {
        return Err(SyscallError::InvalidArgument);
    }

    let registers = copy_from_user::<GeneralGroupRegisters>(regs_ptr as usize).ok_or(SyscallError::InvalidArgument)?;

    unsafe {
        let regs = target_obj.0.registers.get();
        (*regs).rax = registers.rax;
        (*regs).rbx = registers.rbx;
        (*regs).rcx = registers.rcx;
        (*regs).rdx = registers.rdx;
        (*regs).rsi = registers.rsi;
        (*regs).rdi = registers.rdi;
        (*regs).rbp = registers.rbp;
        (*regs).rsp = registers.rsp;
        (*regs).r8  = registers.r8;
        (*regs).r9  = registers.r9;
        (*regs).r10 = registers.r10;
        (*regs).r11 = registers.r11;
        (*regs).r12 = registers.r12;
        (*regs).r13 = registers.r13;
        (*regs).r14 = registers.r14;
        (*regs).r15 = registers.r15;
        (*regs).rip = registers.rip;
        (*regs).rflags = registers.rflags;
    }

    Ok(0)
}

fn handle_thread_run(proc_cap: CapIdx) -> Result<u64, SyscallError> {
    let ctx = get_curr_exec_ctx();

    let target_obj = resolve_thread(&ctx.1.cnode, proc_cap, Rights::WRITE).map_err(|err| err.to_syscall_error())?;

    if ctx.0.tid == target_obj.0.tid {
        return Err(SyscallError::InvalidArgument);
    }

    if target_obj.0.state.load(Ordering::Acquire) != ThreadState::Configuring {
        return Err(SyscallError::InvalidArgument);
    }

    target_obj.0.state.store(ThreadState::Ready, Ordering::Relaxed);

    prepare_new_thread(&target_obj.0);

    spawn_thread(target_obj.0);

    Ok(0)
}

fn handle_thread_exit(capability: CapIdx) -> Result<u64, SyscallError> {
    unimplemented!()
}

fn handle_thread_sleep(nanosecs: u64) -> Result<u64, SyscallError> {
    sleep(nanosecs);
    return Ok(0)
}

pub fn dispatch_thread_actions_syscall_group(syscall: ThreadActionSyscalls, args: &SyscallArguments) -> Result<u64, SyscallError> {
    match syscall {
        ThreadActionSyscalls::ThreadCreate => handle_thread_create(args.arg1 as u32),
        ThreadActionSyscalls::ThreadWriteRegs => handle_thread_write_registers(args.arg1 as u32, args.arg2),
        ThreadActionSyscalls::ThreadRun => handle_thread_run(args.arg1 as u32),
        ThreadActionSyscalls::ThreadExit => handle_thread_exit(args.arg1 as u32),
        ThreadActionSyscalls::ThreadSleep => handle_thread_sleep(args.arg1)
    }
}