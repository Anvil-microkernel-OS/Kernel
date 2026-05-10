use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use alloc::{string::String, sync::Arc};
use alloc::vec;
use spin::mutex::Mutex;
use spin::rwlock::RwLock;

use crate::arch::amd64::capability_sys::cnode::CapIdx;
use crate::arch::amd64::memory::u_k_boundary::uaccsess::copy_to_user;
use crate::arch::amd64::scheduler::task_storage::{get_process, spawn_thread};
use crate::{arch::amd64::{memory::{u_k_boundary::uaccsess::copy_slice_from_user, vmm::create_new_pt4_from_kernel_pt4}, scheduler::{addr_space::AddrSpace, exec_loader::phys_to_offset_page_table, syscall::{SyscallArguments, SyscallError}, task::{Process, ThreadState, Tid}, task_storage::{get_thread, register_process}}}, define_syscall_group};

define_syscall_group! {
    pub enum ProcessActionSyscalls {
        ProcCreate = 60,
        ProcStart = 61
    }
}

static NEXT_PID: AtomicU32 = AtomicU32::new(2);


fn handle_proc_create(
    capability: CapIdx,
    name_ptr: u64,
    name_len: u64,
    thread_cap: u64,
    slave_caps: u64,
) -> Result<u64, SyscallError> {
    todo!()
}

fn handle_proc_start(target_proc_cap: CapIdx) ->Result<u64, SyscallError> {
    todo!()
}

pub fn dispatch_process_action_syscalls(syscall: ProcessActionSyscalls, args: &SyscallArguments) ->Result<u64, SyscallError> {
    match syscall {
        ProcessActionSyscalls::ProcCreate => handle_proc_create(args.arg1 as u32, args.arg2, args.arg3, args.arg4, args.arg5),
        ProcessActionSyscalls::ProcStart => handle_proc_start(args.arg1 as u32)
    }
}