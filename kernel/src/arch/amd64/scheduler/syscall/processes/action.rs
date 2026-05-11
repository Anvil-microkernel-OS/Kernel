use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use alloc::{string::String, sync::Arc};
use alloc::vec::{Vec};
use spin::mutex::Mutex;

use crate::arch::amd64::capability_sys::cap_resolver::resolve_process;
use crate::arch::amd64::capability_sys::capability::{CapType, Capability, Rights};
use crate::arch::amd64::capability_sys::cnode::{CNode, CapIdx};
use crate::arch::amd64::scheduler::syscall::get_curr_exec_ctx;
use crate::{arch::amd64::{memory::{u_k_boundary::uaccsess::copy_slice_from_user, vmm::create_new_pt4_from_kernel_pt4}, scheduler::{addr_space::AddrSpace, exec_loader::phys_to_offset_page_table, syscall::{SyscallArguments, SyscallError}, task::{Process}, task_storage::{register_process}}}, define_syscall_group};

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
) -> Result<u64, SyscallError> {
    if name_len == 0 {
        return Err(SyscallError::BufferTooSmall)
    }

    let mut name = String::with_capacity(name_len as usize);
    if !copy_slice_from_user(name_ptr as usize, unsafe { name.as_bytes_mut() }) {
        return Err(SyscallError::Fault);
    }

    let ctx = get_curr_exec_ctx();

    resolve_process(&ctx.1.cnode, capability, Rights::MANAGE).map_err(|_| SyscallError::Fault)?;

    let new_pml4_phys = create_new_pt4_from_kernel_pt4();
    let pt = phys_to_offset_page_table(new_pml4_phys);

    let process = Arc::new(Process {
        pid: NEXT_PID.fetch_add(1, Ordering::Relaxed),
        name,
        threads: Mutex::new(Vec::new()),
        addr_space: Mutex::new(AddrSpace::new(pt)),
        cnode: CNode::new(),
        iopb_permissions: Mutex::new(None),
        iopb_gen: AtomicU64::new(0)
    });
    
    register_process(process.clone());

    let cap_idx = ctx.1.cnode.alloc(Capability::new(CapType::Process(process), Rights::MANAGE));
    
    Ok(cap_idx as u64)
}

fn handle_proc_start(target_proc_cap: CapIdx) ->Result<u64, SyscallError> {
    todo!()
}

pub fn dispatch_process_action_syscalls(syscall: ProcessActionSyscalls, args: &SyscallArguments) ->Result<u64, SyscallError> {
    match syscall {
        ProcessActionSyscalls::ProcCreate => handle_proc_create(args.arg1 as u32, args.arg2, args.arg3),
        ProcessActionSyscalls::ProcStart => handle_proc_start(args.arg1 as u32)
    }
}