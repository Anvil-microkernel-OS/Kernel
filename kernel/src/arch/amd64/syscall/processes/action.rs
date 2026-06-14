use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use alloc::{string::String, sync::Arc};
use alloc::vec::{Vec};
use spin::mutex::Mutex;

use crate::arch::amd64::capability_sys::cap_resolver::{resolve_domain, resolve_process, resolve_thread};
use crate::arch::amd64::capability_sys::capability::{CapType, Capability, Rights};
use crate::arch::amd64::capability_sys::cnode::{CNode, CapIdx};
use crate::arch::amd64::memory::u_k_boundary::uaccsess::copy_to_user;
use crate::arch::amd64::scheduler::exec_loader::prepare_new_thread;
use crate::arch::amd64::scheduler::task::ThreadState;
use crate::arch::amd64::scheduler::task_storage::spawn_thread;
use crate::arch::amd64::syscall::{SyscallArguments, SyscallError, get_curr_exec_ctx};
use crate::early_println;
use crate::isolation::domain::CollapseAction;
use crate::{arch::amd64::{memory::{u_k_boundary::uaccsess::copy_slice_from_user, vmm::create_new_pt4_from_kernel_pt4}, scheduler::{addr_space::AddrSpace, exec_loader::phys_to_offset_page_table, task::{Process}, task_storage::{register_process}}}, define_syscall_group};

define_syscall_group! {
    pub enum ProcessActionSyscalls {
        ProcCreate = 60,
        ProcStart = 61,
        ProcExit = 62
    }
}

static NEXT_PID: AtomicU32 = AtomicU32::new(2);

#[repr(C)]
#[derive(Clone, Copy)]
struct InitialCapabilities {
    proc_cap_idx: u64,
    cnode_cap_idx: u64,
    vspace_cap_idx: u64
}

fn handle_proc_create(
    capability: CapIdx,
    domain_capability: CapIdx,
    name_ptr: u64,
    name_len: u64,
    capabilities: u64
) -> Result<u64, SyscallError> {
    if name_len == 0 {
        return Err(SyscallError::BufferTooSmall)
    }

    let mut buf = [0u8; 4096];
    let name = &mut buf[..name_len as usize];
    if !copy_slice_from_user(name_ptr as usize, name) {
        return Err(SyscallError::Fault);
    }

    let ctx = get_curr_exec_ctx();

    ctx.1.domain.check_process_limit().map_err(|_| SyscallError::ResourceExhausted)?;

    resolve_process(&ctx.1.cnode, capability, Rights::MANAGE).map_err(|_| SyscallError::Fault)?;

    let domain = resolve_domain(&ctx.1.cnode, domain_capability, Rights::MANAGE).map_err(|_| SyscallError::PermissionDenied)?;

    let new_pml4_phys = create_new_pt4_from_kernel_pt4();
    let pt = phys_to_offset_page_table(new_pml4_phys);

    let s = String::from(
        core::str::from_utf8(&buf[..name_len as usize])
            .map_err(|_| SyscallError::InvalidArgument)?
    );

    let process = Arc::new(Process {
        pid: NEXT_PID.fetch_add(1, Ordering::Relaxed),
        name: s,
        threads: Mutex::new(Vec::new()),
        addr_space: Mutex::new(AddrSpace::new(pt)),
        cnode: CNode::new(),
        iopb_permissions: Mutex::new(None),
        iopb_gen: AtomicU64::new(0),
        domain: domain.0.clone()
    });
    
    register_process(process.clone());

    let process_cap_idx = ctx.1.cnode.alloc(Capability::new(CapType::Process(process.clone()), Rights::ALL));
    let cnode_cap_idx = ctx.1.cnode.alloc(Capability::new(CapType::CNode(process.clone()), Rights::ALL));
    let vspace_cap_idx = ctx.1.cnode.alloc(Capability::new(CapType::VSpace(process.clone()), Rights::ALL));
    
    ctx.1.domain.on_process_created();

    copy_to_user::<InitialCapabilities>(capabilities as usize, InitialCapabilities{
        proc_cap_idx: process_cap_idx as u64, 
        cnode_cap_idx: cnode_cap_idx as u64,
        vspace_cap_idx: vspace_cap_idx as u64
    });

    Ok(0)
}

fn handle_proc_start(target_proc_cap: CapIdx, main_thread_cap: CapIdx) ->Result<u64, SyscallError> {
    let ctx = get_curr_exec_ctx();

    resolve_process(&ctx.1.cnode, target_proc_cap, Rights::MANAGE).map_err(|_| SyscallError::Fault)?;
    
    let target_thread = resolve_thread(&ctx.1.cnode, main_thread_cap, Rights::MANAGE).map_err(|_| SyscallError::Fault)?;

    if target_thread.0.tid == ctx.0.tid {
        return Err(SyscallError::InvalidArgument);
    }

    if target_thread.0.state.load(Ordering::Acquire) != ThreadState::Configuring {
        return Err(SyscallError::InvalidArgument);
    }

    target_thread.0.state.store(ThreadState::Ready, Ordering::Release);

    prepare_new_thread(&target_thread.0.clone());

    spawn_thread(target_thread.0.clone());

    Ok(0)
}

fn handle_proc_exit(target_proc_cap: CapIdx, result_code: CapIdx) -> Result<u64, SyscallError> {
    let ctx = get_curr_exec_ctx();
    
    let target_proc = resolve_process(
        &ctx.1.cnode, target_proc_cap, Rights::MANAGE
    ).map_err(|_| SyscallError::Fault)?;

    let proc = &target_proc.0;

    let result = proc.domain.notify_proc_exit(proc.pid, result_code as i64);

    if let Some(action) = result {
        match action {
            CollapseAction::KernelPanic => panic!("CRITICAL DOMAIN SUTDOWNED"),
            CollapseAction::KillDomain => ()
        }
    }

    Ok(0)
}

pub fn dispatch_process_action_syscalls(syscall: ProcessActionSyscalls, args: &SyscallArguments) ->Result<u64, SyscallError> {
    match syscall {
        ProcessActionSyscalls::ProcCreate => handle_proc_create(args.arg1 as CapIdx, args.arg2 as CapIdx, args.arg3, args.arg4, args.arg5),
        ProcessActionSyscalls::ProcStart => handle_proc_start(args.arg1 as CapIdx, args.arg2 as CapIdx),
        ProcessActionSyscalls::ProcExit => handle_proc_exit(args.arg1 as CapIdx, args.arg2 as CapIdx),
    }
}