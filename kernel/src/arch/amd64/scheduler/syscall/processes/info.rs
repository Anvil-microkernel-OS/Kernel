use alloc::vec::Vec;

use crate::{arch::amd64::{capability_sys::{cap_resolver::resolve_process, capability::Rights, cnode::CapIdx}, memory::u_k_boundary::uaccsess::{copy_slice_to_user, copy_to_user}, scheduler::{syscall::{SyscallArguments, SyscallError, get_curr_exec_ctx}, task::Tid, task_storage::{get_process, get_thread}}}, define_syscall_group};

define_syscall_group! {
    pub enum ProcessInfoSyscalls {
        ProcGetPid = 4,
        ProcGetThreadsTid = 5,
        ProcGetName = 6
    }
}

fn handle_proc_get_pid(capability: CapIdx) -> Result<u64, SyscallError> {
    let ctx = get_curr_exec_ctx();

    let src_obj = resolve_process(&ctx.1.cnode, capability, Rights::READ).map_err(|err| err.to_syscall_error())?;

    Ok(src_obj.0.pid as u64)
}

fn handle_proc_get_threads_tid(
    capability: CapIdx,
    buf_ptr: u64,
    buf_count: u64,  
    out_count: u64,  
) -> Result<u64, SyscallError> {
    let ctx = get_curr_exec_ctx();

    let src_obj = resolve_process(&ctx.1.cnode, capability, Rights::READ).map_err(|err| err.to_syscall_error())?;

    let tids: Vec<Tid> = {
        let threads = src_obj.0.threads.lock();
        threads.iter()
            .filter_map(|w| w.upgrade())
            .map(|t| t.tid)
            .collect()
    };

    let real_count = tids.len();

    if !copy_to_user::<u64>(out_count as usize, real_count as u64) {
        return Err(SyscallError::Fault);
    }

    let to_copy = real_count.min(buf_count as usize);
    if to_copy > 0 {
        if !copy_slice_to_user::<Tid>(buf_ptr as usize, &tids[..to_copy]) {
            return Err(SyscallError::Fault);
        }
    }

    Ok(real_count as u64)
}

fn handle_get_proc_name(capability: CapIdx, ptr: u64, len: u64) -> Result<u64, SyscallError> {
    let ctx = get_curr_exec_ctx();

    let src_obj = resolve_process(&ctx.1.cnode, capability, Rights::READ).map_err(|err| err.to_syscall_error())?;

    let name_bytes = src_obj.0.name.as_bytes();  
    let copy_len = name_bytes.len().min(len as usize);

    copy_slice_to_user(ptr as usize, &name_bytes[..copy_len]);

    Ok(0)
}

pub fn dispatch_process_info_syscall_group(syscall: ProcessInfoSyscalls, args: &SyscallArguments) ->Result<u64, SyscallError> {
    match syscall {
        ProcessInfoSyscalls::ProcGetPid        => handle_proc_get_pid(args.arg1 as u32),
        ProcessInfoSyscalls::ProcGetThreadsTid => handle_proc_get_threads_tid(args.arg1 as u32, args.arg2, args.arg3, args.arg4),
        ProcessInfoSyscalls::ProcGetName       => handle_get_proc_name(args.arg1 as u32, args.arg2, args.arg3)
    }
}