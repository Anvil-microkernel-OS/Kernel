use crate::{arch::amd64::{capability_sys::{cap_resolver::resolve_cnode, capability::Rights, cnode::CapIdx}, scheduler::{syscall::{SyscallArguments, SyscallError, get_curr_exec_ctx}}}, define_syscall_group};

define_syscall_group! {
    pub enum CapabilityActionSyscalls {
        CapCopy = 17,
    }
}

fn handle_cap_copy(cnode_cap_src: CapIdx, cnode_cap_dst: CapIdx, cap_idx_to_copy: CapIdx) -> Result<u64, SyscallError> {
    let ctx = get_curr_exec_ctx();

    let src_obj = resolve_cnode(&ctx.1.cnode, cnode_cap_src, Rights::READ).map_err(|err| err.to_syscall_error())?;

    let dst_obj = resolve_cnode(&ctx.1.cnode, cnode_cap_dst, Rights::WRITE).map_err(|err| err.to_syscall_error())?;

    if src_obj.0.pid == dst_obj.0.pid {
        return Err(SyscallError::InvalidArgument);
    }

    let cap_to_copy = src_obj.0.cnode.get(cap_idx_to_copy).ok_or(SyscallError::InvalidArgument)?;

    let slot = dst_obj.0.cnode.alloc(cap_to_copy);

    Ok(slot as u64)
}

pub fn dispatch_capability_action_syscalls(syscall: CapabilityActionSyscalls, args: &SyscallArguments) -> Result<u64, SyscallError> {
    match syscall {
        CapabilityActionSyscalls::CapCopy => handle_cap_copy(args.arg1 as u32, args.arg2 as u32, args.arg3 as u32)
    }
}