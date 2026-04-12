use crate::{arch::amd64::{ipc::{message::Rights, object_table::{KernelObjType, ObjData, with_object}}, scheduler::{syscall::{SyscallArguments, SyscallError, cap_check::resolve_cap}, task_storage::get_task_by_index}}, define_syscall_group};

define_syscall_group! {
    pub enum CapSyscallNumbers {
        CapCopy = 0x80,
    }   
}

fn cap_copy(curr_task_id: u32, cnode_cap_src: u64, cnode_cap_dst: u64, cap_idx_to_copy: u64) -> Result<u64, SyscallError> {
    let curr = get_task_by_index(curr_task_id).unwrap();

    let (handle_cnode_src, _) = match resolve_cap(
        &curr, cnode_cap_src, KernelObjType::CNode, Rights::READ
    ) {
        Ok(h) => h,
        Err(e) => return Err(e.to_syscall_error())
    };

    let src_task_id = match with_object(handle_cnode_src, |obj| {
        match &obj.data {
            ObjData::CNode(task_id) => Some(*task_id),
            _ => None,
        }
    }).flatten() {
        Some(id) => id,
        None => return Err(SyscallError::InvalidArgument),
    };

    let (handle_cnode_dst, _) = match resolve_cap(
        &curr, cnode_cap_dst, KernelObjType::CNode, Rights::WRITE
    ) {
        Ok(h) => h,
        Err(e) => return Err(e.to_syscall_error())
    };

    let dst_task_id = match with_object(handle_cnode_dst, |obj| {
        match &obj.data {
            ObjData::CNode(task_id) => Some(*task_id),
            _ => None,
        }
    }).flatten() {
        Some(id) => id,
        None => return Err(SyscallError::InvalidArgument),
    };

    let src_task = get_task_by_index(src_task_id).expect("Source task not found");
    let cap = match src_task.tcb.cnode.lock().get(cap_idx_to_copy as u32) {
        Some(c) => c.clone(),
        None => return Err(SyscallError::InvalidArgument),
    };

    let dst_task = get_task_by_index(dst_task_id).expect("Destination task not found");
    let new_slot = match dst_task.tcb.cnode.lock().alloc(cap) {
        Some(slot) => slot as u64,
        None => return Err(SyscallError::ResourceExhausted),
    };

    Ok(new_slot)
}

pub fn dispatch_cap_syscall_group(syscall: CapSyscallNumbers, curr_task_id: u32, args: &SyscallArguments) -> Result<u64, SyscallError> {
    match syscall {
        CapSyscallNumbers::CapCopy => cap_copy(curr_task_id, args.arg1, args.arg2, args.arg3)
    }
}