use crate::{arch::amd64::{ipc::{message::Rights, object_table::{KernelObjType, ObjData, with_object}}, scheduler::{PerCpuSchedulerData, syscall::{SyscallError, cap_check::{CapError, resolve_cap}}, task_storage::get_task_by_index}}, early_print, early_println};

#[repr(i64)]
pub enum CapSyscallNumbers {
    CapCopy = 0x80,
}

impl TryFrom<u64> for CapSyscallNumbers {
    type Error = ();

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0x80 => Ok(CapSyscallNumbers::CapCopy),
            _ => Err(()),
        }
    }
}

pub (crate) fn cap_move() {

}

pub(crate) fn cap_copy(cnode_cap_src: u64, cnode_cap_dst: u64, cap_idx_to_copy: u64) -> i64 {
    let curr_task_id = PerCpuSchedulerData::get().curr_task_id.id();
    let curr = get_task_by_index(curr_task_id).unwrap();
    let (handle_cnode_src, _) = match resolve_cap(
        &curr, cnode_cap_src, KernelObjType::CNode, Rights::READ
    ) {
        Ok(h) => h,
        Err(e) => match e {
            CapError::InvalidIdx => return SyscallError::InvalidArgument as i64,
            CapError::WrongType => return SyscallError::InvalidArgument as i64,
            CapError::WrongOwner => return SyscallError::PermissionDenied as i64,
            CapError::InsufficientRights => return SyscallError::PermissionDenied as i64,
            CapError::NotAllowed => return SyscallError::PermissionDenied as i64,
        },
    };

    let src_task_id = match with_object(handle_cnode_src, |obj| {
        match &obj.data {
            ObjData::CNode(task_id) => Some(*task_id),
            _ => None,
        }
    }).flatten() {
        Some(id) => id,
        None => return SyscallError::InvalidArgument as i64,
    };

    let (handle_cnode_dst, _) = match resolve_cap(
        &curr, cnode_cap_dst, KernelObjType::CNode, Rights::WRITE
    ) {
        Ok(h) => h,
        Err(e) => match e {
            CapError::InvalidIdx => return SyscallError::InvalidArgument as i64,
            CapError::WrongType => return SyscallError::InvalidArgument as i64,
            CapError::WrongOwner => return SyscallError::PermissionDenied as i64,
            CapError::InsufficientRights => return SyscallError::PermissionDenied as i64,
            CapError::NotAllowed => return SyscallError::PermissionDenied as i64,
        },
    };

    let dst_task_id = match with_object(handle_cnode_dst, |obj| {
        match &obj.data {
            ObjData::CNode(task_id) => Some(*task_id),
            _ => None,
        }
    }).flatten() {
        Some(id) => id,
        None => return SyscallError::InvalidArgument as i64,
    };

    let src_task = get_task_by_index(src_task_id).expect("Source task not found");
    let cap = match src_task.tcb.cnode.lock().get(cap_idx_to_copy as u32) {
        Some(c) => c.clone(),
        None => return SyscallError::InvalidArgument as i64,
    };

    let dst_task = get_task_by_index(dst_task_id).expect("Destination task not found");
    let new_slot = match dst_task.tcb.cnode.lock().alloc(cap) {
        Some(slot) => slot as i64,
        None => return SyscallError::ResourceExhausted as i64,
    };

    new_slot
}