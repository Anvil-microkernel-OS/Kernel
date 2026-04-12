use crate::arch::amd64::{ipc::{message::{Rights}, object_table::{HandleRef, KernelObjType, with_object}}, scheduler::{syscall::SyscallError, task::Task}};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapError {
    InvalidIdx,
    WrongType,
    WrongOwner,
    InsufficientRights,
    NotAllowed
}

impl CapError {
    pub fn to_syscall_error(&self) -> SyscallError {
        match self {
                CapError::InvalidIdx => SyscallError::InvalidArgument,
                CapError::WrongType => SyscallError::InvalidArgument,
                CapError::WrongOwner => SyscallError::PermissionDenied,
                CapError::InsufficientRights => SyscallError::PermissionDenied,
                CapError::NotAllowed => SyscallError::PermissionDenied
        }
    }
}

pub enum ExpectedOwner {
    CurrentTask,
    Specific(u64),
    Any,
}

pub fn resolve_cap(
    task: &Task,
    cap_idx: u64,
    expected_type: KernelObjType,
    required_rights: Rights,
) -> Result<(HandleRef, Rights), CapError> {
    let cnode = task.tcb.cnode.lock();
    let cap = cnode.get(cap_idx as u32)
        .ok_or(CapError::InvalidIdx)?;

    if !cap.rights.contains(required_rights) {
        return Err(CapError::InsufficientRights);
    }

    let valid = with_object(cap.handle, |obj| {
        obj.obj_type == expected_type
    }).unwrap_or(false);

    if !valid {
        return Err(CapError::WrongType);
    }

    Ok((cap.handle, cap.rights))
}