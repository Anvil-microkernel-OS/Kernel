use core::cmp::Ordering;

use crate::{arch::amd64::{ipc::{channel::{ChannelAction, ChannelErr, ChannelHandle, ChannelMessage, MsgPayload}, cnode::CapIdx, message::{Capability, Rights}, object_table::{KernelObjType, KernelObject, ObjData, obj_insert, obj_remove, with_object, with_object_mut}}, memory::u_k_boundary::uaccsess::{copy_from_user, copy_to_user}, scheduler::{awaken_task, block_current_task, block_task, sleep, syscall::{SyscallArguments, SyscallError, cap_check::resolve_cap}, task::TaskRegisters, task_storage::get_task_by_index}}, define_syscall_group, early_println};

define_syscall_group!{
    pub enum ChannelSyscallNumbers {
        ChOpen   = 12,
        ChClose  = 13,
        ChWrite  = 14,
        ChRead   = 15,
        ChWait   = 16,
        ChCall   = 17,
        ChStatus = 18
    }
}

fn apply_action(action: ChannelAction) {
    match action {
        ChannelAction::Continue => {}
        ChannelAction::Block { task_id } => {
            if let Some(task) = get_task_by_index(task_id) {
                block_task(task);
            }
        }
        ChannelAction::Wake { task_id } => {
            if let Some(task) = get_task_by_index(task_id) {
                awaken_task(task);
            }
        }
        ChannelAction::WakeAndBlock { wake, block } => {
            if let Some(task) = get_task_by_index(wake) {
                awaken_task(task);
            }
            if let Some(_task) = get_task_by_index(block) {
                block_current_task();
            }
        }
    }
}

fn resolve_channel_cap(
    task: &crate::arch::amd64::scheduler::task::Task,
    cap_idx: u64,
    required_rights: Rights,
) -> Result<crate::arch::amd64::ipc::object_table::HandleRef, SyscallError> {
    let (handle, _) = resolve_cap(task, cap_idx, KernelObjType::Channel, required_rights)
        .map_err(|e| e.to_syscall_error())?;
    Ok(handle)
}

fn handle_channel_open(curr_task_id: u32, out_ptr: u64) -> Result<u64, SyscallError> {
    let (left, right) = ChannelHandle::new_pair();

    let left_obj = KernelObject::new(KernelObjType::Channel, ObjData::Channel(left));
    let right_obj = KernelObject::new(KernelObjType::Channel, ObjData::Channel(right));

    let left_handle = obj_insert(left_obj).map_err(|_| SyscallError::OutOfMemory)?;
    let right_handle = obj_insert(right_obj).map_err(|_| SyscallError::OutOfMemory)?;

    let task = get_task_by_index(curr_task_id).ok_or(SyscallError::NotFound)?;
    let mut cnode = task.tcb.cnode.lock();

    let left_cap  = Capability::new(left_handle,  Rights::ALL);
    let right_cap = Capability::new(right_handle, Rights::ALL);

    let left_slot  = cnode.alloc(left_cap).ok_or(SyscallError::ResourceExhausted)? as u64;
    let right_slot = cnode.alloc(right_cap).ok_or(SyscallError::ResourceExhausted)? as u64;

    if !copy_to_user::<[u64; 2]>(out_ptr as usize, [left_slot, right_slot]) {
        return Err(SyscallError::Fault)
    }

    Ok(0)
}

fn handle_channel_close(curr_task_id: u32, cap_idx: u64) -> Result<u64, SyscallError> {
    let task = get_task_by_index(curr_task_id).ok_or(SyscallError::NotFound)?;

    let handle = resolve_channel_cap(&task, cap_idx, Rights::ALL)?;

    obj_remove(handle).map_err(|_| SyscallError::NotFound)?;

    task.tcb.cnode.lock().delete(cap_idx as CapIdx);

    Ok(0)
}

fn handle_channel_write(
    curr_task_id: u32,
    cap_idx: u64,
    message: u64,
) -> Result<u64, SyscallError> {
    let task = get_task_by_index(curr_task_id).ok_or(SyscallError::NotFound)?;
    let handle = resolve_channel_cap(&task, cap_idx, Rights::WRITE)?;

    let result = copy_from_user::<[u64; 6]>(message as usize).ok_or(SyscallError::Fault)?;

    let msg = ChannelMessage {
        label: result[0],
        handles: alloc::vec![],
        payload: MsgPayload::Registers { data: [result[1], result[2], result[3], result[4], result[5]], len: 5 },
    };

    let action = with_object_mut(handle, |obj| {
        match &mut obj.data {
            ObjData::Channel(ch) => Some(ch.write(msg)),
            _ => None,
        }
    })
    .flatten()
    .ok_or(SyscallError::InvalidArgument)?
    .map_err(|e| match e {
        ChannelErr::PeerClosed => SyscallError::NotFound,
        ChannelErr::QueueFull  => SyscallError::ResourceExhausted,
        _                      => SyscallError::InvalidArgument,
    })?;

    apply_action(action);
    Ok(0)
}

fn handle_channel_read(
    curr_task_id: u32,
    cap_idx: u64,
    regs: &mut TaskRegisters,
) -> Result<u64, SyscallError> {
    let task = get_task_by_index(curr_task_id).ok_or(SyscallError::NotFound)?;
    let handle = resolve_channel_cap(&task, cap_idx, Rights::READ)?;

    let result = with_object_mut(handle, |obj| {
        match &mut obj.data {
            ObjData::Channel(ch) => Some(ch.read(curr_task_id)),
            _ => None,
        }
    })
    .flatten()
    .ok_or(SyscallError::InvalidArgument)?;

    match result {
        Ok((msg, action)) => {
            apply_action(action);
            write_msg_to_regs(&msg, regs);
            Ok(0)
        }
        Err(ChannelErr::WouldBlock(action)) => {
            apply_action(action);
            Ok(0)
        }
        Err(ChannelErr::PeerClosed) => Err(SyscallError::NotFound),
        Err(_) => Err(SyscallError::InvalidArgument),
    }
}

fn handle_channel_wait(
    curr_task_id: u32,
    cap_idx: u64,
    timeout_ns: u64,
    regs: &mut TaskRegisters,
) -> Result<u64, SyscallError> {
    let task = get_task_by_index(curr_task_id).ok_or(SyscallError::NotFound)?;
    let handle = resolve_channel_cap(&task, cap_idx, Rights::READ)?;

    let result = with_object_mut(handle, |obj| {
        match &mut obj.data {
            ObjData::Channel(ch) => Some(ch.read(curr_task_id)),
            _ => None,
        }
    })
    .flatten()
    .ok_or(SyscallError::InvalidArgument)?;

    match result {
        Ok((msg, action)) => {
            apply_action(action);
            write_msg_to_regs(&msg, regs);
            Ok(0)
        }
        Err(ChannelErr::WouldBlock(action)) => {
            if timeout_ns > 0 {
                sleep(timeout_ns);
            } else {
                // timeout == 0 infinity wait
                apply_action(action);
            }

            Ok(0)
        }
        Err(ChannelErr::PeerClosed) => Err(SyscallError::NotFound),
        Err(_) => Err(SyscallError::InvalidArgument),
    }
}

fn handle_channel_call(
    curr_task_id: u32,
    cap_idx: u64,
    message: u64,
    regs: &mut TaskRegisters,
) -> Result<u64, SyscallError> {
    let task = get_task_by_index(curr_task_id).ok_or(SyscallError::NotFound)?;
    let handle = resolve_channel_cap(&task, cap_idx, Rights::WRITE)?;

    let (reply_handle, reply_peer) = ChannelHandle::new_pair();

    let reply_peer_obj = KernelObject::new(KernelObjType::Channel, ObjData::Channel(reply_peer));
    let reply_peer_htable = obj_insert(reply_peer_obj).map_err(|_| SyscallError::OutOfMemory)?;
    let reply_cap = Capability::new(reply_peer_htable, Rights::ALL);
    let reply_cap_idx = task.tcb.cnode.lock()
        .alloc(reply_cap)
        .ok_or(SyscallError::ResourceExhausted)? as u64;

    let result = copy_from_user::<[u64; 6]>(message as usize).ok_or(SyscallError::Fault)?;

    let msg = ChannelMessage {
        label: result[0],
        handles: alloc::vec![reply_cap_idx as CapIdx],
        payload: MsgPayload::Registers { data: [result[1], result[2], result[3], result[4], result[5]], len: 5 },
    };

    let send_action = with_object_mut(handle, |obj| {
        match &mut obj.data {
            ObjData::Channel(ch) => Some(ch.write(msg)),
            _ => None,
        }
    })
    .flatten()
    .ok_or(SyscallError::InvalidArgument)?
    .map_err(|e| match e {
        ChannelErr::PeerClosed => SyscallError::NotFound,
        ChannelErr::QueueFull  => SyscallError::ResourceExhausted,
        _                      => SyscallError::InvalidArgument,
    })?;

    apply_action(send_action);

    let reply_obj = KernelObject::new(KernelObjType::Channel, ObjData::Channel(reply_handle));
    let reply_htable = obj_insert(reply_obj).map_err(|_| SyscallError::OutOfMemory)?;

    let read_result = with_object_mut(reply_htable, |obj| {
        match &mut obj.data {
            ObjData::Channel(ch) => Some(ch.read(curr_task_id)),
            _ => None,
        }
    })
    .flatten()
    .ok_or(SyscallError::InvalidArgument)?;

    match read_result {
        Ok((msg, action)) => {
            apply_action(action);
            write_msg_to_regs(&msg, regs);
            Ok(0)
        }
        Err(ChannelErr::WouldBlock(action)) => {
            apply_action(action);
            Ok(0)
        }
        Err(ChannelErr::PeerClosed) => Err(SyscallError::NotFound),
        Err(_) => Err(SyscallError::InvalidArgument),
    }
}

fn handle_channel_status(curr_task_id: u32, cap_idx: u64, out: u64) -> Result<u64, SyscallError> {
    let task = get_task_by_index(curr_task_id).ok_or(SyscallError::NotFound)?;
    let handle = resolve_channel_cap(&task, cap_idx, Rights::READ)?;

    let status = with_object(handle, |obj| {
        match &obj.data {
            ObjData::Channel(ch) => Some(ch.status()),
            _ => None,
        }
    })
    .flatten()
    .ok_or(SyscallError::InvalidArgument)?;

    if !copy_to_user::<[u64; 3]>(out as usize, [status.readable as u64, status.peer_alive as u64, status.queue_len as u64]) {
        return Err(SyscallError::Fault)
    }

    Ok(0)
}

fn write_msg_to_regs(msg: &ChannelMessage, regs: &mut TaskRegisters) {
    regs.rdi = msg.label;
    match &msg.payload {
        MsgPayload::Registers { data, len } => {
            if *len > 0 { regs.rsi = data[0]; }
            if *len > 1 { regs.rdx = data[1]; }
            if *len > 2 { regs.r10 = data[2]; }
            if *len > 3 { regs.r8  = data[3]; }
            if *len > 4 { regs.r9  = data[4]; }
        }
        MsgPayload::SharedMem(cap) => {
            regs.rsi = *cap as u64;
        }
    }
}

pub fn dispatch_channel_syscall_group(
    syscall: ChannelSyscallNumbers,
    curr_task_id: u32,
    args: &SyscallArguments,
    regs: &mut TaskRegisters,
) -> Result<u64, SyscallError> {
    match syscall {
        ChannelSyscallNumbers::ChOpen => {
            handle_channel_open(curr_task_id, args.arg1)
        }
        ChannelSyscallNumbers::ChClose => {
            handle_channel_close(curr_task_id, args.arg1)
        }
        ChannelSyscallNumbers::ChWrite => {
            handle_channel_write(curr_task_id, args.arg1, args.arg2)
        }
        ChannelSyscallNumbers::ChRead => {
            handle_channel_read(curr_task_id, args.arg1, regs)
        }
        ChannelSyscallNumbers::ChWait => {
            handle_channel_wait(curr_task_id, args.arg1, args.arg2, regs)
        }
        ChannelSyscallNumbers::ChCall => {
            handle_channel_call(curr_task_id, args.arg1, args.arg2, regs)
        }
        ChannelSyscallNumbers::ChStatus => {
            handle_channel_status(curr_task_id, args.arg1, args.arg2)
        }
    }
}