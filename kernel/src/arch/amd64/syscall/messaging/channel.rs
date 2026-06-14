use crate::{arch::amd64::{capability_sys::{cap_resolver::resolve_channel, capability::{CapType, Capability, Rights}, cnode::CapIdx}, ipc::channel::{ChannelAction, ChannelErr, ChannelHandle, ChannelMessage, MsgPayload}, memory::u_k_boundary::uaccsess::{copy_from_user, copy_to_user}, scheduler::{block_current_task, block_thread, sleep, task::{Process, ThreadRegisters, Tid}, task_storage::{get_thread, wake_thread}}, syscall::{SyscallArguments, SyscallError, get_curr_exec_ctx}}, define_syscall_group};

define_syscall_group!{
    pub enum ChannelSyscallNumbers {
        ChOpen   = 33,
        ChClose  = 34,
        ChWrite  = 49,
        ChRead   = 50,
        ChWait   = 51,
        ChCall   = 38,
        ChStatus = 39
    }
}

fn apply_action(action: ChannelAction) {
    match action {
        ChannelAction::Continue => {}
        ChannelAction::Block { task_id } => {
            if let Some(task) = get_thread(task_id) {
                block_thread(task);
            }
        }
        ChannelAction::Wake { task_id } => {
            if let Some(task) = get_thread(task_id) {
                wake_thread(task.tid);
            }
        }
        ChannelAction::WakeAndBlock { wake, block } => {
            if let Some(task) = get_thread(wake) {
                wake_thread(task.tid);
            }
            if let Some(_task) = get_thread(block) {
                block_current_task();
            }
        }
    }
}

fn handle_channel_open(out_ptr: u64) -> Result<u64, SyscallError> {
    let (left, right) = ChannelHandle::new_pair();

    let ctx = get_curr_exec_ctx();

    let left_slot  = ctx.1.cnode.alloc(Capability::new(CapType::Channel(left), Rights::ALL)) as u64;
    let right_slot = ctx.1.cnode.alloc(Capability::new(CapType::Channel(right), Rights::ALL)) as u64;

    if !copy_to_user::<[u64; 2]>(out_ptr as usize, [left_slot, right_slot]) {
        return Err(SyscallError::Fault)
    }

    Ok(0)
}

fn handle_channel_close(cap_idx: CapIdx) -> Result<u64, SyscallError> {
    let ctx = get_curr_exec_ctx();

    resolve_channel(&ctx.1.cnode, cap_idx, Rights::DESTROY).map_err(|err| err.to_syscall_error())?;

    ctx.1.cnode.delete(cap_idx as CapIdx);

    Ok(0)
}

fn handle_channel_write(
    cap_idx: CapIdx,
    message: u64,
) -> Result<u64, SyscallError> {
    let ctx = get_curr_exec_ctx();

    let result = copy_from_user::<[u64; 6]>(message as usize).ok_or(SyscallError::Fault)?;

    let msg = ChannelMessage {
        label: result[0],
        handles: alloc::vec![],
        payload: MsgPayload::Registers { data: [result[1], result[2], result[3], result[4], result[5]], len: 5 },
    };

    let channel_obj = resolve_channel(&ctx.1.cnode, cap_idx, Rights::WRITE).map_err(|err| err.to_syscall_error())?;

    let action = channel_obj.0.write(msg)
    .map_err(|e| match e {
        ChannelErr::PeerClosed => SyscallError::NotFound,
        ChannelErr::QueueFull  => SyscallError::ResourceExhausted,
        _                      => SyscallError::InvalidArgument,
    })?;

    apply_action(action);
    Ok(0)
}

fn handle_channel_read(
    cap_idx: CapIdx,
    regs: &mut ThreadRegisters,
) -> Result<u64, SyscallError> {
    let ctx = get_curr_exec_ctx();

    let channel_obj = resolve_channel(&ctx.1.cnode, cap_idx, Rights::READ).map_err(|err| err.to_syscall_error())?;

    let result = channel_obj.0.read(ctx.0.tid);

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
    cap_idx: CapIdx,
    timeout_ns: u64,
    regs: &mut ThreadRegisters,
) -> Result<u64, SyscallError> {
    let ctx = get_curr_exec_ctx();

    let channel_obj = resolve_channel(&ctx.1.cnode, cap_idx, Rights::WRITE).map_err(|err| err.to_syscall_error())?;

    let result = channel_obj.0.read(ctx.0.tid);

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
    cap_idx: CapIdx,
    message: u64,
    regs: &mut ThreadRegisters,
) -> Result<u64, SyscallError> {
    /*let ctx = get_curr_exec_ctx();

    let channel_obj = resolve_channel(&ctx.1.cnode, cap_idx, Rights::WRITE & Rights::READ).map_err(|err| err.to_syscall_error())?;

    let (reply_handle, reply_peer) = ChannelHandle::new_pair();

    let reply_peer_obj = KernelObject::new(KernelObjType::Channel, ObjData::Channel(reply_peer));
    let reply_peer_htable = obj_insert(reply_peer_obj).map_err(|_| SyscallError::OutOfMemory)?;
    let reply_cap = Capability::new(reply_peer_htable, Rights::ALL);
    let reply_cap_idx = curr_proc.cnode.write()
        .alloc(reply_cap) as u64;

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
            ObjData::Channel(ch) => Some(ch.read(curr_thread_id)),
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
    }*/
    todo!()
}

fn handle_channel_status(cap_idx: CapIdx, out: u64) -> Result<u64, SyscallError> {
    let ctx = get_curr_exec_ctx();

    let channel_obj = resolve_channel(&ctx.1.cnode, cap_idx, Rights::READ).map_err(|err| err.to_syscall_error())?;

    let status = channel_obj.0.status();

    if !copy_to_user::<[u64; 3]>(out as usize, [status.readable as u64, status.peer_alive as u64, status.queue_len as u64]) {
        return Err(SyscallError::Fault)
    }

    Ok(0)
}

fn write_msg_to_regs(msg: &ChannelMessage, regs: &mut ThreadRegisters) {
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
    args: &SyscallArguments,
    regs: &mut ThreadRegisters,
) -> Result<u64, SyscallError> {
    match syscall {
        ChannelSyscallNumbers::ChOpen => {
            handle_channel_open(args.arg1)
        }
        ChannelSyscallNumbers::ChClose => {
            handle_channel_close(args.arg1 as u32)
        }
        ChannelSyscallNumbers::ChWrite => {
            handle_channel_write(args.arg1 as u32, args.arg2)
        }
        ChannelSyscallNumbers::ChRead => {
            handle_channel_read(args.arg1 as u32, regs)
        }
        ChannelSyscallNumbers::ChWait => {
            handle_channel_wait(args.arg1 as u32, args.arg2, regs)
        }
        ChannelSyscallNumbers::ChCall => {
            handle_channel_call(args.arg1 as u32, args.arg2, regs)
        }
        ChannelSyscallNumbers::ChStatus => {
            handle_channel_status(args.arg1 as u32, args.arg2)
        }
    }
}