use crate::{arch::amd64::{
    ipc::{
        IPC_MANAGER, IpcError, IpcResult, cnode::CapIdx, endpoint::EndpointId, message::{Capability, FastMessage, MsgLabel, Rights}, object_table::{KernelObjType, KernelObject, ObjData, obj_insert, with_object}
    },
    scheduler::{
        awaken_task, block_current_on_ipc,
        syscall::{IpcSyscallArguments, SyscallArguments, SyscallError, cap_check::resolve_cap},
        task::{Task, TaskRegisters},
        task_storage::get_task_by_index,
    },
}, define_syscall_group};

define_syscall_group! {
    pub enum IpcSyscallNumbers {
        IpcSend      = 0x60,
        IpcRecv      = 0x61,
        IpcCall      = 0x62,
        IpcReply     = 0x63,
        IpcEpCreate  = 0x64,
        IpcEpDestroy = 0x65,
    }
}

fn resolve_endpoint_cap(
    task: &Task,
    cap_idx: CapIdx,
    required_rights: Rights,
) -> Result<EndpointId, SyscallError> {
    let (handle, _) = resolve_cap(task, cap_idx as u64, KernelObjType::Endpoint, required_rights)
        .map_err(|_| SyscallError::InvalidArgument)?;

    with_object(handle, |obj| {
        match &obj.data {
            ObjData::Endpoint(ep_id) => Some(EndpointId::new(*ep_id as u64)),
            _ => None,
        }
    })
    .flatten()
    .ok_or(SyscallError::InvalidArgument)
}

fn handle_ipc_ep_create(curr_task_id: u32) -> Result<u64, SyscallError> {
    let ep_id = IPC_MANAGER
        .lock()
        .create_endpoint(curr_task_id)
        .unwrap()
        .0;

    let handle = obj_insert(KernelObject::new(
        KernelObjType::Endpoint,
        ObjData::Endpoint(ep_id as u32),
    )).expect("object table full");

    let cap = Capability::new(handle, Rights::ALL);

    let task = get_task_by_index(curr_task_id)
        .expect("handle_ipc_ep_create: task not found");
    let cap_idx = task.tcb.cnode.lock().alloc(cap)
        .expect("handle_ipc_ep_create: CNode full");

    Ok(cap_idx as u64)
}

fn handle_ipc_ep_destroy(
    curr_task_id: u32,
    cap_idx: u64,
) -> Result<u64, SyscallError> {
    let task = get_task_by_index(curr_task_id).unwrap();

    let ep_id = match resolve_endpoint_cap(&task, cap_idx as CapIdx, Rights::ALL) {
        Ok(id) => id,
        Err(e) => return Err(e),
    };

    let handle = {
        let cnode = task.tcb.cnode.lock();
        let cap = cnode.get(cap_idx as CapIdx).unwrap();
        cap.handle
    };

    IPC_MANAGER.lock().destroy_endpoint(ep_id);
    task.tcb.cnode.lock().delete(cap_idx as CapIdx);

    with_object(handle, |obj| obj.dec_ref());

    Ok(0)
}

fn handle_ipc_send(
    curr_task_id: u32,
    ipc: &IpcSyscallArguments,
) -> Result<u64, SyscallError> {
    let task = get_task_by_index(curr_task_id).unwrap();

    let ep_id = match resolve_endpoint_cap(&task, ipc.ep_id as CapIdx, Rights::WRITE) {
        Ok(id) => id,
        Err(e) => return Err(e),
    };

    let msg = FastMessage::with_data(MsgLabel::NOTIFY, ipc.msg);
    let result = IPC_MANAGER.lock().handle_send(curr_task_id, ep_id, msg);

    match result {
        IpcResult::WakeReceiver { receiver } => {
            if let Some(task) = get_task_by_index(receiver) {
                awaken_task(task);
            }
            Ok(0)
        }
        IpcResult::NotReady => Err(SyscallError::NotFound),
        IpcResult::Error(IpcError::InvalidEndpoint) => Err(SyscallError::InvalidArgument),
        IpcResult::Error(_) => Err(SyscallError::InvalidArgument),
        _ => Ok(0),
    }
}

fn handle_ipc_recv(
    curr_task_id: u32,
    cap_idx_raw: u64,
    curr_task_regs: &mut TaskRegisters,
) -> Result<u64, SyscallError> {
    let task = get_task_by_index(curr_task_id).unwrap();

    let ep_id = match resolve_endpoint_cap(&task, cap_idx_raw as CapIdx, Rights::READ) {
        Ok(id) => id,
        Err(e) => return Err(e),
    };

    let result = IPC_MANAGER.lock().handle_recv(curr_task_id, ep_id);

    match result {
        IpcResult::BlockCurrent => {
            block_current_on_ipc();
            if let Some(msg) = IPC_MANAGER.lock().take_pending_message(curr_task_id) {
                curr_task_regs.rdi = msg.label.0;
                curr_task_regs.rsi = msg.data[0];
                curr_task_regs.rdx = msg.data[1];
                curr_task_regs.r10 = msg.data[2];
                curr_task_regs.r8  = msg.data[3];
            }
            Ok(0)
        }
        IpcResult::Error(_) => Err(SyscallError::NotFound),
        _ => Ok(0),
    }
}

fn handle_ipc_call(
    curr_task_id: u32,
    ipc: &IpcSyscallArguments,
    curr_task_regs: &mut TaskRegisters,
) -> Result<u64, SyscallError> {
    let task = get_task_by_index(curr_task_id).unwrap();

    let server_ep = match resolve_endpoint_cap(&task, ipc.ep_id as CapIdx, Rights::WRITE) {
        Ok(id) => id,
        Err(e) => return Err(e),
    };

    let reply_ep = match resolve_endpoint_cap(&task, ipc.msg[0] as CapIdx, Rights::READ) {
        Ok(id) => id,
        Err(e) => return Err(e),
    };

    let msg_data = [ipc.msg[1], ipc.msg[2], ipc.msg[3], 0];
    let msg = FastMessage::with_data(MsgLabel::CALL, msg_data);

    let send_result = IPC_MANAGER.lock().handle_send(curr_task_id, server_ep, msg);
    match send_result {
        IpcResult::WakeReceiver { receiver } => {
            if let Some(task) = get_task_by_index(receiver) {
                awaken_task(task);
            }
        }
        IpcResult::NotReady => return Err(SyscallError::NotFound),
        IpcResult::Error(IpcError::InvalidEndpoint) => return Err(SyscallError::InvalidArgument),
        IpcResult::Error(_) => return Err(SyscallError::NotFound),
        _ => {}
    }

    let recv_result = IPC_MANAGER.lock().handle_recv(curr_task_id, reply_ep);
    match recv_result {
        IpcResult::BlockCurrent => {
            block_current_on_ipc();
            if let Some(msg) = IPC_MANAGER.lock().take_pending_message(curr_task_id) {
                curr_task_regs.rdi = msg.label.0;
                curr_task_regs.rsi = msg.data[0];
                curr_task_regs.rdx = msg.data[1];
                curr_task_regs.r10 = msg.data[2];
                curr_task_regs.r8  = msg.data[3];
            }
            Ok(0)
        }
        IpcResult::Error(_) => Err(SyscallError::NotFound), 
        _ => Ok(0)
    }
}

fn handle_ipc_reply(
    curr_task_id: u32,
    ipc: &IpcSyscallArguments,
) -> Result<u64, SyscallError> {
    let task = get_task_by_index(curr_task_id).unwrap();

    let ep_id = match resolve_endpoint_cap(&task, ipc.ep_id as CapIdx, Rights::WRITE) {
        Ok(id) => id,
        Err(e) => return Err(e),
    };

    let msg = FastMessage::with_data(MsgLabel::REPLY_OK, ipc.msg);
    let result = IPC_MANAGER.lock().handle_send(curr_task_id, ep_id, msg);

    match result {
        IpcResult::WakeReceiver { receiver } => {
            if let Some(task) = get_task_by_index(receiver) {
                awaken_task(task);
            }
            Ok(0)
        }
        IpcResult::NotReady => Err(SyscallError::NotFound),
        IpcResult::Error(IpcError::InvalidEndpoint) => Err(SyscallError::InvalidArgument),
        IpcResult::Error(_) => Err(SyscallError::NotFound),
        _ => Ok(0),
    }
}

pub fn dispatch_ipc_syscall_group(syscall: IpcSyscallNumbers, curr_task_id: u32, args: &SyscallArguments, regs: &mut TaskRegisters) -> Result<u64, SyscallError> {
    let ipc = IpcSyscallArguments {
            ep_id: args.arg1,
            msg: [args.arg2, args.arg3, args.arg4, args.arg5],
    };

    match syscall {
        IpcSyscallNumbers::IpcCall => handle_ipc_call(curr_task_id, &ipc, regs),
        IpcSyscallNumbers::IpcEpCreate => handle_ipc_ep_create(curr_task_id),
        IpcSyscallNumbers::IpcEpDestroy => handle_ipc_ep_destroy(curr_task_id, args.arg1),
        IpcSyscallNumbers::IpcRecv => handle_ipc_recv(curr_task_id, args.arg1, regs),
        IpcSyscallNumbers::IpcReply => handle_ipc_reply(curr_task_id, &ipc),
        IpcSyscallNumbers::IpcSend => handle_ipc_send(curr_task_id, &ipc)
    }
}