use crate::{arch::amd64::{ipc::{message::{Capability, Rights}, object_table::{KernelObjType, KernelObject, ObjData, obj_insert, obj_remove, with_object, with_object_mut}, port::{Port, PortAction, PortErr}}, scheduler::{awaken_task, block_current_task, syscall::{SyscallArguments, SyscallError, cap_check::resolve_cap}, task::TaskRegisters, task_storage::get_task_by_index}}, define_syscall_group};

define_syscall_group! {
    pub enum PortSyscallNumbers {
        PortCreate    = 19,
        PortClose     = 20,
        PortBind      = 21,
        PortUnbind    = 22,
        PortWait      = 23,
        PortPoll      = 24,
    }
}

pub fn apply_port_action(action: PortAction) {
    match action {
        PortAction::Continue => {}
        PortAction::Block { task_id } => {
            if let Some(_) = get_task_by_index(task_id) {
                block_current_task();
            }
        }
        PortAction::Wake { task_id } => {
            if let Some(task) = get_task_by_index(task_id) {
                awaken_task(task);
            }
        }
    }
}

pub fn resolve_port_cap(
    task: &crate::arch::amd64::scheduler::task::Task,
    cap_idx: u64,
    required_rights: Rights,
) -> Result<crate::arch::amd64::ipc::object_table::HandleRef, SyscallError> {
    let (handle, _) = resolve_cap(task, cap_idx, KernelObjType::Port, required_rights)
        .map_err(|e| e.to_syscall_error())?;
    Ok(handle)
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

fn handle_port_create(curr_task_id: u32) -> Result<u64, SyscallError> {
    let port = Port::new();

    let handle = obj_insert(KernelObject::new(
        KernelObjType::Port,
        ObjData::Port(port),
    )).map_err(|_| SyscallError::OutOfMemory)?;

    let task = get_task_by_index(curr_task_id).ok_or(SyscallError::NotFound)?;
    let cap  = Capability::new(handle, Rights::ALL);
    let slot = task.tcb.cnode.lock()
        .alloc(cap)
        .ok_or(SyscallError::ResourceExhausted)? as u64;

    Ok(slot)
}

fn handle_port_close(curr_task_id: u32, cap_idx: u64) -> Result<u64, SyscallError> {
    let task   = get_task_by_index(curr_task_id).ok_or(SyscallError::NotFound)?;
    let handle = resolve_port_cap(&task, cap_idx, Rights::ALL)?;

    let action = with_object(handle, |obj| {
        match &obj.data {
            ObjData::Port(port) => Some(port.close()),
            _ => None,
        }
    })
    .flatten()
    .ok_or(SyscallError::InvalidArgument)?;

    apply_port_action(action);

    obj_remove(handle).map_err(|_| SyscallError::NotFound)?;
    task.tcb.cnode.lock().delete(cap_idx as u32);

    Ok(0)
}

fn handle_port_bind(
    curr_task_id: u32,
    port_cap_idx: u64,
    ch_cap_idx: u64,
    key: u64,
) -> Result<u64, SyscallError> {
    let task = get_task_by_index(curr_task_id).ok_or(SyscallError::NotFound)?;

    let port_handle = resolve_port_cap(&task, port_cap_idx, Rights::WRITE)?;
    let ch_handle   = resolve_channel_cap(&task, ch_cap_idx, Rights::READ)?;

    let port_arc = with_object(port_handle, |obj| {
        match &obj.data {
            ObjData::Port(p) => Some(p.clone()),
            _ => None,
        }
    })
    .flatten()
    .ok_or(SyscallError::InvalidArgument)?;

    with_object_mut(ch_handle, |obj| {
        match &mut obj.data {
            ObjData::Channel(ch) => {
                ch.bind_port(port_arc, key);
                Some(())
            }
            _ => None,
        }
    })
    .flatten()
    .ok_or(SyscallError::InvalidArgument)?;

    Ok(0)
}

fn handle_port_unbind(
    curr_task_id: u32,
    port_cap_idx: u64,
    ch_cap_idx: u64,
) -> Result<u64, SyscallError> {
    let task      = get_task_by_index(curr_task_id).ok_or(SyscallError::NotFound)?;
    let ch_handle = resolve_channel_cap(&task, ch_cap_idx, Rights::READ)?;

    let _ = resolve_port_cap(&task, port_cap_idx, Rights::WRITE)?;

    with_object_mut(ch_handle, |obj| {
        match &mut obj.data {
            ObjData::Channel(ch) => {
                ch.unbind_port();
                Some(())
            }
            _ => None,
        }
    })
    .flatten()
    .ok_or(SyscallError::InvalidArgument)?;

    Ok(0)
}

fn handle_port_wait(
    curr_task_id: u32,
    port_cap_idx: u64,
    _timeout_ns: u64,
    regs: &mut TaskRegisters,
) -> Result<u64, SyscallError> {
    let task        = get_task_by_index(curr_task_id).ok_or(SyscallError::NotFound)?;
    let port_handle = resolve_port_cap(&task, port_cap_idx, Rights::READ)?;

    let result = with_object(port_handle, |obj| {
        match &obj.data {
            ObjData::Port(port) => Some(port.wait(curr_task_id)),
            _ => None,
        }
    })
    .flatten()
    .ok_or(SyscallError::InvalidArgument)?;

    match result {
        Ok(packet) => {
            regs.rdi = packet.key;
            match packet.event {
                crate::arch::amd64::ipc::port::PortEvent::ChannelReadable => {
                    regs.rsi = 0;
                    regs.rdx = 0;
                }
                crate::arch::amd64::ipc::port::PortEvent::ChannelPeerClosed => {
                    regs.rsi = 1;
                    regs.rdx = 0;
                }
                crate::arch::amd64::ipc::port::PortEvent::IrqFired(v) => {
                    regs.rsi = 2;
                    regs.rdx = v as u64;
                }
                crate::arch::amd64::ipc::port::PortEvent::Timer => {
                    regs.rsi = 3;
                    regs.rdx = 0;
                }
            }
            Ok(0)
        }
        Err(PortErr::WouldBlock(action)) => {
            apply_port_action(action);
            Ok(0)
        }
        Err(PortErr::Closed)   => Err(SyscallError::NotFound),
        Err(PortErr::Timeout)  => Err(SyscallError::Timeout),
    }
}

fn handle_port_poll(
    curr_task_id: u32,
    port_cap_idx: u64,
    regs: &mut TaskRegisters,
) -> Result<u64, SyscallError> {
    let task        = get_task_by_index(curr_task_id).ok_or(SyscallError::NotFound)?;
    let port_handle = resolve_port_cap(&task, port_cap_idx, Rights::READ)?;

    let packet = with_object(port_handle, |obj| {
        match &obj.data {
            ObjData::Port(port) => Some(port.poll()),
            _ => None,
        }
    })
    .flatten()
    .ok_or(SyscallError::InvalidArgument)?;

    match packet {
        Some(p) => {
            regs.rdi = p.key;
            match p.event {
                crate::arch::amd64::ipc::port::PortEvent::ChannelReadable    => { regs.rsi = 0; regs.rdx = 0; }
                crate::arch::amd64::ipc::port::PortEvent::ChannelPeerClosed  => { regs.rsi = 1; regs.rdx = 0; }
                crate::arch::amd64::ipc::port::PortEvent::IrqFired(v)        => { regs.rsi = 2; regs.rdx = v as u64; }
                crate::arch::amd64::ipc::port::PortEvent::Timer              => { regs.rsi = 3; regs.rdx = 0; }
            }
            Ok(1) 
        }
        None => Ok(0) 
    }
}

pub fn dispatch_port_syscall_group(
    syscall: PortSyscallNumbers,
    curr_task_id: u32,
    args: &SyscallArguments,
    regs: &mut TaskRegisters,
) -> Result<u64, SyscallError> {
    match syscall {
        PortSyscallNumbers::PortCreate => {
            handle_port_create(curr_task_id)
        }
        PortSyscallNumbers::PortClose => {
            handle_port_close(curr_task_id, args.arg1)
        }
        PortSyscallNumbers::PortBind => {
            handle_port_bind(curr_task_id, args.arg1, args.arg2, args.arg3)
        }
        PortSyscallNumbers::PortUnbind => {
            handle_port_unbind(curr_task_id, args.arg1, args.arg2)
        }
        PortSyscallNumbers::PortWait => {
            handle_port_wait(curr_task_id, args.arg1, args.arg2, regs)
        }
        PortSyscallNumbers::PortPoll => {
            handle_port_poll(curr_task_id, args.arg1, regs)
        }
    }
}