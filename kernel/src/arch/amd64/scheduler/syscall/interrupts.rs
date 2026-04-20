use crate::{arch::amd64::{apic::PercpuLapic, interrupts::irq_trans_manager::IDT_TRANSFER_MANAGER, ipc::{message::Rights, object_table::{ObjData, with_object}}, scheduler::{syscall::{SyscallArguments, SyscallError, messaging::port::resolve_port_cap}, task_storage::get_task_by_index}}, define_syscall_group, early_println};

define_syscall_group! {
    pub enum IrqSyscallNumbers {
        IrqPortBind = 35,
        IrqPortUnbind = 36,
        IrqAck = 37,
    }
}

fn handle_irq_bind_port(
    curr_task_id: u32,
    port_cap_idx: u64,
    vector: u8,
    key: u64
) -> Result<u64, SyscallError> {
    let task = get_task_by_index(curr_task_id).ok_or(SyscallError::NotFound)?;

    let port_handle = resolve_port_cap(&task, port_cap_idx, Rights::WRITE)?;

    let port_arc = with_object(port_handle, |obj| {
        match &obj.data {
            ObjData::Port(p) => Some(p.clone()),
            _ => None,
        }
    })
    .flatten()
    .ok_or(SyscallError::InvalidArgument)?;

    IDT_TRANSFER_MANAGER.bind_irq(task.id, port_arc, vector, key).map_err(|_| SyscallError::ResourceExhausted)?;

    Ok(0)
}

fn handle_irq_port_unbind(
    curr_task_id: u32,
    port_cap_idx: u64,
    vector: u8,
) -> Result<u64, SyscallError> {
    let task = get_task_by_index(curr_task_id).ok_or(SyscallError::NotFound)?;

    let port_handle = resolve_port_cap(&task, port_cap_idx, Rights::WRITE)?;

    with_object(port_handle, |obj| {
        match &obj.data {
            ObjData::Port(p) => Some(p.clone()),
            _ => None,
        }
    })
    .flatten()
    .ok_or(SyscallError::InvalidArgument)?;

    IDT_TRANSFER_MANAGER.unbind_irq(vector).map_err(|_| SyscallError::ResourceExhausted)?;

    Ok(0)
}

fn handle_irq_ack(curr_task_id: u32, vector: u8) -> Result<u64, SyscallError> {
    PercpuLapic::get().lapic.eoi(); // tmp, next step - unmask only used
    Ok(0)
}

pub fn dispatch_irq_syscall_group(
    syscall: IrqSyscallNumbers,
    curr_task_id: u32,
    args: &SyscallArguments,
) -> Result<u64, SyscallError> {
    match syscall {
        IrqSyscallNumbers::IrqPortBind => handle_irq_bind_port(curr_task_id, args.arg1, args.arg2 as u8, args.arg3),
        IrqSyscallNumbers::IrqPortUnbind => handle_irq_port_unbind(curr_task_id, args.arg1, args.arg2 as u8),
        IrqSyscallNumbers::IrqAck => handle_irq_ack(curr_task_id, args.arg1 as u8)
    }
}