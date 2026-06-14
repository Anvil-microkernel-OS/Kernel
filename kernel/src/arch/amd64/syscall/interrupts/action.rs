use crate::{arch::amd64::{apic::{PercpuLapic, ioapic_manager::{DeliveryMode, IrqError, Polarity, TriggerMode, ioapic_manager}}, capability_sys::{cap_resolver::resolve_port, capability::Rights, cnode::CapIdx}, interrupts::irq_trans_manager::IDT_TRANSFER_MANAGER, scheduler::{task::Tid, task_storage::get_thread}, syscall::{SyscallArguments, SyscallError}}, define_syscall_group};

define_syscall_group! {
    pub enum IrqSyscallNumbers {
        IrqPortBind = 35,
        IrqPortUnbind = 36,
        IrqAck = 37,
    }
}

fn handle_irq_bind_port(
    port_cap_idx: CapIdx,
    gsi: u32,
    key: u64,
) -> Result<u64, SyscallError> {
    /*let ctx = get_curr_exec_ctx();

    let dst_obj = resolve_port(&ctx.1.cnode, port_cap_idx, Rights::WRITE).map_err(|err| err.to_syscall_error())?;

    let bsp = PercpuLapic::get().lapic.id() as u8;

    let vector = ioapic_manager().configure_irq_alloc_vector(
        gsi,
        bsp,
        DeliveryMode::Fixed,
        Polarity::ActiveHigh,
        TriggerMode::Edge,
    ).map_err(|e| match e {
        IrqError::GsiNotHandled(_) => SyscallError::InvalidArgument,
        IrqError::AlreadyConfigured(_) => SyscallError::AlreadyExists,
        IrqError::NoFreeVectors => SyscallError::ResourceExhausted,
        _ => SyscallError::Fault,
    })?;

    if IDT_TRANSFER_MANAGER
        .bind_irq(curr_thread.tid, port_arc, vector, key)
        .is_err()
    {
        ioapic_manager().unconfigure_irq(gsi).ok();
        return Err(SyscallError::AlreadyExists);
    }

    if ioapic_manager().unmask_irq(gsi).is_err() {
        IDT_TRANSFER_MANAGER.unbind_irq(vector).ok();
        ioapic_manager().unconfigure_irq(gsi).ok();
        return Err(SyscallError::Fault);
    }

    Ok(vector as u64)*/

    todo!()
}

fn handle_irq_port_unbind(
    port_cap_idx: CapIdx,
    gsi: u32,
) -> Result<u64, SyscallError> {
    /*let curr_thread = get_thread(curr_thread_id)
        .expect("NO VALID THREAD id in handle_get_tid");

    let curr_proc = curr_thread.parent_proc.read().upgrade()
        .expect("NO VALID PROCESS in handle_get_tid");

    let (port_handle, _) = resolve_cap(&curr_proc, port_cap_idx, KernelObjType::Port, Rights::WRITE)
        .map_err(|e| e.to_syscall_error())?;

    with_object(port_handle, |obj| {
        match &obj.data {
            ObjData::Port(p) => Some(p.clone()),
            _ => None,
        }
    })
    .flatten()
    .ok_or(SyscallError::InvalidArgument)?;

    let vector = ioapic_manager()
        .gsi_to_vector(gsi)
        .ok_or(SyscallError::NotFound)?;

    ioapic_manager().unconfigure_irq(gsi).map_err(|err| match err {
        _ => SyscallError::Fault
    })?;

    IDT_TRANSFER_MANAGER.unbind_irq(vector).map_err(|_| SyscallError::ResourceExhausted)?;

    Ok(0)*/
    todo!()
}

fn handle_irq_ack() -> Result<u64, SyscallError> {
    PercpuLapic::get().lapic.eoi(); 
    Ok(0)
}

pub fn dispatch_irq_syscall_group(
    syscall: IrqSyscallNumbers,
    args: &SyscallArguments,
) -> Result<u64, SyscallError> {
    match syscall {
        IrqSyscallNumbers::IrqPortBind => handle_irq_bind_port(args.arg1 as u32, args.arg2 as u32, args.arg3),
        IrqSyscallNumbers::IrqPortUnbind => handle_irq_port_unbind(args.arg1 as u32, args.arg2 as u32),
        IrqSyscallNumbers::IrqAck => handle_irq_ack()
    }
}