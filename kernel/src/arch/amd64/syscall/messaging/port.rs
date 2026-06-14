use crate::{arch::amd64::{capability_sys::{cap_resolver::{resolve_channel, resolve_port}, capability::{CapType, Capability, Rights}, cnode::CapIdx}, ipc::port::{Port, PortAction, PortErr}, scheduler::{block_current_task, task::{Process, ThreadRegisters, Tid}, task_storage::{get_thread, wake_thread}}, syscall::{SyscallArguments, SyscallError, get_curr_exec_ctx}}, define_syscall_group};

define_syscall_group! {
    pub enum PortSyscallNumbers {
        PortCreate    = 40,
        PortClose     = 41,
        PortBind      = 42,
        PortUnbind    = 43,
        PortWait      = 44,
        PortPoll      = 45,
    }
}

fn apply_port_action(action: PortAction) {
    match action {
        PortAction::Continue => {}
        PortAction::Block { task_id } => {
            if let Some(_) = get_thread(task_id) {
                block_current_task();
            }
        }
        PortAction::Wake { task_id } => {
            if let Some(task) = get_thread(task_id) {
                wake_thread(task.tid);
            }
        }
    }
}

fn handle_port_create() -> Result<u64, SyscallError> {
    let ctx = get_curr_exec_ctx();

    let port = Port::new();

    let slot = ctx.1.cnode.alloc(Capability::new(CapType::Port(port), Rights::ALL));

    Ok(slot as u64)
}

fn handle_port_close(cap_idx: CapIdx) -> Result<u64, SyscallError> {
    let ctx = get_curr_exec_ctx();

    let port_obj = resolve_port(&ctx.1.cnode, cap_idx, Rights::DESTROY).map_err(|err| err.to_syscall_error())?;

    let action = port_obj.0.close();

    apply_port_action(action);

    ctx.1.cnode.delete(cap_idx);

    Ok(0)
}

fn handle_port_bind(
    port_cap_idx: CapIdx,
    ch_cap_idx: CapIdx,
    key: u64,
) -> Result<u64, SyscallError> {
    let ctx = get_curr_exec_ctx();

    let port_obj = resolve_port(&ctx.1.cnode, port_cap_idx, Rights::WRITE & Rights::READ).map_err(|err| err.to_syscall_error())?;
    let channel_obj = resolve_channel(&ctx.1.cnode, ch_cap_idx, Rights::WRITE & Rights::READ).map_err(|err| err.to_syscall_error())?;

    channel_obj.0.bind_port(port_obj.0.clone(), key);

    Ok(0)
}

fn handle_port_unbind(
    port_cap_idx: CapIdx,
    ch_cap_idx: CapIdx,
) -> Result<u64, SyscallError> {
    let ctx = get_curr_exec_ctx();

    resolve_port(&ctx.1.cnode, port_cap_idx, Rights::WRITE).map_err(|err| err.to_syscall_error())?;
    let channel_obj = resolve_channel(&ctx.1.cnode, ch_cap_idx, Rights::WRITE).map_err(|err| err.to_syscall_error())?;

    channel_obj.0.unbind_port();

    Ok(0)
}

fn handle_port_wait(
    port_cap_idx: CapIdx,
    _timeout_ns: u64,
    regs: &mut ThreadRegisters,
) -> Result<u64, SyscallError> {
    let ctx = get_curr_exec_ctx();

    let port_obj = resolve_port(&ctx.1.cnode, port_cap_idx, Rights::READ).map_err(|err| err.to_syscall_error())?;
    let result = port_obj.0.wait(ctx.0.tid);

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
    port_cap_idx: CapIdx,
    regs: &mut ThreadRegisters,
) -> Result<u64, SyscallError> {
    let ctx = get_curr_exec_ctx();

    let port_obj = resolve_port(&ctx.1.cnode, port_cap_idx, Rights::READ).map_err(|err| err.to_syscall_error())?;

    let packet = port_obj.0.poll();

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
    args: &SyscallArguments,
    regs: &mut ThreadRegisters,
) -> Result<u64, SyscallError> {
    match syscall {
        PortSyscallNumbers::PortCreate => {
            handle_port_create()
        }
        PortSyscallNumbers::PortClose => {
            handle_port_close(args.arg1 as u32)
        }
        PortSyscallNumbers::PortBind => {
            handle_port_bind(args.arg1 as u32, args.arg2 as u32, args.arg3)
        }
        PortSyscallNumbers::PortUnbind => {
            handle_port_unbind(args.arg1 as u32, args.arg2 as u32)
        }
        PortSyscallNumbers::PortWait => {
            handle_port_wait(args.arg1 as u32, args.arg2, regs)
        }
        PortSyscallNumbers::PortPoll => {
            handle_port_poll(args.arg1 as u32, regs)
        }
    }
}