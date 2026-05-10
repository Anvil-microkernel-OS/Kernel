use core::sync::atomic::Ordering;

use alloc::boxed::Box;

use crate::{arch::amd64::scheduler::{syscall::{SyscallArguments, SyscallError, get_curr_exec_ctx}, task::Tid, task_storage::get_thread}, define_syscall_group};

define_syscall_group! {
    pub enum IoPortSyscalls {
        PortEnable = 31,
        PortDisable = 32,
    }
}

fn handle_enable_port(port: u64) -> Result<u64, SyscallError> {
    if port >= 65536 {
        return Err(SyscallError::InvalidArgument);
    }

    let ctx = get_curr_exec_ctx();

    let mut io_permissions = ctx.1.iopb_permissions.lock();
    
    if io_permissions.is_none() {
        *io_permissions = Some(Box::new([0xFF; 8192]));
    }

    let iopb = io_permissions.as_mut().unwrap();
    let byte = (port / 8) as usize;
    let bit  = port % 8;
    iopb[byte] &= !(1u8 << bit); 
    
    ctx.1.iopb_gen.fetch_add(1, Ordering::Release);
    
    Ok(0)
}

fn handle_disable_port(port: u64) -> Result<u64, SyscallError> {
    if port >= 65536 {
        return Err(SyscallError::InvalidArgument);
    }

    let ctx = get_curr_exec_ctx();

    let mut io_permissions = ctx.1.iopb_permissions.lock();

    if let Some(iopb) = io_permissions.as_mut() {
        let byte = (port / 8) as usize;
        let bit  = port % 8;
        iopb[byte] |= 1u8 << bit; 
        ctx.1.iopb_gen.fetch_add(1, Ordering::Release);
    }

    Ok(0)
}

pub fn dispatch_port_syscall_group(syscall: IoPortSyscalls, args: &SyscallArguments) -> Result<u64, SyscallError> {
    match syscall {
        IoPortSyscalls::PortEnable => handle_enable_port(args.arg1),
        IoPortSyscalls::PortDisable => handle_disable_port(args.arg1),
    }
}