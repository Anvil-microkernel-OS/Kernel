use core::sync::atomic::Ordering;

use alloc::boxed::Box;

use crate::{arch::amd64::{ports::Port, scheduler::{syscall::{SyscallArguments, SyscallError}, task_storage::get_task_by_index}}, define_syscall_group};

define_syscall_group! {
    pub enum IoPortSyscallNumbers {
        PortEnable = 31,
        PortDisable = 32,
        PortRead = 33,
        PortWrite = 34,
    }
}

fn handle_enable_port(curr_task_id: u32, port: u64) -> Result<u64, SyscallError> {
    if port >= 65536 {
        return Err(SyscallError::InvalidArgument);
    }

    let curr = get_task_by_index(curr_task_id).unwrap();
    let mut io_permissions = curr.tcb.iopb_permissons.lock();
    
    if io_permissions.is_none() {
        *io_permissions = Some(Box::new([0xFF; 8192]));
    }

    let iopb = io_permissions.as_mut().unwrap();
    let byte = (port / 8) as usize;
    let bit  = port % 8;
    iopb[byte] &= !(1u8 << bit); 
    
    curr.tcb.iopb_gen.fetch_add(1, Ordering::Release);
    
    Ok(0)
}

fn handle_disable_port(curr_task_id: u32, port: u64) -> Result<u64, SyscallError> {
    if port >= 65536 {
        return Err(SyscallError::InvalidArgument);
    }

    let curr = get_task_by_index(curr_task_id).unwrap();
    let mut io_permissions = curr.tcb.iopb_permissons.lock();

    if let Some(iopb) = io_permissions.as_mut() {
        let byte = (port / 8) as usize;
        let bit  = port % 8;
        iopb[byte] |= 1u8 << bit; 
        curr.tcb.iopb_gen.fetch_add(1, Ordering::Release);
    }

    Ok(0)
}

fn handle_port_write(curr_task_id: u32, port: u64, value: u64) -> Result<u64, SyscallError> {
    if port >= 65536 {
        return Err(SyscallError::InvalidArgument);
    }
    
    let curr = get_task_by_index(curr_task_id).unwrap();
    {
        let io_permissions = curr.tcb.iopb_permissons.lock();
        let iopb = io_permissions.as_ref().ok_or(SyscallError::PermissionDenied)?;
        let byte = (port / 8) as usize;
        let bit  = port % 8;
        if iopb[byte] & (1u8 << bit) != 0 {
            return Err(SyscallError::PermissionDenied);
        }
    } 
    
    let port = port as u16;
    if value <= 0xFF {
        Port::<u8>::new(port).write(value as u8);
    } else if value <= 0xFFFF {
        Port::<u16>::new(port).write(value as u16);
    } else {
        Port::<u32>::new(port).write(value as u32);
    }
    
    Ok(0)
}

fn handle_port_read(curr_task_id: u32, port: u64, size: u64) -> Result<u64, SyscallError> {
    if port >= 65536 {
        return Err(SyscallError::InvalidArgument);
    }

    let curr = get_task_by_index(curr_task_id).unwrap();
    {
        let io_permissions = curr.tcb.iopb_permissons.lock();
        let iopb = io_permissions.as_ref().ok_or(SyscallError::PermissionDenied)?;
        let byte = (port / 8) as usize;
        let bit  = port % 8;
        if iopb[byte] & (1u8 << bit) != 0 {
            return Err(SyscallError::PermissionDenied);
        }
    }

    let port = port as u16;
    let value = match size {
        1 => Port::<u8>::new(port).read() as u64,
        2 => Port::<u16>::new(port).read() as u64,
        4 => Port::<u32>::new(port).read() as u64,
        _ => return Err(SyscallError::InvalidArgument),
    };

    Ok(value)
}

pub fn dispatch_port_syscall_group(syscall: IoPortSyscallNumbers, curr_task_id: u32, args: &SyscallArguments) -> Result<u64, SyscallError> {
    match syscall {
        IoPortSyscallNumbers::PortEnable => handle_enable_port(curr_task_id, args.arg1),
        IoPortSyscallNumbers::PortDisable => handle_disable_port(curr_task_id, args.arg1),
        IoPortSyscallNumbers::PortRead => handle_port_read(curr_task_id, args.arg1, args.arg2),
        IoPortSyscallNumbers::PortWrite => handle_port_write(curr_task_id, args.arg1, args.arg2),
    }
}
