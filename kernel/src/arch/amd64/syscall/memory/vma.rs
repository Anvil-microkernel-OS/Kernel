use x86_64::VirtAddr;

use crate::{
    arch::amd64::{
        capability_sys::{cap_resolver::{resolve_vmo, resolve_vspace}, capability::Rights, cnode::CapIdx}, memory::{u_k_boundary::uaccsess::copy_from_user, vmm::PAGE_SIZE}, scheduler::addr_space::{MapFlags, VmaError}, syscall::{SyscallArguments, SyscallError, get_curr_exec_ctx}
    },
    define_syscall_group, early_println,
};

define_syscall_group! {
    pub enum MemorySyscallNumbers {
        VmaMap   = 11,
        VmaUnmap = 12,
        Mprotect = 13,
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct VmaMapArgs {
    pub vspace_cap: u64,
    pub vmo_cap:    u64,
    pub vaddr:      u64,   
    pub size:       u64,
    pub vmo_offset: u64,
    pub flags:      u32,
    pub _reserved:  u32,   
}

fn vma_err_to_syscall(e: VmaError) -> SyscallError {
    match e {
        VmaError::NotAligned        => SyscallError::InvalidArgument,
        VmaError::Overlap           => SyscallError::AlreadyExists,
        VmaError::NotFound          => SyscallError::NotFound,
        VmaError::OutOfVmoBounds    => SyscallError::InvalidArgument,
        VmaError::OutOfMemory       => SyscallError::OutOfMemory,
        VmaError::PageTableError(_) => SyscallError::Fault,
    }
}

fn handle_vma_map(
    args_user_ptr:  u64,
) -> Result<u64, SyscallError> {
    let args = copy_from_user::<VmaMapArgs>(args_user_ptr as usize).ok_or(SyscallError::Fault)?;

    let ctx = get_curr_exec_ctx();
    let vspace_obj = resolve_vspace(&ctx.1.cnode, args.vspace_cap as u32, Rights::WRITE).map_err(|err| err.to_syscall_error())?;
    let vmo_obj = resolve_vmo(&ctx.1.cnode, args.vmo_cap as u32, Rights::MANAGE).map_err(|err| err.to_syscall_error())?;

    let map_flags = MapFlags::from_bits_truncate(args.flags) | MapFlags::USER;

    if map_flags.contains(MapFlags::WRITE) && !vmo_obj.1.contains(Rights::WRITE) {
        return Err(SyscallError::PermissionDenied);
    }
    if map_flags.contains(MapFlags::EXEC) && !vmo_obj.1.contains(Rights::EXEC) {
        return Err(SyscallError::PermissionDenied);
    }

    let requested_va = if args.vaddr == 0 {
        None
    } else {
        Some(VirtAddr::new(args.vaddr))
    };

    let mut addr_space = vspace_obj.0.addr_space.lock();
    let actual_va = addr_space.map(
        requested_va,
        args.size as usize,
        vmo_obj.0,
        args.vmo_offset as usize,
        map_flags,
    ).map_err(vma_err_to_syscall)?;

    Ok(actual_va.as_u64())
}

fn handle_vma_unmap(
    vspace_cap_idx: CapIdx,
    vaddr:          u64,
) -> Result<u64, SyscallError> {
    let ctx = get_curr_exec_ctx();

    let vspace_obj = resolve_vspace(&ctx.1.cnode, vspace_cap_idx, Rights::WRITE).map_err(|err| err.to_syscall_error())?;

    let virt = VirtAddr::new(vaddr);
    if !virt.is_aligned(PAGE_SIZE as u64) {
        return Err(SyscallError::InvalidArgument);
    }

    vspace_obj.0.addr_space.lock()
        .unmap(virt)
        .map_err(vma_err_to_syscall)?;

    Ok(0)
}

fn handle_mprotect(
    vspace_cap_idx: CapIdx,
    vaddr:          u64,
    flags:          u32,
) -> Result<u64, SyscallError> {
    let ctx = get_curr_exec_ctx();

    let vspace_obj = resolve_vspace(&ctx.1.cnode, vspace_cap_idx, Rights::WRITE).map_err(|err| err.to_syscall_error())?;

    let virt = VirtAddr::new(vaddr);
    if !virt.is_aligned(PAGE_SIZE as u64) {
        return Err(SyscallError::InvalidArgument);
    }

    let map_flags = MapFlags::from_bits_truncate(flags) | MapFlags::USER;

    vspace_obj.0.addr_space.lock()
        .protect(virt, map_flags)
        .map_err(vma_err_to_syscall)?;

    Ok(0)
}

pub fn dispatch_vma_memory_syscall_group(
    syscall: MemorySyscallNumbers,
    args: &SyscallArguments,
) -> Result<u64, SyscallError> {
    match syscall {
        MemorySyscallNumbers::VmaMap => {
            handle_vma_map(args.arg1)
        }
        MemorySyscallNumbers::VmaUnmap => {
            handle_vma_unmap(args.arg1 as u32, args.arg2)
        }
        MemorySyscallNumbers::Mprotect => {
            handle_mprotect(args.arg1 as u32, args.arg2, args.arg3 as u32)
        }
    }
}