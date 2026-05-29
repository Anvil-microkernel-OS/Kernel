use alloc::{sync::Arc, vec::Vec};
use spin::Mutex;
use x86_64::{PhysAddr, VirtAddr};

use crate::{arch::amd64::{capability_sys::{cap_resolver::resolve_vmo, capability::{CapType, Capability, Rights}, cnode::CapIdx}, memory::{misc::{align_up, is_user_space_addr, phys_to_virt}, pmm::pages_allocator::{PAllocFlags, alloc_pages_by_order, free_pages}, vmm::PAGE_SIZE, vmo::{Vmo, VmoType}}, scheduler::{addr_space::MapFlags, syscall::{SyscallArguments, SyscallError, get_curr_exec_ctx}}}, define_syscall_group, early_print, early_println};

define_syscall_group! {
    pub enum MemoryVmoSyscalls {
        VmoCreate = 14,
        VmoRead = 15,
        VmoWrite = 16
    }
}

fn handle_vmo_create(size: u64, _type: u64) -> Result<u64, SyscallError> {
    let ctx = get_curr_exec_ctx();

    ctx.1.domain.check_vmo_limit().map_err(|_| SyscallError::ResourceExhausted)?;

    let aligned     = align_up(size as usize, PAGE_SIZE);
    let num_pages   = aligned / PAGE_SIZE;
    let mut frames  = Vec::<Option<PhysAddr>>::with_capacity(num_pages);

    for _ in 0..num_pages {
        match alloc_pages_by_order(0, PAllocFlags::ZEROED | PAllocFlags::KERNEL) {
            Some(phys) => frames.push(Some(phys)),
            None => {
                for f in &frames { free_pages(f.unwrap()); }
                return Err(SyscallError::OutOfMemory);
            }
        }
    }

    let vmo_type = VmoType::from_id(_type).ok_or(SyscallError::InvalidArgument)?;

    let vmo = Arc::new(Mutex::new(Vmo { frames, size: aligned, _type: vmo_type }));

    let slot = ctx.1.cnode.alloc(Capability::new(CapType::Vmo(vmo), Rights::ALL));

    ctx.1.domain.on_vmo_created();

    Ok(slot as u64)  
}

fn handle_vmo_write(
    vmo_cap: CapIdx,
    data_ptr: u64,
    offset: u64,
    len: u64,
) -> Result<u64, SyscallError> {
    let ctx = get_curr_exec_ctx();
    let vmo_obj = resolve_vmo(&ctx.1.cnode, vmo_cap, Rights::WRITE).map_err(|err| err.to_syscall_error())?;

    let offset = offset as usize;
    let len = len as usize;
    let data_va = VirtAddr::new(data_ptr);

    {
        let vmo = vmo_obj.0.lock();
        if offset.checked_add(len).map(|e| e > vmo.size).unwrap_or(true) {
            return Err(SyscallError::InvalidArgument);
        }
    }

    if !is_user_space_addr(data_va) {
        return Err(SyscallError::InvalidArgument);
    }

    let mut written = 0usize;

    while written < len {
        let remaining = len - written;
        let vmo_off = offset + written;
        let user_va = VirtAddr::new(data_ptr + written as u64);

        let vmo_pidx = vmo_off / PAGE_SIZE;
        
        let vmo_poff = vmo_off % PAGE_SIZE;
        let user_poff = user_va.as_u64() as usize % PAGE_SIZE;

        let chunk = remaining
            .min(PAGE_SIZE - vmo_poff)
            .min(PAGE_SIZE - user_poff);

        let user_pbase = VirtAddr::new(user_va.as_u64() & !(PAGE_SIZE as u64 - 1));
        let user_phys = ctx.1.addr_space.lock()
            .translate(user_pbase)
            .ok_or(SyscallError::Fault)?
            .as_u64() as usize + user_poff;

        let vmo_phys = {
            let vmo = vmo_obj.0.lock();
            vmo.frame_at(vmo_pidx)
                .ok_or(SyscallError::InvalidArgument)?
                .as_u64() as usize + vmo_poff
        };

        unsafe {
            let src = phys_to_virt(user_phys) as *const u8;
            let dst = phys_to_virt(vmo_phys) as *mut u8;
            core::ptr::copy_nonoverlapping(src, dst, chunk);
        }

        written += chunk;
    }

    Ok(written as u64)
}

fn handle_vmo_read(
    vmo_cap: CapIdx,
    data_ptr: u64,
    offset: u64,
    len: u64,
) -> Result<u64, SyscallError> {
    let ctx = get_curr_exec_ctx();

    let vmo_obj = resolve_vmo(&ctx.1.cnode, vmo_cap, Rights::READ).map_err(|err| err.to_syscall_error())?;

    let offset = offset as usize;
    let len = len as usize;
    let data_va = VirtAddr::new(data_ptr);

    {
        let vmo = vmo_obj.0.lock();
        if offset.checked_add(len).map(|e| e > vmo.size).unwrap_or(true) {
            return Err(SyscallError::InvalidArgument);
        }
    }

    if !is_user_space_addr(data_va) {
        return Err(SyscallError::InvalidArgument);
    }

    let mut read = 0usize;

    while read < len {
        let remaining = len - read;
        let vmo_off = offset + read;
        let user_va = VirtAddr::new(data_ptr + read as u64);

        let vmo_pidx = vmo_off / PAGE_SIZE;
        let user_pidx = user_va.as_u64() as usize / PAGE_SIZE;

        let vmo_poff = vmo_off % PAGE_SIZE;
        let user_poff = user_va.as_u64() as usize % PAGE_SIZE;

        let chunk = remaining
            .min(PAGE_SIZE - vmo_poff)
            .min(PAGE_SIZE - user_poff);

        let vmo_phys = {
            let vmo = vmo_obj.0.lock();
            vmo.frame_at(vmo_pidx)
                .ok_or(SyscallError::InvalidArgument)?
                .as_u64() as usize + vmo_poff
        };

        let user_pbase = VirtAddr::new((user_pidx * PAGE_SIZE) as u64);
        let user_phys = {
            let addr_space = ctx.1.addr_space.lock();
            let vma = addr_space.find(user_pbase)
                .ok_or(SyscallError::Fault)?;
            
            if !vma.flags.contains(MapFlags::WRITE) {
                return Err(SyscallError::PermissionDenied);
            }
            
            let phys = addr_space.translate(user_pbase)
                .ok_or(SyscallError::Fault)?;
            
            phys.as_u64() as usize + user_poff
        };


        unsafe {
            let src = phys_to_virt(vmo_phys) as *const u8;
            let dst = phys_to_virt(user_phys) as *mut u8;
            core::ptr::copy_nonoverlapping(src, dst, chunk);
        }

        read += chunk;
    }

    Ok(read as u64)
}

pub fn dispatch_vmo_memory_syscall_group(syscall: MemoryVmoSyscalls, args: &SyscallArguments) -> Result<u64, SyscallError> {
    match syscall {
        MemoryVmoSyscalls::VmoCreate => handle_vmo_create(args.arg1, args.arg2),
        MemoryVmoSyscalls::VmoRead  => handle_vmo_read(args.arg1 as u32, args.arg2, args.arg3, args.arg4),
        MemoryVmoSyscalls::VmoWrite => handle_vmo_write(args.arg1 as u32, args.arg2, args.arg3, args.arg4),
    }
}