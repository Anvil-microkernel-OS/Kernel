use alloc::vec::Vec;
use x86_64::VirtAddr;

use crate::{arch::amd64::{ipc::{message::{Capability, Rights}, object_table::{KernelObjType, KernelObject, ObjData, Vmo, obj_insert, with_object}}, memory::{misc::align_up, pmm::pages_allocator::{PAllocFlags, alloc_pages_by_order, free_pages}, vmm::{PAGE_SIZE, map_single_page}}, scheduler::{addr_space::{MapFlags, Vma, VmaBacking, VmaError}, syscall::{SyscallArguments, SyscallError, cap_check::resolve_cap}, task_storage::get_task_by_index}}, define_syscall_group};

define_syscall_group! {
    pub enum MemorySyscallNumbers {
        VmaMap      = 0x2,
        VmaUnmap    = 0x3,
        Mprotect    = 0x4,
        VmoCreate   = 0x5,
    } 
}

fn vma_map(
    curr_task_id:   u32,
    vspace_cap_idx: u64,
    vmo_cap_idx:    u64,  
    vaddr:          u64,   
    flags:          u32,
) -> Result<u64, SyscallError> {

    let curr = get_task_by_index(curr_task_id).unwrap();

    let (vspace_handle, vspace_rights) = match resolve_cap(
        &curr, vspace_cap_idx, KernelObjType::VSpace, Rights::READ
    ) {
        Ok(h)  => h,
        Err(e) => return Err(e.to_syscall_error())
    };


    let target_task_id = match with_object(vspace_handle, |obj| {
        match &obj.data {
            ObjData::VSpace(id) => Some(*id),
            _                   => None,
        }
    }).flatten() {
        Some(id) => id,
        None     => return Err(SyscallError::NotFound),
    };

    if target_task_id != curr_task_id && !vspace_rights.contains(Rights::MANAGE) {
        return Err(SyscallError::PermissionDenied);
    }

    let (vmo_handle, _) = match resolve_cap(
        &curr, vmo_cap_idx, KernelObjType::Vmo, Rights::READ
    ) {
        Ok(h)  => h,
        Err(e) => return Err(e.to_syscall_error())
    };

    let (frames, vmo_size) = match with_object(vmo_handle, |obj| {
        match &obj.data {
            ObjData::Vmo(vmo) => Some((vmo.frames.clone(), vmo.size)),
            _                  => None,
        }
    }).flatten() {
        Some(v) => v,
        None    => return Err(SyscallError::NotFound),
    };

    let target      = get_task_by_index(target_task_id).unwrap();
    let map_flags   = MapFlags::from_bits_truncate(flags) | MapFlags::USER;
    let mut addr_space = target.tcb.addr_space.lock();

    let virt_start = if vaddr == 0 {
        match addr_space.find_free_region(vmo_size) {
            Some(a) => a,
            None    => return Err(SyscallError::OutOfMemory),
        }
    } else {
        let v = VirtAddr::new(vaddr);
        if !v.is_aligned(PAGE_SIZE as u64) {
            return Err(SyscallError::InvalidArgument);
        }
        v
    };

    for (i, phys) in frames.iter().enumerate() {
        let va = VirtAddr::new(virt_start.as_u64() + (i * PAGE_SIZE) as u64);
        let pt_flags = map_flags.to_page_table_flags();

        if let Err(_) = map_single_page(&mut addr_space.page_table, va, *phys, pt_flags) {
            return Err(SyscallError::InvalidArgument);
        }
    }

    let _ = addr_space.vmas.insert(virt_start.as_u64(), Vma {
        vaddr:   virt_start,
        size:    vmo_size,
        flags:   map_flags,
        backing: VmaBacking::Physical { phys_addr: frames[0] },
    });


    Ok(virt_start.as_u64())
}

fn vma_unmap(curr_task_id: u32, vspace_cap_idx: u64, vaddr: u64) -> Result<u64, SyscallError> {
    let curr = get_task_by_index(curr_task_id).unwrap();

    let (handle, rights) = match resolve_cap(
        &curr, vspace_cap_idx, KernelObjType::VSpace, Rights::WRITE
    ) {
        Ok(h)  => h,
        Err(e) => return Err(e.to_syscall_error())
    };

    let target_task_id = match with_object(handle, |obj| {
        match &obj.data {
            ObjData::VSpace(task_id) => Some(*task_id),
            _                        => None,
        }
    }).flatten() {
        Some(id) => id,
        None     => return Err(SyscallError::NotFound),
    };

    if target_task_id != curr_task_id && !rights.contains(Rights::MANAGE) {
        return Err(SyscallError::PermissionDenied);
    }

    let target = get_task_by_index(target_task_id).unwrap();
    let virt   = VirtAddr::new(vaddr);

    if !virt.is_aligned(PAGE_SIZE as u64) {
        return Err(SyscallError::InvalidArgument);
    }

    match target.tcb.addr_space.lock().unmap(virt) {
        Ok(_)                   => Ok(0),
        Err(VmaError::NotFound) => Err(SyscallError::NotFound),
        Err(_)                  => Err(SyscallError::InvalidArgument),
    }
}

fn mprotect(curr_task_id: u32, vspace_cap_idx: u64, vaddr: u64, flags: u32) -> Result<u64, SyscallError> {
    let curr = get_task_by_index(curr_task_id).unwrap();

    let (handle, rights) = match resolve_cap(
        &curr, vspace_cap_idx, KernelObjType::VSpace, Rights::WRITE
    ) {
        Ok(h)  => h,
        Err(e) => return Err(e.to_syscall_error())
    };

    let target_task_id = match with_object(handle, |obj| {
        match &obj.data {
            ObjData::VSpace(task_id) => Some(*task_id),
            _                        => None,
        }
    }).flatten() {
        Some(id) => id,
        None     => return Err(SyscallError::InvalidArgument),
    };

    if target_task_id != curr_task_id && !rights.contains(Rights::MANAGE) {
        return Err(SyscallError::PermissionDenied);
    }

    let target    = get_task_by_index(target_task_id).unwrap();
    let virt      = VirtAddr::new(vaddr);
    let map_flags = MapFlags::from_bits_truncate(flags);

    if !virt.is_aligned(PAGE_SIZE as u64) {
        return Err(SyscallError::InvalidArgument);
    }

    match target.tcb.addr_space.lock().protect(virt, map_flags) {
        Ok(_)                   => Ok(0),
        Err(VmaError::NotFound) => Err(SyscallError::NotFound),
        Err(_)                  => Err(SyscallError::InvalidArgument),
    }
}

fn vmo_create(curr_task_id: u32, size: u64) -> Result<u64, SyscallError> {
    let curr = get_task_by_index(curr_task_id).unwrap();

    let aligned     = align_up(size as usize, PAGE_SIZE);
    let num_pages   = aligned / PAGE_SIZE;
    let mut frames  = Vec::with_capacity(num_pages);

    for _ in 0..num_pages {
        match alloc_pages_by_order(0, PAllocFlags::ZEROED | PAllocFlags::KERNEL) {
            Some(phys) => frames.push(phys),
            None => {
                for f in &frames { free_pages(*f); }
                return Err(SyscallError::OutOfMemory);
            }
        }
    }

    let vmo = Vmo { owner_id: curr_task_id, frames, size: aligned };

    let handle = match obj_insert(KernelObject::new(
        KernelObjType::Vmo,
        ObjData::Vmo(vmo),
    )) {
        Ok(h)  => h,
        Err(_) => return Err(SyscallError::OutOfMemory),
    };

    let cap  = Capability::new(handle, Rights::ALL);
    let slot = curr.tcb.cnode.lock()
        .alloc(cap)
        .unwrap() as u64;
    
    Ok(slot)  
}

pub fn dispatch_memory_syscall_group(syscall: MemorySyscallNumbers, curr_task_id: u32, args: &SyscallArguments) -> Result<u64, SyscallError> {
    match syscall {
        MemorySyscallNumbers::VmaMap => vma_map(curr_task_id, args.arg1, args.arg2, args.arg3, args.arg4 as u32),
        MemorySyscallNumbers::VmaUnmap => vma_unmap(curr_task_id, args.arg1, args.arg2),
        MemorySyscallNumbers::Mprotect => mprotect(curr_task_id, args.arg1, args.arg2, args.arg3 as u32),
        MemorySyscallNumbers::VmoCreate => vmo_create(curr_task_id, args.arg1)
    }
}