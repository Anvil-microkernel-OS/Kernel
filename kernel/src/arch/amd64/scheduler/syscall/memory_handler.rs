use alloc::vec::Vec;
use x86_64::VirtAddr;

use crate::{arch::amd64::{ipc::{message::{Capability, Rights}, object_table::{KernelObjType, KernelObject, ObjData, Vmo, obj_insert, with_object}}, memory::{misc::align_up, pmm::pages_allocator::{PAllocFlags, alloc_pages_by_order, free_pages}, vmm::{PAGE_SIZE, map_single_page}}, scheduler::{PerCpuSchedulerData, addr_space::{MapFlags, Vma, VmaBacking, VmaError}, syscall::{SyscallError, cap_check::{CapError, resolve_cap}}, task_storage::get_task_by_index}}, early_println};

#[repr(u64)]
pub enum MemorySyscallNumbers {
    VmaMap      = 0x2,
    VmaUnmap    = 0x3,
    Mprotect    = 0x4,
    VmoCreate   = 0x5,
}

impl TryFrom<u64> for MemorySyscallNumbers {
    type Error = ();

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            x if x == Self::VmaMap as u64    => Ok(Self::VmaMap),
            x if x == Self::VmaUnmap as u64  => Ok(Self::VmaUnmap),
            x if x == Self::Mprotect as u64  => Ok(Self::Mprotect),
            x if x == Self::VmoCreate as u64 => Ok(Self::VmoCreate),
            _ => Err(()),
        }
    }
}

pub(crate) fn vma_map(
    vspace_cap_idx: u64,
    vmo_cap_idx:    u64,  
    vaddr:          u64,   
    flags:          u32,
) -> i64 {
    let curr_task_id = PerCpuSchedulerData::get().curr_task_id.id();
    let curr = get_task_by_index(curr_task_id).unwrap();

    let (vspace_handle, vspace_rights) = match resolve_cap(
        &curr, vspace_cap_idx, KernelObjType::VSpace, Rights::READ
    ) {
        Ok(h)  => h,
        Err(e) => match e {
            CapError::InvalidIdx => { return SyscallError::InvalidArgument as i64 },
            CapError::WrongType => { return SyscallError::InvalidArgument as i64 },
            CapError::WrongOwner => { return SyscallError::PermissionDenied as i64 },
            CapError::InsufficientRights => { return SyscallError::PermissionDenied as i64 },
            CapError::NotAllowed => { return SyscallError::PermissionDenied as i64 },
        },
    };


    let target_task_id = match with_object(vspace_handle, |obj| {
        match &obj.data {
            ObjData::VSpace(id) => Some(*id),
            _                   => None,
        }
    }).flatten() {
        Some(id) => id,
        None     => return SyscallError::NotFound as i64,
    };

    if target_task_id != curr_task_id && !vspace_rights.contains(Rights::MANAGE) {
        return SyscallError::PermissionDenied as i64;
    }

    let (vmo_handle, _) = match resolve_cap(
        &curr, vmo_cap_idx, KernelObjType::Vmo, Rights::READ
    ) {
        Ok(h)  => h,
        Err(e) => match e {
            CapError::InvalidIdx => return SyscallError::InvalidArgument as i64,
            CapError::WrongType => return SyscallError::InvalidArgument as i64,
            CapError::WrongOwner => return SyscallError::PermissionDenied as i64,
            CapError::InsufficientRights => return SyscallError::PermissionDenied as i64,
            CapError::NotAllowed => return SyscallError::PermissionDenied as i64,
        },
    };

    let (frames, vmo_size) = match with_object(vmo_handle, |obj| {
        match &obj.data {
            ObjData::Vmo(vmo) => Some((vmo.frames.clone(), vmo.size)),
            _                  => None,
        }
    }).flatten() {
        Some(v) => v,
        None    => return SyscallError::NotFound as i64,
    };

    let target      = get_task_by_index(target_task_id).unwrap();
    let map_flags   = MapFlags::from_bits_truncate(flags) | MapFlags::USER;
    let mut addr_space = target.tcb.addr_space.lock();

    let virt_start = if vaddr == 0 {
        match addr_space.find_free_region(vmo_size) {
            Some(a) => a,
            None    => return SyscallError::OutOfMemory as i64,
        }
    } else {
        let v = VirtAddr::new(vaddr);
        if !v.is_aligned(PAGE_SIZE as u64) {
            return SyscallError::InvalidArgument as i64;
        }
        v
    };

    for (i, phys) in frames.iter().enumerate() {
        let va = VirtAddr::new(virt_start.as_u64() + (i * PAGE_SIZE) as u64);
        let pt_flags = map_flags.to_page_table_flags();

        if let Err(_) = map_single_page(&mut addr_space.page_table, va, *phys, pt_flags) {
            return SyscallError::InvalidArgument as i64;
        }
    }

    let _ = addr_space.vmas.insert(virt_start.as_u64(), Vma {
        vaddr:   virt_start,
        size:    vmo_size,
        flags:   map_flags,
        backing: VmaBacking::Physical { phys_addr: frames[0] },
    });


    virt_start.as_u64() as i64
}

pub(crate) fn vma_unmap(vspace_cap_idx: u64, vaddr: u64) -> i64 {
    let curr_task_id = PerCpuSchedulerData::get().curr_task_id.id();
    let curr = get_task_by_index(curr_task_id).unwrap();

    let (handle, rights) = match resolve_cap(
        &curr, vspace_cap_idx, KernelObjType::VSpace, Rights::WRITE
    ) {
        Ok(h)  => h,
        Err(e) => match e {
            CapError::InvalidIdx => return SyscallError::InvalidArgument as i64,
            CapError::WrongType => return SyscallError::InvalidArgument as i64,
            CapError::WrongOwner => return SyscallError::PermissionDenied as i64,
            CapError::InsufficientRights => return SyscallError::PermissionDenied as i64,
            CapError::NotAllowed => return SyscallError::PermissionDenied as i64,
        },
    };

    let target_task_id = match with_object(handle, |obj| {
        match &obj.data {
            ObjData::VSpace(task_id) => Some(*task_id),
            _                        => None,
        }
    }).flatten() {
        Some(id) => id,
        None     => return SyscallError::NotFound as i64,
    };

    if target_task_id != curr_task_id && !rights.contains(Rights::MANAGE) {
        return SyscallError::PermissionDenied as i64;
    }

    let target = get_task_by_index(target_task_id).unwrap();
    let virt   = VirtAddr::new(vaddr);

    if !virt.is_aligned(PAGE_SIZE as u64) {
        return SyscallError::InvalidArgument as i64;
    }

    match target.tcb.addr_space.lock().unmap(virt) {
        Ok(_)                   => 0,
        Err(VmaError::NotFound) => SyscallError::NotFound as i64,
        Err(_)                  => SyscallError::InvalidArgument as i64,
    }
}

pub(crate) fn mprotect(vspace_cap_idx: u64, vaddr: u64, flags: u32) -> i64 {
    let curr_task_id = PerCpuSchedulerData::get().curr_task_id.id();
    let curr = get_task_by_index(curr_task_id).unwrap();

    let (handle, rights) = match resolve_cap(
        &curr, vspace_cap_idx, KernelObjType::VSpace, Rights::WRITE
    ) {
        Ok(h)  => h,
        Err(e) => match e {
            CapError::InvalidIdx => return SyscallError::InvalidArgument as i64,
            CapError::WrongType => return SyscallError::InvalidArgument as i64,
            CapError::WrongOwner => return SyscallError::PermissionDenied as i64,
            CapError::InsufficientRights => return SyscallError::PermissionDenied as i64,
            CapError::NotAllowed => return SyscallError::PermissionDenied as i64,
        },
    };

    let target_task_id = match with_object(handle, |obj| {
        match &obj.data {
            ObjData::VSpace(task_id) => Some(*task_id),
            _                        => None,
        }
    }).flatten() {
        Some(id) => id,
        None     => return SyscallError::InvalidArgument as i64,
    };

    if target_task_id != curr_task_id && !rights.contains(Rights::MANAGE) {
        return SyscallError::PermissionDenied as i64;
    }

    let target    = get_task_by_index(target_task_id).unwrap();
    let virt      = VirtAddr::new(vaddr);
    let map_flags = MapFlags::from_bits_truncate(flags);

    if !virt.is_aligned(PAGE_SIZE as u64) {
        return SyscallError::InvalidArgument as i64;
    }

    match target.tcb.addr_space.lock().protect(virt, map_flags) {
        Ok(_)                   => 0,
        Err(VmaError::NotFound) => SyscallError::NotFound as i64,
        Err(_)                  => SyscallError::InvalidArgument as i64,
    }
}

pub(crate) fn vmo_create(size: u64) -> i64 {
    let curr_task_id = PerCpuSchedulerData::get().curr_task_id.id();
    let curr = get_task_by_index(curr_task_id).unwrap();

    let aligned     = align_up(size as usize, PAGE_SIZE);
    let num_pages   = aligned / PAGE_SIZE;
    let mut frames  = Vec::with_capacity(num_pages);

    for _ in 0..num_pages {
        match alloc_pages_by_order(0, PAllocFlags::ZEROED | PAllocFlags::KERNEL) {
            Some(phys) => frames.push(phys),
            None => {
                for f in &frames { free_pages(*f); }
                return SyscallError::OutOfMemory as i64;
            }
        }
    }

    let vmo = Vmo { frames, size: aligned };

    let handle = match obj_insert(KernelObject::new(
        KernelObjType::Vmo,
        ObjData::Vmo(vmo),
    )) {
        Ok(h)  => h,
        Err(_) => return SyscallError::OutOfMemory as i64,
    };

    let cap  = Capability::new(handle, Rights::ALL);
    let slot = curr.tcb.cnode.lock()
        .alloc(cap)
        .ok_or(0u64)
        .unwrap() as u64;
    
    slot as i64  
}