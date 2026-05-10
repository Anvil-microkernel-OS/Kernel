use alloc::sync::Arc;
use x86_64::{VirtAddr, registers::control::Cr2};

use crate::{arch::amd64::{cpu::hlt_loop, memory::{vmm::{PAGE_SIZE, map_single_page}, vmo::VmoType}, scheduler::{PerCpuSchedulerData, addr_space::MapFlags, task::Process, task_storage::get_thread}}, early_println, isr};

isr!(14, page_fault, |frame| {
    let fault_addr = Cr2::read().unwrap();
    let error = frame.error;
    let is_present = error & (1 << 0) != 0;
    let is_write   = error & (1 << 1) != 0;
    let is_user    = error & (1 << 2) != 0;

    if !is_user {
        early_println!(
            "Kernel page fault at {:#x} error={:#x}",
            fault_addr.as_u64(), error
        );
        early_println!("{}", frame);
        hlt_loop();
    }

    let curr_thread_id = PerCpuSchedulerData::get().curr_thread_id;

    let thread = match get_thread(curr_thread_id) {
        Some(t) => t,
        None => {
            early_println!(
                "PF from user but no current thread! addr={:#x} err={:#x}",
                fault_addr.as_u64(), error
            );
            hlt_loop();
        }
    };
    let proc = match thread.parent_proc.read().upgrade() {
        Some(p) => p,
        None => {
            early_println!("PF: thread {} has no parent process", curr_thread_id);
            hlt_loop();
        }
    };

    match handle_user_page_fault(&proc, fault_addr, is_present, is_write) {
        Ok(()) => {
            // ret to user
        }
        Err(e) => {
            early_println!(
                "PF: segfault TID={} addr={:#x} reason={:?}",
                curr_thread_id, fault_addr.as_u64(), e
            );
            // TODO: kill process / send signal 
            hlt_loop();
        }
    }
});

#[derive(Debug)]
enum PageFaultError {
    NoVma,
    ProtectionViolation,
    OutOfMemory,
    NotImplemented,
    PageTableError(&'static str),
}

fn handle_user_page_fault(
    proc:        &Arc<Process>,
    fault_addr:  VirtAddr,
    is_present:  bool,
    is_write:    bool,
) -> Result<(), PageFaultError> {
    let page_vaddr = VirtAddr::new(fault_addr.as_u64() & !(PAGE_SIZE as u64 - 1));

    let (vmo_arc, vmo_page_idx, pt_flags, _) = {
        let addr_space = proc.addr_space.lock();

        let vma = addr_space.find(fault_addr)
            .ok_or(PageFaultError::NoVma)?;

        if is_present {
            return Err(PageFaultError::ProtectionViolation);
        }
        if is_write && !vma.flags.contains(MapFlags::WRITE) {
            return Err(PageFaultError::ProtectionViolation);
        }

        let page_idx = vma.vmo_page_index(page_vaddr)
            .ok_or(PageFaultError::NoVma)?;

        (
            Arc::clone(&vma.vmo),
            page_idx,
            vma.flags.to_page_table_flags(),
            vma.flags.contains(MapFlags::WRITE),
        )
    }; 

    let frame = {
        let mut vmo_lock = vmo_arc.lock();  

        match vmo_lock._type {
            VmoType::Anonymous => {
                vmo_lock.populate_anonymous(vmo_page_idx).map_err(|_| PageFaultError::OutOfMemory)?
            }
            VmoType::Contigious | VmoType::Physical => {
                vmo_lock.frame_at(vmo_page_idx)
                    .ok_or(PageFaultError::NotImplemented)?
            }
        }
    };

    {
        let mut addr_space = proc.addr_space.lock();

        if addr_space.find(page_vaddr).is_none() {
            return Err(PageFaultError::NoVma);
        }

        if addr_space.translate(page_vaddr).is_some() {
            return Ok(()); 
        }

        map_single_page(
            &mut addr_space.page_table,
            page_vaddr,
            frame,
            pt_flags,
        ).map_err(PageFaultError::PageTableError)?;
    }

    Ok(())
}