use core::alloc::{GlobalAlloc, Layout};
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicUsize, Ordering};

use limine::memory_map::{Entry, EntryType};
use slabmalloc::{AllocablePage, AllocationError, Allocator, LargeObjectPage, ObjectPage, ZoneAllocator};
use spin::{Mutex, Once};

use crate::arch::CurrentMemArchSpec;
use crate::early_println;
use crate::memory::misc::arch_specific::{Arch, LargePageSupport};
use crate::memory::misc::{phys_to_virt, virt_to_phys};
use crate::memory::misc::{
    align_up,
    primitives::{PhysAddr},
};
use crate::memory::pmm::node::PmmError;
use crate::memory::pmm::test::{run_allocator_tests, run_pmm_tests};

pub mod page;
pub mod arena;
pub mod node;
pub(crate) mod test;

use node::{AllocFlags, PmmNode};

static HHDM_OFFSET: AtomicUsize = AtomicUsize::new(0);
static PMM: Once<PmmNode> = Once::new();

#[inline]
pub fn hhdm_offset() -> usize {
    HHDM_OFFSET.load(Ordering::Relaxed)
}

#[inline]
pub fn pmm() -> &'static PmmNode {
    PMM.get().expect("PMM not initialized")
}

pub fn init_early_physical_memory(hhdm_offset: usize, mmap: &[&Entry]) {
    HHDM_OFFSET.store(hhdm_offset, Ordering::Relaxed);
    PMM.call_once(|| PmmNode::new(hhdm_offset));

    for entry in mmap {
        if entry.entry_type != EntryType::USABLE {
            continue;
        }
        let size = entry.length as usize;
        let base = entry.base as usize;
        unsafe {
            match pmm().add_arena(PhysAddr::new(base), size) {
                Ok(()) => {}
                Err(PmmError::RegionTooSmall) => {
                    early_println!("[PMM] Skipping small region: base={:#x}, size={}KB", base, size / 1024);
                }
                Err(e) => {
                    panic!("failed to add PMM arena: {:?}", e);
                }
            }
        }
    }

    run_pmm_tests();
    run_allocator_tests();
}

#[inline]
pub fn init_percpu(cpu_count: usize) {
    unsafe {
        pmm().init_percpu(cpu_count);
    }
}

pub fn reclaim_regions(mmap: &[&Entry]) {
    unsafe {
        for entry in mmap {
            match entry.entry_type {
                EntryType::BOOTLOADER_RECLAIMABLE | EntryType::ACPI_RECLAIMABLE => {
                    let _ = pmm().reclaim_region(
                        PhysAddr::new(entry.base as usize),
                        entry.length as usize,
                    );
                }
                _ => {}
            }
        }
    }
}

#[global_allocator]
static SLAB_ALLOC: SafeZoneAllocator = SafeZoneAllocator(Mutex::new(ZoneAllocator::new()));

pub struct SafeZoneAllocator(Mutex<ZoneAllocator<'static>>);

unsafe impl GlobalAlloc for SafeZoneAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        match layout.size() {
            CurrentMemArchSpec::PAGE_SIZE => {
                let phys_addr = pmm().alloc_page(AllocFlags::empty()).expect("Can't allocate page").as_usize();
                
                phys_to_virt(phys_addr) as *mut u8
            }
            CurrentMemArchSpec::LARGE_PAGE_SIZE => {
                let pages = align_up(layout.size(), CurrentMemArchSpec::PAGE_SIZE) / CurrentMemArchSpec::PAGE_SIZE;
                let phys_addr = pmm().alloc_contiguous(pages, AllocFlags::empty()).expect("Can't allocate page").as_usize();
                phys_to_virt(phys_addr) as *mut u8
            }
            0..=ZoneAllocator::MAX_ALLOC_SIZE => {
                let mut zone_allocator = self.0.lock();
                match zone_allocator.allocate(layout) {
                    Ok(nptr) => nptr.as_ptr(),
                    Err(AllocationError::OutOfMemory) => {
                        if layout.size() <= ZoneAllocator::MAX_BASE_ALLOC_SIZE {
                            pmm().alloc_page(AllocFlags::empty()).map_or(ptr::null_mut(), |page| {
                                unsafe {
                                    let p = phys_to_virt(page.as_usize()) as *mut ObjectPage;
                                    core::ptr::write_bytes(p, 0, 1);
                                    let obj_page: &'static mut ObjectPage<'static> = &mut *p;

                                    zone_allocator
                                        .refill(layout, obj_page)
                                        .expect("Could not refill?");
                                    zone_allocator
                                        .allocate(layout)
                                        .expect("Should succeed after refill")
                                        .as_ptr()
                                }
                            })
                        } else {
                            let pages = LargeObjectPage::SIZE / CurrentMemArchSpec::PAGE_SIZE;      
                            let align_pages = LargeObjectPage::SIZE / CurrentMemArchSpec::PAGE_SIZE;
                            pmm().alloc_contiguous_aligned(pages, align_pages, AllocFlags::empty())
                                .map_or(ptr::null_mut(), |phys| {
                                    unsafe {
                                        let p = phys_to_virt(phys.as_usize()) as *mut LargeObjectPage;
                                        core::ptr::write_bytes(p, 0, 1); 
                                        let large_page: &'static mut LargeObjectPage<'static> = &mut *p;
                                        zone_allocator.refill_large(layout, large_page)
                                            .expect("Could not refill?");
                                        zone_allocator.allocate(layout)
                                            .expect("Should succeed after refill")
                                            .as_ptr()
                                    }
                                })
                        }
                    }
                    Err(AllocationError::InvalidLayout) => panic!("Can't allocate this size"),
                }
            }
            _ => unimplemented!("Can't handle it, probably needs another allocator."),
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let phys_ptr = PhysAddr::new(virt_to_phys(ptr as usize));
        match layout.size() {
            CurrentMemArchSpec::PAGE_SIZE => pmm().free_page(phys_ptr),
            CurrentMemArchSpec::LARGE_PAGE_SIZE => {
                let pages = align_up(layout.size(), CurrentMemArchSpec::PAGE_SIZE) / CurrentMemArchSpec::PAGE_SIZE;
                pmm().free_contiguous(phys_ptr, pages)
            },
            0..=ZoneAllocator::MAX_ALLOC_SIZE => {
                if let Some(nptr) = NonNull::new(ptr) {
                    self.0
                        .lock()
                        .deallocate(nptr, layout)
                        .expect("Couldn't deallocate");
                } else {
                    // Nothing to do (don't dealloc null pointers).
                }
            }
            _ => unimplemented!("Can't handle it, probably needs another allocator."),
        }
    }
}