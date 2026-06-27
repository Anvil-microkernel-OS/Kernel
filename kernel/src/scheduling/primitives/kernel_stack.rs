use core::sync::atomic::{AtomicU64, Ordering};

use alloc::vec::Vec;

use crate::{arch::CurrentMemArchSpec, memory::{misc::{arch_specific::Arch, primitives::{PhysAddr, VirtAddr}}, pmm::{node::AllocFlags, pmm}, vmm::{kernel_pt_mapper, pflags::PFlags}}};

pub const DEFAULT_KERNEL_STACK_SIZE: usize = 16 * CurrentMemArchSpec::PAGE_SIZE;

const KERNEL_STACKS_VA_BASE: u64 = 0xFFFF_C000_0000_0000;
const KERNEL_STACKS_VA_SIZE: u64 = 256 * 1024 * 1024 * 1024; 

static STACK_VA_BUMP: AtomicU64 = AtomicU64::new(KERNEL_STACKS_VA_BASE);


fn reserve_stack_va(pages: usize) -> VirtAddr {
    let size = (pages * CurrentMemArchSpec::PAGE_SIZE) as u64;
    let base = STACK_VA_BUMP.fetch_add(
        size,
        Ordering::Relaxed,
    );
    assert!(
        base + size <= KERNEL_STACKS_VA_BASE + KERNEL_STACKS_VA_SIZE,
        "reserve_stack_va: kernel stack VA space exhausted"
    );
    VirtAddr::new(base as usize)
}

pub struct KernelStack {
    pub bottom:     VirtAddr,
    pub top:        VirtAddr,
    pages:          Vec<PhysAddr>,
}

impl KernelStack {
    #[inline]
    pub fn guard_page_va(&self) -> VirtAddr {
        self.bottom - CurrentMemArchSpec::PAGE_SIZE
    }
}

pub fn allocate_kernel_stack(size: usize) -> KernelStack {
    assert!(
        size > 0 && size % CurrentMemArchSpec::PAGE_SIZE == 0,
        "allocate_kernel_stack: size must be page-aligned and non-zero, got {}",
        size
    );

    let page_count = size / CurrentMemArchSpec::PAGE_SIZE;

    let mut phys_pages: Vec<PhysAddr> = Vec::with_capacity(page_count);

    for i in 0..page_count {
        let phys = pmm().alloc_page(AllocFlags::ZEROED)
            .unwrap_or_else(|_| {
                for p in &phys_pages {
                    pmm().free_page(*p);
                }
                panic!("allocate_kernel_stack: OOM at page {}/{}", i, page_count);
            });
        phys_pages.push(phys);
    }

    let va_base   = reserve_stack_va(1 + page_count);                    
    let stack_va  = va_base + CurrentMemArchSpec::PAGE_SIZE;      

    let flags = PFlags::new().write(true).execute(false);
        
    let mut pt = kernel_pt_mapper();

    for (i, &phys) in phys_pages.iter().enumerate() {
        let virt = stack_va + (i * CurrentMemArchSpec::PAGE_SIZE);
        match pt.map_phys(virt, phys, flags) {
            Some(fls) => fls.flush(),
            None => {
                for j in 0..i {
                    let v = stack_va + (j * CurrentMemArchSpec::PAGE_SIZE);
                    pt.unmap_phys(v).unwrap();
                }

                drop(pt);

                for p in &phys_pages {
                    pmm().free_page(*p);
                }

                panic!(
                    "allocate_kernel_stack: map_single_page failed at va={:#x}",
                    virt.as_usize(),
               );
            }
        }
    }

    KernelStack {
        bottom: stack_va,
        top:    stack_va + size,
        pages:  phys_pages,
    }
}

pub fn deallocate_kernel_stack(stack: KernelStack) {
    let mut pt = kernel_pt_mapper();
    for (i, phys) in stack.pages.iter().enumerate() {
        let virt = stack.bottom + (i * CurrentMemArchSpec::PAGE_SIZE);
        pt.unmap_phys(virt)
            .unwrap_or_else(|| {
                panic!(
                    "deallocate_kernel_stack: unmap failed at va={:#x}",
                    virt.as_usize()
                )
            });
        pmm().free_page(*phys);
    }
}

