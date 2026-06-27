use crate::{arch::CurrentMemArchSpec, memory::misc::{arch_specific::Arch, primitives::{Pfn, PhysAddr}}};

use super::page::{VmPage, PageState};

pub const MAX_ARENAS: usize = 16;

pub struct PmmArena {
    id: u8,

    base: PhysAddr,

    size: usize,

    page_count: usize,

    pages: *mut VmPage,

    hhdm_offset: usize,

    metadata_pages: usize,
}

unsafe impl Send for PmmArena {}
unsafe impl Sync for PmmArena {}

pub struct ArenaInitResult {
    pub metadata_pages: usize,
    pub usable_pages: usize,
}

impl PmmArena {
    pub unsafe fn init(
        id: u8,
        base: PhysAddr,
        size: usize,
        hhdm_offset: usize,
    ) -> (Self, ArenaInitResult) {
        assert!(base.is_page_aligned(), "arena base not page-aligned: {}", base);
        assert!(size % CurrentMemArchSpec::PAGE_SIZE == 0, "arena size not page-aligned: {:#x}", size);
        assert!(size >= CurrentMemArchSpec::PAGE_SIZE * 2, "arena too small: {:#x}", size);

        let page_count = size / CurrentMemArchSpec::PAGE_SIZE;

        let metadata_bytes = page_count * core::mem::size_of::<VmPage>();
        let metadata_pages = (metadata_bytes + CurrentMemArchSpec::PAGE_SIZE - 1) / CurrentMemArchSpec::PAGE_SIZE;

        assert!(
            metadata_pages < page_count,
            "arena too small for metadata: {} metadata pages >= {} total pages",
            metadata_pages, page_count
        );

        let metadata_virt = (base.as_usize() + hhdm_offset) as *mut VmPage;

        for i in 0..page_count {
            let paddr = PhysAddr::new(base.as_usize() + i * CurrentMemArchSpec::PAGE_SIZE);
            core::ptr::write(metadata_virt.add(i), VmPage::new(paddr, id));
        }

        for i in 0..metadata_pages {
            let page = &*metadata_virt.add(i);
            page.set_state(PageState::Wired);
        }

        let usable_pages = page_count - metadata_pages;

        let arena = Self {
            id,
            base,
            size,
            page_count,
            pages: metadata_virt,
            hhdm_offset,
            metadata_pages,
        };

        let result = ArenaInitResult {
            metadata_pages,
            usable_pages,
        };

        (arena, result)
    }

    #[inline]
    pub fn id(&self) -> u8 {
        self.id
    }

    #[inline]
    pub fn base(&self) -> PhysAddr {
        self.base
    }

    #[inline]
    pub fn size(&self) -> usize {
        self.size
    }

    #[inline]
    pub fn end(&self) -> PhysAddr {
        self.base + self.size
    }

    #[inline]
    pub fn page_count(&self) -> usize {
        self.page_count
    }

    #[inline]
    pub fn contains(&self, paddr: PhysAddr) -> bool {
        paddr >= self.base && paddr < self.end()
    }

    #[inline]
    pub fn contains_pfn(&self, pfn: Pfn) -> bool {
        self.contains(pfn.to_phys())
    }

    pub fn paddr_to_page(&self, paddr: PhysAddr) -> Option<&VmPage> {
        if !self.contains(paddr) {
            return None;
        }
        let index = (paddr.as_usize() - self.base.as_usize()) >> CurrentMemArchSpec::PAGE_SHIFT;
        debug_assert!(index < self.page_count);
        unsafe { Some(&*self.pages.add(index)) }
    }

    pub unsafe fn paddr_to_page_mut(&self, paddr: PhysAddr) -> Option<&mut VmPage> {
        if !self.contains(paddr) {
            return None;
        }
        let index = (paddr.as_usize() - self.base.as_usize()) >> CurrentMemArchSpec::PAGE_SHIFT;
        debug_assert!(index < self.page_count);
        Some(&mut *self.pages.add(index))
    }

    #[inline]
    pub fn page_at(&self, index: usize) -> &VmPage {
        debug_assert!(index < self.page_count);
        unsafe { &*self.pages.add(index) }
    }

    pub fn first_usable_index(&self) -> usize {
        self.metadata_pages
    }

    pub fn usable_pages(&self) -> impl Iterator<Item = &VmPage> {
        let start = self.metadata_pages;
        (start..self.page_count).map(move |i| self.page_at(i))
    }

    pub fn find_contiguous(&self, count: usize) -> Option<PhysAddr> {
        if count == 0 || count > self.page_count {
            return None;
        }

        let start_idx = self.metadata_pages;
        let mut run_start = start_idx;
        let mut run_len = 0;

        for i in start_idx..self.page_count {
            if self.page_at(i).is_free() {
                run_len += 1;
                if run_len >= count {
                    return Some(self.page_at(run_start).paddr());
                }
            } else {
                run_start = i + 1;
                run_len = 0;
            }
        }

        None
    }

    pub fn find_contiguous_aligned(&self, count: usize, align_pages: usize) -> Option<PhysAddr> {
        if count == 0 || count > self.page_count || !align_pages.is_power_of_two() {
            return None;
        }

        let align_bytes = align_pages * CurrentMemArchSpec::PAGE_SIZE;
        let start_idx = self.metadata_pages;

        let mut i = start_idx;
        while i + count <= self.page_count {
            let paddr = self.base.as_usize() + i * CurrentMemArchSpec::PAGE_SIZE;

            if paddr % align_bytes != 0 {
                let next_aligned = (paddr + align_bytes - 1) & !(align_bytes - 1);
                i = (next_aligned - self.base.as_usize()) / CurrentMemArchSpec::PAGE_SIZE;
                continue;
            }

            let mut all_free = true;
            for j in 0..count {
                if !self.page_at(i + j).is_free() {
                    i = i + j + 1;
                    all_free = false;
                    break;
                }
            }

            if all_free {
                return Some(PhysAddr::new(paddr));
            }
        }

        None
    }
}