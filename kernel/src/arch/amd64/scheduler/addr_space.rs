use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use spin::Mutex;
use x86_64::{
    PhysAddr, VirtAddr,
    structures::paging::{
        OffsetPageTable, PageTable, PageTableFlags,
        mapper::Translate,
    },
};
use crate::{arch::amd64::memory::{
        misc::virt_to_phys,
        pmm::pages_allocator::free_pages,
        vmm::{PAGE_SIZE, map_single_page, unmap_single_page, update_page_flags}, vmo::Vmo,
    }, early_println};

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug)]
    pub struct MapFlags: u32 {
        const READ    = 1 << 0;
        const WRITE   = 1 << 1;
        const EXEC    = 1 << 2;
        const USER    = 1 << 3;
        const NOCACHE = 1 << 4;
    }
}

impl MapFlags {
    pub fn to_page_table_flags(&self) -> PageTableFlags {
        let mut f = PageTableFlags::PRESENT;
        if self.contains(Self::WRITE)   { f |= PageTableFlags::WRITABLE; }
        if self.contains(Self::USER)    { f |= PageTableFlags::USER_ACCESSIBLE; }
        if self.contains(Self::NOCACHE) { f |= PageTableFlags::NO_CACHE; }
        if !self.contains(Self::EXEC)   { f |= PageTableFlags::NO_EXECUTE; }
        f
    }
}

pub struct Vma {
    pub vaddr:      VirtAddr,
    pub size:       usize,
    pub flags:      MapFlags,
    pub vmo:        Arc<Mutex<Vmo>>,
    pub vmo_offset: usize,
}

impl Vma {
    pub fn end(&self) -> VirtAddr {
        VirtAddr::new(self.vaddr.as_u64() + self.size as u64)
    }
    pub fn contains(&self, addr: VirtAddr) -> bool {
        addr >= self.vaddr && addr < self.end()
    }
    pub fn overlaps(&self, other: &Vma) -> bool {
        self.vaddr < other.end() && other.vaddr < self.end()
    }

    pub fn vmo_page_index(&self, va: VirtAddr) -> Option<usize> {
        if !self.contains(va) { return None; }
        let offset_in_vma = (va.as_u64() - self.vaddr.as_u64()) as usize;
        Some((self.vmo_offset + offset_in_vma) / PAGE_SIZE)
    }
}

pub struct AddrSpace {
    pub vmas:       BTreeMap<u64, Vma>,
    pub page_table: OffsetPageTable<'static>,
}

#[derive(Debug)]
pub enum VmaError {
    NotAligned,
    Overlap,
    NotFound,
    OutOfVmoBounds,
    OutOfMemory,
    PageTableError(&'static str),
}

impl AddrSpace {
    pub fn new(page_table: OffsetPageTable<'static>) -> Self {
        Self { vmas: BTreeMap::new(), page_table }
    }

    pub fn get_page_table_phys(&self) -> PhysAddr {
        let virt = self.page_table.level_4_table() as *const PageTable as u64;
        PhysAddr::new(virt_to_phys(virt as usize) as u64)
    }

    pub fn map(
        &mut self,
        vaddr:      Option<VirtAddr>,
        size:       usize,
        vmo:        Arc<Mutex<Vmo>>,
        vmo_offset: usize,
        flags:      MapFlags,
    ) -> Result<VirtAddr, VmaError> {
        early_println!("Penis size {} vmo offs {}", size, vmo_offset);
        if size == 0
            || size % PAGE_SIZE != 0
            || vmo_offset % PAGE_SIZE != 0
        {
            return Err(VmaError::NotAligned);
        }

        if let Some(va) = vaddr {
            if !va.is_aligned(PAGE_SIZE as u64) {
                return Err(VmaError::NotAligned);
            }
        }
       
        {
            let v = vmo.lock();
            if vmo_offset.checked_add(size).map(|e| e > v.size).unwrap_or(true) {
                return Err(VmaError::OutOfVmoBounds);
            }
        }

        let chosen = match vaddr {
            Some(va) => va,
            None => self.find_free_region(size).ok_or(VmaError::OutOfMemory)?,
        };

        let vma = Vma { vaddr: chosen, size, flags, vmo, vmo_offset };

        if self.find_overlapping(&vma).is_some() {
            return Err(VmaError::Overlap);
        }

        self.populate_page_table(&vma)
            .map_err(VmaError::PageTableError)?;

        self.vmas.insert(chosen.as_u64(), vma);
        Ok(chosen)
    }

    pub fn unmap(&mut self, vaddr: VirtAddr) -> Result<(), VmaError> {
        let vma = self.vmas.remove(&vaddr.as_u64())
            .ok_or(VmaError::NotFound)?;

        let pages = vma.size / PAGE_SIZE;
        for i in 0..pages {
            let va = VirtAddr::new(vma.vaddr.as_u64() + (i * PAGE_SIZE) as u64);
            let _ = unmap_single_page(&mut self.page_table, va);
        }
        // TODO: TLB shootdown на всех CPU, где активна эта AddrSpace.
        Ok(())
    }

    pub fn find_free_region(&self, size: usize) -> Option<VirtAddr> {
        const USER_ALLOC_BASE: u64 = 0x0000_0010_0000_0000;
        const USER_ALLOC_TOP:  u64 = 0x0000_7FFF_FFFF_F000;

        let mut candidate = USER_ALLOC_BASE;

        for (_, vma) in &self.vmas {
            if vma.end().as_u64() <= candidate {
                continue;
            }
            if vma.vaddr.as_u64() >= candidate + size as u64 {
                return Some(VirtAddr::new(candidate));
            }
            candidate = vma.end().as_u64();
        }

        if candidate + size as u64 <= USER_ALLOC_TOP {
            Some(VirtAddr::new(candidate))
        } else {
            None
        }
    }

    pub fn translate(&self, vaddr: VirtAddr) -> Option<PhysAddr> {
        self.page_table.translate_addr(vaddr)
    }

    pub fn protect(
        &mut self,
        vaddr: VirtAddr,
        flags: MapFlags,
    ) -> Result<(), VmaError> {
        let size = self.vmas.get(&vaddr.as_u64())
            .ok_or(VmaError::NotFound)?
            .size;

        let pt_flags = flags.to_page_table_flags();
        let pages = size / PAGE_SIZE;

        for i in 0..pages {
            let va = VirtAddr::new(vaddr.as_u64() + (i * PAGE_SIZE) as u64);
            let _ = update_page_flags(&mut self.page_table, va, pt_flags);
        }
        // TODO: TLB shootdown.

        self.vmas.get_mut(&vaddr.as_u64()).unwrap().flags = flags;
        Ok(())
    }

    pub fn find(&self, addr: VirtAddr) -> Option<&Vma> {
        self.vmas
            .range(..=addr.as_u64())
            .next_back()
            .map(|(_, vma)| vma)
            .filter(|vma| vma.contains(addr))
    }

    fn populate_page_table(&mut self, vma: &Vma) -> Result<(), &'static str> {
        let pages = vma.size / PAGE_SIZE;
        let pt_flags = vma.flags.to_page_table_flags();
        let start_idx = vma.vmo_offset / PAGE_SIZE;

        let vmo = vma.vmo.lock();
        for i in 0..pages {
            let va = VirtAddr::new(vma.vaddr.as_u64() + (i * PAGE_SIZE) as u64);
            if let Some(frame) = vmo.frame_at(start_idx + i) {
                map_single_page(&mut self.page_table, va, frame, pt_flags)?;
            }
        }
        Ok(())
    }

    fn find_overlapping(&self, new: &Vma) -> Option<&Vma> {
        self.vmas
            .range(..new.end().as_u64())
            .next_back()
            .map(|(_, vma)| vma)
            .filter(|vma| vma.overlaps(new))
    }
}

impl Drop for AddrSpace {
    fn drop(&mut self) {
        let vaddrs: Vec<u64> = self.vmas.keys().copied().collect();
        for vaddr in vaddrs {
            let vma = self.vmas.remove(&vaddr).unwrap();
            let pages = vma.size / PAGE_SIZE;
            for i in 0..pages {
                let va = VirtAddr::new(vma.vaddr.as_u64() + (i * PAGE_SIZE) as u64);
                let _ = unmap_single_page(&mut self.page_table, va);
            }
        }

        // TODO: рекурсивно пройти L4 → L3 → L2 → L1 и освободить все
        // промежуточные page tables, которые относятся к user-half.
        // Сейчас free_pages освобождает только L4, а L1/L2/L3 утекают.
        // Kernel-half таблицы — общие между всеми процессами, их трогать нельзя.
        let pt_phys = self.get_page_table_phys();
        free_pages(pt_phys);
    }
}