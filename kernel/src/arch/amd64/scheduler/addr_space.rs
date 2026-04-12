use alloc::{collections::BTreeMap, vec::Vec};
use x86_64::{PhysAddr, VirtAddr, structures::paging::{OffsetPageTable, PageTable, PageTableFlags}};
use crate::{arch::amd64::memory::{misc::virt_to_phys, pmm::pages_allocator::{PAllocFlags, alloc_pages_by_order, free_pages}, vmm::{
    PAGE_SIZE, map_single_page, unmap_single_page
}}, early_println};

bitflags::bitflags! {
    #[derive(Clone, Copy)]
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

pub enum VmaBacking {
    Physical { phys_addr: PhysAddr },
    Device   { phys_addr: PhysAddr },
    Reserved,
    Allocated,
    Vmo      { frames: Vec<PhysAddr> }
}

pub struct Vma {
    pub vaddr:   VirtAddr,
    pub size:    usize,
    pub flags:   MapFlags,
    pub backing: VmaBacking,
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
        vaddr:   VirtAddr,
        size:    usize,
        backing: VmaBacking,
        flags:   MapFlags,
    ) -> Result<(), VmaError> {
        if !vaddr.is_aligned(PAGE_SIZE as u64) || size % PAGE_SIZE != 0 {
            return Err(VmaError::NotAligned);
        }


        let vma = Vma { vaddr, size, flags, backing };

        if self.find_overlapping(&vma).is_some() {
            return Err(VmaError::Overlap);
        }

        self.map_in_page_table(&vma)
            .map_err(VmaError::PageTableError)?;

        self.vmas.insert(vaddr.as_u64(), vma);
        Ok(())
    }

    pub fn unmap(&mut self, vaddr: VirtAddr) -> Result<(), VmaError> {
        let vma = self.vmas.remove(&vaddr.as_u64())
            .ok_or(VmaError::NotFound)?;
        
        let pages = vma.size / PAGE_SIZE;
        for i in 0..pages {
            let va = VirtAddr::new(vma.vaddr.as_u64() + (i * PAGE_SIZE) as u64);
            match &vma.backing {
                VmaBacking::Reserved => {
                    let _ = unmap_single_page(&mut self.page_table, va);
                }
                VmaBacking::Physical { .. } | VmaBacking::Device { .. } => {
                    unmap_single_page(&mut self.page_table, va)
                        .map_err(VmaError::PageTableError)?;
                },
                VmaBacking::Allocated => {
                    if let Ok(pa) = unmap_single_page(&mut self.page_table, va) {
                        free_pages(pa);  
                    }
                },
                VmaBacking::Vmo { .. } => {
                    let _ = unmap_single_page(&mut self.page_table, va);
                }
            }
        }
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
        use x86_64::structures::paging::mapper::Translate;
        self.page_table
            .translate_addr(vaddr)
    }

    pub fn protect(
        &mut self,
        vaddr: VirtAddr,
        flags: MapFlags,
    ) -> Result<(), VmaError> {
        let (size, backing) = {
            let vma = self.vmas.get(&vaddr.as_u64())
                .ok_or(VmaError::NotFound)?;
            (vma.size, &vma.backing as *const VmaBacking)
        };

        let pt_flags = flags.to_page_table_flags();
        let pages    = size / PAGE_SIZE;

        for i in 0..pages {
            let va = VirtAddr::new(vaddr.as_u64() + (i * PAGE_SIZE) as u64);

            let phys = unsafe { match &*backing {
                VmaBacking::Physical { phys_addr } |
                VmaBacking::Device   { phys_addr } => {
                    PhysAddr::new(phys_addr.as_u64() + (i * PAGE_SIZE) as u64)
                }
                VmaBacking::Allocated => {
                    use x86_64::structures::paging::mapper::Translate;
                    self.page_table
                        .translate_addr(va)
                        .ok_or(VmaError::NotFound)?
                }
                VmaBacking::Vmo { frames } => {
                    *frames.get(i).ok_or(VmaError::NotFound)?
                }
                VmaBacking::Reserved => continue,
            }};

            unmap_single_page(&mut self.page_table, va)
                .map_err(VmaError::PageTableError)?;
            map_single_page(&mut self.page_table, va, phys, pt_flags)
                .map_err(VmaError::PageTableError)?;
        }

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

    fn map_in_page_table(&mut self, vma: &Vma) -> Result<(), &'static str> {
        let pages    = vma.size / PAGE_SIZE;
        let pt_flags = vma.flags.to_page_table_flags();

        for i in 0..pages {
            let va = VirtAddr::new(vma.vaddr.as_u64() + (i * PAGE_SIZE) as u64);

            match &vma.backing {
                VmaBacking::Physical { phys_addr } |
                VmaBacking::Device   { phys_addr } => {
                    let pa = PhysAddr::new(phys_addr.as_u64() + (i * PAGE_SIZE) as u64);
                    map_single_page(&mut self.page_table, va, pa, pt_flags)?;
                }
                VmaBacking::Reserved => {
                },

                VmaBacking::Allocated => {
                    let pa = alloc_pages_by_order(0, PAllocFlags::KERNEL | PAllocFlags::ZEROED)
                        .ok_or("OOM")?;
                    map_single_page(&mut self.page_table, va, pa, pt_flags)?;
                },
                VmaBacking::Vmo { frames } => {
                    let pa = frames[i];  
                    map_single_page(&mut self.page_table, va, pa, pt_flags)?;
                }
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

                match &vma.backing {
                    VmaBacking::Physical { .. } => {
                        let _ = unmap_single_page(&mut self.page_table, va);
                    }
                    VmaBacking::Device { .. } => {
                        let _ = unmap_single_page(&mut self.page_table, va);
                    }
                    VmaBacking::Reserved => {
                        let _ = unmap_single_page(&mut self.page_table, va);
                    }
                    VmaBacking::Allocated => {
                        if let Ok(pa) = unmap_single_page(&mut self.page_table, va) {
                            free_pages(pa);
                        }
                    }
                    VmaBacking::Vmo { .. } => {
                        let _ = unmap_single_page(&mut self.page_table, va);
                    }
                }
            }
        }

        let pt_phys = self.get_page_table_phys();
        free_pages(pt_phys);
    }
}