use core::{marker::PhantomData, ops::Add};

use crate::memory::{misc::{arch_specific::Arch, primitives::{PhysAddr, VirtAddr}}, vmm::vpage::VPage};

pub struct PageTable<A> {
    base: VirtAddr,
    phys: PhysAddr,
    level: usize,
    _phantom: PhantomData<A>,
}

impl<A: Arch> PageTable<A> {
    pub(super) unsafe fn new(base: VirtAddr, phys: PhysAddr, level: usize) -> Self {
        Self {
            base,
            phys,
            level,
            _phantom: PhantomData,
        }
    }

    pub fn base(&self) -> VirtAddr {
        self.base
    }

    pub fn phys(&self) -> PhysAddr {
        self.phys
    }

    pub fn level(&self) -> usize {
        self.level
    }

    pub fn entry_base(&self, i: usize) -> Option<VirtAddr> {
        if i < A::PAGE_ENTRIES {
            let level_shift = self.level * A::PAGE_ENTRY_SHIFT + A::PAGE_SHIFT;
            Some(self.base.add(i << level_shift))
        } else {
            None
        }
    }

    unsafe fn entry_virt(&self, i: usize) -> Option<VirtAddr> {
        if i < A::PAGE_ENTRIES {
            Some(A::phys_to_virt(self.phys).add(i * A::PAGE_ENTRY_SIZE))
        } else {
            None
        }
    }

    pub unsafe fn entry(&self, i: usize) -> Option<VPage<A>> {
        unsafe {
            let addr = self.entry_virt(i)?;
            Some(VPage::from_data(A::read::<usize>(addr)))
        }
    }

    pub(super) unsafe fn set_entry(&mut self, i: usize, entry: VPage<A>) -> Option<()> {
        unsafe {
            let addr = self.entry_virt(i)?;
            A::write::<usize>(addr, entry.data());
            Some(())
        }
    }

    pub(super) fn index_of(&self, address: VirtAddr) -> Option<usize> {
        let address = VirtAddr::new(address.as_usize() & A::PAGE_ADDRESS_MASK);
        let level_shift = self.level * A::PAGE_ENTRY_SHIFT + A::PAGE_SHIFT;
        let level_mask = A::PAGE_ENTRIES
            .wrapping_shl(level_shift as u32)
            .wrapping_sub(1);
        if address >= self.base && address <= self.base.add(level_mask) {
            Some((address.as_usize() >> level_shift) & A::PAGE_ENTRY_MASK)
        } else {
            None
        }
    }

    pub unsafe fn next(&self, i: usize) -> Option<Self> {
        if self.level == 0 {
            return None;
        }

        unsafe {
            Some(PageTable::new(
                self.entry_base(i)?,
                self.entry(i)?.address().ok()?,
                self.level - 1,
            ))
        }
    }
}