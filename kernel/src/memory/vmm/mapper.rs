use core::marker::PhantomData;

use crate::memory::{misc::{arch_specific::Arch, primitives::{PhysAddr, TableKind, VirtAddr}}, pmm::{node::AllocFlags, pmm}, vmm::{pflags::PFlags, table::PageTable, table_flush::PageFlush, vpage::VPage}};

pub struct PageMapper<A> {
    table_kind: TableKind,
    table_addr: PhysAddr,
    _phantom: PhantomData<fn() -> A>,
}

impl <A: Arch> PageMapper<A> {
    pub fn create(table_kind: TableKind) -> Option<Self> {
        unsafe {
            let table_addr = pmm().alloc_page(AllocFlags::ZEROED).ok()?;
            let table = Self::new(table_kind, table_addr);

            match (table_kind, A::KERNEL_SEPARATE_TABLE) {
                (TableKind::Kernel, false) => {
                    for i in A::PAGE_ENTRIES / 2..A::PAGE_ENTRIES {
                        let phys =  pmm()
                            .alloc_page(AllocFlags::ZEROED)
                            .expect("failed to map page table");
                        let flags = A::ENTRY_FLAG_DEFAULT_TABLE;
                        table
                            .table()
                            .set_entry(i, VPage::new(phys.as_usize(), flags));
                    }
                }
                (TableKind::User, false) => {
                    let active_ktable = PageMapper::current(TableKind::Kernel);
                    for i in A::PAGE_ENTRIES / 2..A::PAGE_ENTRIES {
                        if let Some(entry) = active_ktable.table().entry(i) {
                            table.table().set_entry(i, entry);
                        }
                    }
                }
                (_, true) => {
                    // There is a separate page table for the kernel. No need to copy the kernel
                    // mappings to the user page table.
                }
            }

            Some(table)
        }
    }

    fn new(table_kind: TableKind, table_addr: PhysAddr) -> Self {
        Self {
            table_kind,
            table_addr,
            _phantom: PhantomData,
        }
    }

    pub fn current(table_kind: TableKind) -> Self {
        unsafe {
            let table_addr = A::table(table_kind);
            Self::new(table_kind, table_addr)
        }
    }

    pub fn is_current(&self) -> bool {
        self.table().phys() == A::table(self.table_kind)
    }

    pub fn make_current(&self) {
        unsafe {
            A::set_table(self.table_kind, self.table_addr);
        }
    }

    pub fn table(&self) -> PageTable<A> {
        unsafe { PageTable::new(VirtAddr::new(0), self.table_addr, A::PAGE_LEVELS - 1) }
    }

    fn visit<T>(
        &self,
        virt: VirtAddr,
        f: impl FnOnce(&mut PageTable<A>, usize) -> T,
    ) -> Option<T> {
        let mut table = self.table();
        loop {
            let i = table.index_of(virt)?;
            if table.level() == 0 {
                return Some(f(&mut table, i));
            } else {
                table = unsafe { table.next(i)? };
            }
        }
    }

    pub fn translate(&self, virt: VirtAddr) -> Option<(PhysAddr, PFlags<A>)> {
        let entry = self.visit(virt, |p1, i| unsafe { p1.entry(i) })??;
        Some((entry.address().ok()?, entry.flags()))
    }

    pub fn remap_with_full(
        &mut self,
        virt: VirtAddr,
        f: impl FnOnce(PhysAddr, PFlags<A>) -> Option<(PhysAddr, PFlags<A>)>,
    ) -> Option<(PFlags<A>, PhysAddr, PageFlush<A>)> {
        unsafe {
            self.visit(virt, |p1, i| {
                let old_entry = p1.entry(i)?;
                let old_phys = old_entry.address().ok()?;
                let old_flags = old_entry.flags();
                let (new_phys, new_flags) = f(old_phys, old_flags)?;
                let new_entry = VPage::new(new_phys.as_usize(), new_flags.data());
                p1.set_entry(i, new_entry);
                Some((old_flags, old_phys, PageFlush::new(virt)))
            })
            .flatten()
        }
    }

    pub fn remap_with(
        &mut self,
        virt: VirtAddr,
        map_flags: impl FnOnce(PFlags<A>) -> PFlags<A>,
    ) -> Option<(PFlags<A>, PhysAddr, PageFlush<A>)> {
        self.remap_with_full(virt, |same_phys, old_flags| {
            Some((same_phys, map_flags(old_flags)))
        })
    }

    pub fn remap(
        &mut self,
        virt: VirtAddr,
        flags: PFlags<A>,
    ) -> Option<PageFlush<A>> {
        self.remap_with(virt, |_| flags).map(|(_, _, flush)| flush)
    }

    pub fn map_phys(
        &mut self,
        virt: VirtAddr,
        phys: PhysAddr,
        flags: PFlags<A>,
    ) -> Option<PageFlush<A>> {
        unsafe {
            let entry = VPage::new(phys.as_usize(), flags.data());
            let mut table = self.table();
            loop {
                let i = table.index_of(virt)?;
                if table.level() == 0 {
                    table.set_entry(i, entry);
                    return Some(PageFlush::new(virt));
                }

                let next = match table.next(i) {
                    Some(some) => some,
                    None => {
                        let next_phys = pmm().alloc_page(AllocFlags::ZEROED).ok()?;
                        let flags = A::ENTRY_FLAG_DEFAULT_TABLE
                            | if virt.kind() == TableKind::User {
                                A::ENTRY_FLAG_TABLE_USER
                            } else {
                                0
                            };
                        table.set_entry(i, VPage::new(next_phys.as_usize(), flags));
                        table.next(i)?
                    }
                };
                table = next;
            }
        }
    }   

    pub fn unmap_phys(
        &mut self,
        virt: VirtAddr,
    ) -> Option<(PhysAddr, PFlags<A>, PageFlush<A>)> {
        let mut table = self.table();

        let unmap_parents = A::KERNEL_SEPARATE_TABLE || table.index_of(virt)? < A::PAGE_ENTRIES / 2; 

        unsafe {
            unmap_phys_inner(virt, &mut table, unmap_parents)
                .map(|(pa, pf)| (pa, pf, PageFlush::new(virt)))
        }
    }

    pub fn map_linearly(
        &mut self,
        phys: PhysAddr,
        flags: PFlags<A>,
    ) -> Option<(VirtAddr, PageFlush<A>)> {
        let virt = A::phys_to_virt(phys);
        self.map_phys(virt, phys, flags).map(|flush| (virt, flush))
    }
}

fn unmap_phys_inner<A: Arch>(
    virt: VirtAddr,
    table: &mut PageTable<A>,
    unmap_parents: bool,
) -> Option<(PhysAddr, PFlags<A>)> {
    unsafe {
        let i = table.index_of(virt)?;

        if table.level() == 0 {
            let entry_opt = table.entry(i);
            table.set_entry(i, VPage::new(0, 0));
            let entry = entry_opt?;

            return Some((entry.address().ok()?, entry.flags()));
        }

        let mut subtable = table.next(i)?;

        let res = unmap_phys_inner(virt, &mut subtable, unmap_parents)?;

        if unmap_parents {
            let is_still_populated = (0..A::PAGE_ENTRIES)
                .map(|j| subtable.entry(j).expect("must be within bounds"))
                .any(|e| e.present());

            if !is_still_populated {
                pmm().free_page(subtable.phys());
                table.set_entry(i, VPage::new(0, 0));
            }
        }

        Some(res)
    }
}