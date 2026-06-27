use core::arch::asm;

use crate::memory::misc::{arch_specific::{Arch, LargePageSupport}, primitives::{PhysAddr, TableKind, VirtAddr}};

pub(crate) const _PAT_WB: usize = (0b0 << 7) + (0b00 << 3);
pub(crate) const _PAT_WT: usize = (0b0 << 7) + (0b01 << 3);
pub(crate) const PAT_UC_: usize = (0b0 << 7) + (0b10 << 3);
pub(crate) const _PAT_UC: usize = (0b0 << 7) + (0b11 << 3); 
pub(crate) const PAT_WC: usize = (0b1 << 7) + (0b00 << 3);

pub fn init_page_table_attributes() {
    unsafe {
        let uncacheable = 0; // UC
        let write_combining = 1; // WC
        let write_through = 4; // WT
        let _write_protected = 5; // WP
        let write_back = 6; // WB
        let uncached = 7; // UC- (overridable by WC MTRR)

        let pat0 = write_back;
        let pat1 = write_through;
        let pat2 = uncached;
        let pat3 = uncacheable;

        let pat4 = write_combining;
        let pat5 = pat1;
        let pat6 = pat2;
        let pat7 = pat3;

        let msr = 631; // IA32_PAT
        let low = u32::from_be_bytes([pat3, pat2, pat1, pat0]);
        let high = u32::from_be_bytes([pat7, pat6, pat5, pat4]);
        asm!("wrmsr", in("ecx") msr, in("eax") low, in("edx") high);
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Adm64MemArch;

impl LargePageSupport for Adm64MemArch {
    const LARGE_PAGE_SIZE: usize = 2 * 1024 * 1024;
}

impl Arch for Adm64MemArch {
    const KERNEL_SEPARATE_TABLE: bool = false;

    const PAGE_SHIFT: usize = 12;

    const PAGE_ENTRY_SHIFT: usize = 9;

    const PAGE_LEVELS: usize = 4;

    const ENTRY_ADDRESS_WIDTH: usize = 40;

    const ENTRY_FLAG_DEFAULT_PAGE: usize = Self::ENTRY_FLAG_PRESENT;

    const ENTRY_FLAG_DEFAULT_TABLE: usize = Self::ENTRY_FLAG_PRESENT | Self::ENTRY_FLAG_READWRITE;

    const ENTRY_FLAG_PRESENT: usize = 1 << 0;

    const ENTRY_FLAG_READONLY: usize = 0;

    const ENTRY_FLAG_READWRITE: usize = 1 << 1;

    const ENTRY_FLAG_PAGE_USER: usize = 1 << 2;

    const ENTRY_FLAG_NO_EXEC: usize = 1 << 63;

    const ENTRY_FLAG_EXEC: usize = 0;

    const ENTRY_FLAG_GLOBAL: usize = 1 << 8;

    const ENTRY_FLAG_NO_GLOBAL: usize = 0;

    const ENTRY_FLAG_DEVICE_MEMORY: usize = PAT_UC_;

    const ENTRY_FLAG_UNCACHEABLE: usize = PAT_UC_;

    const ENTRY_FLAG_WRITE_COMBINING: usize = PAT_WC;

    const PHYS_OFFSET: usize = Self::PAGE_NEGATIVE_MASK + (Self::PAGE_ADDRESS_SIZE >> 1) as usize;

    #[inline(always)]
    fn invalidate(address: VirtAddr) {
        unsafe { asm!("invlpg [{0}]", in(reg) address.as_usize()) };
    }

    #[inline(always)]
    fn invalidate_all() {
        unsafe { Self::set_table(TableKind::User, Self::table(TableKind::User)) };
    }

    fn table(_table_kind: TableKind) -> PhysAddr {
        let address: usize;
        unsafe { asm!("mov {0}, cr3", out(reg) address) };
        PhysAddr::new(address)
    }

    unsafe fn set_table(_table_kind: TableKind, address: PhysAddr) {
        unsafe { asm!("mov cr3, {0}", in(reg) address.as_usize()) };
    }

    fn virt_is_valid(address: VirtAddr) -> bool {
        let masked = address.as_usize() & 0xFFFF_8000_0000_0000;
        masked == 0xFFFF_8000_0000_0000 || masked == 0
    }
}