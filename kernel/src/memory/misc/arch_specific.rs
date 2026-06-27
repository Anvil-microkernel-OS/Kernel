use core::ptr;
use crate::memory::misc::primitives::{PhysAddr, TableKind, VirtAddr};

pub trait LargePageSupport: Arch {
    const LARGE_PAGE_SIZE: usize;
}

pub trait Arch: Clone + Copy {
    const KERNEL_SEPARATE_TABLE: bool;

    const PAGE_SHIFT: usize;
    const PAGE_ENTRY_SHIFT: usize;
    const PAGE_LEVELS: usize;

    const ENTRY_ADDRESS_WIDTH: usize;
    const ENTRY_ADDRESS_SHIFT: usize = Self::PAGE_SHIFT;
    const ENTRY_FLAG_DEFAULT_PAGE: usize;
    const ENTRY_FLAG_DEFAULT_TABLE: usize;
    const ENTRY_FLAG_PRESENT: usize;
    const ENTRY_FLAG_READONLY: usize;
    const ENTRY_FLAG_READWRITE: usize;
    const ENTRY_FLAG_PAGE_USER: usize;
    const ENTRY_FLAG_TABLE_USER: usize = Self::ENTRY_FLAG_PAGE_USER;
    const ENTRY_FLAG_NO_EXEC: usize;
    const ENTRY_FLAG_EXEC: usize;
    const ENTRY_FLAG_GLOBAL: usize;
    const ENTRY_FLAG_NO_GLOBAL: usize;
    const ENTRY_FLAG_DEVICE_MEMORY: usize;
    const ENTRY_FLAG_UNCACHEABLE: usize;
    const ENTRY_FLAG_WRITE_COMBINING: usize;

    const PHYS_OFFSET: usize;

    const PAGE_SIZE: usize = 1 << Self::PAGE_SHIFT;
    const PAGE_OFFSET_MASK: usize = Self::PAGE_SIZE - 1;
    const PAGE_ADDRESS_SHIFT: usize = Self::PAGE_LEVELS * Self::PAGE_ENTRY_SHIFT + Self::PAGE_SHIFT;
    const PAGE_ADDRESS_SIZE: u64 = 1 << (Self::PAGE_ADDRESS_SHIFT as u64);
    const PAGE_ADDRESS_MASK: usize = (Self::PAGE_ADDRESS_SIZE - (Self::PAGE_SIZE as u64)) as usize;
    const PAGE_ENTRY_SIZE: usize = 1 << (Self::PAGE_SHIFT - Self::PAGE_ENTRY_SHIFT);
    const PAGE_ENTRIES: usize = 1 << Self::PAGE_ENTRY_SHIFT;
    const PAGE_ENTRY_MASK: usize = Self::PAGE_ENTRIES - 1;
    const PAGE_NEGATIVE_MASK: usize = !(Self::PAGE_ADDRESS_SIZE - 1) as usize;

    const ENTRY_ADDRESS_SIZE: usize = 1 << Self::ENTRY_ADDRESS_WIDTH;
    const ENTRY_ADDRESS_MASK: usize = Self::ENTRY_ADDRESS_SIZE - 1;
    const ENTRY_FLAGS_MASK: usize = !(Self::ENTRY_ADDRESS_MASK << Self::ENTRY_ADDRESS_SHIFT);


    #[inline(always)]
    unsafe fn read<T>(address: VirtAddr) -> T {
        unsafe { ptr::read(address.as_ptr() as *const T) }
    }

    #[inline(always)]
    unsafe fn write<T>(address: VirtAddr, value: T) {
        unsafe { ptr::write(address.as_mut_ptr() as *mut T, value) }
    }

    #[inline(always)]
    unsafe fn read_volatile<T>(address: VirtAddr) -> T {
        unsafe { ptr::read_volatile(address.as_ptr() as *const T) }
    }

    #[inline(always)]
    unsafe fn write_volatile<T>(address: VirtAddr, value: T) {
        unsafe { ptr::write_volatile(address.as_mut_ptr() as *mut T, value) }
    }

    #[inline(always)]
    unsafe fn write_bytes(address: VirtAddr, value: u8, count: usize) {
        unsafe { ptr::write_bytes(address.as_mut_ptr() as *mut u8, value, count) }
    }

    fn invalidate(address: VirtAddr);
    fn invalidate_all();

    fn table(table_kind: TableKind) -> PhysAddr;
    unsafe fn set_table(table_kind: TableKind, address: PhysAddr);

    #[inline(always)]
    fn phys_to_virt(phys: PhysAddr) -> VirtAddr {
        match phys.as_usize().checked_add(Self::PHYS_OFFSET) {
            Some(some) => VirtAddr::new(some),
            None => panic!("phys_to_virt({:#x}) overflow", phys.as_usize()),
        }
    }

    #[inline(always)]
    fn virt_to_phys(virt: VirtAddr) -> PhysAddr {
        match virt.as_usize().checked_sub(Self::PHYS_OFFSET) {
            Some(some) => PhysAddr::new(some),
            None => panic!("virt_to_phys({:#x}) overflow", virt.as_usize()),
        }
    }

    fn virt_is_valid(address: VirtAddr) -> bool;
}