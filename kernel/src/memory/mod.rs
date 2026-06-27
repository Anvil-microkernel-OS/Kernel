use limine::memory_map::Entry;

use crate::{memory::{pmm::{init_early_physical_memory}, vmm::{init_virtual_memory_manager}}, serial_println};

pub mod pmm;
pub mod vmm;
pub mod misc;

pub struct MemoryInitInfo<'a> {
    pub hhdm_offset: u64,
    pub memmap_entry: &'a[&'a Entry]
}

pub fn init_memory_subsys(init_info: MemoryInitInfo) {
    serial_println!("Hhdm offset: {:#018x}", init_info.hhdm_offset);
    serial_println!("Initializing early physical memory manager...");
    init_early_physical_memory(init_info.hhdm_offset as usize, init_info.memmap_entry);
    serial_println!("Early physical memory manager initialized!");

    serial_println!("Initializing  virtual memory manager...");
    init_virtual_memory_manager();
    serial_println!("Early virtual memory manager initialized!");
}