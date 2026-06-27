use core::ptr;
use alloc::vec::Vec;
use spin::Once;

pub mod macros;
pub mod preempt;

use crate::{arch::{CurrentMemArchSpec, load_percpu_region_ptr_to_core}, memory::{misc::{align_up, arch_specific::Arch, primitives::VirtAddr}, pmm::{node::AllocFlags, pmm}}, platform_description::get_basic_board_info, serial_println};

unsafe extern "C" {
    static _percpu_start: u8;
    static _percpu_data_end: u8;
    static _percpu_end: u8;
    static _percpu_load: u8;
    static _percpu_vma_base: u8;
}

pub struct PerCpuTemplate {
    pub data_size: usize,
    pub bss_size: usize,
    pub total_size: usize,
    pub load_ptr: *const u8, 
}

fn construct_percpu_template() -> PerCpuTemplate {
    let percpu_start    = ptr::addr_of!(_percpu_start) as *const u8;
    let percpu_data_end = ptr::addr_of!(_percpu_data_end) as *const u8;
    let percpu_end      = ptr::addr_of!(_percpu_end) as *const u8;

    let data_size = percpu_data_end as usize - percpu_start as usize;
    let bss_size  = percpu_end as usize - percpu_data_end as usize;

    let total_size = align_up(data_size + bss_size, CurrentMemArchSpec::PAGE_SIZE);

    let load_ptr = ptr::addr_of!(_percpu_load) as *const u8;

    PerCpuTemplate { data_size, bss_size, total_size, load_ptr }
}

fn construct_region_from_template(dst: *mut u8, tpl: &PerCpuTemplate) {
    unsafe {
        ptr::copy_nonoverlapping(tpl.load_ptr, dst, tpl.data_size);
        ptr::write_bytes(dst.add(tpl.data_size), 0, tpl.bss_size);
    }
}

fn alloc_percpu_region(total_size: usize) -> VirtAddr {
    let pages = align_up(total_size, CurrentMemArchSpec::PAGE_SIZE) / CurrentMemArchSpec::PAGE_SIZE;

    if pages == 1 {
        let phys = pmm().alloc_page(AllocFlags::ZEROED).expect("Can't allocate page for pregion");
        return CurrentMemArchSpec::phys_to_virt(phys);
    }

    serial_println!("Pages: {}", pages);

    let phys = pmm().alloc_contiguous(pages, AllocFlags::ZEROED).expect("Can't allocate phys region for percpu region");

    CurrentMemArchSpec::phys_to_virt(phys)
}

static PERCPU_REGIONS: Once<Vec<VirtAddr>> = Once::new();

pub fn init_percpu_regions() {
    let cpu_count = get_basic_board_info().cpu_cores.len();

    let tpl = construct_percpu_template();    

    if tpl.total_size == 0 {
        serial_println!("[PERCPU WARN] percpu regions not defined! Skip initializing...");
        return;
    }

    let mut regions = Vec::with_capacity(cpu_count);

    for _ in 0..cpu_count {
        let base = alloc_percpu_region(tpl.total_size);

        construct_region_from_template(base.as_mut_ptr(), &tpl);

        regions.push(base);
    }

    PERCPU_REGIONS.call_once(|| {
        regions
    });
}

pub fn attach_percpu_region_to_core(region_base: VirtAddr) {
    let percpu_vma_base = core::ptr::addr_of!(_percpu_vma_base) as u64;
    let kgs_delta = region_base.as_usize().wrapping_sub(percpu_vma_base as usize);
    
    load_percpu_region_ptr_to_core(kgs_delta);
}

pub fn get_region_by_id<'a>(id: usize) -> &'a VirtAddr {
    &PERCPU_REGIONS.get().expect("Percpu regions not initialized!")[id]
}

pub fn get_percpu_regions_ammo() -> usize {
    return PERCPU_REGIONS.get().expect("Percpu regions not initialized!").len()
}