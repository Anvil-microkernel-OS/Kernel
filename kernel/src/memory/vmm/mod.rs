use spin::{Mutex, MutexGuard, Once, Spin};

use crate::{arch::CurrentMemArchSpec, memory::{misc::primitives::TableKind, vmm::{mapper::PageMapper, test::run_vmm_tests}}};

pub mod vpage;
pub mod pflags;
pub mod table_flush;
pub mod table;
pub mod mapper;
pub (crate) mod test;
static KERNEL_PT_MAPPER: Once<Mutex<PageMapper<CurrentMemArchSpec>>> = Once::new();


#[inline(always)]
pub fn kernel_pt_mapper() -> MutexGuard<'static, PageMapper<CurrentMemArchSpec>, Spin> {
    KERNEL_PT_MAPPER.get().unwrap().lock()
}

pub fn init_virtual_memory_manager() {
    KERNEL_PT_MAPPER.call_once(|| {
        Mutex::new(PageMapper::current(TableKind::Kernel))
    });

    run_vmm_tests();
}