use crate::{arch::apic::setup_local_interrupt_controller, bootinfo::BootInfo, memory::{MemoryInitInfo, init_memory_subsys}, percpu::{attach_percpu_region_to_core, get_region_by_id, init_percpu_regions}, platform_description::initialize_board_info, serial_println, timer::setup_platform_timer};

#[cfg(target_arch = "x86_64")]
#[macro_use]
pub mod amd64;
#[cfg(target_arch = "x86_64")]
pub use self::amd64::*;
#[cfg(target_arch = "x86_64")]
pub use self::amd64::memory::Adm64MemArch as CurrentMemArchSpec;
#[cfg(target_arch = "x86_64")]
pub use self::amd64::io::PortIo as CurrentIOProvider;

#[cfg(target_arch = "riscv64")]
#[macro_use]
pub mod riscv64;
#[cfg(target_arch = "riscv64")]
pub use self::riscv64::*;

pub fn early_startup() {
    serial_println!("Running early startup...");

    unsafe {
        interrupt::disable();
    }

    serial_println!("Init interrupt system...");
    init_interrupts();
    serial_println!("Interrupt system initialized!");

    serial_println!("Init memory subsystem...");
    init_memory_subsys(MemoryInitInfo {
        hhdm_offset: BootInfo::get().hhdm_offset().unwrap(),
        memmap_entry: BootInfo::get().memmap_entries().unwrap()
    });
    serial_println!("Memory subsystem initialized!");

    serial_println!("Initialize board basic info...");
    initialize_board_info();
    serial_println!("Board basic info initialized!");

    serial_println!("Initialize percpu regions...");
    init_percpu_regions();
    serial_println!("Percpu regions initialized!");

    serial_println!("Set percpu region base to bsp processor core...");
    attach_percpu_region_to_core(*get_region_by_id(0));
    serial_println!("Percpu region setted!");

    serial_println!("Setup local interrupt controller...");
    setup_local_interrupt_controller();
    serial_println!("Local interrupt controller setuped!");

    //todo global interrupt controllers

    serial_println!("Setup timers...");
    setup_platform_timer();
    serial_println!("Setup timers completed!");

    unsafe {
        interrupt::enable_and_nop();
    }

    serial_println!("Early startup finished!");
}