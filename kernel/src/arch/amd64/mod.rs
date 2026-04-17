use x86_64::{VirtAddr, instructions};

use crate::{arch::amd64::{acpi::{get_acpi_tables, init_acpi, madt::MadTable}, apic::{init_ioapic, init_lapic}, cpu::{cpuid::get_cpuid_full, smp::{percpu::{get_region_by_id, init_percpu_regions}, startup::{early_setup_percpu_bsp, smp_startup}}}, gdt::init_bootstrap_gdt, interrupts::idt::init_idt, memory::{MemoryInitInfo, init_memory_subsys}, scheduler::global_init_scheduler, timer::initialize_hpet}, bootinfo::BootInfo, early_println};

pub mod serial;
pub mod cpu;
mod gdt;
mod interrupts;
mod ports;
mod memory;
mod acpi;
mod apic;
mod timer;
pub mod scheduler;
pub mod ipc;

fn early_startup() {
    instructions::interrupts::disable();

    early_println!("Initializing GDT...");
    init_bootstrap_gdt();
    early_println!("GDT initialized!");

    early_println!("Initializing IDT...");
    init_idt();
    early_println!("IDT Initialized!");

    early_println!("Initializing memory subsystem...");
    init_memory_subsys(MemoryInitInfo {
        hhdm_offset: BootInfo::get().hhdm_offset().unwrap(),
        memmap_entry: BootInfo::get().memmap_entries().unwrap()
    });
    early_println!("Memory subsystem initialized!");

    early_println!("Initializing cpu submodule...");
    let cpu_info = get_cpuid_full();
    early_println!("{}", cpu_info);
    early_println!("Cpu submodule intialized!");

    early_println!("Initializing ACPI submodule...");
    init_acpi(BootInfo::get().rsdp_addr().unwrap(), BootInfo::get().memmap_entries().unwrap());
    early_println!("ACPI submodule intialized!");

    early_println!("Initializing percpu memory regions...");
    init_percpu_regions();
    early_println!("Percpu memory regions initialized!");

    early_println!("Attach PerCpu region to BSP core...");
    early_setup_percpu_bsp(get_region_by_id(0).base);
    early_println!("PerCpu region attached to BSP core!");

    early_println!("Initializing HPET timer...");
    initialize_hpet();
    early_println!("HPET timer initialized!");

    early_println!("Initializing LAPIC for BSP...");
    init_lapic();
    early_println!("LAPIC initialized!");

    early_println!("Initializing IOAPIC...");
    init_ioapic();
    early_println!("IOAPIC initialized!");

    early_println!("Prepare scheduler...");
    global_init_scheduler();
    early_println!("Scheduler prepared!");

    instructions::interrupts::enable();
}

pub fn init_arch() {
    early_println!("Initializing amd64 arch early startup...");
    early_startup();
    early_println!("Early startup finished!");
}

pub fn final_arch_init() -> ! {
    smp_startup();
}