use spin::Once;
use x86_64::instructions;

use crate::{arch::amd64::{acpi::init_acpi, apic::{disable_pic, init_lapic, ioapic_manager::ioapic_manager_init}, cpu::{cpuid::{CpuIdInfoFull, get_cpuid_full}, smp::{percpu::{get_region_by_id, init_percpu_regions}, startup::{early_setup_percpu_bsp, smp_startup}}}, gdt::init_bootstrap_gdt, interrupts::idt::init_idt, memory::{MemoryInitInfo, init_memory_subsys, u_k_boundary::uaccsess::enable_smep}, scheduler::global_init_scheduler, timer::initialize_hpet}, bootinfo::BootInfo, early_println, isolation::init_root_domain};

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
pub mod capability_sys;

static CPUID_INFO: Once<CpuIdInfoFull> = Once::new();

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

    CPUID_INFO.call_once(|| {
        early_println!("[CPUID] Fetching CPUID information...");
        get_cpuid_full()
    });


    early_println!("{}", CPUID_INFO.get().expect("Not initialized"));
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

    early_println!("Disabling legacy PIC...");
    disable_pic();
    early_println!("Legacy PIC disabled!");

    early_println!("Initializing LAPIC for BSP...");
    init_lapic(CPUID_INFO.get().unwrap().has_x2apic);
    early_println!("LAPIC initialized!");

    early_println!("Initializing IOAPIC...");
    ioapic_manager_init();
    early_println!("IOAPIC initialized!");

    early_println!("Initializing root domain...");
    init_root_domain();
    early_println!("Root domain initialized!");

    early_println!("Prepare scheduler...");
    global_init_scheduler();
    early_println!("Scheduler prepared!");

    if !enable_smep() {
        early_println!("SMEP NOT DETECTED :(");
    } else {
        early_println!("SMEP enabled!");
    }

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