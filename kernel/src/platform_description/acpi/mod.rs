use acpi::{AcpiTables, sdt::{hpet::HpetTable, madt::{Madt, MadtEntry}}};
use alloc::vec::Vec;
use limine::memory_map::{Entry, EntryType};

use crate::{arch::CurrentMemArchSpec, memory::{misc::{align_down, align_up, arch_specific::Arch, primitives::PhysAddr}, vmm::{kernel_pt_mapper, pflags::PFlags}}, platform_description::{BASIC_BOARD_INFO, BoardInfo, CpuCoreInfo, HpetInfo, InterruptControllerInfo, IoapicInfo, IrqOverride, IrqSubsystemInfo, LapicInfo, LocalInterruptControllerInfo, TimerInfo, acpi::main_table_parse::MainTableParser, cpuid_info::get_cpuid_full}};

mod main_table_parse;

pub struct DeviceDescrCfg<'a> {
    pub rsdrp_addr: usize, 
    pub memmap: &'a [&'a Entry]
}   

fn map_regions(memmap: &[&Entry]) {
    let map_flags = PFlags::new().execute(false);

    for entry in memmap {
        if !matches!(entry.entry_type, EntryType::ACPI_RECLAIMABLE | EntryType::ACPI_NVS) {
            continue;
        }

        let base = entry.base as usize;
        let len = entry.length as usize;

        let start = align_down(base, CurrentMemArchSpec::PAGE_SIZE);
        let end   = align_up(base + len, CurrentMemArchSpec::PAGE_SIZE);
        
        let mut p = start;

        while p < end {
            let phys_addr = PhysAddr::new(p);
            let va = CurrentMemArchSpec::phys_to_virt(phys_addr);

            kernel_pt_mapper().map_phys(va, phys_addr, map_flags).unwrap().flush();

            p += CurrentMemArchSpec::PAGE_SIZE;
        }
    }

}

pub fn init_device_info(cfg: DeviceDescrCfg) {
    map_regions(cfg.memmap);

    let acpi = unsafe {
        AcpiTables::from_rsdp(MainTableParser, cfg.rsdrp_addr).expect("ACPI parse failed")
    };

    let madt = acpi.find_table::<Madt>().expect("ACPI MADT parse failed");
    let hpet = acpi.find_table::<HpetTable>().expect("ACPI MADT parse failed");

    let mut cpu_cores: Vec<CpuCoreInfo> = Vec::new();
    let mut interr_controllers: Vec<InterruptControllerInfo> = Vec::new();
    let mut irq_overrides: Vec<IrqOverride> = Vec::new();

    for entry in madt.get().entries() {
        match entry {
            MadtEntry::LocalApic(p) if p.flags & 1 != 0 => {
                cpu_cores.push(CpuCoreInfo {
                    id: p.apic_id as usize,
                    boot_capable: true
                });
            }

            MadtEntry::LocalX2Apic(p) if p.flags & 1 != 0 => {
                cpu_cores.push(CpuCoreInfo {
                    id: p.x2apic_id as usize,
                    boot_capable: true
                });
            }

            MadtEntry::IoApic(io) => {
                interr_controllers.push(InterruptControllerInfo { 
                    base_address: PhysAddr::new(io.io_apic_address as usize), 
                    kind: IoapicInfo {
                        id: io.io_apic_id,
                        gsi_base: io.global_system_interrupt_base
                    }
                })
            },
            MadtEntry::InterruptSourceOverride(iso) => {
                irq_overrides.push(IrqOverride {
                    source_irq: iso.irq,
                    global_irq: iso.global_system_interrupt,
                    flags: iso.flags,
                });
            }
            _ => {}
        }
    }

    let gas = hpet.get().base_address;

    let phys = PhysAddr::new(gas.address as usize);

    assert!(
        phys.as_usize() & 0x7 == 0,
        "HPET base address is not aligned"
    );

    let page_protection = hpet.get().page_protection_and_oem & 0b1_1111;

    let timer_info = TimerInfo {
        base_address: phys,
        frequency_hz: hpet.get().clock_tick_unit as u64,
        kind: HpetInfo {
            clock_period_fs: hpet.get().clock_tick_unit as u32,
            hpet_number: hpet.get().hpet_number,
            page_protection
        }
    };

    let lapic_addr = madt.get().local_apic_address;

    let lapic_ent = LapicInfo {
        support_x2_init: get_cpuid_full().has_x2apic
    };  

    let local_controller = LocalInterruptControllerInfo {
        physical_addr: PhysAddr::new(lapic_addr as usize),
        kind: lapic_ent
    };  

    BASIC_BOARD_INFO.call_once(|| {
        BoardInfo {
            cpu_cores,
            irq: IrqSubsystemInfo {
                local_controller,
                controllers: interr_controllers,
                overrides: irq_overrides
            },
            timer: timer_info,
            early_console: None
        }
    });
}