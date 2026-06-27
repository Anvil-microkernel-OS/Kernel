use crate::{arch::{CurrentIOProvider, CurrentMemArchSpec, amd64::apic::lapic::Lapic}, define_per_cpu_struct, io_ops::IoOperations, memory::{misc::arch_specific::Arch, vmm::{kernel_pt_mapper, pflags::PFlags}}, platform_description::get_basic_board_info, serial_println};

pub (crate) mod lapic;
pub (crate) mod ioapic;

define_per_cpu_struct! {
    pub struct PERCPU_LAPIC {
        pub lapic: Lapic
    }
}

const PIC_MASTER_PORT: u16 = 0x20;
const PIC_SLAVE_PORT: u16 = 0xA0;

fn disable_pic() {
    CurrentIOProvider::write8((PIC_MASTER_PORT + 1) as usize, 0xFF);
    CurrentIOProvider::write8((PIC_SLAVE_PORT + 1) as usize, 0xFF);
}

pub fn setup_local_interrupt_controller() {
    disable_pic();

    let has_x2 = get_basic_board_info().irq.local_controller.kind.support_x2_init;

    if has_x2 {
        serial_println!("Setup x2lapic controllers...");
        PERCPU_LAPIC::with_guard(|x2lapic| {
            x2lapic.lapic = Lapic::newx2();
            x2lapic.lapic.enable();
            x2lapic.lapic.set_task_priority(0);
        });
        return;
    }

    let lapic_addr = get_basic_board_info().irq.local_controller.physical_addr;

    let lapic_virt = CurrentMemArchSpec::phys_to_virt(lapic_addr);

    let flags = unsafe {
        PFlags::from_data(
            1 << 0 |  // PRESENT
            1 << 1 |  // RW
            1 << 3 |  // PWT
            1 << 4 |  // PCD
            1 << 8 |  // GLOBAL
            (1 << 63) // NX
        )
    };

    let mut mapper = kernel_pt_mapper(); 

    mapper.map_phys(lapic_virt, lapic_addr, flags)
            .expect("LAPIC MMIO mapping failed")
            .flush();

    PERCPU_LAPIC::with_guard(|plapic| {
        plapic.lapic = Lapic::new(lapic_virt);
        plapic.lapic.enable();
        plapic.lapic.set_task_priority(0);
    });
}

pub fn setup_global_interrupt_controllers() {
    //todo setup ioapic

    let ioapic_controllers = &get_basic_board_info().irq.controllers;
}