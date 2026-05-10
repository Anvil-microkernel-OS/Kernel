use core::u32;

use x86_64::VirtAddr;

use crate::{
    arch::amd64::{
        acpi::{get_acpi_tables, madt::MadTable}, apic::lapic::{Lapic, LapicTimerDivide}, memory::misc::phys_to_virt, ports::Port, timer::get_hpet
    }, define_per_cpu_struct, early_println, irq
};

pub mod lapic;
pub mod ioapic;
pub mod ioapic_manager;

define_per_cpu_struct! {
    pub struct PercpuLapic {
        pub lapic: Lapic
    }
}

const PIC_MASTER_PORT: u16 = 0x20;
const PIC_SLAVE_PORT: u16 = 0xA0;
const TIMER_VECTOR: u8 = 0x30;

pub fn disable_pic() {
    let pic1 = Port::<u8>::new(PIC_MASTER_PORT + 1);
    let pic2 = Port::<u8>::new(PIC_SLAVE_PORT + 1);

    pic1.write(0xFF);
    pic2.write(0xFF);
}

pub fn calibrate_lapic_timer(lapic: &Lapic) -> u32 {
    const CALIBRATION_MS: u64 = 10;

    let hpet_ticks_target =
        (CALIBRATION_MS * 1_000_000_000_000u64) / get_hpet().read().period_fs();

    lapic.set_timer_divide(LapicTimerDivide::Div16);
    lapic.set_lvt_timer(TIMER_VECTOR, false);
    lapic.set_timer_initial(u32::MAX);

    let hpet_start = get_hpet().read().read_counter();
    let lapic_start = lapic.read_timer_current();

    while get_hpet().read().read_counter().wrapping_sub(hpet_start) < hpet_ticks_target {
        core::hint::spin_loop();
    }

    let lapic_end = lapic.read_timer_current();

    lapic_start.wrapping_sub(lapic_end)
}

pub fn init_lapic(x2_supported: bool) {
    if x2_supported {
        PercpuLapic::with_guard(|plapic| {
            plapic.lapic = Lapic::newx2();
            plapic.lapic.enable();
            plapic.lapic.set_task_priority(0);
        });
        early_println!("Initialized x2lapic");
        return;
    }

    let lapic_addr = get_acpi_tables().read().get_table::<MadTable>().unwrap().lapic_addr;
    PercpuLapic::with_guard(|plapic| {
        let lapic_virt = VirtAddr::new(phys_to_virt(lapic_addr.as_u64() as usize) as u64);
        plapic.lapic = Lapic::new(lapic_addr, lapic_virt);
        plapic.lapic.enable();
        plapic.lapic.set_task_priority(0);
    });
}

pub fn start_timer(lapic: &Lapic) {
    let ticks_10ms = calibrate_lapic_timer(lapic);
    let ticks_1ms = ticks_10ms / 10;

    lapic.setup_timer_periodic(
        TIMER_VECTOR,
        LapicTimerDivide::Div16,          
        ticks_1ms,  
    );
}
