use core::{sync::atomic::{AtomicU8, Ordering}};

use limine::{mp::Cpu, response::MpResponse};
use x86_64::{VirtAddr, instructions};

use crate::{arch::amd64::{apic::init_lapic, cpu::smp::percpu::{PerCpuRegion, get_percpu_regions_ammo, get_region_by_id, set_gsbase_for_percpu_region}, gdt::setup_gdt_for_local_core, interrupts::idt::init_idt, scheduler::init_scheduler_percpu}, bootinfo::BootInfo, early_println};

static NUM_CPUS_BOOTSTRAPPED: AtomicU8 = AtomicU8::new(0);

pub(crate) struct LimineCPU {
    pub(crate) mp_response: &'static MpResponse,
    pub(crate) cpu: &'static Cpu,
}

impl LimineCPU {
    pub(crate) fn bootstrap_cpu(
        &self,
        entry: unsafe extern "C" fn(&Cpu) -> !,
        region: &'static PerCpuRegion,
    ) {

        let ptr = region as *const PerCpuRegion as u64;
        self.cpu.extra.store(ptr, Ordering::Release);

        self.cpu.goto_address.write(entry);
    }
}

struct CPUIterator {
    mp_response: &'static MpResponse,
    current: usize,
}

impl Iterator for CPUIterator {
    type Item = LimineCPU;

    fn next(&mut self) -> Option<Self::Item> {
        let cpu = self.mp_response.cpus().get(self.current)?;
        self.current += 1;

        Some(LimineCPU {
            mp_response: self.mp_response,
            cpu: *cpu,
        })
    }
}

fn get_smp_entries() -> impl Iterator<Item = LimineCPU> {
    let mp_response = BootInfo::get().get_smp_response()
        .expect("failed to get limine SMP response");

    CPUIterator {
        mp_response,
        current: 0,
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn start_ap(info: &Cpu) -> ! {
    instructions::interrupts::disable();
    let region_ptr = info.extra.load(Ordering::Acquire) as *const PerCpuRegion;
    assert!(!region_ptr.is_null());
    let local_region = unsafe { &*region_ptr };
    
    set_gsbase_for_percpu_region(local_region.base);
    setup_gdt_for_local_core();
    init_idt();
    init_lapic();
    NUM_CPUS_BOOTSTRAPPED.fetch_add(1, Ordering::Release);
    instructions::interrupts::enable();
    init_scheduler_percpu();
}

pub fn smp_startup() -> ! {
    early_println!("All cpus count: {}", get_percpu_regions_ammo());

    let mp_response = BootInfo::get()
        .get_smp_response()
        .expect("failed to get limine SMP response");

    for entry in get_smp_entries() {
        let i = mp_response
            .cpus()
            .iter()
            .position(|c| c.lapic_id == entry.cpu.lapic_id)
            .expect("CPU not found in mp_response");

        //allready setupped data for BSP
        if entry.cpu.lapic_id != mp_response.bsp_lapic_id() {
            entry.bootstrap_cpu(start_ap, &get_region_by_id(i));
        }
    }

    early_println!("Waiting for slave cpus...");
    while NUM_CPUS_BOOTSTRAPPED.load(Ordering::Acquire) < (get_percpu_regions_ammo() - 1) as u8 {
        core::hint::spin_loop();
    }
    early_println!("All slave cpus initialized!");

    early_println!("Initializing bsp...");
    //allready initialized all usefull data for BSP
    init_scheduler_percpu();
}

pub fn early_setup_percpu_bsp(region_base: VirtAddr) {
    instructions::interrupts::without_interrupts(|| {
        set_gsbase_for_percpu_region(region_base);
        setup_gdt_for_local_core();
    });
}