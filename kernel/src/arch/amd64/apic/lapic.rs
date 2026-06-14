use x86_64::{
    PhysAddr, VirtAddr,
    structures::paging::{Page, PageTableFlags, Size4KiB},
    registers::model_specific::Msr,
};
use raw_cpuid::CpuId;

use crate::{
    arch::amd64::memory::vmm::kmap_mmio_page,
    misc::registers::{RegisterRO, RegisterRW, RegisterWO},
    register_struct,
};

// xAPIC flags
const SVR_ENABLE: u32 = 0x100;
const SVR_SUPPRESS_EOI_BROADCAST: u32 = 0x1000;

const ICR_DELIVERY_FIXED: u32 = 0x000;
const ICR_DELIVERY_INIT: u32 = 0x500;
const ICR_DELIVERY_STARTUP: u32 = 0x600;
const ICR_DEST_PHYSICAL: u32 = 0x000;
const ICR_DEST_LOGICAL: u32 = 0x800;
const ICR_LEVEL_ASSERT: u32 = 0x4000;
const ICR_TRIGGER_EDGE: u32 = 0x0000;
const ICR_TRIGGER_LEVEL: u32 = 0x8000;
const ICR_DEST_SELF: u32 = 0x40000;
const ICR_DEST_ALL: u32 = 0x80000;
const ICR_DEST_ALL_EX_SELF: u32 = 0xC0000;
const ICR_DELIVERY_STATUS_PENDING: u32 = 1 << 12;
const SPURIOUS_VECTOR: u32 = 0xEF;

// x2APIC MSR constants
const IA32_APIC_BASE: u32 = 0x1B;
const X2APIC_MODE_FLAG: u64 = 1 << 10;
const APIC_GLOBAL_ENABLE: u64 = 1 << 11;

const X2APIC_ICR: u32 = 0x830;
const X2APIC_SVR: u32 = 0x80F;
const X2APIC_TPR: u32 = 0x808;
const X2APIC_EOI: u32 = 0x80B;
const X2APIC_LAPIC_ID: u32 = 0x802;
const X2APIC_LVT_TIMER: u32 = 0x832;
const X2APIC_LVT_THERMAL: u32 = 0x833;
const X2APIC_LVT_PERFMON: u32 = 0x834;
const X2APIC_LVT_LINT0: u32 = 0x835;
const X2APIC_LVT_LINT1: u32 = 0x836;
const X2APIC_LVT_ERROR: u32 = 0x837;
const X2APIC_TIMER_INIT: u32 = 0x838;
const X2APIC_TIMER_CURR: u32 = 0x839;
const X2APIC_TIMER_DIV: u32 = 0x83E;
const X2APIC_SELF_IPI: u32 = 0x83F;

#[repr(u32)]
pub enum LapicTimerDivide {
    Div1   = 0b1011,
    Div2   = 0b0000,
    Div4   = 0b0001,
    Div8   = 0b0010,
    Div16  = 0b0011,
    Div32  = 0b1000,
    Div64  = 0b1001,
    Div128 = 0b1010,
}

register_struct! {
    LAPICRegisters {
        0x020 => lapic_id: RegisterRO<u32>,
        0x030 => lapic_ver: RegisterRO<u32>,
        0x080 => lapic_tpr: RegisterRW<u32>,
        0x0B0 => lapic_eoi: RegisterWO<u32>,
        0x0F0 => lapic_svr: RegisterRW<u32>,
        0x280 => lapic_esr: RegisterRW<u32>,
        0x300 => lapic_icr_low: RegisterRW<u32>,
        0x310 => lapic_icr_high: RegisterRW<u32>,
        0x320 => lapic_timer: RegisterRW<u32>,
        0x330 => lapic_thermal: RegisterRW<u32>,
        0x340 => lapic_perf: RegisterRW<u32>,
        0x350 => lapic_lint0: RegisterRW<u32>,
        0x360 => lapic_lint1: RegisterRW<u32>,
        0x370 => lapic_lvt_err: RegisterRW<u32>,
        0x380 => lapic_timer_init: RegisterRW<u32>,
        0x390 => lapic_timer_curr: RegisterRW<u32>,
        0x3E0 => lapic_timer_div: RegisterRW<u32>,
    }
}

enum LapicMode {
    Xapic { registers: LAPICRegisters },
    X2apic,
}

pub struct Lapic {
    mode: LapicMode,
}

unsafe impl Send for Lapic {}
unsafe impl Sync for Lapic {}

impl Lapic {
    pub fn new(phys_addr: PhysAddr, virt_addr: VirtAddr) -> Self {
        let page = Page::<Size4KiB>::containing_address(virt_addr);
        let aligned_virt_addr = page.start_address();

        let flags = PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::NO_CACHE;

        kmap_mmio_page(aligned_virt_addr, phys_addr, flags);
        let registers = unsafe {
            LAPICRegisters::from_address(aligned_virt_addr.as_u64() as usize)
        };

        Self {
            mode: LapicMode::Xapic { registers },
        }
    }

    pub fn newx2() -> Self {
        let mut msr =  Msr::new(IA32_APIC_BASE);
        let value = unsafe { msr.read() };

        if value & X2APIC_MODE_FLAG == 0 {
            let new_value = value | APIC_GLOBAL_ENABLE | X2APIC_MODE_FLAG;
            unsafe { msr.write(new_value); }
        }

        const SVR_SOFTWARE_ENABLE: u64 = 1 << 8;
        const SPURIOUS_VECTOR_X2: u64 = 0xFF;
        unsafe {
            Msr::new(X2APIC_SVR).write(SVR_SOFTWARE_ENABLE | SPURIOUS_VECTOR_X2);
        }

        unsafe { Msr::new(X2APIC_TPR).write(0); }

        const LVT_MASKED: u64 = 1 << 16;
        unsafe {
            Msr::new(X2APIC_LVT_TIMER).write(LVT_MASKED);
            Msr::new(X2APIC_LVT_THERMAL).write(LVT_MASKED);
            Msr::new(X2APIC_LVT_PERFMON).write(LVT_MASKED);
            Msr::new(X2APIC_LVT_LINT0).write(LVT_MASKED);
            Msr::new(X2APIC_LVT_LINT1).write(LVT_MASKED);
            Msr::new(X2APIC_LVT_ERROR).write(LVT_MASKED);
        }

        Self {
            mode: LapicMode::X2apic,
        }
    }
}

impl Lapic {
    pub fn eoi(&self) {
        match &self.mode {
            LapicMode::Xapic { registers } => {
                registers.lapic_eoi().write(0);
            }
            LapicMode::X2apic => {
                unsafe { Msr::new(X2APIC_EOI).write(0); }
            }
        }
    }

    pub fn id(&self) -> u32 {
        match &self.mode {
            LapicMode::Xapic { registers } => {
                registers.lapic_id().read() >> 24
            }
            LapicMode::X2apic => {
                unsafe { (Msr::new(X2APIC_LAPIC_ID).read() & 0xFFFFFFFF) as u32 }
            }
        }
    }

    pub fn enable(&self) {
        match &self.mode {
            LapicMode::Xapic { registers } => {
                let mut svr = registers.lapic_svr().read();
                svr &= !0xFF;
                svr |= SPURIOUS_VECTOR;
                svr |= SVR_ENABLE;
                registers.lapic_svr().write(svr);
                registers.lapic_svr().read();
            }
            LapicMode::X2apic => {
                unsafe {
                    let mut svr = Msr::new(X2APIC_SVR).read();
                    svr |= 1 << 8; 
                    Msr::new(X2APIC_SVR).write(svr);
                }
            }
        }
    }

    pub fn set_task_priority(&self, priority: u32) {
        match &self.mode {
            LapicMode::Xapic { registers } => {
                registers.lapic_tpr().write(priority);
            }
            LapicMode::X2apic => {
                unsafe { Msr::new(X2APIC_TPR).write(priority as u64); }
            }
        }
    }

    pub fn setup_timer_periodic(
        &self,
        vector: u8,
        div: LapicTimerDivide,
        initial_count: u32,
    ) {
        self.set_timer_divide(div);
        self.set_lvt_timer(vector, true);
        self.set_timer_initial(initial_count);
    }

    pub fn stop_timer(&self) {
        match &self.mode {
            LapicMode::Xapic { registers } => {
                registers.lapic_timer_init().write(0);
            }
            LapicMode::X2apic => {
                unsafe { Msr::new(X2APIC_TIMER_INIT).write(0); }
            }
        }
    }

    pub fn set_timer_divide(&self, div: LapicTimerDivide) {
        match &self.mode {
            LapicMode::Xapic { registers } => {
                registers.lapic_timer_div().write(div as u32);
            }
            LapicMode::X2apic => {
                unsafe { Msr::new(X2APIC_TIMER_DIV).write(div as u64); }
            }
        }
    }

    pub fn set_lvt_timer(&self, vector: u8, periodic: bool) {
        let mut value = vector as u64;
        if periodic {
            value |= 1 << 17;
        }

        match &self.mode {
            LapicMode::Xapic { registers } => {
                registers.lapic_timer().write(value as u32);
            }
            LapicMode::X2apic => {
                unsafe { Msr::new(X2APIC_LVT_TIMER).write(value); }
            }
        }
    }

    pub fn set_timer_initial(&self, count: u32) {
        match &self.mode {
            LapicMode::Xapic { registers } => {
                registers.lapic_timer_init().write(count);
            }
            LapicMode::X2apic => {
                unsafe { Msr::new(X2APIC_TIMER_INIT).write(count as u64); }
            }
        }
    }

    pub fn read_timer_current(&self) -> u32 {
        match &self.mode {
            LapicMode::Xapic { registers } => {
                registers.lapic_timer_curr().read()
            }
            LapicMode::X2apic => {
                unsafe { Msr::new(X2APIC_TIMER_CURR).read() as u32 }
            }
        }
    }

    pub fn read_icr_low(&self) -> u32 {
        match &self.mode {
            LapicMode::Xapic { registers } => {
                registers.lapic_icr_low().read()
            }
            LapicMode::X2apic => {
                unsafe { Msr::new(X2APIC_ICR).read() as u32 }
            }
        }
    }

    pub fn write_icr_low(&self, val: u32) {
        match &self.mode {
            LapicMode::Xapic { registers } => {
                while registers.lapic_icr_low().read() & ICR_DELIVERY_STATUS_PENDING != 0 {
                    core::hint::spin_loop();
                }
                registers.lapic_icr_low().write(val);
            }
            LapicMode::X2apic => {
                unsafe { Msr::new(X2APIC_ICR).write(val as u64); }
            }
        }
    }

    pub fn self_ipi_x2apic(&self, vector: u8) {
        match &self.mode {
            LapicMode::Xapic { .. } => {
                panic!("self_ipi_x2apic called on xAPIC mode");
            }
            LapicMode::X2apic => {
                unsafe { Msr::new(X2APIC_SELF_IPI).write(vector as u64); }
            }
        }
    }

    pub fn is_x2apic(&self) -> bool {
        matches!(&self.mode, LapicMode::X2apic)
    }

    pub fn is_initialized(&self) -> bool {
        match &self.mode {
            LapicMode::Xapic { registers } => registers.address != 0,
            LapicMode::X2apic => true, 
        }
    }

    pub fn send_ipi(&self, dest_apic_id: u32, vector: u8) {
        match &self.mode {
            LapicMode::Xapic { registers } => {
                self.wait_icr_idle(registers);
                registers.lapic_icr_high().write(dest_apic_id << 24);
                registers.lapic_icr_low().write(
                    vector as u32 | ICR_DELIVERY_FIXED | ICR_DEST_PHYSICAL
                    | ICR_LEVEL_ASSERT | ICR_TRIGGER_EDGE
                );
            }
            LapicMode::X2apic => {
                let icr = (vector as u64) | ((dest_apic_id as u64) << 32);
                unsafe { Msr::new(X2APIC_ICR).write(icr); }
            }
        }
    }

    pub fn send_ipi_others(&self, vector: u8) {
        match &self.mode {
            LapicMode::Xapic { registers } => {
                self.wait_icr_idle(registers);
                registers.lapic_icr_high().write(0);
                registers.lapic_icr_low().write(
                    vector as u32 | ICR_DELIVERY_FIXED
                    | ICR_DEST_ALL_EX_SELF | ICR_LEVEL_ASSERT | ICR_TRIGGER_EDGE
                );
            }
            LapicMode::X2apic => {
                let icr = (vector as u64) | (ICR_DEST_ALL_EX_SELF as u64);
                unsafe { Msr::new(X2APIC_ICR).write(icr); }
            }
        }
    }

    pub fn send_self_ipi(&self, vector: u8) {
        match &self.mode {
            LapicMode::Xapic { registers } => {
                self.wait_icr_idle(registers);
                registers.lapic_icr_high().write(0);
                registers.lapic_icr_low().write(
                    vector as u32 | ICR_DELIVERY_FIXED | ICR_DEST_SELF
                    | ICR_LEVEL_ASSERT | ICR_TRIGGER_EDGE
                );
            }
            LapicMode::X2apic => {
                unsafe { Msr::new(X2APIC_SELF_IPI).write(vector as u64); }
            }
        }
    }

    fn wait_icr_idle(&self, registers: &LAPICRegisters) {
        while registers.lapic_icr_low().read() & ICR_DELIVERY_STATUS_PENDING != 0 {
            core::hint::spin_loop();
        }
    }
}