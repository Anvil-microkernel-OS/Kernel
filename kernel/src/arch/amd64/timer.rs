use core::ptr::{self, NonNull};

use spin::{Once, RwLock};

use crate::{arch::apic::{PERCPU_LAPIC, lapic::LapicTimerDivide}, early_println, irq, memory::{misc::primitives::VirtAddr, vmm::{kernel_pt_mapper, pflags::PFlags}}, platform_description::get_basic_board_info};

const HPET_CFG_ENABLE: u64 = 1 << 0;
const HPET_CFG_LEGACY: u64 = 1 << 1;
pub const TIMER_VECTOR: u8 = 0x30;

static HPET_GLOBAL: Once<RwLock<HPET>> = Once::new();

#[repr(C)]
struct HpetRegisters {
    general_cap_id:     u64,      // 0x000
    _rsv0:              u64,      // 0x008
    general_config:     u64,      // 0x010
    _rsv_cfg2:          u64,      // 0x018 (RESERVED)
    general_int_status: u64,      // 0x020
    _rsv1:              [u64; 25],// 0x028 .. 0x0EF
    main_counter:       u64,      // 0x0F0
}

pub struct HPET {
    regs: NonNull<HpetRegisters>,
    /// femtoseconds per tick (from capabilities bits 63:32)
    period_fs: u64,
}

unsafe impl Send for HPET {}
unsafe impl Sync for HPET {}

impl HPET {
    pub fn init(&mut self, enable_legacy: bool) {
        unsafe {
            let r = self.regs.as_ptr();
            ptr::write_volatile(&mut (*r).general_config, 0);
            let caps = ptr::read_volatile(&(*r).general_cap_id);
            self.period_fs = caps >> 32;
            ptr::write_volatile(&mut (*r).main_counter, 0);
            let mut cfg = HPET_CFG_ENABLE;
            if enable_legacy {
                cfg |= HPET_CFG_LEGACY;
            }
            ptr::write_volatile(&mut (*r).general_config, cfg);
        }
    }

    #[inline(always)]
    pub fn read_counter(&self) -> u64 {
        unsafe {
            ptr::read_volatile(&(*self.regs.as_ptr()).main_counter)
        }
    }

    #[inline(always)]
    pub fn period_fs(&self) -> u64 {
        self.period_fs
    }

    pub fn is_ticking(&self, spins: u32) -> bool {
        let a = self.read_counter();
        let mut b = a;

        for _ in 0..spins {
            core::hint::spin_loop();
            b = self.read_counter();
            if b != a {
                return true;
            }
        }
        false
    }
}

pub fn arch_setup_timer() {
    let hpet_phys_base = get_basic_board_info().timer.base_address;

    let hpet_virt_base = VirtAddr::new(0xFFFF_FF80_0000_0000);

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

    if let Some((_, old_flags)) = mapper.translate(hpet_virt_base) {
        early_println!("HPET already mapped with flags {:#x}, remapping...", old_flags.data());
        mapper.remap(hpet_virt_base, flags).unwrap().flush();
    } else {
        mapper.map_phys(hpet_virt_base, hpet_phys_base, flags)
            .expect("HPET MMIO mapping failed")
            .flush();
    }

    let regs = NonNull::new(hpet_virt_base.as_mut_ptr::<HpetRegisters>())
        .expect("HPET MMIO mapping failed");

    let mut hpet = HPET {
        regs,
        period_fs: 0,
    };

    hpet.init(true);

    let ticking = hpet.is_ticking(50_000_000);
    if !ticking {
        early_println!("HPET is not ticking! Fallback to pic timer...");
    }

    HPET_GLOBAL.call_once(|| {
        RwLock::new(hpet)
    });
}

const CALIBRATION_MS: u64 = 10;

//todo - percpu timer calibration
pub static TIMER_CALIBRATION_OFFSET_10MS: Once<u32> = Once::new();

pub fn arch_calibrate_timer() {
    let hpet_ticks_target =
        (CALIBRATION_MS * 1_000_000_000_000u64) / HPET_GLOBAL.get().unwrap().read().period_fs();

    PERCPU_LAPIC::with_guard(|llapic| {
        llapic.lapic.set_timer_divide(LapicTimerDivide::Div16);
        llapic.lapic.set_lvt_timer(TIMER_VECTOR, false);
        llapic.lapic.set_timer_initial(u32::MAX);
    });

    let hpet_start = HPET_GLOBAL.get().unwrap().read().read_counter();
    let lapic_start = PERCPU_LAPIC::get().lapic.read_timer_current();

    while HPET_GLOBAL.get().unwrap().read().read_counter().wrapping_sub(hpet_start) < hpet_ticks_target {
        core::hint::spin_loop();
    }

    let lapic_end = PERCPU_LAPIC::get().lapic.read_timer_current();

    TIMER_CALIBRATION_OFFSET_10MS.call_once(|| {
        lapic_start.wrapping_sub(lapic_end)
    });
}

pub fn arch_enable_timer(initial_count: u32) {
    PERCPU_LAPIC::get().lapic.setup_timer_periodic(TIMER_VECTOR, LapicTimerDivide::Div16, initial_count);
}

pub fn arch_stop_timer() {
    PERCPU_LAPIC::get().lapic.stop_timer();
}