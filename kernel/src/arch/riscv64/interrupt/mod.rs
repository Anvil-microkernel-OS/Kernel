use core::arch::asm;

pub mod init_table;
pub mod frame;

pub const INTERRUPT_COUNT: usize = 0;
pub const EXCEPTION_COUNT: usize = 32; 
pub const IRQ_BASE: usize = 0; 

#[inline(always)]
pub unsafe fn disable() {
    unsafe { asm!("csrci sstatus, 1 << 1") }
}

#[inline(always)]
pub unsafe fn enable_and_halt() {
    unsafe { asm!("wfi", "csrsi sstatus, 1 << 1", "nop") }
}

#[inline(always)]
pub unsafe fn enable_and_nop() {
    unsafe { asm!("csrsi sstatus, 1 << 1", "nop") }
}

#[inline(always)]
pub fn halt() {
    unsafe { asm!("wfi", options(nomem, nostack)) }
}

#[inline]
pub fn without_interrupts<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    let sstatus: u64;
    unsafe {
        core::arch::asm!("csrr {}, sstatus", out(reg) sstatus, options(nomem, nostack));
    }

    let was_enabled = sstatus & (1 << 1) != 0;

    unsafe {
        core::arch::asm!("csrci sstatus, 0x2", options(nomem, nostack));
    }

    let result = f();

    if was_enabled {
        unsafe {
            core::arch::asm!("csrsi sstatus, 0x2", options(nomem, nostack));
        }
    }

    result
}