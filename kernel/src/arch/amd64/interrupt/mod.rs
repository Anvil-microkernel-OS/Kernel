pub mod init_table;
pub mod frame;
mod basic_exceptions;
mod basic_interrupts;

pub const INTERRUPT_COUNT: usize = 256;
pub const EXCEPTION_COUNT: u8 = 32;
pub const IRQ_BASE: usize = 32;

#[inline(always)]
pub unsafe fn disable() {
    unsafe {
        core::arch::asm!("cli", options(nomem, nostack));
    }
}

#[inline(always)]
pub unsafe fn enable_and_halt() {
    unsafe {
        core::arch::asm!("sti; hlt", options(nomem, nostack));
    }
}

#[inline(always)]
pub unsafe fn enable_and_nop() {
    unsafe {
        core::arch::asm!("sti; nop", options(nomem, nostack));
    }
}

#[inline(always)]
pub fn halt() {
    unsafe {
        core::arch::asm!("hlt", options(nomem, nostack));
    }
}

#[inline]
pub fn without_interrupts<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    let flags: u64;
    unsafe {
        core::arch::asm!("pushfq; pop {}", out(reg) flags, options(nomem, preserves_flags));
    }

    let was_enabled = flags & (1 << 9) != 0;

    unsafe { disable(); }

    let result = f();

    if was_enabled {
        unsafe {
            core::arch::asm!("sti", options(nomem, nostack));
        }
    }

    result
}