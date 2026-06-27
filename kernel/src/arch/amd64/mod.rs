use crate::{arch::{amd64::gdt::init_bootstrap_gdt, interrupt::init_table::init_interrupt_table}};

pub mod serial;
pub mod interrupt;
pub mod memory;
pub mod io;
pub mod timer;
pub mod apic;
pub mod thread_registers;
mod gdt;

pub fn init_interrupts() {
    init_bootstrap_gdt();
    init_interrupt_table();
}

const MSR_GS_BASE: u32 = 0xC000_0101;        
const MSR_KERNEL_GS_BASE: u32 = 0xC000_0102; 

#[inline(always)]
unsafe fn rdmsr(msr: u32) -> u64 {
    unsafe {
        let lo: u32;
        let hi: u32;
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") hi,
            options(nostack, preserves_flags),
        );
        ((hi as u64) << 32) | (lo as u64)
    }
}

#[inline(always)]
fn wrmsr(msr: u32, val: u64) {
    unsafe {
        let lo = val as u32;
        let hi = (val >> 32) as u32;
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") lo,
            in("edx") hi,
            options(nostack, preserves_flags),
        );
    }
}

#[inline]
pub(crate) fn barrier() {
    unsafe {
        core::arch::asm!(
            "mfence",
            options(nomem, nostack, preserves_flags)
        );
    }
}

#[inline(always)]
pub fn get_arch_specific_percpu_rg_ptr() -> u64 {
    unsafe { rdmsr(MSR_GS_BASE) }
}

pub fn load_percpu_region_ptr_to_core(ptr: usize) {
    let hi = ptr >> 48;
    if hi != 0 && hi != 0xFFFF {
        panic!("non-canonical GS base: {:#x}", ptr);
    }

    wrmsr(MSR_GS_BASE, ptr as u64); 
    wrmsr(MSR_KERNEL_GS_BASE, ptr as u64); 
}