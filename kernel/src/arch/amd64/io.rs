use core::arch::asm;

use crate::io_ops::IoOperations;

pub struct PortIo;

impl IoOperations for PortIo {
    fn read8(addr: usize) -> u8 {
        let mut val;
        unsafe { asm!("in al, dx", out("al") val, in("dx") addr); }
        return val;
    }

    fn write8(addr: usize, val: u8) {
        unsafe { asm!("out dx, al", in("al") val, in("dx") addr); }
    }

    fn read16(addr: usize) -> u16 {
        let mut val;
        unsafe { asm!("in ax, dx", out("ax") val, in("dx") addr); }
        return val;
    }
    
    fn write16(addr: usize, val: u16) {
        unsafe { asm!("out dx, ax", in("ax") val, in("dx") addr); }
    }

    fn read32(addr: usize) -> u32 {
        let mut val;
        unsafe { asm!("in eax, dx", out("eax") val, in("dx") addr); }
        return val;
    }

    fn write32(addr: usize, val: u32) {
        unsafe { asm!("out dx, eax", in("eax") val, in("dx") addr); }
    }
}