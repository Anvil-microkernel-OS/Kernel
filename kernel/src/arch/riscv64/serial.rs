
pub fn putb(b: u8) {
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") 1u64,
            in("a0") b as u64,
        );
    }
}