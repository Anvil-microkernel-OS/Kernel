#[cfg(target_arch = "x86_64")]
pub mod amd64;

#[cfg(target_arch = "x86_64")]
pub use amd64 as current;

pub fn hlt_loop() -> ! {
    current::cpu::hlt_loop();
}

pub fn early_arch_init() {
    current::init_arch();
}

pub fn final_arch_init() -> ! {
    current::final_arch_init()
}