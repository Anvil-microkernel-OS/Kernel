#[cfg(target_arch = "x86_64")]
pub mod amd64;

#[cfg(target_arch = "x86_64")]
pub use amd64 as current;

pub fn hlt_loop() -> ! {
    current::cpu::hlt_loop();
}

pub fn phase1_init_platform_specific() {
    current::init_arch();
}

pub fn phase2_init_platform_specific() -> ! {
    current::final_arch_init()
}

