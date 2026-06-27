use crate::arch::timer::{arch_calibrate_timer, arch_enable_timer, arch_setup_timer, arch_stop_timer};

pub fn setup_platform_timer() {
    arch_setup_timer();

    arch_calibrate_timer();
}

pub fn enable_platform_timer(initial_count: u32) {
    arch_enable_timer(initial_count);
}

pub fn stop_platfrom_timer() {
    arch_stop_timer();
}