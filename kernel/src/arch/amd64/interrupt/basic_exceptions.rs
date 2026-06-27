use crate::{arch::interrupt::halt, isr, serial_println};

const DEBUG: u8 = 0x1;
const BREACKPOINT: u8 = 0x2;
const OVERFLOW: u8 = 0x4;
const PAGE_FAULT: u8 = 0x0E;

isr!(DEBUG, debug_ex, |frame| {
    serial_println!("DEBUG EXC.\n{}", frame);

    loop {
        halt();
    }
});

isr!(BREACKPOINT, break_point_ex, |frame| {
    serial_println!("BREACKPOINT EXC.\n{}", frame);

    loop {
        halt();
    }
});

isr!(OVERFLOW, overflow_ex, |frame| {
    serial_println!("OVERFLOW EXC.\n{}", frame);

    loop {
        halt();
    }
});

isr!(PAGE_FAULT, page_fault, |frame| {
    let cr2 = x86_64::registers::control::Cr2::read_raw();
    serial_println!("PAGE_FAULT EXC. CR2: {}\n{}", cr2, frame);
    loop {
        halt();
    }
});