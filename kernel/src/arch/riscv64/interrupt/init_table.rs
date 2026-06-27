use crate::{arch::interrupt::INTERRUPT_COUNT, interrupt::Handler};

pub static mut HANDLERS: [Option<Handler>; INTERRUPT_COUNT] = [None; INTERRUPT_COUNT];

pub fn init_interrupt_table() {
    panic!("Error!")
}