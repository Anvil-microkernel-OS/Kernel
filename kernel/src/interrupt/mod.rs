use crate::arch::interrupt::frame::InterruptFrame;

mod base_trap;
pub mod macros;
pub mod interrupt_numbers;

pub type Handler = extern "C" fn(&InterruptFrame);

#[repr(C)]
pub struct InterruptDescriptor {
    pub vector: u8,
    pub handler: Handler,
}

unsafe extern "C" {
    pub static __isr_table_start: InterruptDescriptor;
    pub static __isr_table_end: InterruptDescriptor;

    pub static __irq_table_start: InterruptDescriptor;
    pub static __irq_table_end: InterruptDescriptor;
}