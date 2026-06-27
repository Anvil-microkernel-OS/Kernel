use crate::{arch::interrupt::{EXCEPTION_COUNT, frame::InterruptFrame, halt, init_table::HANDLERS}, serial_print};

#[unsafe(no_mangle)]
extern "C" fn base_trap(stack_frame: *const InterruptFrame) {
    let frame = unsafe { &*stack_frame };

    let vec = frame.interrupt as usize;

    let handler = unsafe { HANDLERS[vec] };
    if let Some(h) = handler {
        h(&frame);

        return;
    } 

    if (frame.interrupt as u8) < EXCEPTION_COUNT {
        serial_print!("UNHANDLED PROCESSOR EXCEPTION!\n");
        serial_print!("{}\n", frame);
    }

    loop {
        halt();
    }
}