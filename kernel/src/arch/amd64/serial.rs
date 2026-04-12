use core::fmt;

use lazy_static::lazy_static;
use spin::Mutex;
use uart_16550::SerialPort;
use x86_64::instructions::interrupts;

const COM1_PORT: u16 = 0x3F8;

lazy_static! {
    pub static ref SERIAL1: Mutex<SerialPort> = {
        let mut serial = unsafe { SerialPort::new(COM1_PORT) };
        serial.init();
        Mutex::new(serial)
    };
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    use core::fmt::Write;
    interrupts::without_interrupts(|| {
        if let Some(mut serial) = SERIAL1.try_lock() {
            serial
                .write_fmt(args)
                .expect("Problem occured, while trying to write serial port");
        }
    });
}
