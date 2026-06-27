use crate::arch::{interrupt::without_interrupts, serial::putb};


pub fn print(s: &str) {
    without_interrupts(|| {
        for b in s.bytes() {
            if b == b'\n' { putb(b'\r'); }
            putb(b);
        }
    });
}

#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let _ = write!($crate::serial::SerialWriter, $($arg)*);
    }};
}

#[macro_export]
macro_rules! serial_println {
    () => ($crate::serial_print!("\n"));
    ($($arg:tt)*) => {{
        $crate::serial_print!("{}\n", format_args!($($arg)*))
    }};
}

pub struct SerialWriter;

impl core::fmt::Write for SerialWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        print(s);
        Ok(())
    }
}