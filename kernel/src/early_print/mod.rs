pub mod fb_printer;

#[macro_export]
macro_rules! early_print {
    ($($arg:tt)*) => {{
        $crate::serial_print!($($arg)*);
    }};
}

#[macro_export]
macro_rules! early_println {
    () => {
        $crate::serial_print!("\n");
    };
    ($($arg:tt)*) => {{
        $crate::serial_print!($($arg)*);
        $crate::serial_print!("\n");
    }};
}

