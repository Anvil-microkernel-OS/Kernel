#[macro_export]
#[cfg(target_arch = "x86_64")]
macro_rules! isr {
    ($vec:expr, $name:ident, |$stack:ident| $body:block) => {
        const _: () = {
            assert!(
                $vec < $crate::arch::interrupt::EXCEPTION_COUNT,
                "ISR vector must be in range 0..31"
            );
        };

        paste::paste! {
            extern "C" fn $name($stack: &$crate::arch::interrupt::frame::InterruptFrame) {
                $body
            }

            #[used]
            #[unsafe(link_section = ".isr_table")]
            static [<$name:upper _ISR>]: $crate::interrupt::InterruptDescriptor =
                $crate::interrupt::InterruptDescriptor {
                    vector: $vec,
                    handler: $name,
                };
        }
    };
}

#[macro_export]
#[cfg(target_arch = "x86_64")]
macro_rules! irq {
    ($vec:expr, $name:ident, |$stack:ident| $body:block) => {
        const _: () = {
            assert!(
                ($vec as usize) < $crate::arch::interrupt::INTERRUPT_COUNT && ($vec as usize) >= $crate::arch::interrupt::IRQ_BASE,
                "IRQ vector out of IDT range"
            );
        };

        paste::paste! {
            extern "C" fn $name($stack: &$crate::arch::interrupt::frame::InterruptFrame) {
                $body
            }

            #[used]
            #[unsafe(link_section = ".irq_table")]
            static [<$name:upper _IRQ>]: $crate::interrupt::InterruptDescriptor =
                $crate::interrupt::InterruptDescriptor {
                    vector: $vec as u8,
                    handler: $name,
                };
        }
    };
}

#[macro_export]
#[cfg(target_arch = "riscv64")]
macro_rules! isr {
    ($vec:expr, $name:ident, |$stack:ident| $body:block) => {
        const _: () = {
            assert!(
                $vec < $crate::arch::interrupt::EXCEPTION_COUNT,
                "ISR vector must be in range 0..31"
            );
        };

        paste::paste! {
            extern "C" fn $name($stack: &$crate::arch::interrupt::frame::InterruptFrame) {
                $body
            }

            #[used]
            #[unsafe(link_section = ".isr_table")]
            static [<$name:upper _ISR>]: $crate::interrupt::InterruptDescriptor =
                $crate::interrupt::InterruptDescriptor {
                    vector: $vec,
                    handler: $name,
                };
        }
    };
}

#[macro_export]
#[cfg(target_arch = "riscv64")]
macro_rules! irq {
    ($vec:expr, $name:ident, |$stack:ident| $body:block) => {
        const _: () = {
            assert!(
                ($vec as usize) < $crate::arch::interrupt::MAX_PLIC_INTERRUPTS,
                "IRQ vector out of IDT range"
            );
        };

        paste::paste! {
            extern "C" fn $name($stack: &$crate::arch::interrupt::frame::InterruptFrame) {
                $body
            }

            #[used]
            #[unsafe(link_section = ".irq_table")]
            static [<$name:upper _IRQ>]: $crate::interrupt::InterruptDescriptor =
                $crate::interrupt::InterruptDescriptor {
                    vector: $vec as u8,
                    handler: $name,
                };
        }
    };
}