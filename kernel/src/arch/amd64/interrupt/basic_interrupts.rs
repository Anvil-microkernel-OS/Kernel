use crate::{arch::{apic::PERCPU_LAPIC, timer::TIMER_VECTOR}, irq};

irq!(TIMER_VECTOR, timer_irq, |frame| {
    PERCPU_LAPIC::get().lapic.eoi();
});