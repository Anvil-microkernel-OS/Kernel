use crate::{arch::amd64::{apic::PercpuLapic, cpu::{frames::InterruptFrame, hlt_loop, smp::percpu::PerCpuRegion}, interrupts::{idt::{IDT_COUNT, ISR_COUNT}, tables::{__irq_table_end, __irq_table_start, __isr_table_end, __isr_table_start, Handler, InterruptDescriptor}}, scheduler::{PerCpuSchedulerData, SCHEDULING_STARTED, task_storage::get_task_by_index}}, early_println};

static mut HANDLERS: [Option<Handler>; IDT_COUNT] = [None; IDT_COUNT];

pub fn init_dispatch_from_sections() {
    unsafe {
        register_range(&__isr_table_start, &__isr_table_end);
        register_range(&__irq_table_start, &__irq_table_end);
    }
}

fn register_range(start: *const InterruptDescriptor, end: *const InterruptDescriptor) {
    let mut cur = start;
    while cur < end {
        unsafe {
            let d = &*cur;
            HANDLERS[d.vector as usize] = Some(d.handler);
            cur = cur.add(1);
        }
    }
}

fn check_allowed_for_transfer(num: usize) -> bool {
    matches!(num, 0 | 5 | 6 | 7 | 13 | 14 | 16 | 19)
}

#[unsafe(no_mangle)]
extern "C" fn base_trap(stack_frame: *const InterruptFrame) {
    let frame = unsafe { &*stack_frame };

    let vec = frame.interrupt as usize;

    let handler = unsafe { HANDLERS[vec] };
    if let Some(h) = handler {
        h(&frame);

        return;
    } 

    if (frame.interrupt as usize) < ISR_COUNT {
        early_println!("Unhandled isr interrupt!\n {}", frame);
        if SCHEDULING_STARTED.get().is_some() {
            if check_allowed_for_transfer(vec) {
                let curr_id = PerCpuSchedulerData::get().curr_task_id;
                let curr_task = get_task_by_index(curr_id.id());

                //todo send ipc_message to supervisor
            }
        }
        hlt_loop();
    }

    //todo - impl mechanism, that pushes irq to user task
    early_println!("Unhandled irq interrupt! Code: {}. ACKing...", vec);
    PercpuLapic::get().lapic.eoi();
}