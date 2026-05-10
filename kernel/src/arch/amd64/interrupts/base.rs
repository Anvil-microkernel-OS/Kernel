use alloc::format;

use crate::{arch::amd64::{apic::{PercpuLapic, ioapic_manager::ioapic_manager}, cpu::{frames::InterruptFrame, hlt_loop}, interrupts::{idt::{IDT_COUNT, ISR_COUNT}, irq_trans_manager::IDT_TRANSFER_MANAGER, tables::{__irq_table_end, __irq_table_start, __isr_table_end, __isr_table_start, Handler, InterruptDescriptor}}, ipc::port::{PortAction, PortEvent, PortPacket}, scheduler::{SCHEDULING_STARTED, task_storage::{get_thread, wake_thread}}}, early_println, panic::panic_screen};

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
        if SCHEDULING_STARTED.get().is_some() {
            if check_allowed_for_transfer(vec) {
                //let curr_id = PerCpuSchedulerData::get().curr_task_id;
                //let curr_task = get_task_by_index(curr_id);

                //todo send ipc_message to supervisor
            }
        }
        panic_screen(format!("UNHANDLED PROCESSOR EXCEPTION!\n SPECIFIC ERROR:\n{}", frame).as_str(), false);
    }

    if SCHEDULING_STARTED.get().is_some() {
        if let Some((_binding_task_id, port, key)) = IDT_TRANSFER_MANAGER.get_irq(vec as u8) {
            let action = port.notify(PortPacket {
                key,
                event: PortEvent::IrqFired(vec as u8),
            });
            match action {
                PortAction::Wake { task_id } => {
                    if let Some(task) = get_thread(task_id) {
                        wake_thread(task.tid);
                    }
                }
                PortAction::Continue => {}
                PortAction::Block { .. } => {}
            }
            return;
        }
    }

    //TODO: ACK unhandled irq & mask it.
    early_println!("Unhandled irq interrupt! Code: {}. Ack & Mask", vec);
    PercpuLapic::get().lapic.eoi();
    if let Err(e) = ioapic_manager().mask_by_vector(vec as u8) {
        early_println!("Failed to mask vector {}: {:?}", vec, e);
    }
}