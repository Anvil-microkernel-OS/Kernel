use core::{cell::UnsafeCell, sync::atomic::AtomicU64};

use alloc::{string::String, sync::Arc};
use spin::{Mutex, RwLock};

use crate::{arch::{interrupt, sched_data::ThreadRegisters}, scheduling::primitives::{kernel_stack::{DEFAULT_KERNEL_STACK_SIZE, allocate_kernel_stack}, process::{Pid, Process}, thread::{AtomicThreadState, RunsOnCpuId, Thread, ThreadState, Tid}}};

pub fn make_kernel_task(pid: Pid, tid: Tid, name: &'static str, entry_point: u64) -> (Arc<Process>, Thread) {
    let kernel_stack  = allocate_kernel_stack(DEFAULT_KERNEL_STACK_SIZE);
    let stack_top_ptr = kernel_stack.top.as_usize() as *mut u64;
    unsafe {
        stack_top_ptr.sub(1).write(kernel_task_trampoline as u64);
        for i in 2..=16 { stack_top_ptr.sub(i).write(0); }
        stack_top_ptr.sub(8).write(entry_point);
    }
    let initial_rsp = unsafe { stack_top_ptr.sub(16) } as u64;

    let process = Arc::new(Process {
        pid,
        name: String::from(name),
        threads:          Mutex::new(alloc::vec![]),
       // addr_space:       Mutex::new(AddrSpace::new(page_table)),
      //  cnode:            CNode::new(),
      //  iopb_permissions: Mutex::new(None),
      //  iopb_gen:         AtomicU64::new(0),
       // domain: root_domain().clone()
    });

    let thread = Thread {
        parent_proc:  RwLock::new(Arc::downgrade(&process)),
        tid,
        wake_at_tick: AtomicU64::new(0),
        kernel_stack,
        registers:    UnsafeCell::new(ThreadRegisters {
            rsp: initial_rsp,
            ..ThreadRegisters::default()
        }),
        state: AtomicThreadState::new(ThreadState::Ready),
        runs_on: RunsOnCpuId::new_undefined()
    };

    (process, thread)
}

extern "C" fn kernel_task_trampoline(entry: u64) -> ! {
    unsafe {
        interrupt::enable_and_nop();
        let func: extern "C" fn() -> ! = core::mem::transmute(entry);
        func();
    }
}