use core::sync::atomic::Ordering;

use alloc::sync::Arc;

use crate::scheduling::{collections::{injection_table::{init_injection_table, injection_table}, process_table::{init_process_table, process_table}, thread_table::{init_thread_table, thread_table}}, primitives::{process::{Pid, Process}, thread::{Thread, ThreadState, Tid}}};

pub mod core_local_queue;
pub mod process_table;
pub mod thread_table;
pub mod injection_table;

pub fn wake_thread(tid: Tid) {
    if let Some(thread) = thread_table().get(tid) {
        thread.state.store(ThreadState::Ready, Ordering::Release);
        injection_table().push(thread);
    }
}

pub fn spawn_thread(thread: Arc<Thread>) -> Tid {
    let tid = thread.tid;
    injection_table().push(thread);
    tid
}

pub fn register_process(process: Arc<Process>) -> Pid {
    let pid = process.pid;
    process_table().insert(process);
    pid
}

pub fn register_thread(thread: &Arc<Thread>) {
    thread_table().insert(thread.clone());
}

pub fn initialize_scheduler_collections() {
    init_process_table();
    init_thread_table();
    init_injection_table();
}