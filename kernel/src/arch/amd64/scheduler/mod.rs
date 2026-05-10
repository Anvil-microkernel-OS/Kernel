use core::{arch::naked_asm, cell::UnsafeCell, ptr::addr_of, sync::atomic::{AtomicU64, Ordering}};
use alloc::{sync::Arc, vec::Vec};
use spin::Once;
use x86_64::{VirtAddr, instructions::hlt};

pub mod task;
mod stack;
mod cpu_local;
pub mod exec_loader;
pub mod addr_space;
pub mod task_storage;
pub mod syscall;

use crate::{
    arch::amd64::{
        acpi::{get_acpi_tables, madt::MadTable},
        apic::{PercpuLapic, start_timer},
        gdt::{set_tss_iopb_enabled, set_tss_rsp0, tss_copy_iopb_data},
        scheduler::{
            cpu_local::ExecCpu,
            exec_loader::make_kernel_task,
            syscall::{init_syscall_subsystem, set_per_cpu_TOP_OF_KERNEL_STACK},
            task::{Pid, Process, Thread, ThreadState, Tid},
            task_storage::{
                get_thread, initialize_task_storage, steal_from_global,
                thread_table, wake_thread,
            },
        },
    }, define_per_cpu_struct, early_println, irq
};

static CPU_NUM:    AtomicU64 = AtomicU64::new(0);
static TICK_COUNT: AtomicU64 = AtomicU64::new(0);

struct CpuDescriptorStorage {
    cpus: Vec<UnsafeCell<ExecCpu>>,
    idle_processes: Vec<Arc<Process>>
}

unsafe impl Sync for CpuDescriptorStorage {}

impl CpuDescriptorStorage {
    pub fn new(n_cpus: usize) -> Self {
        initialize_task_storage();
        let mut cpus = Vec::with_capacity(n_cpus);
        let mut idle_processes = Vec::with_capacity(n_cpus);
        
        for cpu_id in 0..n_cpus {
            let (proc, thread) = make_kernel_task(
                cpu_id as Pid, cpu_id as Tid, "idle", idle_task as u64);
            idle_processes.push(proc);
            cpus.push(UnsafeCell::new(ExecCpu::new(thread)));
        }
        
        Self { cpus, idle_processes }
    }

    pub fn cpu(&self, cpu: usize) -> &ExecCpu {
        unsafe { &*self.cpus[cpu].get() }
    }

    pub fn cpu_mut(&self, cpu: usize) -> &mut ExecCpu {
        unsafe { &mut *self.cpus[cpu].get() }
    }

    pub fn try_to_steal_into(&self, me: usize, buf: &mut [Option<Arc<Thread>>]) -> usize {
        let mut count = 0;
        let steal_batch = 1; 

        for (idx, cpu_cell) in self.cpus.iter().enumerate() {
            if idx == me { continue; }
            let cpu = unsafe { &*cpu_cell.get() };
            if cpu.tasks.len() < buf.len() { continue; }

            let tasks = cpu.tasks.steal_n(steal_batch);
            for task in tasks {
                if count >= buf.len() { return count; }
                buf[count] = Some(task);
                count += 1;
            }
        }
        count
    }
}

static CPU_DESCRIPTORS:     Once<CpuDescriptorStorage> = Once::new();
pub static SCHEDULING_STARTED: Once<bool>              = Once::new();

define_per_cpu_struct! {
    pub(super) struct PerCpuSchedulerData {
        cpu_id:          usize,
        pub curr_thread_id: Tid,
        in_rescheduling: bool,
        descriptors:     &'static CpuDescriptorStorage,
        iopb_generation: usize,
        iopb_owner:      Option<Pid>,
    }
}

pub fn global_init_scheduler() {
    let cpu_count = get_acpi_tables()
        .read()
        .get_table::<MadTable>()
        .expect("Unable to get cpu_count from MADT")
        .cpus.len();

    CPU_DESCRIPTORS.call_once(|| CpuDescriptorStorage::new(cpu_count));
}

pub fn init_scheduler_percpu() -> ! {
    let cpu_id = CPU_NUM.fetch_add(1, Ordering::Relaxed) as usize;
    let descriptors = CPU_DESCRIPTORS.get().expect("CPU_DESCRIPTORS not initialized");

    PerCpuSchedulerData::with_guard(|data| {
        data.cpu_id          = cpu_id;
        data.curr_thread_id  = descriptors.cpu(cpu_id).idle_task.tid;
        data.in_rescheduling = false;
        data.descriptors     = CPU_DESCRIPTORS.get().unwrap();
        data.iopb_generation = 0;
        data.iopb_owner      = None;
    });

    init_syscall_subsystem();
    start_timer(&PercpuLapic::get().lapic);

    let my_desc  = descriptors.cpu(cpu_id);
    let dummy_rsp: u64 = 0;
    let idle_rsp  = unsafe { (*my_desc.idle_task.registers.get()).rsp };
    let idle_cr3 = unsafe { thread_cr3(my_desc.idle_task_ptr()) };

    SCHEDULING_STARTED.call_once(|| true);
    unsafe {
        switch_to_task(addr_of!(dummy_rsp), idle_rsp, idle_cr3);
    }

    unreachable!();
}

unsafe fn thread_cr3(thread: *const Thread) -> u64 {
    let proc = unsafe {
        (*thread).parent_proc.read().upgrade().expect("thread has no live process")
    };
    proc.addr_space.lock().get_page_table_phys().as_u64()
}

unsafe fn apply_iopb(thread: *const Thread) {
    let proc = unsafe {
        (*thread).parent_proc.read().upgrade().expect("thread has no live process")
    };
    let perms = proc.iopb_permissions.lock();
    match &*perms {
        Some(permissions) => {
            let cpu = PerCpuSchedulerData::get_mut();
            let _gen = proc.iopb_gen.load(Ordering::Acquire) as usize;
            if _gen != cpu.iopb_generation || cpu.iopb_owner != Some(proc.pid) {
                tss_copy_iopb_data(permissions.as_ref());
                set_tss_iopb_enabled(true);
                cpu.iopb_generation = _gen;
                cpu.iopb_owner      = Some(proc.pid);
            }
        }
        None => {
            set_tss_iopb_enabled(false);
            PerCpuSchedulerData::get_mut().iopb_owner = None;
        }
    }
}

pub fn block_current_task() {
    let my_id    = PerCpuSchedulerData::get().cpu_id;
    let my_desc  = PerCpuSchedulerData::get().descriptors.cpu_mut(my_id);
    let curr_ptr = my_desc.get_curr_task();

    if curr_ptr.is_null() {
        panic!("block_current_task: no current task");
    }

    unsafe {
        (*curr_ptr).state.store(ThreadState::Sleep, Ordering::Relaxed);
        let task_rsp_ptr = addr_of!((*(*curr_ptr).registers.get()).rsp);

        my_desc.set_curr_task(core::ptr::null_mut());
        PerCpuSchedulerData::get_mut().curr_thread_id = my_desc.idle_task.tid;

        let idle_rsp = (*my_desc.idle_task.registers.get()).rsp;
        let idle_cr3 = thread_cr3(my_desc.idle_task_ptr());

        switch_to_task(task_rsp_ptr, idle_rsp, idle_cr3);
    }
}

pub fn block_thread(thread: Arc<Thread>) {
    thread.state.store(ThreadState::Sleep, Ordering::Relaxed);
}

pub fn sleep(ns: u64) {
    let ticks = (ns + 999_999) / 1_000_000;
    if ticks == 0 { return; }

    let my_id    = PerCpuSchedulerData::get().cpu_id;
    let my_desc  = PerCpuSchedulerData::get().descriptors.cpu_mut(my_id);
    let curr_ptr = my_desc.get_curr_task();

    let wake_at = TICK_COUNT.load(Ordering::Relaxed) + ticks;

    unsafe {
        (*curr_ptr).wake_at_tick.store(wake_at, Ordering::Relaxed);
        (*curr_ptr).state.store(ThreadState::Sleep, Ordering::Release);

        let task_rsp_ptr = addr_of!((*(*curr_ptr).registers.get()).rsp);
        my_desc.set_curr_task(core::ptr::null_mut());
        PerCpuSchedulerData::get_mut().curr_thread_id = my_desc.idle_task.tid;

        let idle_rsp = (*my_desc.idle_task.registers.get()).rsp;
        let idle_cr3 = thread_cr3(my_desc.idle_task_ptr());

        switch_to_task(task_rsp_ptr, idle_rsp, idle_cr3);
    }
}

fn wake_sleeping_tasks() {
    if PerCpuSchedulerData::get().cpu_id != 0 { return; }

    let now = TICK_COUNT.load(Ordering::Relaxed);

    let to_wake: Vec<Tid> = {
        let tasks = thread_table().inner.lock();
        tasks.values()
            .filter(|t| {
                matches!(t.state.load(Ordering::Acquire), ThreadState::Sleep)
                    && { let w = t.wake_at_tick.load(Ordering::Acquire); w != 0 && now >= w }
            })
            .map(|t| t.tid)
            .collect()
    };

    for tid in to_wake {
        if let Some(thread) = get_thread(tid) {
            thread.wake_at_tick.store(0, Ordering::Release);
            wake_thread(thread.tid);
        }
    }
}

extern "C" fn idle_task() -> ! {
    loop {
        PerCpuSchedulerData::with_guard(|data| { data.in_rescheduling = true; });

        const STEAL_BATCH: usize = 4;
        let mut global_buf: [Option<Arc<Thread>>; STEAL_BATCH] = [None, None, None, None];
        let mut steal_buf:  [Option<Arc<Thread>>; STEAL_BATCH] = [None, None, None, None];

        let my_descr = PerCpuSchedulerData::get_mut().descriptors;
        let my_id    = PerCpuSchedulerData::get().cpu_id;
        let my_cpu   = my_descr.cpu_mut(my_id);

        let n = my_descr.try_to_steal_into(my_id, &mut steal_buf);
        if n > 0 {
            for slot in steal_buf[..n].iter_mut() {
                if let Some(task) = slot.take() { my_cpu.tasks.push(task); }
            }
        } else {
            let n = steal_from_global(&mut global_buf);
            for slot in global_buf[..n].iter_mut() {
                if let Some(task) = slot.take() { my_cpu.tasks.push(task); }
            }
        }

        PerCpuSchedulerData::with_guard(|data| { data.in_rescheduling = false; });

        hlt();
    }
}

fn process_tick() {
    if PerCpuSchedulerData::get().in_rescheduling { return; }

    let my_id    = PerCpuSchedulerData::get().cpu_id;
    let my_desc  = PerCpuSchedulerData::get().descriptors.cpu_mut(my_id);
    let curr_ptr = my_desc.get_curr_task();
    let next_task = my_desc.tasks.pop();

    match (curr_ptr.is_null(), next_task) {
        (true, None) => {}

        (false, None) => {}

        (true, Some(next)) => {
            let next_ptr = Arc::into_raw(next) as *mut Thread;
            unsafe {
                (*next_ptr).state.store(ThreadState::Running, Ordering::Release);
                my_desc.set_curr_task(next_ptr);
                PerCpuSchedulerData::get_mut().curr_thread_id = (*next_ptr).tid;

                set_per_cpu_TOP_OF_KERNEL_STACK((*next_ptr).kernel_stack.top.as_u64());
                set_tss_rsp0(VirtAddr::new((*next_ptr).kernel_stack.top.as_u64()));

                let idle_rsp_ptr = addr_of!((*my_desc.idle_task.registers.get()).rsp);
                let next_rsp     = (*(*next_ptr).registers.get()).rsp;
                let next_cr3     = thread_cr3(next_ptr);

                apply_iopb(next_ptr);

                switch_to_task(idle_rsp_ptr, next_rsp, next_cr3);
            }
        }

        (false, Some(next)) => {
            let next_ptr = Arc::into_raw(next) as *mut Thread;
            unsafe {
                let task_rsp_ptr = addr_of!((*(*curr_ptr).registers.get()).rsp);

                (*curr_ptr).state.store(ThreadState::Ready, Ordering::Release);
                let curr_arc = Arc::from_raw(curr_ptr);
                my_desc.tasks.push(curr_arc);

                (*next_ptr).state.store(ThreadState::Running, Ordering::Release);
                my_desc.set_curr_task(next_ptr);
                PerCpuSchedulerData::get_mut().curr_thread_id = (*next_ptr).tid;

                set_per_cpu_TOP_OF_KERNEL_STACK((*next_ptr).kernel_stack.top.as_u64());
                set_tss_rsp0(VirtAddr::new((*next_ptr).kernel_stack.top.as_u64()));

                let next_rsp = (*(*next_ptr).registers.get()).rsp;
                let next_cr3 = thread_cr3(next_ptr);

                apply_iopb(next_ptr);

                switch_to_task(task_rsp_ptr, next_rsp, next_cr3);
            }
        }
    }
}

#[unsafe(naked)]
pub(super) unsafe extern "C" fn switch_to_task(
    previous_task_stack_pointer: *const u64,
    next_task_stack_pointer: u64,
    next_page_table: u64,
) {
    naked_asm!(
        "push rax", "push rbx", "push rcx", "push rdx",
        "push rbp", "push rsi", "push rdi",
        "push r8",  "push r9",  "push r10", "push r11",
        "push r12", "push r13", "push r14", "push r15",
        "mov [rdi], rsp",
        "mov rsp, rsi",
        "mov cr3, rdx",
        "pop r15", "pop r14", "pop r13", "pop r12",
        "pop r11", "pop r10", "pop r9",  "pop r8",
        "pop rdi", "pop rsi", "pop rbp", "pop rdx",
        "pop rcx", "pop rbx", "pop rax",
        "ret",
    );
}

irq!(0x30, scheduler_tick_irq, |_stack| {
    TICK_COUNT.fetch_add(1, Ordering::Relaxed);
    PercpuLapic::get().lapic.eoi();
    wake_sleeping_tasks();
    process_tick();
});