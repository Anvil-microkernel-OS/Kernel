use core::{cell::UnsafeCell, cmp::min, ptr::addr_of_mut, sync::atomic::{AtomicU64, Ordering}};

use alloc::{sync::Arc, vec::Vec};
use spin::Once;

use crate::{arch::{CurrentMemArchSpec, interrupt::halt, sched_data::switch_to_task, timer::TIMER_CALIBRATION_OFFSET_10MS}, define_per_cpu_struct, define_per_cpu_u64, memory::misc::primitives::TableKind, scheduling::{collections::{core_local_queue::ExecCpu, initialize_scheduler_collections, injection_table::injection_table}, primitives::{process::{Pid, Process}, thread::{Thread, Tid}}, task_loader::make_kernel_task}, timer::enable_platform_timer};

static CPU_NUM:    AtomicU64 = AtomicU64::new(0);
static TICK_COUNT: AtomicU64 = AtomicU64::new(0);

struct CpuDescriptorStorage {
    cpus: Vec<UnsafeCell<ExecCpu>>,
    kernel_processes: Vec<Arc<Process>>
}

unsafe impl Sync for CpuDescriptorStorage {}

impl CpuDescriptorStorage {
    pub fn new(n_cpus: usize) -> Self {
        initialize_scheduler_collections();
        let mut cpus = Vec::with_capacity(n_cpus);
        let mut kernel_processes = Vec::with_capacity(n_cpus);

        for cpu_id in 0..n_cpus {
            let (idle_proc, idle_thread) = make_kernel_task(
                cpu_id as Pid, cpu_id as Tid, "idle", idle_task as usize as u64);

            kernel_processes.push(idle_proc);
            cpus.push(UnsafeCell::new(ExecCpu::new(idle_thread)));
        }

        Self { cpus, kernel_processes }
    }

    pub fn cpu_count(&self) -> usize {
        self.cpus.len()
    }

    pub fn kernel_process(&self, cpu: usize) -> &Arc<Process> {
        &self.kernel_processes[cpu]
    }

    pub fn cpu(&self, cpu: usize) -> &ExecCpu {
        unsafe { &*self.cpus[cpu].get() }
    }

    pub unsafe fn cpu_mut(&self, cpu: usize) -> &mut ExecCpu {
        unsafe { &mut *self.cpus[cpu].get() }
    }

    pub fn try_to_steal_into(&self, me: usize, buf: &mut [Option<Arc<Thread>>], steal_batch: usize) -> usize {
        let mut count = 0;
        if buf.is_empty() || steal_batch == 0 { return 0; }

        let my_len = self.cpu(me).tasks.len();

        for (idx, cpu_cell) in self.cpus.iter().enumerate() {
            if idx == me { continue; }
            if count >= buf.len() { break; }

            let cpu = unsafe { &*cpu_cell.get() };
            if cpu.tasks.len() <= my_len + 1 { continue; }

            let take = min(steal_batch, buf.len() - count);
            let tasks = cpu.tasks.steal_n(take);
            for task in tasks {
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
    pub(super) struct PERCPU_SCHEDULER_DAT {
        cpu_id:          usize,
        pub curr_thread_id: Tid,
        in_rescheduling: bool,
        descriptors:     &'static CpuDescriptorStorage,
        iopb_generation: usize,
        iopb_owner:      Option<Pid>,
    }
}

define_per_cpu_u64!(
    pub(super) TOP_OF_KERNEL_STACK
);

define_per_cpu_u64!(
    pub(super) USER_STACK_SCRATCH
);

pub fn initialize_cpu_descr_storages(cpu_count: usize) {
    CPU_DESCRIPTORS.call_once(|| CpuDescriptorStorage::new(cpu_count));
}

pub fn init_scheduler_percpu() -> ! {
    let descriptors = CPU_DESCRIPTORS.get().expect("CPU_DESCRIPTORS not initialized");
    let cpu_id = CPU_NUM.fetch_add(1, Ordering::AcqRel) as usize;
    assert!(cpu_id < descriptors.cpu_count(), "more CPUs started than descriptors allocated");

    PERCPU_SCHEDULER_DAT::with_guard(|data| {
        data.cpu_id          = cpu_id;
        data.curr_thread_id  = descriptors.cpu(cpu_id).idle_task.tid;
        data.in_rescheduling = false;
        data.descriptors     = descriptors;
        data.iopb_generation = 0;
        data.iopb_owner      = None;
    });

    //init_syscall_subsystem();

    let my_desc  = descriptors.cpu(cpu_id);
    let mut dummy_rsp: u64 = 0;
    let idle_rsp  = unsafe { (*my_desc.idle_task.registers.get()).get_stack_ptr() };
    let idle_cr3 = CurrentMemArchSpec::table(TableKind::Kernel).as_usize() as u64;

    SCHEDULING_STARTED.call_once(|| true);
    unsafe {
        switch_to_task(addr_of_mut!(dummy_rsp), idle_rsp, idle_cr3);
    }

    unreachable!();
}

extern "C" fn idle_task() -> ! {
    enable_platform_timer(TIMER_CALIBRATION_OFFSET_10MS.get().unwrap() / 10);

    loop {
        //serial_println!("Hello from idle task!");
        PERCPU_SCHEDULER_DAT::with_guard(|data| { data.in_rescheduling = true; });

        const STEAL_BATCH: usize = 4;
        let mut global_buf: [Option<Arc<Thread>>; STEAL_BATCH] = [None, None, None, None];
        let mut steal_buf:  [Option<Arc<Thread>>; STEAL_BATCH] = [None, None, None, None];

        let my_descr = PERCPU_SCHEDULER_DAT::get().descriptors;
        let my_id    = PERCPU_SCHEDULER_DAT::get().cpu_id;

        let stolen = my_descr.try_to_steal_into(my_id, &mut steal_buf, STEAL_BATCH);
        let taken = if stolen > 0 {
            let my_cpu = unsafe { my_descr.cpu_mut(my_id) };
            for slot in steal_buf[..stolen].iter_mut() {
                if let Some(task) = slot.take() { my_cpu.tasks.push(task); }
            }
            stolen
        } else {
            let n = injection_table().steal_into(&mut global_buf);
            let my_cpu = unsafe { my_descr.cpu_mut(my_id) };
            for slot in global_buf[..n].iter_mut() {
                if let Some(task) = slot.take() { my_cpu.tasks.push(task); }
            }
            n
        };

        PERCPU_SCHEDULER_DAT::with_guard(|data| { data.in_rescheduling = false; });

        if taken == 0 {
            halt();
        }
    }
}

/*
pub fn process_scheduler_tick() {
    if PERCPU_SCHEDULER_DAT::get().in_rescheduling { return; }

    let my_id    = PERCPU_SCHEDULER_DAT::get().cpu_id;
    let my_desc  = PERCPU_SCHEDULER_DAT::get().descriptors.cpu_mut(my_id);
    let curr_ptr = my_desc.get_curr_task();
    let next_task = my_desc.tasks.pop();

    match (curr_ptr.is_null(), next_task) {
        (true, None) => {}

        (false, None) => {}

        (true, Some(next)) => {
            let next_ptr = Arc::into_raw(next) as *mut Thread;
            unsafe {
                (*next_ptr).runs_on.set_new_runner(my_id as i32);

                (*next_ptr).state.store(ThreadState::Running, Ordering::Release);
                my_desc.set_curr_task(next_ptr);
                PERCPU_SCHEDULER_DAT::get_mut().curr_thread_id = (*next_ptr).tid;

                set_per_cpu_TOP_OF_KERNEL_STACK((*next_ptr).kernel_stack.top.as_usize() as u64);
                //set_tss_rsp0(VirtAddr::new((*next_ptr).kernel_stack.top.as_u64()));

                let idle_rsp_ptr = addr_of!((*my_desc.idle_task.registers.get()).rsp);
                let next_rsp     = (*(*next_ptr).registers.get()).rsp;
                let next_cr3     = thread_cr3(next_ptr);

                // apply_iopb(next_ptr);

                switch_to_task(idle_rsp_ptr, next_rsp, next_cr3);
            }
        }

        (false, Some(next)) => {
            let next_ptr = Arc::into_raw(next) as *mut Thread;
            unsafe {
                let task_rsp_ptr = addr_of!((*(*curr_ptr).registers.get()).rsp);

                (*curr_ptr).runs_on.set_new_runner(UNDEFINED_APIC_RUNNER_ID);
                (*next_ptr).runs_on.set_new_runner(my_id as i32);

                (*curr_ptr).state.store(ThreadState::Ready, Ordering::Release);
                let curr_arc = Arc::from_raw(curr_ptr);
                my_desc.tasks.push(curr_arc);

                (*next_ptr).state.store(ThreadState::Running, Ordering::Release);
                my_desc.set_curr_task(next_ptr);
                PERCPU_SCHEDULER_DAT::get_mut().curr_thread_id = (*next_ptr).tid;

                set_per_cpu_TOP_OF_KERNEL_STACK((*next_ptr).kernel_stack.top.as_usize() as u64);
                set_tss_rsp0(VirtAddr::new((*next_ptr).kernel_stack.top.as_usize()));

                let next_rsp = (*(*next_ptr).registers.get()).rsp;
                let next_cr3 = thread_cr3(next_ptr);

                //apply_iopb(next_ptr);

                switch_to_task(task_rsp_ptr, next_rsp, next_cr3);
            }
        }
    }
}*/
