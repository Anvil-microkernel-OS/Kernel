use core::{cell::UnsafeCell, ptr::addr_of, sync::atomic::{AtomicU64, Ordering}};

use alloc::{sync::Arc, vec::Vec};
use spin::Once;

use crate::{arch::{CurrentMemArchSpec, interrupt::halt, sched_data::switch_to_task, timer::TIMER_CALIBRATION_OFFSET_10MS}, define_per_cpu_struct, memory::misc::{arch_specific::Arch, primitives::TableKind}, scheduling::{collections::{core_local_queue::ExecCpu, initialize_scheduler_collections, injection_table::injection_table}, primitives::{process::{Pid, Process}, thread::{Thread, Tid}}, task_loader::make_kernel_task}, serial_println, timer::enable_platform_timer};

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
                cpu_id as Pid, cpu_id as Tid, "idle", idle_task as u64);
                
            kernel_processes.push(idle_proc);
            cpus.push(UnsafeCell::new(ExecCpu::new(idle_thread)));
        }
        
        Self { cpus, kernel_processes }
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
    pub(super) struct PERCPU_SCHEDULER_DAT {
        cpu_id:          usize,
        pub curr_thread_id: Tid,
        in_rescheduling: bool,
        descriptors:     &'static CpuDescriptorStorage,
        iopb_generation: usize,
        iopb_owner:      Option<Pid>,
    }
}

pub fn initialize_cpu_descr_storages(cpu_count: usize) {
    CPU_DESCRIPTORS.call_once(|| CpuDescriptorStorage::new(cpu_count));
}

pub fn init_scheduler_percpu() -> ! {
    let cpu_id = CPU_NUM.fetch_add(1, Ordering::Relaxed) as usize;
    let descriptors = CPU_DESCRIPTORS.get().expect("CPU_DESCRIPTORS not initialized");

    PERCPU_SCHEDULER_DAT::with_guard(|data| {
        data.cpu_id          = cpu_id;
        data.curr_thread_id  = descriptors.cpu(cpu_id).idle_task.tid;
        data.in_rescheduling = false;
        data.descriptors     = CPU_DESCRIPTORS.get().unwrap();
        data.iopb_generation = 0;
        data.iopb_owner      = None;
    });

    //init_syscall_subsystem();
    enable_platform_timer(TIMER_CALIBRATION_OFFSET_10MS.get().unwrap() / 10);

    let my_desc  = descriptors.cpu(cpu_id);
    let dummy_rsp: u64 = 0;
    let idle_rsp  = unsafe { (*my_desc.idle_task.registers.get()).get_stack_ptr() };
    let idle_cr3 = CurrentMemArchSpec::table(TableKind::Kernel).as_usize() as u64;

    SCHEDULING_STARTED.call_once(|| true);
    unsafe {
        switch_to_task(addr_of!(dummy_rsp), idle_rsp, idle_cr3);
    }

    unreachable!();
}

extern "C" fn idle_task() -> ! {
    loop {
        serial_println!("Hello from idle task!");
        PERCPU_SCHEDULER_DAT::with_guard(|data| { data.in_rescheduling = true; });

        const STEAL_BATCH: usize = 4;
        let mut global_buf: [Option<Arc<Thread>>; STEAL_BATCH] = [None, None, None, None];
        let mut steal_buf:  [Option<Arc<Thread>>; STEAL_BATCH] = [None, None, None, None];

        let my_descr = PERCPU_SCHEDULER_DAT::get_mut().descriptors;
        let my_id    = PERCPU_SCHEDULER_DAT::get().cpu_id;
        let my_cpu   = my_descr.cpu_mut(my_id);

        let n = my_descr.try_to_steal_into(my_id, &mut steal_buf);
        if n > 0 {
            for slot in steal_buf[..n].iter_mut() {
                if let Some(task) = slot.take() { my_cpu.tasks.push(task); }
            }
        } else {
            let n = injection_table().steal_into(&mut global_buf);
            for slot in global_buf[..n].iter_mut() {
                if let Some(task) = slot.take() { my_cpu.tasks.push(task); }
            }
        }

        PERCPU_SCHEDULER_DAT::with_guard(|data| { data.in_rescheduling = false; });

        halt();
    }
}