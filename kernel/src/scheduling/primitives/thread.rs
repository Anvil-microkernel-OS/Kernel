use core::{cell::UnsafeCell, sync::atomic::{AtomicI32, AtomicU64, Ordering}};

use alloc::sync::Weak;
use atomic_enum::atomic_enum;
use spin::RwLock;

use crate::{arch::sched_data::ThreadRegisters, scheduling::primitives::{kernel_stack::KernelStack, process::Process}};

pub type Tid = u32;
pub struct RunsOnCpuId(AtomicI32);

impl RunsOnCpuId {
    pub fn new_undefined() -> Self {
        RunsOnCpuId(AtomicI32::new(-1))
    }

    pub fn set_new_runner(&self, id: i32) {
        self.0.store(id, Ordering::Release);
    }

    pub fn runs_on(&self) -> i32 {
        self.0.load(Ordering::Acquire)
    }
}

#[derive(PartialEq)]
#[atomic_enum]
#[repr(u8)]
pub enum ThreadState {
    Running = 0,
    Ready = 1,
    Exiting = 2,
    Sleep = 3,
    Configuring = 4,
}

pub struct Thread {
    pub parent_proc: RwLock<Weak<Process>>,
    pub tid: Tid,
    pub wake_at_tick: AtomicU64,
    pub kernel_stack: KernelStack,
    pub registers: UnsafeCell<ThreadRegisters>,
    pub state: AtomicThreadState,
    pub runs_on: RunsOnCpuId
}

unsafe impl Send for Thread {}
unsafe impl Sync for Thread {}
