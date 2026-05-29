use core::{cell::UnsafeCell, sync::atomic::AtomicU64};

use alloc::{boxed::Box, string::String, sync::{Arc, Weak}, vec::Vec};
use atomic_enum::atomic_enum;
use spin::{Mutex, RwLock};
use crate::{arch::amd64::{capability_sys::cnode::CNode, gdt::IO_PORTS, scheduler::{addr_space::AddrSpace, stack::KernelStack}}, isolation::domain::Domain};

pub type Pid = u32;
pub type Tid = u32;

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
}

pub struct Process {
    pub pid: Pid,
    pub name: String,
    pub threads: Mutex<Vec<Weak<Thread>>>,
    pub addr_space: Mutex<AddrSpace>,
    pub cnode: CNode,
    pub iopb_permissions: Mutex<Option<Box<[u8; IO_PORTS]>>>,
    pub iopb_gen: AtomicU64,
    pub domain: Arc<Domain>
}

unsafe impl Send for Thread {}
unsafe impl Sync for Thread {}

#[derive(Debug, Default)]
#[repr(C)]
#[allow(dead_code)]
pub struct ThreadRegisters {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,

    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,

    pub syscall_number_or_irq_or_error_code: u64,

    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

