use core::sync::atomic::AtomicU64;

use alloc::{string::String, sync::Weak, vec::Vec};
use spin::Mutex;

use crate::scheduling::primitives::thread::Thread;

pub type Pid = u32;

pub struct Process {
    pub pid: Pid,
    pub name: String,
    pub threads: Mutex<Vec<Weak<Thread>>>,
   // pub addr_space: Mutex<AddrSpace>,
    //pub cnode: CNode,
    //pub iopb_permissions: Mutex<Option<Box<[u8; IO_PORTS]>>>,
   // pub iopb_gen: AtomicU64,
    //pub domain: Arc<Domain>
}