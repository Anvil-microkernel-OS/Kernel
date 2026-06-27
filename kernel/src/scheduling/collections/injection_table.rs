use alloc::{collections::vec_deque::VecDeque, sync::Arc};
use spin::{Mutex, Once};

use crate::scheduling::primitives::thread::Thread;

pub struct InjectionTable {
    inner: Mutex<VecDeque<Arc<Thread>>>,
}

impl InjectionTable {
    pub const fn new() -> Self {
        Self { inner: Mutex::new(VecDeque::new()) }
    }

    pub fn push(&self, thread: Arc<Thread>) {
        self.inner.lock().push_back(thread);
    }

    pub fn pop(&self) -> Option<Arc<Thread>> {
        self.inner.lock().pop_front()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }

    pub fn steal_into(&self, buf: &mut [Option<Arc<Thread>>]) -> usize {
        let mut q = self.inner.lock();
        let mut count = 0;
        while count < buf.len() {
            match q.pop_front() {
                Some(t) => { buf[count] = Some(t); count += 1; }
                None    => break,
            }
        }
        count
    }
}

static INJECTION_TABLE: Once<InjectionTable>  = Once::new();

#[inline] pub fn injection_table()   -> &'static InjectionTable { INJECTION_TABLE.get().expect("global run queue not initialized") }

pub fn init_injection_table() {
    INJECTION_TABLE.call_once(InjectionTable::new);
}
