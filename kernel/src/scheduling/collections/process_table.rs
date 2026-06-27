use alloc::{collections::btree_map::BTreeMap, sync::Arc};
use spin::{Mutex, Once};

use crate::scheduling::primitives::process::{Pid, Process};

pub struct ProcessTable {
    inner: Mutex<BTreeMap<Pid, Arc<Process>>>,
}

impl ProcessTable {
    pub fn new() -> Self {
        Self { inner: Mutex::new(BTreeMap::new()) }
    }

    pub fn insert(&self, process: Arc<Process>) {
        self.inner.lock().insert(process.pid, process);
    }

    pub fn get(&self, pid: Pid) -> Option<Arc<Process>> {
        self.inner.lock().get(&pid).cloned()
    }

    pub fn remove(&self, pid: Pid) -> Option<Arc<Process>> {
        self.inner.lock().remove(&pid)
    }

    pub fn for_each<F: FnMut(&Arc<Process>)>(&self, mut f: F) {
        for proc in self.inner.lock().values() {
            f(proc);
        }
    }
}

static PROCESS_TABLE: Once<ProcessTable> = Once::new();

#[inline] pub fn process_table() -> &'static ProcessTable { PROCESS_TABLE.get().expect("process table not initialized") }

#[inline]
pub fn init_process_table() {
    PROCESS_TABLE.call_once(ProcessTable::new);
}