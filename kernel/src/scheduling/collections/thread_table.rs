use alloc::{collections::btree_map::BTreeMap, sync::Arc};
use spin::{Mutex, Once};

use crate::scheduling::primitives::thread::{Thread, Tid};

pub struct ThreadTable {
    pub inner: Mutex<BTreeMap<Tid, Arc<Thread>>>,
}

impl ThreadTable {
    pub fn new() -> Self {
        Self { inner: Mutex::new(BTreeMap::new()) }
    }

    pub fn insert(&self, thread: Arc<Thread>) {
        self.inner.lock().insert(thread.tid, thread);
    }

    pub fn get(&self, tid: Tid) -> Option<Arc<Thread>> {
        self.inner.lock().get(&tid).cloned()
    }

    pub fn remove(&self, tid: Tid) -> Option<Arc<Thread>> {
        self.inner.lock().remove(&tid)
    }

    pub fn for_each<F: FnMut(&Arc<Thread>)>(&self, mut f: F) {
        for thread in self.inner.lock().values() {
            f(thread);
        }
    }
}

static THREAD_TABLE: Once<ThreadTable> = Once::new();

#[inline] pub fn thread_table() -> &'static ThreadTable { THREAD_TABLE.get().expect("thread table not initialized") }

pub fn init_thread_table() {
    THREAD_TABLE.call_once(ThreadTable::new);
}