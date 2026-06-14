use core::sync::atomic::Ordering;

use alloc::{collections::{VecDeque, btree_map::BTreeMap}, sync::Arc};
use spin::{Mutex, Once};
use crate::arch::amd64::scheduler::task::{Pid, Process, Thread, ThreadState, Tid};

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

pub struct DeadQueue {
    inner: Mutex<BTreeMap<Tid, Arc<Thread>>>,
}

impl DeadQueue {
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

pub struct GlobalRunQueue {
    inner: Mutex<VecDeque<Arc<Thread>>>,
}

impl GlobalRunQueue {
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

static PROCESS_TABLE:    Once<ProcessTable>    = Once::new();
static THREAD_TABLE:     Once<ThreadTable>     = Once::new();
static GLOBAL_RUN_QUEUE: Once<GlobalRunQueue>  = Once::new();
static DEAD_QUEUE: Once<DeadQueue>        = Once::new();

#[inline] pub fn process_table()  -> &'static ProcessTable   { PROCESS_TABLE.get().expect("process table not initialized") }
#[inline] pub fn thread_table()   -> &'static ThreadTable    { THREAD_TABLE.get().expect("thread table not initialized") }
#[inline] pub fn global_queue()   -> &'static GlobalRunQueue { GLOBAL_RUN_QUEUE.get().expect("global run queue not initialized") }
#[inline] pub fn dead_queue()   -> &'static DeadQueue { DEAD_QUEUE.get().expect("global run queue not initialized") }

pub fn initialize_task_storage() {
    PROCESS_TABLE.call_once(ProcessTable::new);
    THREAD_TABLE.call_once(ThreadTable::new);
    GLOBAL_RUN_QUEUE.call_once(GlobalRunQueue::new);
    DEAD_QUEUE.call_once(DeadQueue::new);
}

pub fn move_to_dead_queue(tid: Tid) {
    let thread = thread_table().remove(tid).unwrap_or_else(|| panic!("NO THREAD WITH TID: {}", tid));
    DEAD_QUEUE.get().unwrap().insert(thread);
}

pub fn register_process(process: Arc<Process>) -> Pid {
    let pid = process.pid;
    process_table().insert(process);
    pid
}

pub fn register_thread(thread: &Arc<Thread>) {
    thread_table().insert(thread.clone());
}

pub fn spawn_thread(thread: Arc<Thread>) -> Tid {
    let tid = thread.tid;
    global_queue().push(thread);
    tid
}

pub fn get_process(pid: Pid) -> Option<Arc<Process>> {
    process_table().get(pid)
}

pub fn get_thread(tid: Tid) -> Option<Arc<Thread>> {
    thread_table().get(tid)
}

pub fn wake_thread(tid: Tid) {
    if let Some(thread) = thread_table().get(tid) {
        thread.state.store(ThreadState::Ready, Ordering::Release);
        global_queue().push(thread);
    }
}

pub fn reap_thread(tid: Tid) {
    let Some(thread) = thread_table().remove(tid) else { return };

    let Some(proc) = thread.parent_proc.read().upgrade() else { return };

    {
        let mut threads = proc.threads.lock();
        threads.retain(|w| w.upgrade().map(|t| t.tid != tid).unwrap_or(false));

        if threads.is_empty() {
            drop(threads); 
            process_table().remove(proc.pid);
        }
    }
}

pub fn steal_from_global(buf: &mut [Option<Arc<Thread>>]) -> usize {
    global_queue().steal_into(buf)
}

pub fn global_queue_empty() -> bool {
    global_queue().is_empty()
}

pub fn for_each_thread<F: FnMut(&Arc<Thread>)>(f: F) {
    thread_table().for_each(f);
}

pub fn for_each_process<F: FnMut(&Arc<Process>)>(f: F) {
    process_table().for_each(f);
}