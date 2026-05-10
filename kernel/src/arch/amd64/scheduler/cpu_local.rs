use core::{ptr::null_mut, sync::atomic::{AtomicPtr, AtomicUsize, Ordering, fence}};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use crate::arch::amd64::scheduler::task::Thread;

pub const RQ_CAP: usize = 1024;

pub struct Runqueue {
    top:    AtomicUsize,
    bottom: AtomicUsize,
    buf:    [AtomicPtr<Thread>; RQ_CAP],
}

impl Runqueue {
    pub const fn new() -> Self {
        const NULL: AtomicPtr<Thread> = AtomicPtr::new(null_mut());
        Self {
            top:    AtomicUsize::new(0),
            bottom: AtomicUsize::new(0),
            buf:    [NULL; RQ_CAP],
        }
    }

    pub fn push(&self, thread: Arc<Thread>) {
        let ptr = Arc::into_raw(thread) as *mut Thread;
        let b = self.bottom.load(Ordering::Relaxed);
        let t = self.top.load(Ordering::Acquire);

        if b.wrapping_sub(t) >= RQ_CAP {
            panic!("Runqueue overflow! bottom={} top={}", b, t);
        }

        self.buf[b % RQ_CAP].store(ptr, Ordering::Relaxed);
        fence(Ordering::Release);
        self.bottom.store(b.wrapping_add(1), Ordering::Relaxed);
    }

    pub fn pop(&self) -> Option<Arc<Thread>> {
        let b_orig = self.bottom.load(Ordering::Relaxed);
        let t_snap  = self.top.load(Ordering::Acquire);

        if b_orig == t_snap {
            return None;
        }

        let b = b_orig.wrapping_sub(1);
        self.bottom.store(b, Ordering::Relaxed);

        fence(Ordering::SeqCst);
        let t = self.top.load(Ordering::Relaxed);

        if t <= b {
            let ptr = self.buf[b % RQ_CAP].load(Ordering::Relaxed);

            if t == b {
                let won = self.top
                    .compare_exchange(t, t.wrapping_add(1),
                                      Ordering::SeqCst,
                                      Ordering::Relaxed)
                    .is_ok();
                self.bottom.store(b.wrapping_add(1), Ordering::Relaxed);
                if !won { return None; }
            }

            debug_assert!(!ptr.is_null(), "runqueue: null pointer in occupied slot");
            if ptr.is_null() { return None; }
            Some(unsafe { Arc::from_raw(ptr) })
        } else {
            self.bottom.store(b.wrapping_add(1), Ordering::Relaxed);
            None
        }
    }

    pub fn steal(&self) -> Option<Arc<Thread>> {
        loop {
            let t = self.top.load(Ordering::Acquire);
            fence(Ordering::SeqCst);
            let b = self.bottom.load(Ordering::Acquire);

            if t >= b { return None; }

            let ptr = self.buf[t % RQ_CAP].load(Ordering::Relaxed);

            if self.top
                .compare_exchange(t, t.wrapping_add(1),
                                  Ordering::SeqCst,
                                  Ordering::Relaxed)
                .is_ok()
            {
                if ptr.is_null() { continue; }
                return Some(unsafe { Arc::from_raw(ptr) });
            }
        }
    }

    pub fn steal_n(&self, n: usize) -> Vec<Arc<Thread>> {
        let mut stolen = Vec::new();
        for _ in 0..n {
            match self.steal() {
                Some(t) => stolen.push(t),
                None    => break,
            }
        }
        stolen
    }

    pub fn len(&self) -> usize {
        let b = self.bottom.load(Ordering::Relaxed);
        let t = self.top.load(Ordering::Acquire);
        b.wrapping_sub(t)
    }
}

pub struct ExecCpu {
    pub tasks:     Runqueue,
    pub curr_task: *mut Thread,
    pub idle_task: Box<Thread>,
}

unsafe impl Send for ExecCpu {}
unsafe impl Sync for ExecCpu {}

impl ExecCpu {
    pub fn new(idle_task: Thread) -> Self {
        Self {
            tasks:     Runqueue::new(),
            curr_task: null_mut(),
            idle_task: Box::new(idle_task),
        }
    }

    pub fn get_curr_task(&self) -> *mut Thread {
        self.curr_task
    }

    pub fn set_curr_task(&mut self, thread: *mut Thread) {
        self.curr_task = thread;
    }

    pub fn idle_task_ptr(&self) -> *const Thread {
        self.idle_task.as_ref() as *const Thread
    }

    pub fn accept_n_tasks(&self, tasks: Vec<Arc<Thread>>) {
        for task in tasks {
            self.tasks.push(task);
        }
    }
}