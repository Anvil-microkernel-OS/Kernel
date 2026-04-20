use alloc::{collections::vec_deque::VecDeque, sync::Arc};
use spin::Mutex;

use crate::arch::amd64::scheduler::task::TaskId;

#[derive(Debug, Clone)]
pub enum PortEvent {
    ChannelReadable,
    ChannelPeerClosed,
    IrqFired(u8),
    Timer,
}

#[derive(Debug, Clone)]
pub struct PortPacket {
    pub key:   u64,
    pub event: PortEvent,
}

#[derive(Debug)]
pub enum PortAction {
    Continue,
    Block  { task_id: TaskId },
    Wake   { task_id: TaskId },
}


#[derive(Debug)]
pub enum PortErr {
    WouldBlock(PortAction),
    Timeout,
    Closed,
}

const PORT_QUEUE_LIMIT: usize = 256;

struct PortInner {
    queue:  VecDeque<PortPacket>,
    waiter: Option<TaskId>,
    closed: bool,
}

impl PortInner {
    const fn new() -> Self {
        Self {
            queue:  VecDeque::new(),
            waiter: None,
            closed: false,
        }
    }
}

pub struct Port {
    inner: Mutex<PortInner>,
}

impl Port {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(PortInner::new()),
        })
    }

    pub fn notify(&self, packet: PortPacket) -> PortAction {
        let mut inner = self.inner.lock();

        if inner.closed {
            return PortAction::Continue;
        }

        if inner.queue.len() >= PORT_QUEUE_LIMIT {
            inner.queue.pop_front();
        }

        inner.queue.push_back(packet);

        match inner.waiter.take() {
            Some(waiter) => PortAction::Wake { task_id: waiter },
            None         => PortAction::Continue,
        }
    }

    pub fn poll(&self) -> Option<PortPacket> {
        self.inner.lock().queue.pop_front()
    }

    pub fn wait(&self, current_task: TaskId) -> Result<PortPacket, PortErr> {
        let mut inner = self.inner.lock();

        if let Some(packet) = inner.queue.pop_front() {
            return Ok(packet);
        }

        if inner.closed {
            return Err(PortErr::Closed);
        }

        inner.waiter = Some(current_task);
        Err(PortErr::WouldBlock(PortAction::Block { task_id: current_task }))
    }

    pub fn close(&self) -> PortAction {
        let mut inner = self.inner.lock();
        inner.closed = true;
        match inner.waiter.take() {
            Some(waiter) => PortAction::Wake { task_id: waiter },
            None         => PortAction::Continue,
        }
    }

    pub fn is_closed(&self) -> bool {
        self.inner.lock().closed
    }

    pub fn queue_len(&self) -> usize {
        self.inner.lock().queue.len()
    }
}
