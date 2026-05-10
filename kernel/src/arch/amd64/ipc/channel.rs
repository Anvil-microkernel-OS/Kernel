use core::sync::atomic::{AtomicBool, Ordering};

use alloc::{collections::vec_deque::VecDeque, sync::Arc, vec::Vec};
use spin::Mutex;

use crate::arch::amd64::{capability_sys::cnode::CapIdx, ipc::port::{Port, PortAction, PortEvent, PortPacket}, scheduler::task::Tid};

pub struct ChannelMessage {
    pub label: u64,
    pub handles: Vec<CapIdx>,
    pub payload: MsgPayload
}

pub enum MsgPayload {
    Registers {
        data: [u64; 5],
        len: u8
    },
    SharedMem(CapIdx)
}

#[derive(Debug)]
pub enum ChannelAction {
    Continue,
    Block { task_id: Tid },
    Wake { task_id: Tid },
    WakeAndBlock { wake: Tid, block: Tid },
}

pub enum ChannelErr {
    PeerClosed,
    QueueFull,
    Empty,
    InvalidHandle,
    WouldBlock(ChannelAction)
}

const QUEUE_LIMIT: usize = 64;

struct ChannelInner {
    queue:       VecDeque<ChannelMessage>,
    waiter:      Option<Tid>,
    peer_closed: bool,
}

impl ChannelInner {
    const fn new() -> Self {
        Self {
            queue:       VecDeque::new(),
            waiter:      None,
            peer_closed: false,
        }
    }
}

pub struct ChannelStatus {
    pub readable:   bool,
    pub peer_alive: bool,
    pub queue_len:  usize,
}

struct ChannelEnd {
    inner:  Mutex<ChannelInner>,
    closed: AtomicBool,
    port_sub: Mutex<Option<(Arc<Port>, u64)>>, 
}

impl ChannelEnd {
    fn new() -> Self {
        Self {
            inner:  Mutex::new(ChannelInner::new()),
            closed: AtomicBool::new(false),
            port_sub: Mutex::new(None),
        }
    }

    fn push(&self, msg: ChannelMessage) -> Result<ChannelAction, ChannelErr> {
        let mut inner = self.inner.lock();
        if self.closed.load(Ordering::Acquire) || inner.peer_closed {
            return Err(ChannelErr::PeerClosed);
        }
        if inner.queue.len() >= QUEUE_LIMIT {
            return Err(ChannelErr::QueueFull);
        }
        inner.queue.push_back(msg);

        if let Some((port, key)) = self.port_sub.lock().as_ref() {
            let port_action = port.notify(PortPacket {
                key:   *key,
                event: PortEvent::ChannelReadable,
            });
            return Ok(match port_action {
                PortAction::Wake { task_id } => ChannelAction::Wake { task_id },
                _ => ChannelAction::Continue,
            });
        }

        Ok(match inner.waiter.take() {
            Some(waiter) => ChannelAction::Wake { task_id: waiter },
            None         => ChannelAction::Continue,
        })
    }

    fn pop(&self, current_thread: Tid) -> Result<(ChannelMessage, ChannelAction), ChannelErr> {
        let mut inner = self.inner.lock();

        if let Some(msg) = inner.queue.pop_front() {
            return Ok((msg, ChannelAction::Continue));
        }

        if inner.peer_closed {
            return Err(ChannelErr::PeerClosed);
        }

        inner.waiter = Some(current_thread);
        Err(ChannelErr::WouldBlock(ChannelAction::Block { task_id: current_thread }))
    }

    fn notify_peer_closed(&self) -> ChannelAction {
        let mut inner = self.inner.lock();
        inner.peer_closed = true;

        if let Some((port, key)) = self.port_sub.lock().as_ref() {
            port.notify(PortPacket {
                key:   *key,
                event: PortEvent::ChannelPeerClosed,
            });
        }

        match inner.waiter.take() {
            Some(waiter) => ChannelAction::Wake { task_id: waiter },
            None         => ChannelAction::Continue,
        }
    }

    fn is_readable(&self) -> bool {
        !self.inner.lock().queue.is_empty()
    }

    fn is_peer_closed(&self) -> bool {
        self.inner.lock().peer_closed
    }

    fn queue_len(&self) -> usize {
        self.inner.lock().queue.len()
    }
}

#[derive(Clone)]
pub struct ChannelHandle {
    own_end:  Arc<ChannelEnd>,
    peer_end: Arc<ChannelEnd>,
}

impl ChannelHandle {
    pub fn new_pair() -> (Self, Self) {
        let left  = Arc::new(ChannelEnd::new());
        let right = Arc::new(ChannelEnd::new());

        let left_handle = ChannelHandle {
            own_end:  left.clone(),
            peer_end: right.clone(),
        };
        let right_handle = ChannelHandle {
            own_end:  right,
            peer_end: left,
        };
        (left_handle, right_handle)
    }

    pub fn write(&self, msg: ChannelMessage) -> Result<ChannelAction, ChannelErr> {
        if self.own_end.closed.load(Ordering::Acquire) {
            return Err(ChannelErr::PeerClosed);
        }
        self.peer_end.push(msg)
    }

    pub fn read(
        &self,
        current_thread: Tid,
    ) -> Result<(ChannelMessage, ChannelAction), ChannelErr> {
        self.own_end.pop(current_thread)
    }

    pub fn call(
        &self,
        mut msg: ChannelMessage,
        current_task: Tid,
        register_cap: impl FnOnce(ChannelHandle) -> CapIdx,
    ) -> Result<(ChannelHandle, ChannelAction), ChannelErr> {
        if self.own_end.closed.load(Ordering::Acquire) {
            return Err(ChannelErr::PeerClosed);
        }

        let (reply_handle, reply_peer) = ChannelHandle::new_pair();
        let reply_cap = register_cap(reply_peer); 
        msg.handles.insert(0, reply_cap);

        let action = self.peer_end.push(msg)?;
        Ok((reply_handle, action))
    }

    pub fn status(&self) -> ChannelStatus {
        ChannelStatus {
            readable:   self.own_end.is_readable(),
            peer_alive: !self.own_end.is_peer_closed(),
            queue_len:  self.own_end.queue_len(),
        }
    }

    pub fn bind_port(&self, port: Arc<Port>, key: u64) {
        *self.own_end.port_sub.lock() = Some((port, key));
    }

    pub fn unbind_port(&self) {
        *self.own_end.port_sub.lock() = None;
    }
}

impl Drop for ChannelHandle {
    fn drop(&mut self) {
        self.own_end.closed.store(true, Ordering::Release);
        self.peer_end.notify_peer_closed();
    }
}