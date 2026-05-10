use alloc::{collections::btree_map::BTreeMap, sync::Arc};
use spin::RwLock;

use crate::arch::amd64::{interrupts::idt::ISR_COUNT, ipc::port::Port, scheduler::task::Tid};

struct IrqBinding {
    pinned_thread_id: Tid,
    port: Arc<Port>,
    key: u64
}

pub struct IDTTransferManager {
    bindings: RwLock<BTreeMap<u8, IrqBinding>>,
}

pub enum IDTTransferManagerErr {
    AlreadyBound,
    NotAllowed,
    NotBound,
}

impl IDTTransferManager {
    pub const ISR_SLOT: u8 = 0;

    pub const fn new() -> Self {
        Self {
            bindings: RwLock::new(BTreeMap::new()),
        }
    }

    pub fn bind_irq(&self, thread_id: Tid, port_arc: Arc<Port>, vector: u8, key: u64) -> Result<(), IDTTransferManagerErr> {
        if (vector as usize) <= ISR_COUNT {
            return Err(IDTTransferManagerErr::NotAllowed);
        }
        let mut bindings = self.bindings.write();
        if bindings.contains_key(&vector) {
            return Err(IDTTransferManagerErr::AlreadyBound);
        }
        bindings.insert(vector, IrqBinding { pinned_thread_id: thread_id, port: port_arc, key });
        Ok(())
    }

    pub fn bind_isr(&self, thread_id: Tid, port_arc: Arc<Port>, key: u64) -> Result<(), IDTTransferManagerErr> {
        let mut bindings = self.bindings.write();
        if bindings.contains_key(&Self::ISR_SLOT) {
            return Err(IDTTransferManagerErr::AlreadyBound);
        }
        bindings.insert(Self::ISR_SLOT, IrqBinding { pinned_thread_id: thread_id, port: port_arc, key });
        Ok(())
    }

    pub fn unbind_irq(&self, vector: u8) -> Result<(), IDTTransferManagerErr> {
        if (vector as usize) <= ISR_COUNT {
            return Err(IDTTransferManagerErr::NotAllowed);
        }
        self.bindings.write().remove(&vector)
            .map(|_| ())
            .ok_or(IDTTransferManagerErr::NotBound)
    }

    pub fn unbind_isr(&self) -> Result<(), IDTTransferManagerErr> {
        self.bindings.write().remove(&Self::ISR_SLOT)
            .map(|_| ())
            .ok_or(IDTTransferManagerErr::NotBound)
    }

    pub fn unbind_task(&self, thread_id: Tid) {
        self.bindings.write().retain(|_, b| b.pinned_thread_id != thread_id);
    }

    pub fn get_isr(&self) -> Option<(Tid, Arc<Port>)> {
        self.bindings.read().get(&Self::ISR_SLOT)
            .map(|b| (b.pinned_thread_id, b.port.clone()))
    }

    pub fn get_irq(&self, vector: u8) -> Option<(Tid, Arc<Port>, u64)> {
        self.bindings.read().get(&vector)
            .map(|b| (b.pinned_thread_id, b.port.clone(), b.key))
    }

    pub fn bound_vectors(&self) -> alloc::vec::Vec<u8> {
        self.bindings.read().keys().copied().collect()
    }
}

pub static IDT_TRANSFER_MANAGER: IDTTransferManager = IDTTransferManager::new();