use alloc::vec::Vec;
use alloc::vec;
use spin::RwLock;

use crate::arch::amd64::capability_sys::capability::Capability;

pub type CapIdx = u32;

pub struct CNode {
    entries: RwLock<Vec<Capability>>,
}

impl CNode {
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(Vec::new()),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        let slots = vec![Capability::null(); capacity];
        Self {
            entries: RwLock::new(slots),
        }
    }

    pub fn get(&self, idx: CapIdx) -> Option<Capability> {
        let entries = self.entries.read();
        entries
            .get(idx as usize)
            .filter(|c| !c.is_null())
            .cloned()
    }

    pub fn find_free(&self) -> Option<CapIdx> {
        let entries = self.entries.read();
        entries
            .iter()
            .enumerate()
            .find(|(_, c)| c.is_null())
            .map(|(i, _)| i as CapIdx)
    }

    pub fn alloc(&self, cap: Capability) -> CapIdx {
        let mut entries = self.entries.write();

        if let Some(idx) = entries
            .iter()
            .enumerate()
            .find(|(_, c)| c.is_null())
            .map(|(i, _)| i as CapIdx)
        {
            entries[idx as usize] = cap;
            return idx;
        }

        let idx = entries.len() as CapIdx;
        entries.push(cap);
        idx
    }

    pub fn insert_at(&self, idx: CapIdx, cap: Capability) -> Result<(), &'static str> {
        let mut entries = self.entries.write();
        let idx_usize = idx as usize;

        if idx_usize >= entries.len() {
            entries.resize(idx_usize + 1, Capability::null());
        }

        entries[idx_usize] = cap;
        Ok(())
    }

    pub fn delete(&self, idx: CapIdx) -> bool {
        let mut entries = self.entries.write();
        match entries.get_mut(idx as usize) {
            Some(slot) if !slot.is_null() => {
                *slot = Capability::null();
                true
            }
            _ => false,
        }
    }

    pub fn clear(&self) {
        let mut entries = self.entries.write();
        entries.clear();
    }

    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    pub fn is_empty(&self) -> bool {
        let entries = self.entries.read();
        entries.is_empty() || entries.iter().all(|c| c.is_null())
    }

    pub fn iter(&self) -> Vec<(CapIdx, Capability)> {
        let entries = self.entries.read();
        entries
            .iter()
            .enumerate()
            .filter(|(_, c)| !c.is_null())
            .map(|(i, c)| (i as CapIdx, c.clone()))
            .collect()
    }
}

impl Default for CNode {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for CNode {
    fn clone(&self) -> Self {
        let entries = self.entries.read().clone();
        Self {
            entries: RwLock::new(entries),
        }
    }
}