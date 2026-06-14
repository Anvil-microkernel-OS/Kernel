use alloc::vec::Vec;
use x86_64::PhysAddr;

use crate::arch::amd64::{memory::pmm::pages_allocator::{PAllocFlags, alloc_pages_by_order, free_pages}};

pub enum VmoType {
    Contigious,
    Anonymous,
    Physical
}

impl VmoType {
    pub fn from_id(id: u64) -> Option<Self> {
        match id {
            0 => Some(VmoType::Contigious),
            1 => Some(VmoType::Anonymous),
            2 => Some(VmoType::Physical),
            _ => None
        }
    }
}

pub struct Vmo {
    pub frames:   Vec<Option<PhysAddr>>,
    pub size:     usize,
    pub _type:    VmoType,
}

impl Vmo {
    pub fn frame_at(&self, page_idx: usize) -> Option<PhysAddr> {
        self.frames.get(page_idx).copied().flatten()
    }

    pub fn populate_anonymous(&mut self, page_idx: usize) -> Result<PhysAddr, &'static str> {
        if !matches!(self._type, VmoType::Anonymous) {
            return Err("not anonymous");
        }
        if let Some(Some(pa)) = self.frames.get(page_idx) {
            return Ok(*pa); 
        }
        let pa = alloc_pages_by_order(0, PAllocFlags::ZEROED).ok_or("invalid allocation")?;
        self.frames[page_idx] = Some(pa);
        Ok(pa)
    }
}

impl Drop for Vmo {
    fn drop(&mut self) {
        match self._type {
            VmoType::Anonymous | VmoType::Contigious => {
                for frame in self.frames.iter().flatten() {
                    free_pages(*frame);
                }
            }
            VmoType::Physical => {
            }
        }
    }
}