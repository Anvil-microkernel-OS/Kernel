use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use spin::{Mutex, RwLock};
use x86_64::{PhysAddr};

use crate::arch::amd64::{ipc::{channel::ChannelHandle, port::Port}, memory::pmm::pages_allocator::free_pages, scheduler::task::TaskId};


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum KernelObjType {
    VSpace   = 0,
    Endpoint = 1,
    Frame    = 2,
    Thread   = 3,
    Irq      = 4,
    CNode    = 5,
    Vmo      = 6,
    Channel  = 7,
    Port = 8,
}

pub enum ObjData {
    VSpace(TaskId),
    Endpoint(TaskId),
    CNode(TaskId),
    Thread(TaskId),
    Vmo(Vmo),
    Channel(ChannelHandle),
    Port(Arc<Port>)
}

pub struct Vmo {
    pub owner_id: TaskId,
    pub frames: Vec<PhysAddr>,
    pub size:   usize,
}

impl Drop for Vmo {
    fn drop(&mut self) {
        for frame in &self.frames {
            free_pages(*frame);
        }
    }
}

pub struct KernelObject {
    pub obj_type: KernelObjType,
    pub refcount: AtomicU32,
    pub data: ObjData,
}

impl KernelObject {
    pub fn new(obj_type: KernelObjType, data: ObjData) -> Self {
        Self {
            obj_type,
            refcount: AtomicU32::new(1),
            data,
        }
    }

    pub fn inc_ref(&self) -> u32 {
        self.refcount.fetch_add(1, Ordering::Relaxed)
    }

    pub fn dec_ref(&self) -> bool {
        self.refcount.fetch_sub(1, Ordering::Release) == 1
    }
}

pub struct Slot {
    generation: AtomicU32,
    occupied: AtomicBool,
    obj: RwLock<Option<KernelObject>>,
}


impl Slot {
    const fn empty() -> Self {
        Self {
            generation: AtomicU32::new(0),
            occupied: AtomicBool::new(false),
            obj: RwLock::new(None),
        }
    }
}

const SLAB_SIZE: usize = 256;

struct ObjectTable {
    slabs: RwLock<Vec<Box<[Slot]>>>,
    free_list: Mutex<Vec<u32>>,
    total_slots: AtomicU32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandleRef {
    pub index: u16,
    pub generation: u32,
}

impl ObjectTable {
    pub const fn new() -> Self {
        Self {
            slabs: RwLock::new(Vec::new()),
            free_list: Mutex::new(Vec::new()),
            total_slots: AtomicU32::new(0),
        }
    }

    fn grow(&self) {
        let slab: Vec<Slot> = (0..SLAB_SIZE).map(|_| Slot::empty()).collect();
        let slab = slab.into_boxed_slice();
        
        let mut slabs = self.slabs.write();
        let base = self.total_slots.load(Ordering::Relaxed) as usize;
        slabs.push(slab);
        let mut free = self.free_list.lock();
        for i in (0..SLAB_SIZE).rev() {
            free.push((base + i) as u32);
        }
        self.total_slots.fetch_add(SLAB_SIZE as u32, Ordering::Relaxed);
    }

    fn slot(&self, index: u32) -> Option<&Slot> {
        let slabs = self.slabs.read();
        let slab_idx = index as usize / SLAB_SIZE;
        let slot_idx = index as usize % SLAB_SIZE;

        unsafe {
            slabs.get(slab_idx).map(|slab| {
                &*(&slab[slot_idx] as *const Slot)
            })
        }
    }

    pub fn insert(&self, obj: KernelObject) -> Result<HandleRef, ()> {
        let index = {
            let mut free = self.free_list.lock();
            if free.is_empty() {
                drop(free);
                self.grow();
                self.free_list.lock().pop()
            } else {
                free.pop()
            }
        }.ok_or(())?;

        let slot = self.slot(index).ok_or(())?;
        let generation = slot.generation.load(Ordering::Acquire);
        *slot.obj.write() = Some(obj);
        slot.occupied.store(true, Ordering::Release);

        Ok(HandleRef { index: index as u16, generation })
    }

    pub fn get<F, R>(&self, handle: HandleRef, f: F) -> Option<R>
    where
        F: FnOnce(&KernelObject) -> R,
    {
        let slot = self.slot(handle.index as u32)?;
        if slot.generation.load(Ordering::Acquire) != handle.generation {
            return None;
        }
        if !slot.occupied.load(Ordering::Acquire) {
            return None;
        }
        slot.obj.read().as_ref().map(f)
    }

    pub fn get_mut<F, R>(&self, handle: HandleRef, f: F) -> Option<R>
    where
        F: FnOnce(&mut KernelObject) -> R,
    {
        let slot = self.slot(handle.index as u32)?;
        if slot.generation.load(Ordering::Acquire) != handle.generation {
            return None;
        }
        if !slot.occupied.load(Ordering::Acquire) {
            return None;
        }
        slot.obj.write().as_mut().map(f)
    }

    pub fn remove(&self, handle: HandleRef) -> Option<KernelObject> {
        let slot = self.slot(handle.index as u32)?;
        if slot.generation.load(Ordering::Acquire) != handle.generation {
            return None;
        }
        let obj = slot.obj.write().take()?;
        slot.occupied.store(false, Ordering::Release);
        slot.generation.fetch_add(1, Ordering::Release);
        self.free_list.lock().push(handle.index as u32);
        Some(obj)
    }
}

static OBJECT_TABLE: ObjectTable = ObjectTable::new();

pub fn obj_insert(obj: KernelObject) -> Result<HandleRef, ()> {
    OBJECT_TABLE.insert(obj)
}

pub fn obj_remove(handle: HandleRef) -> Result<(), ()> {
    OBJECT_TABLE.remove(handle).map(|_| ()).ok_or(())
}

pub fn with_object<F, R>(h: HandleRef, f: F) -> Option<R>
where
    F: FnOnce(&KernelObject) -> R,
{
    OBJECT_TABLE.get(h, f)
}

pub fn with_object_mut<F, R>(h: HandleRef, f: F) -> Option<R>
where
    F: FnOnce(&mut KernelObject) -> R,
{
    OBJECT_TABLE.get_mut(h, f)
}