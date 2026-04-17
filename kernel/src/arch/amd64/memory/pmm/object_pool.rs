#![allow(dead_code)]

use core::{
    marker::PhantomData,
    mem,
    ptr::{self, NonNull},
};

use spin::Mutex;
use x86_64::PhysAddr;

use crate::arch::amd64::memory::{
    misc::{align_up, phys_to_virt, virt_to_phys},
    pmm::{
        pages_allocator::{KERNEL_PAGES, alloc_pages_by_order, free_pages},
        sparsemem::PAGE_SIZE,
    },
};

const MIN_CHUNK_OBJECTS: usize = 8;
const MAX_CHUNK_ORDER:   usize = 4;

#[cfg(debug_assertions)]
const FREE_POISON: usize = 0xFEED_FACE_FEED_FACE;

#[repr(C)]
struct FreeNode {
    next: *mut FreeNode,
    #[cfg(debug_assertions)]
    poison: usize,
}

#[repr(C)]
struct ChunkHeader {
    next:  *mut ChunkHeader,
    order: usize,
}

struct PoolState {
    free_head:    *mut FreeNode,
    chunk_head:   *mut ChunkHeader,
    slot_size:    usize,
    slot_align:   usize,
    per_chunk:    usize,
    chunk_order:  usize,
    layout_ready: bool,
    allocated:    usize,
    capacity:     usize,
}

unsafe impl Send for PoolState {}

impl PoolState {
    const fn new(slot_size: usize, slot_align: usize) -> Self {
        Self {
            free_head:    ptr::null_mut(),
            chunk_head:   ptr::null_mut(),
            slot_size,
            slot_align,
            per_chunk:    0,
            chunk_order:  0,
            layout_ready: false,
            allocated:    0,
            capacity:     0,
        }
    }

    fn ensure_layout(&mut self) {
        if self.layout_ready {
            return;
        }

        let raw  = self.slot_size.max(mem::size_of::<FreeNode>());
        let slot = align_up(raw, self.slot_align);

        let header = align_up(mem::size_of::<ChunkHeader>(), self.slot_align);

        let mut order = 0usize;
        loop {
            let span   = PAGE_SIZE << order;
            let usable = span.saturating_sub(header);
            let n      = usable / slot;

            if n >= MIN_CHUNK_OBJECTS || order >= MAX_CHUNK_ORDER {
                self.slot_size    = slot;
                self.per_chunk    = n.max(1);
                self.chunk_order  = order;
                self.layout_ready = true;
                return;
            }
            order += 1;
        }
    }

    fn grow(&mut self) -> bool {
        let phys = match alloc_pages_by_order(self.chunk_order, KERNEL_PAGES) {
            Some(p) => p,
            None    => return false,
        };

        let base   = phys_to_virt(phys.as_u64() as usize);
        let chunk  = base as *mut ChunkHeader;
        let offset = align_up(mem::size_of::<ChunkHeader>(), self.slot_align);

        unsafe {
            (*chunk).next  = self.chunk_head;
            (*chunk).order = self.chunk_order;
            self.chunk_head = chunk;

            for i in (0..self.per_chunk).rev() {
                let node = (base + offset + i * self.slot_size) as *mut FreeNode;
                (*node).next = self.free_head;
                #[cfg(debug_assertions)]
                { (*node).poison = FREE_POISON; }
                self.free_head = node;
            }
        }

        self.capacity += self.per_chunk;
        true
    }

    fn alloc(&mut self) -> Option<NonNull<u8>> {
        self.ensure_layout();

        if self.free_head.is_null() && !self.grow() {
            return None;
        }

        let node       = self.free_head;
        self.free_head = unsafe { (*node).next };

        #[cfg(debug_assertions)]
        unsafe { (*node).poison = 0; }

        self.allocated += 1;
        Some(unsafe { NonNull::new_unchecked(node as *mut u8) })
    }

    fn free(&mut self, ptr: NonNull<u8>) {
        debug_assert!(self.allocated > 0, "ObjectPool: free underflow");

        let node = ptr.as_ptr() as *mut FreeNode;

        #[cfg(debug_assertions)]
        unsafe {
            if (*node).poison == FREE_POISON {
                panic!("ObjectPool: double-free at {:#x}", ptr.as_ptr() as usize);
            }
            (*node).poison = FREE_POISON;
        }

        unsafe { (*node).next = self.free_head; }
        self.free_head  = node;
        self.allocated -= 1;
    }

    fn prefill(&mut self, n: usize) -> usize {
        self.ensure_layout();

        let available = self.capacity - self.allocated;
        if available >= n {
            return 0;
        }

        let deficit   = n - available;
        let chunks    = (deficit + self.per_chunk - 1) / self.per_chunk;
        let mut added = 0usize;

        for _ in 0..chunks {
            if !self.grow() { break; }
            added += self.per_chunk;
        }

        added
    }

    unsafe fn flush(&mut self) {
        debug_assert_eq!(
            self.allocated, 0,
            "ObjectPool::flush with {} live objects", self.allocated
        );

        let mut chunk = self.chunk_head;
        while !chunk.is_null() {
            let order = unsafe { (*chunk).order };
            let next  = unsafe { (*chunk).next };
            let phys  = virt_to_phys(chunk as usize);
            free_pages(PhysAddr::new(phys as u64));
            let _ = order;
            chunk = next;
        }

        self.chunk_head = ptr::null_mut();
        self.free_head  = ptr::null_mut();
        self.capacity   = 0;
    }
}

pub struct ObjectPool<T> {
    state:   Mutex<PoolState>,
    _marker: PhantomData<*mut T>,
}

unsafe impl<T: Send> Send for ObjectPool<T> {}
unsafe impl<T: Send> Sync for ObjectPool<T> {}

impl<T> ObjectPool<T> {
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(PoolState::new(
                mem::size_of::<T>(),
                mem::align_of::<T>(),
            )),
            _marker: PhantomData,
        }
    }

    pub fn alloc_uninit(&self) -> Option<NonNull<T>> {
        self.state.lock().alloc().map(NonNull::cast)
    }

    pub fn alloc(&self, value: T) -> Option<NonNull<T>> {
        let ptr = self.alloc_uninit()?;
        unsafe { ptr::write(ptr.as_ptr(), value); }
        Some(ptr)
    }

    pub fn free(&self, ptr: NonNull<T>) {
        self.state.lock().free(ptr.cast());
    }

    pub fn drop_and_free(&self, ptr: NonNull<T>) {
        unsafe { ptr::drop_in_place(ptr.as_ptr()); }
        self.free(ptr);
    }

    pub fn prefill(&self, n: usize) -> usize {
        self.state.lock().prefill(n)
    }

    pub fn allocated(&self) -> usize {
        self.state.lock().allocated
    }

    pub fn capacity(&self) -> usize {
        self.state.lock().capacity
    }

    pub unsafe fn flush(&self) {
        unsafe { self.state.lock().flush(); }
    }
}
