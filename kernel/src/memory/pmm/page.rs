use core::cell::UnsafeCell;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU8, AtomicU32, Ordering};

use crate::memory::misc::primitives::PhysAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PageState {
    Free = 0,
    Object = 1,
    Wired = 2,
    Slab = 3,
    Contiguous = 4,
}

impl TryFrom<u8> for PageState {
    type Error = ();
    fn try_from(v: u8) -> Result<Self, ()> {
        match v {
            0 => Ok(Self::Free),
            1 => Ok(Self::Object),
            2 => Ok(Self::Wired),
            3 => Ok(Self::Slab),
            4 => Ok(Self::Contiguous),
            _ => Err(()),
        }
    }
}

#[repr(C)]
pub struct QueueNode {
    pub next: UnsafeCell<Option<NonNull<VmPage>>>,
    pub prev: UnsafeCell<Option<NonNull<VmPage>>>,
}

impl QueueNode {
    pub const fn new() -> Self {
        Self {
            next: UnsafeCell::new(None),
            prev: UnsafeCell::new(None),
        }
    }
}

#[repr(C)]
pub struct VmPage {
    paddr: PhysAddr,

    state: AtomicU8,

    refcount: AtomicU32,

    arena_id: u8,

    _pad: [u8; 2],

    pub queue_node: QueueNode,
}

unsafe impl Send for VmPage {}
unsafe impl Sync for VmPage {}

impl VmPage {
    pub const fn new(paddr: PhysAddr, arena_id: u8) -> Self {
        Self {
            paddr,
            state: AtomicU8::new(PageState::Free as u8),
            refcount: AtomicU32::new(0),
            arena_id,
            _pad: [0; 2],
            queue_node: QueueNode::new(),
        }
    }

    #[inline]
    pub fn paddr(&self) -> PhysAddr {
        self.paddr
    }

    #[inline]
    pub fn arena_id(&self) -> u8 {
        self.arena_id
    }

    #[inline]
    pub fn state(&self) -> PageState {
        PageState::try_from(self.state.load(Ordering::Relaxed))
            .expect("invalid page state")
    }

    #[inline]
    pub fn set_state(&self, state: PageState) {
        self.state.store(state as u8, Ordering::Relaxed);
    }

    #[inline]
    pub fn is_free(&self) -> bool {
        self.state() == PageState::Free
    }

    #[inline]
    pub fn refcount(&self) -> u32 {
        self.refcount.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn ref_acquire(&self) -> u32 {
        self.refcount.fetch_add(1, Ordering::AcqRel) + 1
    }

    #[inline]
    pub fn ref_release(&self) -> u32 {
        let prev = self.refcount.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(prev > 0, "refcount underflow on page {}", self.paddr);
        prev - 1
    }

    pub fn alloc_transition(&self, new_state: PageState) -> bool {
        debug_assert!(new_state != PageState::Free);
        self.state
            .compare_exchange(
                PageState::Free as u8,
                new_state as u8,
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_ok()
    }

    pub fn free_transition(&self) {
        debug_assert!(!self.is_free(), "double free on page {}", self.paddr);
        debug_assert!(self.refcount() == 0, "freeing page {} with refcount {}", self.paddr, self.refcount());
        self.state.store(PageState::Free as u8, Ordering::Release);
    }
}