use core::cell::UnsafeCell;
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

use spin::Mutex;

use crate::arch::CurrentMemArchSpec;
use crate::memory::misc::arch_specific::Arch;
use crate::memory::misc::primitives::{PhysAddr};

use super::arena::{PmmArena, MAX_ARENAS};
use super::page::{PageState, VmPage};

const PER_CPU_CACHE_SIZE: usize = 64;
const BATCH_SIZE: usize = 32;

#[repr(C)]
struct PerCpuCache {
    pages: [PhysAddr; PER_CPU_CACHE_SIZE],
    count: usize,
}

impl PerCpuCache {
    const fn new() -> Self {
        Self {
            pages: [PhysAddr::new(0); PER_CPU_CACHE_SIZE],
            count: 0,
        }
    }

    #[inline]
    fn pop(&mut self) -> Option<PhysAddr> {
        if self.count == 0 {
            return None;
        }
        self.count -= 1;
        Some(self.pages[self.count])
    }

    #[inline]
    fn push(&mut self, paddr: PhysAddr) -> Result<(), PhysAddr> {
        if self.count >= PER_CPU_CACHE_SIZE {
            return Err(paddr);
        }
        self.pages[self.count] = paddr;
        self.count += 1;
        Ok(())
    }
}

#[repr(C)]
struct PerCpuSet {
    cpu_count: usize,
}

impl PerCpuSet {
    unsafe fn get(&self, cpu_id: usize) -> &Mutex<PerCpuCache> {
        debug_assert!(cpu_id < self.cpu_count);
        let header_size = core::mem::size_of::<Self>();
        let cache_align = core::mem::align_of::<Mutex<PerCpuCache>>();
        let header_padded = (header_size + cache_align - 1) & !(cache_align - 1);
        let base = (self as *const Self as *const u8).add(header_padded)
            as *const Mutex<PerCpuCache>;
        &*base.add(cpu_id)
    }
}

struct FreeList {
    head: Option<NonNull<VmPage>>,
    count: usize,
}

unsafe impl Send for FreeList {}

impl FreeList {
    const fn new() -> Self {
        Self { head: None, count: 0 }
    }

    unsafe fn push(&mut self, page: &VmPage) {
        let ptr = NonNull::from(page);
        *page.queue_node.next.get() = self.head;
        *page.queue_node.prev.get() = None;

        if let Some(old_head) = self.head {
            *old_head.as_ref().queue_node.prev.get() = Some(ptr);
        }

        self.head = Some(ptr);
        self.count += 1;
    }

    unsafe fn pop(&mut self) -> Option<NonNull<VmPage>> {
        let page_ptr = self.head?;
        let page = page_ptr.as_ref();

        self.head = *page.queue_node.next.get();
        if let Some(new_head) = self.head {
            *new_head.as_ref().queue_node.prev.get() = None;
        }

        *page.queue_node.next.get() = None;
        *page.queue_node.prev.get() = None;
        self.count -= 1;

        Some(page_ptr)
    }

    unsafe fn remove(&mut self, page: &VmPage) {
        let prev = *page.queue_node.prev.get();
        let next = *page.queue_node.next.get();

        match prev {
            Some(p) => *p.as_ref().queue_node.next.get() = next,
            None => self.head = next,
        }
        if let Some(n) = next {
            *n.as_ref().queue_node.prev.get() = prev;
        }

        *page.queue_node.next.get() = None;
        *page.queue_node.prev.get() = None;
        self.count -= 1;
    }

    fn len(&self) -> usize {
        self.count
    }
}

struct ArenaSet {
    arenas: [UnsafeCell<Option<PmmArena>>; MAX_ARENAS],
    count: AtomicUsize,
}

unsafe impl Send for ArenaSet {}
unsafe impl Sync for ArenaSet {}

impl ArenaSet {
    const EMPTY_SLOT: UnsafeCell<Option<PmmArena>> = UnsafeCell::new(None);

    const fn new() -> Self {
        Self {
            arenas: [Self::EMPTY_SLOT; MAX_ARENAS],
            count: AtomicUsize::new(0),
        }
    }

    fn get(&self, index: usize) -> Option<&PmmArena> {
        if index >= self.count.load(Ordering::Acquire) {
            return None;
        }
        unsafe { (*self.arenas[index].get()).as_ref() }
    }

    fn len(&self) -> usize {
        self.count.load(Ordering::Acquire)
    }

    unsafe fn add(&self, arena: PmmArena) -> Result<u8, PmmError> {
        let idx = self.count.load(Ordering::Acquire);
        if idx >= MAX_ARENAS {
            return Err(PmmError::TooManyArenas);
        }
        *self.arenas[idx].get() = Some(arena);
        self.count.store(idx + 1, Ordering::Release);
        Ok(idx as u8)
    }

    fn find_for_paddr(&self, paddr: PhysAddr) -> Option<&PmmArena> {
        for i in 0..self.len() {
            if let Some(arena) = self.get(i) {
                if arena.contains(paddr) {
                    return Some(arena);
                }
            }
        }
        None
    }
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug)]
    pub struct AllocFlags: u32 {
        const ZEROED = 1 << 0;
        const WIRED  = 1 << 1;
        const OBJECT = 1 << 2;
        const SLAB   = 1 << 3;
    }
}

impl AllocFlags {
    fn to_page_state(self) -> PageState {
        if self.contains(Self::WIRED) {
            PageState::Wired
        } else if self.contains(Self::SLAB) {
            PageState::Slab
        } else if self.contains(Self::OBJECT) {
            PageState::Object
        } else {
            PageState::Wired
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum PmmError {
    NoMemory,
    InvalidPhysAddr,
    BadPageState,
    TooManyArenas,
    RegionTooSmall,
}

pub struct PmmNode {
    free_list: Mutex<FreeList>,
    free_count: AtomicUsize,
    arenas: ArenaSet,
    init_lock: Mutex<()>,
    per_cpu: AtomicPtr<PerCpuSet>,
    hhdm_offset: usize,
}

unsafe impl Send for PmmNode {}
unsafe impl Sync for PmmNode {}

impl PmmNode {
    pub const fn new(hhdm_offset: usize) -> Self {
        Self {
            free_list: Mutex::new(FreeList::new()),
            free_count: AtomicUsize::new(0),
            arenas: ArenaSet::new(),
            init_lock: Mutex::new(()),
            per_cpu: AtomicPtr::new(ptr::null_mut()),
            hhdm_offset,
        }
    }

    pub unsafe fn add_arena(
        &self,
        base: PhysAddr,
        size: usize,
    ) -> Result<(), PmmError> {
        let _lock = self.init_lock.lock();

        if size < CurrentMemArchSpec::PAGE_SIZE * 2 {
            return Err(PmmError::RegionTooSmall);
        }

        let base = base.page_align_up();
        let end = PhysAddr::new(base.as_usize() + size).page_align_down();
        let aligned_size = end - base;
        let id = self.arenas.len() as u8;

        let (arena, init_result) = PmmArena::init(
            id, base, aligned_size, self.hhdm_offset,
        );

        self.arenas.add(arena)?;

        let arena_ref = self.arenas.get(id as usize).unwrap();
        let mut fl = self.free_list.lock();
        for page in arena_ref.usable_pages() {
            fl.push(page);
        }
        self.free_count.fetch_add(init_result.usable_pages, Ordering::Relaxed);

        Ok(())
    }

    pub unsafe fn reclaim_region(
        &self,
        base: PhysAddr,
        size: usize,
    ) -> Result<(), PmmError> {
        self.add_arena(base, size)
    }

    pub unsafe fn init_percpu(&self, cpu_count: usize) {
        let _lock = self.init_lock.lock();

        assert!(
            self.per_cpu.load(Ordering::Relaxed).is_null(),
            "init_percpu called twice"
        );
        assert!(cpu_count > 0);

        let header_size = core::mem::size_of::<PerCpuSet>();
        let cache_size = core::mem::size_of::<Mutex<PerCpuCache>>();
        let cache_align = core::mem::align_of::<Mutex<PerCpuCache>>();
        let header_padded = (header_size + cache_align - 1) & !(cache_align - 1);
        let total_bytes = header_padded + cache_size * cpu_count;
        let pages_needed = (total_bytes + CurrentMemArchSpec::PAGE_SIZE - 1) / CurrentMemArchSpec::PAGE_SIZE;

        let phys_base = self.alloc_contiguous_internal(pages_needed)
            .expect("init_percpu: not enough contiguous memory");

        let vaddr = phys_base.as_usize() + self.hhdm_offset;
        ptr::write_bytes(vaddr as *mut u8, 0, pages_needed * CurrentMemArchSpec::PAGE_SIZE);

        let set_ptr = vaddr as *mut PerCpuSet;
        ptr::write(&raw mut (*set_ptr).cpu_count, cpu_count);

        let caches_base = (vaddr + header_padded) as *mut Mutex<PerCpuCache>;
        for i in 0..cpu_count {
            ptr::write(caches_base.add(i), Mutex::new(PerCpuCache::new()));
        }

        for i in 0..pages_needed {
            let paddr = phys_base + i * CurrentMemArchSpec::PAGE_SIZE;
            if let Some(page) = self.paddr_to_page(paddr) {
                page.set_state(PageState::Wired);
            }
        }

        self.per_cpu.store(set_ptr, Ordering::Release);
    }

    pub fn alloc_page(&self, flags: AllocFlags) -> Result<PhysAddr, PmmError> {
        let page_state = flags.to_page_state();

        let percpu = self.per_cpu.load(Ordering::Acquire);
        if !percpu.is_null() {
            let cpu = Self::current_cpu();
            let set = unsafe { &*percpu };

            if cpu < set.cpu_count {
                let cache = unsafe { set.get(cpu) };
                let mut guard = cache.lock();

                if let Some(paddr) = guard.pop() {
                    let page = self.paddr_to_page(paddr)
                        .ok_or(PmmError::InvalidPhysAddr)?;
                    debug_assert!(page.is_free());
                    page.alloc_transition(page_state);
                    if flags.contains(AllocFlags::ZEROED) {
                        self.zero_page(paddr);
                    }
                    return Ok(paddr);
                }
                drop(guard);

                self.refill_cache(cpu);

                let mut guard = unsafe { set.get(cpu) }.lock();
                if let Some(paddr) = guard.pop() {
                    let page = self.paddr_to_page(paddr)
                        .ok_or(PmmError::InvalidPhysAddr)?;
                    page.alloc_transition(page_state);
                    if flags.contains(AllocFlags::ZEROED) {
                        self.zero_page(paddr);
                    }
                    return Ok(paddr);
                }
            }
        }

        self.alloc_page_global(flags)
    }

    fn alloc_page_global(&self, flags: AllocFlags) -> Result<PhysAddr, PmmError> {
        let page_state = flags.to_page_state();
        let mut fl = self.free_list.lock();

        let page_ptr = unsafe { fl.pop() }.ok_or(PmmError::NoMemory)?;
        let page = unsafe { page_ptr.as_ref() };
        let paddr = page.paddr();
        page.alloc_transition(page_state);
        self.free_count.fetch_sub(1, Ordering::Relaxed);
        drop(fl);

        if flags.contains(AllocFlags::ZEROED) {
            self.zero_page(paddr);
        }
        Ok(paddr)
    }

    pub fn alloc_pages(
        &self,
        count: usize,
        flags: AllocFlags,
    ) -> Result<alloc::vec::Vec<PhysAddr>, PmmError> {
        let mut pages = alloc::vec::Vec::with_capacity(count);
        for _ in 0..count {
            match self.alloc_page(flags) {
                Ok(p) => pages.push(p),
                Err(e) => {
                    for &p in &pages { self.free_page(p); }
                    return Err(e);
                }
            }
        }
        Ok(pages)
    }

    pub fn alloc_contiguous(
        &self,
        count: usize,
        flags: AllocFlags,
    ) -> Result<PhysAddr, PmmError> {
        let base = self.alloc_contiguous_internal(count)?;
        if flags.contains(AllocFlags::ZEROED) {
            for i in 0..count {
                self.zero_page(base + i * CurrentMemArchSpec::PAGE_SIZE);
            }
        }
        Ok(base)
    }

    fn alloc_contiguous_internal(&self, count: usize) -> Result<PhysAddr, PmmError> {
        for i in 0..self.arenas.len() {
            let arena = self.arenas.get(i).unwrap();
            if let Some(base) = arena.find_contiguous(count) {
                let mut fl = self.free_list.lock();
                for j in 0..count {
                    let paddr = base + j * CurrentMemArchSpec::PAGE_SIZE;
                    let page = arena.paddr_to_page(paddr).unwrap();
                    unsafe { fl.remove(page); }
                    page.set_state(PageState::Contiguous);
                    self.free_count.fetch_sub(1, Ordering::Relaxed);
                }
                return Ok(base);
            }
        }
        Err(PmmError::NoMemory)
    }

    pub fn alloc_contiguous_aligned(
        &self,
        count: usize,
        align_pages: usize,
        flags: AllocFlags,
    ) -> Result<PhysAddr, PmmError> {
        let base = self.alloc_contiguous_aligned_internal(count, align_pages)?;
        if flags.contains(AllocFlags::ZEROED) {
            for i in 0..count {
                self.zero_page(base + i * CurrentMemArchSpec::PAGE_SIZE);
            }
        }
        Ok(base)
    }

    fn alloc_contiguous_aligned_internal(
        &self,
        count: usize,
        align_pages: usize,
    ) -> Result<PhysAddr, PmmError> {
        for i in 0..self.arenas.len() {
            let arena = self.arenas.get(i).unwrap();
            if let Some(base) = arena.find_contiguous_aligned(count, align_pages) {
                let mut fl = self.free_list.lock();
                for j in 0..count {
                    let paddr = base + j * CurrentMemArchSpec::PAGE_SIZE;
                    let page = arena.paddr_to_page(paddr).unwrap();
                    unsafe { fl.remove(page); }
                    page.set_state(PageState::Contiguous);
                    self.free_count.fetch_sub(1, Ordering::Relaxed);
                }
                return Ok(base);
            }
        }
        Err(PmmError::NoMemory)
    }

    pub fn free_page(&self, paddr: PhysAddr) {
        debug_assert!(paddr.is_page_aligned());

        let page = self.paddr_to_page(paddr)
            .expect("free_page: invalid physical address");
        page.free_transition();

        let percpu = self.per_cpu.load(Ordering::Acquire);
        if !percpu.is_null() {
            let cpu = Self::current_cpu();
            let set = unsafe { &*percpu };

            if cpu < set.cpu_count {
                let cache = unsafe { set.get(cpu) };
                let mut guard = cache.lock();

                if guard.push(paddr).is_ok() {
                    self.free_count.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                drop(guard);

                self.drain_cache(cpu);
                let mut guard = unsafe { set.get(cpu) }.lock();
                let _ = guard.push(paddr);
                self.free_count.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }

        let mut fl = self.free_list.lock();
        unsafe { fl.push(page); }
        self.free_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn free_contiguous(&self, base: PhysAddr, count: usize) {
        for i in 0..count {
            let paddr = base + i * CurrentMemArchSpec::PAGE_SIZE;
            let page = self.paddr_to_page(paddr)
                .expect("free_contiguous: invalid address");
            debug_assert!(page.state() == PageState::Contiguous);
            page.set_state(PageState::Wired); 
            self.free_page(paddr);
        }
    }

    fn refill_cache(&self, cpu: usize) {
        let percpu = self.per_cpu.load(Ordering::Acquire);
        if percpu.is_null() { return; }
        let set = unsafe { &*percpu };
        if cpu >= set.cpu_count { return; }

        let mut fl = self.free_list.lock();
        let cache = unsafe { set.get(cpu) };
        let mut guard = cache.lock();

        for _ in 0..BATCH_SIZE {
            unsafe {
                if let Some(page_ptr) = fl.pop() {
                    let page = page_ptr.as_ref();
                    if guard.push(page.paddr()).is_err() {
                        fl.push(page);
                        break;
                    }
                    self.free_count.fetch_sub(1, Ordering::Relaxed);
                } else {
                    break;
                }
            }
        }
    }

    fn drain_cache(&self, cpu: usize) {
        let percpu = self.per_cpu.load(Ordering::Acquire);
        if percpu.is_null() { return; }
        let set = unsafe { &*percpu };
        if cpu >= set.cpu_count { return; }

        let mut fl = self.free_list.lock();
        let cache = unsafe { set.get(cpu) };
        let mut guard = cache.lock();

        for _ in 0..(BATCH_SIZE / 2) {
            if let Some(paddr) = guard.pop() {
                if let Some(page) = self.paddr_to_page(paddr) {
                    unsafe { fl.push(page); }
                }
            } else {
                break;
            }
        }
    }

    pub fn paddr_to_page(&self, paddr: PhysAddr) -> Option<&VmPage> {
        self.arenas.find_for_paddr(paddr)
            .and_then(|arena| arena.paddr_to_page(paddr))
    }

    pub fn free_pages(&self) -> usize {
        self.free_count.load(Ordering::Relaxed)
    }

    pub fn free_bytes(&self) -> usize {
        self.free_pages() * CurrentMemArchSpec::PAGE_SIZE
    }

    pub fn arena_count(&self) -> usize {
        self.arenas.len()
    }

    pub fn has_percpu(&self) -> bool {
        !self.per_cpu.load(Ordering::Relaxed).is_null()
    }

    fn zero_page(&self, paddr: PhysAddr) {
        let vaddr = paddr.as_usize() + self.hhdm_offset;
        unsafe { ptr::write_bytes(vaddr as *mut u8, 0, CurrentMemArchSpec::PAGE_SIZE); }
    }

    fn current_cpu() -> usize {
        // TODO: arch-specific (LAPIC ID / tp register / MPIDR)
        0
    }
}

extern crate alloc;