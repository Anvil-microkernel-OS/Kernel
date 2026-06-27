use core::alloc::Layout;

use alloc::boxed::Box;

use crate::arch::CurrentMemArchSpec;
use crate::memory::misc::arch_specific::Arch;
use crate::memory::misc::primitives::{PhysAddr};
use crate::memory::pmm::page::PageState;
use crate::memory::pmm::{pmm};
use crate::memory::pmm::hhdm_offset;
use crate::memory::pmm::node::{AllocFlags, PmmError};
use crate::early_println;

fn assert(condition: bool, msg: &str) {
    if !condition {
        early_println!("[FAIL] {}", msg);
        loop {}
    }
}

fn assert_eq<T: core::fmt::Debug + PartialEq>(left: T, right: T, msg: &str) {
    if left != right {
        early_println!("[FAIL] {}: {:?} != {:?}", msg, left, right);
        loop {}
    }
}

static mut STORAGE: [PhysAddr; 4096] = [PhysAddr::new(0); 4096];
static mut COUNT: usize = 0;

unsafe fn push(p: PhysAddr) { if COUNT < 4096 { STORAGE[COUNT] = p; COUNT += 1; } }
unsafe fn pop() -> Option<PhysAddr> { if COUNT > 0 { COUNT -= 1; Some(STORAGE[COUNT]) } else { None } }
unsafe fn clear() { while let Some(p) = pop() { pmm().free_page(p); } }

pub fn run_pmm_tests() {
    early_println!("[PMM] Running tests...");
    test_single_page_alloc_free();
    test_multiple_pages_alloc_free();
    test_zeroed_allocation();
    test_contiguous_allocation();
    test_contiguous_zeroed();
    test_oom_single_page();
    test_oom_contiguous();
    test_fragmentation_resilience();
    test_page_state_transitions();
    test_slab_flag_page_state();
    test_object_flag_page_state();
    test_page_alignment();
    test_contiguous_alignment();
    test_statistics_consistency();
    test_free_count_after_all_operations();
    test_concurrent_alloc_free_single_threaded();
    early_println!("[PMM] All tests passed!");
}

fn test_single_page_alloc_free() {
    let fb = pmm().free_pages();
    let p = pmm().alloc_page(AllocFlags::WIRED).unwrap();
    assert(p.is_page_aligned(), "single: align");
    assert_eq(pmm().free_pages(), fb - 1, "single: after alloc");
    pmm().free_page(p);
    assert_eq(pmm().free_pages(), fb, "single: after free");
}

fn test_multiple_pages_alloc_free() {
    let fb = pmm().free_pages();
    for _ in 0..100 {
        unsafe { push(pmm().alloc_page(AllocFlags::WIRED).unwrap()); }
    }
    assert_eq(pmm().free_pages(), fb - 100, "multiple: after alloc");
    unsafe { clear(); }
    assert_eq(pmm().free_pages(), fb, "multiple: after free");
}

fn test_zeroed_allocation() {
    let p = pmm().alloc_page(AllocFlags::WIRED).unwrap();
    let v = p.as_usize() + hhdm_offset();
    unsafe { core::ptr::write_bytes(v as *mut u8, 0xFF, CurrentMemArchSpec::PAGE_SIZE); }
    pmm().free_page(p);
    let p2 = pmm().alloc_page(AllocFlags::WIRED | AllocFlags::ZEROED).unwrap();
    let v2 = p2.as_usize() + hhdm_offset();
    unsafe {
        for i in 0..CurrentMemArchSpec::PAGE_SIZE {
            assert(*((v2 + i) as *const u8) == 0, "zeroed: not zeroed");
        }
    }
    pmm().free_page(p2);
}

fn test_contiguous_allocation() {
    let c = 8;
    let b = pmm().alloc_contiguous(c, AllocFlags::WIRED).unwrap();
    assert(b.is_page_aligned(), "contig: align");
    for i in 0..c {
        assert_eq(pmm().paddr_to_page(b + i * CurrentMemArchSpec::PAGE_SIZE).unwrap().state(), PageState::Contiguous, "contig: state");
    }
    pmm().free_contiguous(b, c);
}

fn test_contiguous_zeroed() {
    let b = pmm().alloc_contiguous(4, AllocFlags::WIRED | AllocFlags::ZEROED).unwrap();
    let v = b.as_usize() + hhdm_offset();
    unsafe {
        for i in 0..(4 * CurrentMemArchSpec::PAGE_SIZE) {
            assert(*((v + i) as *const u8) == 0, "contig_zeroed: not zeroed");
        }
    }
    pmm().free_contiguous(b, 4);
}

fn test_oom_single_page() {
    while let Ok(p) = pmm().alloc_page(AllocFlags::WIRED) { unsafe { push(p); } }
    let r = pmm().alloc_page(AllocFlags::WIRED);
    assert(r.is_err(), "oom_single: should fail");
    assert(matches!(r.unwrap_err(), PmmError::NoMemory), "oom_single: wrong err");
    unsafe { clear(); }
}

fn test_oom_contiguous() {
    let t = pmm().free_pages();
    assert(pmm().alloc_contiguous(t + 1, AllocFlags::WIRED).is_err(), "oom_contig: should fail");
}

fn test_fragmentation_resilience() {
    let t = pmm().free_pages();
    for _ in (0..t).step_by(2) {
        if let Ok(p) = pmm().alloc_page(AllocFlags::WIRED) { unsafe { push(p); } }
    }
    let r = pmm().alloc_contiguous(2, AllocFlags::WIRED);
    assert(r.is_ok(), "frag: should find");
    if let Ok(b) = r { pmm().free_contiguous(b, 2); }
    unsafe { clear(); }
}

fn test_page_state_transitions() {
    let p = pmm().alloc_page(AllocFlags::WIRED).unwrap();
    assert_eq(pmm().paddr_to_page(p).unwrap().state(), PageState::Wired, "state: Wired");
    pmm().free_page(p);
    assert(pmm().paddr_to_page(p).unwrap().is_free(), "state: Free");
}

fn test_slab_flag_page_state() {
    let p = pmm().alloc_page(AllocFlags::SLAB).unwrap();
    assert_eq(pmm().paddr_to_page(p).unwrap().state(), PageState::Slab, "state: Slab");
    pmm().free_page(p);
}

fn test_object_flag_page_state() {
    let p = pmm().alloc_page(AllocFlags::OBJECT).unwrap();
    assert_eq(pmm().paddr_to_page(p).unwrap().state(), PageState::Object, "state: Object");
    pmm().free_page(p);
}

fn test_page_alignment() {
    for _ in 0..100 {
        let p = pmm().alloc_page(AllocFlags::WIRED).unwrap();
        assert(p.as_usize() % CurrentMemArchSpec::PAGE_SIZE == 0, "align: page");
        pmm().free_page(p);
    }
}

fn test_contiguous_alignment() {
    for c in [1, 2, 4, 8, 16].iter() {
        if let Ok(b) = pmm().alloc_contiguous(*c, AllocFlags::WIRED) {
            assert(b.as_usize() % CurrentMemArchSpec::PAGE_SIZE == 0, "align: contig");
            pmm().free_contiguous(b, *c);
        }
    }
}

fn test_statistics_consistency() {
    assert_eq(pmm().free_pages() * CurrentMemArchSpec::PAGE_SIZE, pmm().free_bytes(), "stats: pages vs bytes");
}

fn test_free_count_after_all_operations() {
    let init = pmm().free_pages();
    let p1 = pmm().alloc_page(AllocFlags::WIRED).unwrap();
    pmm().free_page(p1);
    assert_eq(pmm().free_pages(), init, "count: single");
    let c1 = pmm().alloc_contiguous(4, AllocFlags::WIRED).unwrap();
    pmm().free_contiguous(c1, 4);
    assert_eq(pmm().free_pages(), init, "count: contig");
    for _ in 0..10 { unsafe { push(pmm().alloc_page(AllocFlags::WIRED).unwrap()); } }
    unsafe { clear(); }
    assert_eq(pmm().free_pages(), init, "count: multiple");
}

fn test_concurrent_alloc_free_single_threaded() {
    let init = pmm().free_pages();
    let mut b1 = [PhysAddr::new(0); 50];
    let mut b2 = [PhysAddr::new(0); 50];
    for i in 0..50 {
        b1[i] = pmm().alloc_page(AllocFlags::WIRED).unwrap();
        b2[i] = pmm().alloc_page(AllocFlags::WIRED).unwrap();
    }
    for i in 0..50 {
        if i % 3 == 0 { pmm().free_page(b1[i]); }
        if i % 2 == 0 { pmm().free_page(b2[i]); }
    }
    for i in 0..50 {
        if i % 3 != 0 { pmm().free_page(b1[i]); }
        if i % 2 != 0 { pmm().free_page(b2[i]); }
    }
    assert_eq(pmm().free_pages(), init, "concurrent: pages");
}

fn warmup_slab() {
    // Base slabs (ObjectPage, 1 page each)
    drop(Box::new([0u8; 8]));     // 0..=8
    drop(Box::new([0u8; 16]));    // 9..=16
    drop(Box::new([0u8; 32]));    // 17..=32
    drop(Box::new([0u8; 64]));    // 33..=64
    drop(Box::new([0u8; 128]));   // 65..=128
    drop(Box::new([0u8; 256]));   // 129..=256

    // Large slabs (LargeObjectPage, 512 pages each)
    drop(Box::new([0u8; 512]));   // 257..=512
    drop(Box::new([0u8; 1024]));  // 513..=1024
    drop(Box::new([0u8; 2048]));  // 1025..=2048
}

pub fn run_allocator_tests() {
    early_println!("[ALLOC] Running tests...");
    warmup_slab();
    test_alloc_small();
    test_alloc_medium();
    test_alloc_large();
    test_alloc_zeroed();
    test_realloc_grow();
    test_realloc_shrink();
    test_alloc_free_stress();
    early_println!("[ALLOC] All tests passed!");
}

fn test_alloc_small() {
    let _warmup = Box::new(0u64);
    drop(_warmup);

    let fb = pmm().free_pages();
    {
        let b1 = Box::new(42u64);
        let b2 = Box::new(1337u64);
        let b3 = Box::new(31337u64);
        assert(*b1 == 42, "alloc_small: b1");
        assert(*b2 == 1337, "alloc_small: b2");
        assert(*b3 == 31337, "alloc_small: b3");
    }
    // After warmup, no new pages should be consumed
    assert_eq(pmm().free_pages(), fb, "alloc_small: pages leaked");
}

fn test_alloc_medium() {
    let _warmup = Box::new([0u8; 512]);
    drop(_warmup);

    let fb = pmm().free_pages();
    {
        let arr = Box::new([0u8; 512]);
        assert(arr.len() == 512, "alloc_medium: len");
        assert(arr[0] == 0, "alloc_medium: zeroed");
    }
    assert_eq(pmm().free_pages(), fb, "alloc_medium: pages leaked");
}

fn test_alloc_large() {
    let fb = pmm().free_pages();
    {
        let arr = Box::new([0xA5u8; 4096]);
        assert(arr.len() == 4096, "alloc_large: len");
        assert(arr[0] == 0xA5, "alloc_large: value");
        core::mem::drop(arr);
    }
    assert_eq(pmm().free_pages(), fb, "alloc_large: pages leaked");
}

fn test_alloc_zeroed() {
    let fb = pmm().free_pages();
    {
        let layout = Layout::from_size_align(128, 8).unwrap();
        unsafe {
            let ptr = alloc::alloc::alloc_zeroed(layout);
            assert(!ptr.is_null(), "alloc_zeroed: null");
            for i in 0..128 {
                assert(*ptr.add(i) == 0, "alloc_zeroed: not zeroed");
            }
            alloc::alloc::dealloc(ptr, layout);
        }
    }
    assert_eq(pmm().free_pages(), fb, "alloc_zeroed: pages leaked");
}

fn test_realloc_grow() {
    let fb = pmm().free_pages();
    {
        let layout_small = Layout::from_size_align(32, 8).unwrap();
        let layout_big = Layout::from_size_align(256, 8).unwrap();
        
        unsafe {
            let ptr = alloc::alloc::alloc(layout_small);
            assert(!ptr.is_null(), "realloc_grow: alloc small");
            core::ptr::write_bytes(ptr, 0x42, 32);
            
            let new_ptr = alloc::alloc::realloc(ptr, layout_small, 256);
            assert(!new_ptr.is_null(), "realloc_grow: realloc");
            
            for i in 0..32 {
                assert(*new_ptr.add(i) == 0x42, "realloc_grow: data preserved");
            }
            
            alloc::alloc::dealloc(new_ptr, layout_big);
        }
    }
    assert_eq(pmm().free_pages(), fb, "realloc_grow: pages leaked");
}

fn test_realloc_shrink() {
    let fb = pmm().free_pages();
    {
        let layout_big = Layout::from_size_align(512, 8).unwrap();
        let layout_small = Layout::from_size_align(64, 8).unwrap();
        
        unsafe {
            let ptr = alloc::alloc::alloc(layout_big);
            assert(!ptr.is_null(), "realloc_shrink: alloc big");
            core::ptr::write_bytes(ptr, 0x99, 512);
            
            let new_ptr = alloc::alloc::realloc(ptr, layout_big, 64);
            assert(!new_ptr.is_null(), "realloc_shrink: realloc");
            
            for i in 0..64 {
                assert(*new_ptr.add(i) == 0x99, "realloc_shrink: data preserved");
            }
            
            alloc::alloc::dealloc(new_ptr, layout_small);
        }
    }
    assert_eq(pmm().free_pages(), fb, "realloc_shrink: pages leaked");
}

fn test_alloc_free_stress() {
    let fb = pmm().free_pages();
    
    let mut ptrs: [usize; 128] = [0; 128];
    let mut sizes: [usize; 128] = [0; 128];
    let sizes_pool = [8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096];
    
    for i in 0..128 {
        let size = sizes_pool[i % sizes_pool.len()];
        let layout = Layout::from_size_align(size, 8).unwrap();
        unsafe {
            let ptr = alloc::alloc::alloc(layout);
            assert(!ptr.is_null(), "stress: alloc null");
            core::ptr::write_bytes(ptr, (i as u8), size);
            ptrs[i] = ptr as usize;
            sizes[i] = size;
        }
    }
    
    let after_alloc = pmm().free_pages();
    
    // Фаза 2: освобождаем всё
    for i in 0..128 {
        if ptrs[i] != 0 {
            let layout = Layout::from_size_align(sizes[i], 8).unwrap();
            unsafe {
                alloc::alloc::dealloc(ptrs[i] as *mut u8, layout);
            }
        }
    }
    
    let before_realloc = pmm().free_pages();
    
    let mut new_ptrs: [usize; 128] = [0; 128];
    for i in 0..128 {
        let size = sizes_pool[i % sizes_pool.len()];
        let layout = Layout::from_size_align(size, 8).unwrap();
        unsafe {
            let ptr = alloc::alloc::alloc(layout);
            assert(!ptr.is_null(), "stress: re-alloc null");
            new_ptrs[i] = ptr as usize;
        }
    }
    
    let after_realloc = pmm().free_pages();
    
    let new_pages_used = before_realloc - after_realloc;
    assert(new_pages_used < 32, "stress: slab didn't reuse pages");
    
    for i in 0..128 {
        if new_ptrs[i] != 0 {
            let layout = Layout::from_size_align(sizes_pool[i % sizes_pool.len()], 8).unwrap();
            unsafe {
                alloc::alloc::dealloc(new_ptrs[i] as *mut u8, layout);
            }
        }
    }
    
    early_println!("[ALLOC] stress: slab cached pages OK");
}