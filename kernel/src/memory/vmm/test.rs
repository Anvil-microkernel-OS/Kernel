use crate::{arch::CurrentMemArchSpec, memory::{
    misc::{arch_specific::Arch as _, primitives::{PhysAddr, VirtAddr}},
    pmm::{node::AllocFlags, pmm},
    vmm::{kernel_pt_mapper, pflags::PFlags},
}, serial_println};

struct Test {
    a: u64,
    b: u64,
}

const PAGE_SIZE: usize = CurrentMemArchSpec::PAGE_SIZE;

fn test_vaddr(n: usize) -> VirtAddr {
    VirtAddr::new(0x10_0000 + n * PAGE_SIZE)
}

pub fn run_vmm_tests() {
    serial_println!("=== VMM Tests ===");

    test_map_and_readwrite();
    test_map_multiple_pages();
    test_translate();
    test_remap_flags();
    test_unmap();
    test_unmap_then_remap();
    test_map_contiguous_region();
    test_write_pattern_full_page();
    test_isolation_between_pages();

    serial_println!("=== All VMM tests passed! ===");
}

fn test_map_and_readwrite() {
    let virt = test_vaddr(0);
    let phys = pmm().alloc_page(AllocFlags::ZEROED).unwrap();
    let flags = PFlags::new().write(true);

    kernel_pt_mapper()
        .map_phys(virt, phys, flags)
        .expect("map failed")
        .flush();

    unsafe {
        let ptr = virt.as_mut_ptr() as *mut u64;
        ptr.write_volatile(0xDEAD_BEEF_CAFE_BABE);
        assert_eq!(ptr.read_volatile(), 0xDEAD_BEEF_CAFE_BABE);
    }

    kernel_pt_mapper().unmap_phys(virt).unwrap().2.flush();
    pmm().free_page(phys);

    serial_println!("  [PASS] map_and_readwrite");
}

fn test_map_multiple_pages() {
    let count = 8;
    let mut pages = [(VirtAddr::new(0), PhysAddr::new(0)); 8];

    for i in 0..count {
        let virt = test_vaddr(10 + i);
        let phys = pmm().alloc_page(AllocFlags::ZEROED).unwrap();
        let flags = PFlags::new().write(true);

        kernel_pt_mapper()
            .map_phys(virt, phys, flags)
            .expect("map failed")
            .flush();

        unsafe {
            let ptr = virt.as_mut_ptr() as *mut u64;
            ptr.write_volatile(i as u64);
        }

        pages[i] = (virt, phys);
    }

    for i in 0..count {
        unsafe {
            let ptr = pages[i].0.as_mut_ptr() as *const u64;
            assert_eq!(ptr.read_volatile(), i as u64, "page {} corrupted", i);
        }
    }

    // cleanup
    for i in 0..count {
        kernel_pt_mapper().unmap_phys(pages[i].0).unwrap().2.flush();
        pmm().free_page(pages[i].1);
    }

    serial_println!("  [PASS] map_multiple_pages");
}

fn test_translate() {
    let virt = test_vaddr(20);
    let phys = pmm().alloc_page(AllocFlags::ZEROED).unwrap();
    let flags = PFlags::new().write(true).execute(true);

    kernel_pt_mapper()
        .map_phys(virt, phys, flags)
        .expect("map failed")
        .flush();

    let (translated_phys, translated_flags) = kernel_pt_mapper()
        .translate(virt)
        .expect("translate failed");

    assert_eq!(translated_phys.as_usize(), phys.as_usize(), "phys mismatch");
    assert!(translated_flags.has_write(), "write flag missing");

    // cleanup
    kernel_pt_mapper().unmap_phys(virt).unwrap().2.flush();
    pmm().free_page(phys);

    serial_println!("  [PASS] translate");
}

fn test_remap_flags() {
    let virt = test_vaddr(30);
    let phys = pmm().alloc_page(AllocFlags::ZEROED).unwrap();
    let flags_rw = PFlags::new().write(true);

    kernel_pt_mapper()
        .map_phys(virt, phys, flags_rw)
        .expect("map failed")
        .flush();

    unsafe {
        (virt.as_mut_ptr() as *mut u64).write_volatile(0x1234);
    }

    let flags_ro = PFlags::new().write(false);
    kernel_pt_mapper()
        .remap(virt, flags_ro)
        .expect("remap failed")
        .flush();

    let (t_phys, t_flags) = kernel_pt_mapper().translate(virt).unwrap();
    assert_eq!(t_phys.as_usize(), phys.as_usize(), "phys changed after remap");
    assert!(!t_flags.has_write(), "write flag should be cleared");

    unsafe {
        assert_eq!((virt.as_mut_ptr() as *const u64).read_volatile(), 0x1234);
    }

    kernel_pt_mapper().unmap_phys(virt).unwrap().2.flush();
    pmm().free_page(phys);

    serial_println!("  [PASS] remap_flags");
}

fn test_unmap() {
    let virt = test_vaddr(40);
    let phys = pmm().alloc_page(AllocFlags::ZEROED).unwrap();
    let flags = PFlags::new().write(true);

    kernel_pt_mapper()
        .map_phys(virt, phys, flags)
        .expect("map failed")
        .flush();

    let (unmapped_phys, _, flush) = kernel_pt_mapper()
        .unmap_phys(virt)
        .expect("unmap failed");
    flush.flush();

    assert_eq!(unmapped_phys.as_usize(), phys.as_usize(), "unmap returned wrong phys");
    assert!(kernel_pt_mapper().translate(virt).is_none(), "translate should be None after unmap");

    pmm().free_page(phys);

    serial_println!("  [PASS] unmap");
}

fn test_unmap_then_remap() {
    let virt = test_vaddr(50);

    let phys1 = pmm().alloc_page(AllocFlags::ZEROED).unwrap();
    kernel_pt_mapper()
        .map_phys(virt, phys1, PFlags::new().write(true))
        .unwrap()
        .flush();

    unsafe { (virt.as_mut_ptr() as *mut u64).write_volatile(0xAAAA); }

    kernel_pt_mapper().unmap_phys(virt).unwrap().2.flush();

    let phys2 = pmm().alloc_page(AllocFlags::ZEROED).unwrap();
    kernel_pt_mapper()
        .map_phys(virt, phys2, PFlags::new().write(true))
        .unwrap()
        .flush();

    unsafe {
        let val = (virt.as_mut_ptr() as *const u64).read_volatile();
        assert_ne!(val, 0xAAAA, "stale data from old mapping");
    }

    kernel_pt_mapper().unmap_phys(virt).unwrap().2.flush();
    pmm().free_page(phys1);
    pmm().free_page(phys2);

    serial_println!("  [PASS] unmap_then_remap");
}

fn test_map_contiguous_region() {
    let count = 4;
    let mut addrs = [(PhysAddr::new(0), VirtAddr::new(0)); 4];

    for i in 0..count {
        let phys = pmm().alloc_page(AllocFlags::ZEROED).unwrap();
        let flags = PFlags::new().write(true);

        let (virt, flush) = kernel_pt_mapper()
            .map_linearly(phys, flags)
            .expect("map_linearly failed");
        flush.flush();

        unsafe {
            (virt.as_mut_ptr() as *mut u64).write_volatile(0xF00D + i as u64);
        }

        addrs[i] = (phys, virt);
    }

    for i in 0..count {
        unsafe {
            let val = (addrs[i].1.as_mut_ptr() as *const u64).read_volatile();
            assert_eq!(val, 0xF00D + i as u64);
        }
    }

    for i in 0..count {
        pmm().free_page(addrs[i].0);
    }

    serial_println!("  [PASS] map_contiguous_region");
}

fn test_write_pattern_full_page() {
    let virt = test_vaddr(60);
    let phys = pmm().alloc_page(AllocFlags::ZEROED).unwrap();

    kernel_pt_mapper()
        .map_phys(virt, phys, PFlags::new().write(true))
        .unwrap()
        .flush();

    let count = PAGE_SIZE / core::mem::size_of::<u64>();
    unsafe {
        let base = virt.as_mut_ptr() as *mut u64;
        for i in 0..count {
            base.add(i).write_volatile(i as u64);
        }
        for i in 0..count {
            assert_eq!(base.add(i).read_volatile(), i as u64, "mismatch at offset {}", i);
        }
    }

    kernel_pt_mapper().unmap_phys(virt).unwrap().2.flush();
    pmm().free_page(phys);

    serial_println!("  [PASS] write_pattern_full_page");
}

fn test_isolation_between_pages() {
    let virt_a = test_vaddr(70);
    let virt_b = test_vaddr(71);
    let phys_a = pmm().alloc_page(AllocFlags::ZEROED).unwrap();
    let phys_b = pmm().alloc_page(AllocFlags::ZEROED).unwrap();
    let flags = PFlags::new().write(true);

    kernel_pt_mapper().map_phys(virt_a, phys_a, flags).unwrap().flush();
    kernel_pt_mapper().map_phys(virt_b, phys_b, flags).unwrap().flush();

    unsafe {
        (virt_a.as_mut_ptr() as *mut u64).write_volatile(0x1111);
        (virt_b.as_mut_ptr() as *mut u64).write_volatile(0x2222);

        assert_eq!((virt_a.as_mut_ptr() as *const u64).read_volatile(), 0x1111);
        assert_eq!((virt_b.as_mut_ptr() as *const u64).read_volatile(), 0x2222);
    }

    kernel_pt_mapper().unmap_phys(virt_a).unwrap().2.flush();
    kernel_pt_mapper().unmap_phys(virt_b).unwrap().2.flush();
    pmm().free_page(phys_a);
    pmm().free_page(phys_b);

    serial_println!("  [PASS] isolation_between_pages");
}