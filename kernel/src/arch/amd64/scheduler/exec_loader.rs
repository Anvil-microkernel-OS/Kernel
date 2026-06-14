use core::{arch::naked_asm, cell::UnsafeCell, sync::atomic::{AtomicI32, AtomicU32, AtomicU64}};
use alloc::{string::String, sync::Arc};
use spin::{Mutex, rwlock::RwLock};
use x86_64::{PhysAddr, VirtAddr, instructions::interrupts, registers::control::Cr3, structures::paging::{Mapper, OffsetPageTable, Page, PageTable, PageTableFlags, PhysFrame, Size4KiB}};

use crate::{arch::amd64::{
    capability_sys::{capability::{CapType, Capability, Rights}, cnode::CNode}, memory::{
        misc::{align_up, pages_to_order, phys_to_virt, virt_to_phys},
        pmm::{HHDM_OFFSET, pages_allocator::{PAllocFlags, alloc_pages_by_order}},
        vmm::{KernelFrameAllocator, PAGE_SIZE, create_new_pt4_from_kernel_pt4, kernel_pt},
    }, scheduler::{
        addr_space::AddrSpace,
        stack::{DEFAULT_KERNEL_STACK_SIZE, allocate_kernel_stack},
        task::{AtomicThreadState, Pid, Process, RunsOnApicId, Thread, ThreadRegisters, ThreadState, Tid},
    }
}, early_println, isolation::{domain::{self, Domain}, root_domain}};

const RFLAGS_WITH_IR: u64 = 0x202;
pub const USER_STACK_PAGES_COUNT: usize = 4;
pub const USER_STACK_TOP_VIRT_ADDR: u64 = 0x7FFF_FFFF_0000;
pub const USER_LOAD_VADDR:    u64 = 0x0040_0000;
pub const USER_ENTRY_VADDR:   u64 = USER_LOAD_VADDR;
pub const USER_CPIO_START_VADDR: u64 = 0x7FFF_F000_0000;

pub fn phys_to_offset_page_table(table: PhysAddr) -> OffsetPageTable<'static> {
    let phys_offset = kernel_pt().lock().phys_offset();
    let virt = phys_offset + table.as_u64();
    let page_table_ptr = virt.as_mut_ptr::<PageTable>();
    unsafe { OffsetPageTable::new(&mut *page_table_ptr, phys_offset) }
}


#[repr(C)]
pub struct InitSvrsBootInfo {
    pub self_vspace_cap: u64,
    pub self_cnode_cap:  u64,
    pub self_thread_cap: u64,
    pub self_proc_cap: u64,
    pub self_domain_cap: u64,
    pub cpio_base_addr:  u64,
    pub cpio_size:       u64,
}

pub fn make_init_caps(proc: &Arc<Process>, thread: &Arc<Thread>, cnode: &CNode, domain: &Arc<Domain>) -> InitSvrsBootInfo {
    let self_vspace_cap = cnode.alloc(Capability::new(CapType::VSpace(proc.clone()), Rights::all())) as u64;
    let self_cnode_cap  = cnode.alloc(Capability::new(CapType::CNode(proc.clone()),  Rights::all())) as u64;
    let self_thread_cap = cnode.alloc(Capability::new(CapType::Thread(thread.clone()),  Rights::all())) as u64;
    let self_proc_cap   = cnode.alloc(Capability::new(CapType::Process(proc.clone()),  Rights::all())) as u64;
    let self_domain_cap      = cnode.alloc(Capability::new(CapType::Domain(domain.clone()), Rights::all())) as u64;

    InitSvrsBootInfo {
        self_vspace_cap,
        self_cnode_cap,
        self_thread_cap,
        self_proc_cap,
        self_domain_cap,
        cpio_base_addr: 0,
        cpio_size: 0,
    }
}

pub fn make_init_task(
    bytes: &[u8],
    pid: Pid,
    tid: Tid,
    name: &'static str,
    cpio: &[u8],
) -> Result<(Arc<Process>, Arc<Thread>), &'static str> {
    let new_pml4_phys = create_new_pt4_from_kernel_pt4();
    let mut pt = phys_to_offset_page_table(new_pml4_phys);

    let page_count = bytes.len().div_ceil(PAGE_SIZE);
    for i in 0..page_count {
        let va    = VirtAddr::new(USER_LOAD_VADDR + (i * PAGE_SIZE) as u64);
        let page  = Page::<Size4KiB>::containing_address(va);
        let phys  = alloc_pages_by_order(0, PAllocFlags::KERNEL | PAllocFlags::ZEROED)
            .expect("make_init_task: OOM");
        let frame = PhysFrame::<Size4KiB>::containing_address(phys);

        let src_offset = i * PAGE_SIZE;
        let src_end    = (src_offset + PAGE_SIZE).min(bytes.len());
        unsafe {
            let dst = phys_to_virt(phys.as_u64() as usize) as *mut u8;
            core::ptr::copy_nonoverlapping(bytes.as_ptr().add(src_offset), dst, src_end - src_offset);
            pt.map_to(page, frame,
                PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE | PageTableFlags::WRITABLE,
                &mut KernelFrameAllocator)
                .unwrap().flush();
        }
    }

    let order           = pages_to_order(USER_STACK_PAGES_COUNT);
    let stack_bottom_phys = alloc_pages_by_order(order, PAllocFlags::KERNEL | PAllocFlags::ZEROED)
        .expect("make_init_task: stack OOM");
    let stack_size   = PAGE_SIZE * USER_STACK_PAGES_COUNT;
    let stack_top_va = USER_STACK_TOP_VIRT_ADDR;
    let stack_bot_va = stack_top_va - stack_size as u64;
    let stack_flags  = PageTableFlags::PRESENT
        | PageTableFlags::USER_ACCESSIBLE
        | PageTableFlags::WRITABLE
        | PageTableFlags::NO_EXECUTE;

    let stack_bot_page = Page::<Size4KiB>::containing_address(VirtAddr::new(stack_bot_va));
    let stack_top_page = Page::<Size4KiB>::containing_address(VirtAddr::new(stack_top_va - 1));
    let mut curr_phys  = stack_bottom_phys.as_u64();
    for page in Page::range_inclusive(stack_bot_page, stack_top_page) {
        let frame = PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(curr_phys));
        curr_phys += PAGE_SIZE as u64;
        unsafe {
            pt.map_to(page, frame, stack_flags, &mut KernelFrameAllocator).unwrap().flush();
        }
    }

    let cpio_phys_base  = virt_to_phys(cpio.as_ptr() as usize);
    let cpio_page_start = Page::<Size4KiB>::containing_address(VirtAddr::new(USER_CPIO_START_VADDR));
    let cpio_page_end   = Page::<Size4KiB>::containing_address(
        VirtAddr::new(USER_CPIO_START_VADDR + align_up(cpio.len(), PAGE_SIZE) as u64 - 1)
    );
    for (i, page) in Page::range_inclusive(cpio_page_start, cpio_page_end).enumerate() {
        let phys  = PhysAddr::new(cpio_phys_base as u64 + (i * PAGE_SIZE) as u64);
        let frame = PhysFrame::<Size4KiB>::containing_address(phys);
        unsafe { pt.map_to(page, frame, stack_flags, &mut KernelFrameAllocator).unwrap().flush(); }
    }

    let kernel_stack = allocate_kernel_stack(DEFAULT_KERNEL_STACK_SIZE);

    let root_domain = root_domain();

    let process = Arc::new(Process {
        pid,
        name: String::from(name),
        threads:          Mutex::new(alloc::vec![]),
        addr_space:       Mutex::new(AddrSpace::new(pt)),
        cnode:            CNode::new(),
        iopb_permissions: Mutex::new(None),
        iopb_gen:         AtomicU64::new(0),
        domain: root_domain.clone()
    });

    let thread = Arc::new(Thread {
        parent_proc: RwLock::new(Arc::downgrade(&process)),
        tid,
        wake_at_tick: AtomicU64::new(0),
        kernel_stack,
        registers: UnsafeCell::new(ThreadRegisters {
            rip: USER_ENTRY_VADDR,
            rsp: stack_top_va - 8,  
            ..Default::default()
        }),
        state: AtomicThreadState::new(ThreadState::Ready),
        runs_on: RunsOnApicId::new_undefined()
    });

    let mut boot_info = make_init_caps(&process, &thread, &process.cnode, root_domain);
    boot_info.cpio_base_addr = USER_CPIO_START_VADDR;
    boot_info.cpio_size      = cpio.len() as u64;

    let bootinfo_size = core::mem::size_of::<InitSvrsBootInfo>();
    let bootinfo_stack_va = stack_top_va - bootinfo_size as u64;
    let bootinfo_offset_in_stack = bootinfo_stack_va - stack_bot_va;
    let bootinfo_phys = stack_bottom_phys.as_u64() + bootinfo_offset_in_stack;

    unsafe {
        let dst = phys_to_virt(bootinfo_phys as usize) as *mut InitSvrsBootInfo;
        core::ptr::write(dst, boot_info);
    }

    unsafe {
        let regs = thread.registers.get();
        (*regs).rdi = bootinfo_stack_va;
        (*regs).rsp = bootinfo_stack_va;
    }

    prepare_new_thread(&thread);
    process.threads.lock().push(Arc::downgrade(&thread));

    Ok((process, thread))
}


pub fn make_kernel_task(pid: Pid, tid: Tid, name: &'static str, entry_point: u64) -> (Arc<Process>, Thread) {
    let (phys_frame, _) = Cr3::read();
    let phys_addr_of_pt = phys_frame.start_address();
    let hhdm_offset     = VirtAddr::new(unsafe { HHDM_OFFSET as u64 });
    let page_table = unsafe {
        let virt = phys_to_virt(phys_addr_of_pt.as_u64() as usize);
        let pml4 = &mut *(virt as *mut PageTable);
        OffsetPageTable::new(pml4, hhdm_offset)
    };

    let kernel_stack  = allocate_kernel_stack(DEFAULT_KERNEL_STACK_SIZE);
    let stack_top_ptr = kernel_stack.top.as_u64() as *mut u64;
    unsafe {
        stack_top_ptr.sub(1).write(kernel_task_trampoline as u64);
        for i in 2..=16 { stack_top_ptr.sub(i).write(0); }
        stack_top_ptr.sub(8).write(entry_point);
    }
    let initial_rsp = unsafe { stack_top_ptr.sub(16) } as u64;

    let process = Arc::new(Process {
        pid,
        name: String::from(name),
        threads:          Mutex::new(alloc::vec![]),
        addr_space:       Mutex::new(AddrSpace::new(page_table)),
        cnode:            CNode::new(),
        iopb_permissions: Mutex::new(None),
        iopb_gen:         AtomicU64::new(0),
        domain: root_domain().clone()
    });

    let thread = Thread {
        parent_proc:  RwLock::new(Arc::downgrade(&process)),
        tid,
        wake_at_tick: AtomicU64::new(0),
        kernel_stack,
        registers:    UnsafeCell::new(ThreadRegisters {
            rsp: initial_rsp,
            ..ThreadRegisters::default()
        }),
        state: AtomicThreadState::new(ThreadState::Ready),
        runs_on: RunsOnApicId::new_undefined()
    };

    (process, thread)
}

#[unsafe(naked)]
pub unsafe extern "C" fn new_thread_trampoline() {
    naked_asm!(
        "pop r15",
        "pop r14", "pop r13", "pop r12",
        "pop r11", "pop r10", "pop r9", "pop r8",
        "pop rdi", "pop rsi", "pop rbp", "pop rdx",
        "pop rcx",
        "pop rbx",
        "pop rax",
        "mov rsp, r15",
        "xor r15, r15",
        "mov r11, {rflags}",
        "swapgs",
        "sysretq",
        rflags = const RFLAGS_WITH_IR,
    );
}

pub fn prepare_new_thread(thread: &Arc<Thread>) {
    unsafe {
        let regs = &*thread.registers.get();

        let kstack_top = thread.kernel_stack.top.as_u64();
        let sp = kstack_top as *mut u64;

        sp.sub(1).write(regs.rax);   
        sp.sub(2).write(regs.rbx);   
        sp.sub(3).write(regs.rip);   
        sp.sub(4).write(regs.rdx);   
        sp.sub(5).write(regs.rbp);   
        sp.sub(6).write(regs.rsi);   
        sp.sub(7).write(regs.rdi);   
        sp.sub(8).write(regs.r8);    
        sp.sub(9).write(regs.r9);    
        sp.sub(10).write(regs.r10);  
        sp.sub(11).write(regs.r11);  
        sp.sub(12).write(regs.r12);  
        sp.sub(13).write(regs.r13);  
        sp.sub(14).write(regs.r14);   
        sp.sub(15).write(regs.rsp);  

        // ret 
        sp.sub(16).write(new_thread_trampoline as u64);

        let kregs = &mut *thread.registers.get();
        kregs.rsp = sp.sub(31) as u64;
    }
}

extern "C" fn kernel_task_trampoline(entry: u64) -> ! {
    interrupts::enable();
    let func: extern "C" fn() -> ! = unsafe { core::mem::transmute(entry) };
    func();
}