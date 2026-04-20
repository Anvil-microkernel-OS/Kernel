use core::{mem::MaybeUninit, ptr};


use x86_64::{
    VirtAddr, instructions::tables::load_tss, registers::{
        model_specific::Star,
        segmentation::{CS, DS, ES, FS, GS, SS, Segment},
    }, structures::{
        gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector},
        tss::TaskStateSegment,
    }
};

#[repr(C)]
pub struct TssWithIopb {
    pub tss: TaskStateSegment,
    pub iopb: [u8; 8192],
    pub terminal: u8, 
}

impl TssWithIopb {
    pub const fn new() -> Self {
        let tss = TaskStateSegment::new();
        Self {
            tss,
            iopb: [0xFF; 8192], 
            terminal: 0xFF,
        }
    }

    pub fn enable_iopb(&mut self) {
        self.tss.iomap_base = size_of::<TaskStateSegment>() as u16;
    }

    pub fn disable_iopb(&mut self) {
        self.tss.iomap_base = u16::MAX;
    }

    pub fn copy_from(&mut self, permissions: &[u8; 8192]) {
        self.iopb.copy_from_slice(permissions);
    }
}

use crate::{define_per_cpu_struct};

pub(crate) const DOUBLE_FAULT_IST_INDEX: u16 = 0;
pub(crate) const PAGE_FAULT_IST_INDEX: u16 = 1;

const TSS_STACK_SIZE_BYTES: usize = 4096 * 5;

pub(crate) const KERNEL_CODE_SELECTOR: SegmentSelector =
    SegmentSelector::new(1, x86_64::PrivilegeLevel::Ring0);
pub(crate) const KERNEL_DATA_SELECTOR: SegmentSelector =
    SegmentSelector::new(2, x86_64::PrivilegeLevel::Ring0);
pub(crate) const USER_DATA_SELECTOR: SegmentSelector =
    SegmentSelector::new(3, x86_64::PrivilegeLevel::Ring3);
pub(crate) const USER_CODE_SELECTOR: SegmentSelector =
    SegmentSelector::new(4, x86_64::PrivilegeLevel::Ring3);
pub(crate) const TSS_SELECTOR: SegmentSelector =
    SegmentSelector::new(5, x86_64::PrivilegeLevel::Ring0);

static mut BOOTSTRAP_GDT: MaybeUninit<GlobalDescriptorTable> = MaybeUninit::uninit();
static mut BOOTSTRAP_TSS: MaybeUninit<TaskStateSegment> = MaybeUninit::uninit();

static mut BOOTSTRAP_DOUBLE_FAULT_STACK: [u8; TSS_STACK_SIZE_BYTES] = [0; TSS_STACK_SIZE_BYTES];
static mut BOOTSTRAP_PAGE_FAULT_STACK: [u8; TSS_STACK_SIZE_BYTES] = [0; TSS_STACK_SIZE_BYTES];

fn stack_top_ptr_raw(stack: *const u8) -> VirtAddr {
    let start = VirtAddr::from_ptr(stack);
    start + TSS_STACK_SIZE_BYTES as u64
}

fn build_gdt(tss: &'static TaskStateSegment) -> GlobalDescriptorTable {
    let mut gdt = GlobalDescriptorTable::new();

    let kernel_code_selector = gdt.append(Descriptor::kernel_code_segment());
    let kernel_data_selector = gdt.append(Descriptor::kernel_data_segment());
    let user_data_selector = gdt.append(Descriptor::user_data_segment());
    let user_code_selector = gdt.append(Descriptor::user_code_segment());
    let tss_selector = gdt.append(Descriptor::tss_segment(tss));

    assert_eq!(kernel_code_selector, KERNEL_CODE_SELECTOR);
    assert_eq!(kernel_data_selector, KERNEL_DATA_SELECTOR);
    assert_eq!(user_data_selector, USER_DATA_SELECTOR);
    assert_eq!(user_code_selector, USER_CODE_SELECTOR);
    assert_eq!(tss_selector, TSS_SELECTOR);

    gdt
}

fn load_gdt_and_segments(gdt: &'static GlobalDescriptorTable) {
    gdt.load();

    unsafe {
        CS::set_reg(KERNEL_CODE_SELECTOR);
        DS::set_reg(KERNEL_DATA_SELECTOR);
        load_tss(TSS_SELECTOR);

        ES::set_reg(SegmentSelector(0));
        FS::set_reg(SegmentSelector(0));
        GS::set_reg(SegmentSelector(0));
        SS::set_reg(SegmentSelector(0));
    }
}

fn create_bootstrap_tss() -> TaskStateSegment {
    let mut tss = TaskStateSegment::new();
    tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] =
            stack_top_ptr_raw((&raw const BOOTSTRAP_DOUBLE_FAULT_STACK) as *const u8);

    tss.interrupt_stack_table[PAGE_FAULT_IST_INDEX as usize] =
            stack_top_ptr_raw((&raw const BOOTSTRAP_PAGE_FAULT_STACK) as *const u8);
    tss
}

pub fn init_bootstrap_gdt() {
    unsafe {
        let tss_slot: *mut MaybeUninit<TaskStateSegment> = ptr::addr_of_mut!(BOOTSTRAP_TSS);
        let gdt_slot: *mut MaybeUninit<GlobalDescriptorTable> = ptr::addr_of_mut!(BOOTSTRAP_GDT);

        ptr::write(tss_slot, MaybeUninit::new(create_bootstrap_tss()));

        let tss_ptr: *const TaskStateSegment = (*tss_slot).as_ptr();

        ptr::write(gdt_slot, MaybeUninit::new(build_gdt(&*tss_ptr)));

        let gdt_ptr: *const GlobalDescriptorTable = (*gdt_slot).as_ptr();
        load_gdt_and_segments(&*gdt_ptr);
    }
}

define_per_cpu_struct! {
    pub struct PercpuGdt {
        pub gdt: MaybeUninit<GlobalDescriptorTable>,
        pub tss: MaybeUninit<TssWithIopb>,
        pub pgf_stack: [u8; TSS_STACK_SIZE_BYTES],
        pub df_stack: [u8; TSS_STACK_SIZE_BYTES],
        pub kernel_stack: [u8; TSS_STACK_SIZE_BYTES],

        pub sel_kcode: MaybeUninit<SegmentSelector>,
        pub sel_kdata: MaybeUninit<SegmentSelector>,
        pub sel_ucode: MaybeUninit<SegmentSelector>,
        pub sel_udata: MaybeUninit<SegmentSelector>,
        pub sel_tss:  MaybeUninit<SegmentSelector>,
    }
}

pub const IO_PORTS: usize = 8192;

pub fn set_tss_rsp0(rsp0: VirtAddr) {
    PercpuGdt::with_guard(|local_gdt| {
        unsafe {
            let tss = &mut *local_gdt.tss.as_mut_ptr();
            tss.tss.privilege_stack_table[0] = rsp0;
        }
    });
}

pub fn set_tss_iopb_enabled(enabled: bool) {
    PercpuGdt::with_guard(|local_gdt| {
        unsafe {
            let tss = &mut *local_gdt.tss.as_mut_ptr();
            if enabled {
                tss.enable_iopb();
            } else {
                tss.disable_iopb();
            }
        }
    });
}

pub fn tss_copy_iopb_data(slice: &[u8; IO_PORTS]) {
    PercpuGdt::with_guard(|local_gdt| {
        unsafe {
            let tss = &mut *local_gdt.tss.as_mut_ptr();
            tss.copy_from(slice);
        }
    });
}

fn tss_descriptor_with_iopb(tss: &'static TaskStateSegment) -> Descriptor {
    let ptr = tss as *const _ as u64;
    let limit = (size_of::<TssWithIopb>() - 1) as u64; 
    
    let lo = limit & 0xFFFF                          
        | (ptr & 0xFF_FFFF) << 16                   
        | 0x0000_8900_0000_0000                      
        | ((limit >> 16) & 0xF) << 48               
        | (ptr >> 24 & 0xFF) << 56;                  
    
    let hi = ptr >> 32;
    
    Descriptor::SystemSegment(lo, hi) 
}

pub fn setup_gdt_for_local_core() {
    PercpuGdt::with_guard(|local_gdt| {
        let df_stack_top = VirtAddr::from_ptr(local_gdt.df_stack.as_ptr())
            + TSS_STACK_SIZE_BYTES as u64;
        let pgf_stack_top = VirtAddr::from_ptr(local_gdt.pgf_stack.as_ptr())
            + TSS_STACK_SIZE_BYTES as u64;

        let kernel_stack_top = VirtAddr::from_ptr(local_gdt.kernel_stack.as_ptr())
            + TSS_STACK_SIZE_BYTES as u64;

        let mut tss = TssWithIopb::new();
        tss.tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = df_stack_top;
        tss.tss.interrupt_stack_table[PAGE_FAULT_IST_INDEX as usize] = pgf_stack_top;
        tss.tss.privilege_stack_table[0]  = kernel_stack_top;

        unsafe {
            local_gdt.tss.as_mut_ptr().write(tss);

           let tss_ref: &'static TaskStateSegment = &(*local_gdt.tss.as_ptr()).tss;

            let mut gdt = GlobalDescriptorTable::new();

            let sel_kcode = gdt.append(Descriptor::kernel_code_segment());
            let sel_kdata = gdt.append(Descriptor::kernel_data_segment());
            let sel_udata = gdt.append(Descriptor::user_data_segment());
            let sel_ucode = gdt.append(Descriptor::user_code_segment());

            let sel_tss   = gdt.append(tss_descriptor_with_iopb(tss_ref));

            local_gdt.sel_kcode.as_mut_ptr().write(sel_kcode);
            local_gdt.sel_kdata.as_mut_ptr().write(sel_kdata);
            local_gdt.sel_ucode.as_mut_ptr().write(sel_ucode);
            local_gdt.sel_udata.as_mut_ptr().write(sel_udata);
            local_gdt.sel_tss.as_mut_ptr().write(sel_tss);

            local_gdt.gdt.as_mut_ptr().write(gdt);

            (&*local_gdt.gdt.as_ptr()).load();

            CS::set_reg(sel_kcode);

            SS::set_reg(sel_kdata);

            DS::set_reg(sel_kdata);
            ES::set_reg(sel_kdata);
            
            load_tss(sel_tss);
        }
        Star::write(
            unsafe { *local_gdt.sel_ucode.as_ptr() },
            unsafe { *local_gdt.sel_udata.as_ptr() },
            unsafe { *local_gdt.sel_kcode.as_ptr() },
            unsafe { *local_gdt.sel_kdata.as_ptr() },
        )
        .unwrap_or_else(|err| panic!("Failed to set STAR: {err}"));
    });
}
