use core::{mem::MaybeUninit, ptr};

use x86_64::{VirtAddr, instructions::tables::load_tss, registers::segmentation::{CS, DS, ES, FS, GS, SS, Segment}, structures::{gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector}, tss::TaskStateSegment}};

use crate::arch::interrupt::init_table::{DOUBLE_FAULT_IST_INDEX, PAGE_FAULT_IST_INDEX};

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