use spin::{Mutex};
use x2apic::ioapic::{IoApic, IrqFlags, IrqMode, RedirectionTableEntry};
use x86_64::{PhysAddr, VirtAddr, structures::paging::{Page, PageTableFlags, Size4KiB}};

use crate::{arch::amd64::{memory::{misc::phys_to_virt, vmm::kmap_mmio_page}}};


pub struct IOApic {
    ioapic: Mutex<IoApic>,
    gsi_base: u32,
    max_entries: u32,
}

impl IOApic {
    pub fn new(id: u8, gsi_base: u32, regs_phys_addr: PhysAddr) -> Self {
        let ioapic_converted = VirtAddr::new(phys_to_virt(regs_phys_addr.as_u64() as usize) as u64);
        let page = Page::<Size4KiB>::containing_address(ioapic_converted);
        let aligned_virt_addr = page.start_address();
        let flags = PageTableFlags::PRESENT 
            | PageTableFlags::WRITABLE 
            | PageTableFlags::NO_CACHE;
        kmap_mmio_page(aligned_virt_addr, regs_phys_addr, flags);

        unsafe {
            let mut ioapic = IoApic::new(aligned_virt_addr.as_u64());
            ioapic.set_id(id);
            let max_entries = ioapic.max_table_entry() as u32;

            for pin in 0..=max_entries as u8 {
                ioapic.disable_irq(pin);
            }

            Self {
                ioapic: Mutex::new(ioapic),
                gsi_base,
                max_entries,
            }
        }
    }

    pub fn setup_irq(&self, pin: u8, vector: u8, mode: IrqMode, flags: IrqFlags, dest: u8) {
        let mut entry = RedirectionTableEntry::default();
        entry.set_vector(vector);
        entry.set_mode(mode);
        entry.set_flags(flags);
        entry.set_dest(dest);
        unsafe {
            self.ioapic.lock().set_table_entry(pin, entry);
        }
    }

    pub fn enable_irq(&self, irq_num: u8) {
        unsafe {
            self.ioapic.lock().enable_irq(irq_num);
        }
    }

    pub fn disable_irq(&self, irq_num: u8) {
        unsafe {
            self.ioapic.lock().disable_irq(irq_num);
        }
    }

    pub fn handles_gsi(&self, gsi: u32) -> bool {
        gsi >= self.gsi_base && gsi <= self.gsi_base + self.max_entries
    }

    pub fn gsi_to_pin(&self, gsi: u32) -> u8 {
        (gsi - self.gsi_base) as u8
    }
}