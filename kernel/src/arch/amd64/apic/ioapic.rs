use bitfield_struct::bitfield;
use x86_64::{PhysAddr, VirtAddr, structures::paging::{Page, PageTableFlags, Size4KiB}};

use crate::{arch::amd64::{acpi::{get_acpi_tables, madt::MadTable}, memory::{misc::phys_to_virt, vmm::kmap_mmio_page}}, misc::registers::RegisterRW, register_struct};

const IOAPIC_ID_REGISTER_OFFSET: u8 = 0x00;

#[bitfield(u32)]
pub struct IOAPICID {
    #[bits(24)]
    __reserved: u32,
    #[bits(4)]
    pub id: u8,
    #[bits(4)]
    __reserved: u8,
}

pub const IOAPIC_REDIRECTION_TABLE_REGISTER_OFFSET: u8 = 0x10;

#[bitfield(u64)]
pub struct IOAPICRedirectionTableRegister {
    pub interrupt_vector: u8,
    #[bits(3)]
    pub delivery_mode: u8,
    pub destination_mode: bool,
    pub delivery_status: bool,
    pub interrupt_input_pin_polarity: bool,
    pub remote_irr: bool,
    pub trigger_mode: bool,
    pub interrupt_mask: bool,
    #[bits(39)]
    __reserved: u64,
    pub destination_field: u8,
}

const IOAPIC_VER_REGISTER_OFFSET: u8 = 0x01;
#[bitfield(u32)]
pub struct IOAPICVer {
    pub apic_version: u8,
    __reserved0: u8,
    pub max_redirection_entry: u8,
    __reserved1: u8,
}

register_struct! {
    IOApicRegisters {
        0x00 => io_reg_select: RegisterRW<u8>,
        0x10 => io_window: RegisterRW<u32>
    }
}

pub struct IOApic {
    id: u8,
    gsi_base: u32,
    registers: IOApicRegisters,
    num_redir_entries: u32,
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

        let registers = unsafe { IOApicRegisters::from_address(aligned_virt_addr.as_u64() as usize) };

        registers.io_reg_select().write(IOAPIC_VER_REGISTER_OFFSET);
        let ver_raw = registers.io_window().read();
        let ver = IOAPICVer::from(ver_raw);
        let num_redir_entries = ver.max_redirection_entry() as u32 + 1;

        Self {
            id,
            gsi_base,
            registers,
            num_redir_entries
        }
    }

    
    pub fn num_redir_entries(&self) -> u32 {
        self.num_redir_entries
    }

    pub fn ioapic_ver(&self) -> IOAPICVer {
        let raw = self.read_32b_from_reg(IOAPIC_VER_REGISTER_OFFSET);
        IOAPICVer::from(raw)
    }

    pub fn read_32b_from_reg(&self, reg: u8) -> u32 {
        self.registers.io_reg_select().write(reg);
        self.registers.io_window().read()
    }

    pub fn read_64b_from_reg(&self, reg: u8) -> u64 {
        let low = self.read_32b_from_reg(reg);
        let high = self.read_32b_from_reg(((reg as u16) + 1) as u8);
        (u64::from(high) << 32) | u64::from(low)
    }

    pub fn write_32b_to_reg(&self, register: u8, value: u32) {
        self.registers.io_reg_select().write(register);
        self.registers.io_window().write(value);
    }

    pub fn write_64b_to_reg(&self, register: u8, value: u64) {
        let low = value as u32;
        let high = (value >> 32) as u32;
        self.write_32b_to_reg(register, low);
        self.write_32b_to_reg(register + 1, high);
    }

    pub fn ioapic_id(&self) -> IOAPICID {
        let raw = self.read_32b_from_reg(IOAPIC_ID_REGISTER_OFFSET);
        IOAPICID::from(raw)
    }

    fn set_pin_mask(&self, pin: u8, masked: bool) {
        assert!((pin as u32) < self.num_redir_entries(), "pin out of range");
        let reg_index = IOAPIC_REDIRECTION_TABLE_REGISTER_OFFSET + pin * 2;
        let raw = self.read_64b_from_reg(reg_index);
        let mut entry = IOAPICRedirectionTableRegister::from(raw);
        entry.set_interrupt_mask(masked);
        self.write_ioredtbl(pin, entry);
    }

    pub fn mask_pin(&self, pin: u8)   { self.set_pin_mask(pin, true);  }
    pub fn unmask_pin(&self, pin: u8) { self.set_pin_mask(pin, false); }

    pub fn handles_gsi(&self, gsi: u32) -> bool {
        gsi >= self.gsi_base && gsi < self.gsi_base + self.num_redir_entries()
    }

    pub fn gsi_to_pin(&self, gsi: u32) -> Option<u8> {
        if self.handles_gsi(gsi) {
            Some((gsi - self.gsi_base) as u8)
        } else {
            None
        }
    }

    pub fn write_ioredtbl(&self, entry: u8, value: IOAPICRedirectionTableRegister) {
        assert!(
            (entry as u32) < self.num_redir_entries,
            "IOAPIC entry {} >= num_redir_entries {}",
            entry, self.num_redir_entries
        );
        let offset = IOAPIC_REDIRECTION_TABLE_REGISTER_OFFSET + (entry * 2);
        self.write_64b_to_reg(offset, value.into());
    }
}