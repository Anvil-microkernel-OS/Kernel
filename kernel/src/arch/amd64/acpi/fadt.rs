use acpi::{PhysicalMapping, sdt::fadt::{Fadt, FixedFeatureFlags}};
use x86_64::instructions::port::Port;
use crate::{
    arch::amd64::{
        acpi::{dsdt::DsdtTable, get_acpi_tables, main_table_parser::MainTableParser, parsed_table::AcpiParsedTable}, cpu::hlt_loop, memory::misc::phys_to_virt
    },
    early_println,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressSpace {
    SystemMemory,
    SystemIO,
    Unsupported(u8),
}

#[derive(Debug, Clone, Copy)]
pub struct ResetReg {
    pub address_space: AddressSpace,
    pub address:       u64,
    pub bit_width:     u8,
}

pub struct FadtTable {
    pub reset_reg:          Option<ResetReg>,
    pub reset_value:        u8,

    pub pm1a_control_block: u32,
    pub pm1b_control_block: u32,
    pub pm1_control_length: u8,

    pub pm1a_event_block:   u32,
    pub pm1b_event_block:   u32,
    pub pm1_event_length:   u8,

    pub flags:              FixedFeatureFlags,
}

impl FadtTable {
    const SLP_EN: u16 = 1 << 13;

    pub fn reboot(&self) -> ! {
        if let Some(reg) = &self.reset_reg {
            match reg.address_space {
                AddressSpace::SystemIO => {
                    early_println!("ACPI reboot: I/O port {:#x} <- {:#x}",
                                   reg.address, self.reset_value);
                    unsafe {
                        let mut port = Port::<u8>::new(reg.address as u16);
                        port.write(self.reset_value);
                    }
                }
                AddressSpace::SystemMemory => {
                    early_println!("ACPI reboot: MMIO {:#x} <- {:#x}",
                                   reg.address, self.reset_value);
                    unsafe {
                        let virt = phys_to_virt(reg.address as usize);
                        core::ptr::write_volatile(virt as *mut u8, self.reset_value);
                    }
                }
                AddressSpace::Unsupported(id) => {
                    early_println!("ACPI reset_reg: unsupported address space {}", id);
                }
            }
        }

        early_println!("ACPI reset failed, fallback to 0xCF9");
        unsafe {
            let mut port = Port::<u8>::new(0xCF9);
            port.write(0x06); 
        }

        early_println!("0xCF9 reset failed, triple fault");

        self.triple_fault()
    }

    fn triple_fault(&self) -> ! {
        unsafe {
            let null_idtr: [u8; 10] = [0; 10];
            core::arch::asm!(
                "lidt [{}]",
                "int3",
                in(reg) &null_idtr,
                options(noreturn),
            );
        }
    }

    pub fn shutdown(&self) -> ! {
        let slp_typ_a = get_acpi_tables().read().get_table::<DsdtTable>().unwrap().slp_typ_a;
        let slp_typ_b = get_acpi_tables().read().get_table::<DsdtTable>().unwrap().slp_typ_b;

        if self.pm1a_control_block != 0 {
            let val = (slp_typ_a as u16) << 10 | Self::SLP_EN;
            early_println!("ACPI shutdown: PM1a_CNT {:#x} <- {:#x}",
                self.pm1a_control_block, val);
            unsafe {
                Port::<u16>::new(self.pm1a_control_block as u16).write(val);
            }
        }

        if self.pm1b_control_block != 0 {
            let val = (slp_typ_b as u16) << 10 | Self::SLP_EN;
            early_println!("ACPI shutdown: PM1b_CNT {:#x} <- {:#x}",
                self.pm1b_control_block, val);
            unsafe {
                Port::<u16>::new(self.pm1b_control_block as u16).write(val);
            }
        }

        early_println!("ACPI shutdown failed");
        loop { x86_64::instructions::hlt(); }
    }
}

impl AcpiParsedTable for FadtTable {
    type Raw = Fadt;

    fn parse(mapping: PhysicalMapping<MainTableParser, Self::Raw>) -> Self {
        let table = mapping.get();

        let flags = table.flags;
        let reset_reg_raw = table.reset_reg;
        let reset_value = table.reset_value;
        let pm1a_control_block = table.pm1a_control_block;
        let pm1b_control_block = table.pm1b_control_block;
        let pm1_control_length = table.pm1_control_length;
        let pm1a_event_block = table.pm1a_event_block;
        let pm1b_event_block = table.pm1b_event_block;
        let pm1_event_length = table.pm1_event_length;

        let reset_reg = if flags.supports_system_reset_via_fadt() {
            let space = match reset_reg_raw.address_space {
                0 => AddressSpace::SystemMemory,
                1 => AddressSpace::SystemIO,
                n => AddressSpace::Unsupported(n),
            };
            if reset_reg_raw.address != 0 {
                Some(ResetReg {
                    address_space: space,
                    address:       reset_reg_raw.address,
                    bit_width:     reset_reg_raw.bit_width,
                })
            } else {
                None
            }
        } else {
            None
        };

        // дальше используешь локалки вместо table.*
        FadtTable {
            reset_reg,
            reset_value,
            pm1a_control_block,
            pm1b_control_block,
            pm1_control_length,
            pm1a_event_block,
            pm1b_event_block,
            pm1_event_length,
            flags,
        }
    }
}