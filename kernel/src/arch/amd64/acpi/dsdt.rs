use acpi::AcpiTables;

use crate::arch::amd64::{acpi::main_table_parser::MainTableParser, memory::misc::phys_to_virt};

pub struct DsdtTable {
    pub slp_typ_a: u8,
    pub slp_typ_b: u8
}

fn find_s5_slp_typ(dsdt: &[u8]) -> Option<(u8, u8)> {
    let sig = b"_S5_";
    let pos = dsdt.windows(4).position(|w| w == sig)?;

    let mut i = pos + 4;

    if *dsdt.get(i)? != 0x12 {
        return None;
    }
    i += 1;

    let lead = *dsdt.get(i)?;
    let pkg_len_bytes = if lead & 0xC0 == 0 { 1 } else { ((lead >> 6) + 1) as usize };
    i += pkg_len_bytes;

    let num_elements = *dsdt.get(i)?;
    if num_elements != 4 {
        return None;
    }
    i += 1;

    let slp_typ_a = parse_aml_byte(dsdt, &mut i)?;
    let slp_typ_b = parse_aml_byte(dsdt, &mut i)?;

    Some((slp_typ_a, slp_typ_b))
}

fn parse_aml_byte(dsdt: &[u8], i: &mut usize) -> Option<u8> {
    match *dsdt.get(*i)? {
        0x0A => {
            *i += 1;
            let val = *dsdt.get(*i)?;
            *i += 1;
            Some(val)
        }
        0x0B => {
            *i += 1;
            let val = *dsdt.get(*i)?;
            *i += 3;
            Some(val)
        }
        0x00 => { *i += 1; Some(0) }
        0x01 => { *i += 1; Some(1) }
        0xFF => { *i += 1; Some(0xFF) }
        _ => None,
    }
}

impl DsdtTable {
    pub fn init(acpi: &AcpiTables<MainTableParser>) -> Self {
        let dsdt = acpi.dsdt().unwrap();

        let dsdt_bytes = unsafe { 
            core::slice::from_raw_parts(
                phys_to_virt(dsdt.phys_address) as *const u8, 
                dsdt.length as usize
            ) 
        };
        let (slp_typ_a, slp_typ_b) = find_s5_slp_typ(dsdt_bytes).unwrap();
        
        Self {
            slp_typ_a,
            slp_typ_b
        }
    }
}