use core::ptr::NonNull;

use acpi::{Handler, PhysicalMapping};

use crate::{arch::{CurrentIOProvider, CurrentMemArchSpec, interrupt::halt}, io_ops::IoOperations, memory::misc::{arch_specific::Arch, primitives::PhysAddr}};

#[derive(Clone)]
pub struct MainTableParser;

impl Handler for MainTableParser {
    unsafe fn map_physical_region<T>(&self, physical_address: usize, size: usize) -> PhysicalMapping<Self, T> {
        let va = CurrentMemArchSpec::phys_to_virt(PhysAddr::new(physical_address)).as_mut_ptr();

        let virt_ptr = NonNull::new(va as *mut T)
            .expect("HHDM produced null virtual address for ACPI mapping");

        PhysicalMapping {
            physical_start: physical_address,
            virtual_start: virt_ptr,
            region_length: size,
            mapped_length: size,
            handler: self.clone(),
        }
    }

    fn unmap_physical_region<T>(_: &acpi::PhysicalMapping<Self, T>) {

    }

    fn read_u8(&self, address: usize) -> u8 {
        unsafe { CurrentMemArchSpec::read_volatile::<u8>(CurrentMemArchSpec::phys_to_virt(PhysAddr::new(address))) }
    }

    fn read_u16(&self, address: usize) -> u16 {
        unsafe { CurrentMemArchSpec::read_volatile::<u16>(CurrentMemArchSpec::phys_to_virt(PhysAddr::new(address))) }
    }

    fn read_u32(&self, address: usize) -> u32 {
        unsafe { CurrentMemArchSpec::read_volatile::<u32>(CurrentMemArchSpec::phys_to_virt(PhysAddr::new(address))) }
    }

    fn read_u64(&self, address: usize) -> u64 {
        unsafe { CurrentMemArchSpec::read_volatile::<u64>(CurrentMemArchSpec::phys_to_virt(PhysAddr::new(address))) }
    }

    fn write_u8(&self, address: usize, value: u8) {
        unsafe { CurrentMemArchSpec::write_volatile::<u8>(CurrentMemArchSpec::phys_to_virt(PhysAddr::new(address)), value) }
    }

    fn write_u16(&self, address: usize, value: u16) {
        unsafe { CurrentMemArchSpec::write_volatile::<u16>(CurrentMemArchSpec::phys_to_virt(PhysAddr::new(address)), value) }
    }

    fn write_u32(&self, address: usize, value: u32) {
        unsafe { CurrentMemArchSpec::write_volatile::<u32>(CurrentMemArchSpec::phys_to_virt(PhysAddr::new(address)), value) }
    }

    fn write_u64(&self, address: usize, value: u64) {
        unsafe { CurrentMemArchSpec::write_volatile::<u64>(CurrentMemArchSpec::phys_to_virt(PhysAddr::new(address)), value) }
    }

    fn read_io_u8(&self, port: u16) -> u8 {
        CurrentIOProvider::read8(port as usize)
    }

    fn read_io_u16(&self, port: u16) -> u16 {
        CurrentIOProvider::read16(port as usize)
    }

    fn read_io_u32(&self, port: u16) -> u32 {
        CurrentIOProvider::read32(port as usize)
    }

    fn write_io_u8(&self, port: u16, value: u8) {
        CurrentIOProvider::write8(port as usize, value)
    }

    fn write_io_u16(&self, port: u16, value: u16) {
        CurrentIOProvider::write16(port as usize, value)
    }

    fn write_io_u32(&self, port: u16, value: u32) {
        CurrentIOProvider::write32(port as usize, value)
    }

    fn read_pci_u8(&self, address: acpi::PciAddress, offset: u16) -> u8 {
        todo!()
    }

    fn read_pci_u16(&self, address: acpi::PciAddress, offset: u16) -> u16 {
        todo!()
    }

    fn read_pci_u32(&self, address: acpi::PciAddress, offset: u16) -> u32 {
        todo!()
    }

    fn write_pci_u8(&self, address: acpi::PciAddress, offset: u16, value: u8) {
        todo!()
    }

    fn write_pci_u16(&self, address: acpi::PciAddress, offset: u16, value: u16) {
        todo!()
    }

    fn write_pci_u32(&self, aaddress: acpi::PciAddress, offset: u16, value: u32) {
        todo!()
    }

    fn nanos_since_boot(&self) -> u64 {
        0
    }

    fn stall(&self, microseconds: u64) {
        loop {
            halt();
        }
    }

    fn sleep(&self, milliseconds: u64) {
        loop {
            halt();
        }
    }

    fn create_mutex(&self) -> acpi::Handle {
        acpi::Handle(0)
    }

    fn acquire(&self, mutex: acpi::Handle, timeout: u16) -> Result<(), acpi::aml::AmlError> {
        todo!()
    }

    fn release(&self, mutex: acpi::Handle) {}
}