use crate::{
    memory::misc::primitives::VirtAddr,
    misc::registers::{RegisterRO, RegisterRW},
    register_struct,
};

register_struct! {
    IOAPICMmio {
        0x00 => ioregsel: RegisterRW<u32>,
        0x10 => iowin:    RegisterRW<u32>,
    }
}

const IOAPIC_REG_ID: u32 = 0x00;
const IOAPIC_REG_VER: u32 = 0x01;
const IOAPIC_REG_ARB: u32 = 0x02;

const IOAPIC_REDTBL_BASE: u32 = 0x10;

const DELIVERY_FIXED: u64 = 0b000 << 8;
const DELIVERY_LOWEST_PRIORITY: u64 = 0b001 << 8;
const DELIVERY_SMI: u64 = 0b010 << 8;
const DELIVERY_NMI: u64 = 0b100 << 8;
const DELIVERY_INIT: u64 = 0b101 << 8;
const DELIVERY_EXTINT: u64 = 0b111 << 8;

const DEST_MODE_PHYSICAL: u64 = 0 << 11;
const DEST_MODE_LOGICAL: u64 = 1 << 11;
const PIN_POLARITY_HIGH: u64 = 0 << 13;
const PIN_POLARITY_LOW: u64 = 1 << 13;
const TRIGGER_EDGE: u64 = 0 << 15;
const TRIGGER_LEVEL: u64 = 1 << 15;
const MASK_BIT: u64 = 1 << 16;

const MAX_REDIR_ENTRIES: u8 = 240;

#[derive(Debug, Clone, Copy)]
#[repr(u64)]
pub enum DeliveryMode {
    Fixed           = DELIVERY_FIXED,
    LowestPriority  = DELIVERY_LOWEST_PRIORITY,
    Smi             = DELIVERY_SMI,
    Nmi             = DELIVERY_NMI,
    Init            = DELIVERY_INIT,
    ExtInt          = DELIVERY_EXTINT,
}

#[derive(Debug, Clone, Copy)]
pub enum Polarity {
    ActiveHigh,
    ActiveLow,
}

#[derive(Debug, Clone, Copy)]
pub enum TriggerMode {
    Edge,
    Level,
}

#[derive(Debug, Clone, Copy)]
pub enum DestinationMode {
    Physical,
    Logical,
}

#[derive(Debug, Clone, Copy)]
pub struct RedirectionEntry(u64);

impl RedirectionEntry {
    pub const fn new() -> Self {
        Self(MASK_BIT)
    }

    pub const fn vector(mut self, vector: u8) -> Self {
        self.0 = (self.0 & !0xFF) | (vector as u64);
        self
    }

    pub const fn delivery(mut self, mode: DeliveryMode) -> Self {
        self.0 = (self.0 & !(0b111 << 8)) | (mode as u64);
        self
    }

    pub const fn destination_mode(mut self, mode: DestinationMode) -> Self {
        self.0 = match mode {
            DestinationMode::Physical => self.0 & !DEST_MODE_LOGICAL,
            DestinationMode::Logical  => self.0 | DEST_MODE_LOGICAL,
        };
        self
    }

    pub const fn polarity(mut self, pol: Polarity) -> Self {
        self.0 = match pol {
            Polarity::ActiveHigh => self.0 & !PIN_POLARITY_LOW,
            Polarity::ActiveLow  => self.0 | PIN_POLARITY_LOW,
        };
        self
    }

    pub const fn trigger(mut self, trig: TriggerMode) -> Self {
        self.0 = match trig {
            TriggerMode::Edge  => self.0 & !TRIGGER_LEVEL,
            TriggerMode::Level => self.0 | TRIGGER_LEVEL,
        };
        self
    }

    pub const fn masked(mut self, mask: bool) -> Self {
        if mask {
            self.0 |= MASK_BIT;
        } else {
            self.0 &= !MASK_BIT;
        }
        self
    }

    pub const fn destination(mut self, apic_id: u8) -> Self {
        self.0 = (self.0 & !(0xFF << 56)) | ((apic_id as u64) << 56);
        self
    }

    pub const fn raw(self) -> u64 {
        self.0
    }

    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    pub const fn is_masked(self) -> bool {
        self.0 & MASK_BIT != 0
    }

    pub const fn get_vector(self) -> u8 {
        (self.0 & 0xFF) as u8
    }
}

pub struct Ioapic {
    mmio: IOAPICMmio,
    gsi_base: u32,
    num_entries: u8,
}

unsafe impl Send for Ioapic {}
unsafe impl Sync for Ioapic {}

impl Ioapic {
    pub fn new(mapped_addr: VirtAddr, gsi_base: u32) -> Self {
        let mmio = unsafe { IOAPICMmio::from_address(mapped_addr.as_usize()) };

        let ver = read_indirect(&mmio, IOAPIC_REG_VER);
        let max_redir = ((ver >> 16) & 0xFF) as u8;

        let num_entries = if max_redir < MAX_REDIR_ENTRIES {
            max_redir + 1
        } else {
            MAX_REDIR_ENTRIES
        };

        let mut ioapic = Self {
            mmio,
            gsi_base,
            num_entries,
        };

        ioapic.mask_all();

        ioapic
    }

    fn read_reg(&self, index: u32) -> u32 {
        read_indirect(&self.mmio, index)
    }

    fn write_reg(&self, index: u32, value: u32) {
        write_indirect(&self.mmio, index, value);
    }

    pub fn id(&self) -> u8 {
        ((self.read_reg(IOAPIC_REG_ID) >> 24) & 0x0F) as u8
    }

    pub fn version(&self) -> u8 {
        (self.read_reg(IOAPIC_REG_VER) & 0xFF) as u8
    }

    pub fn num_entries(&self) -> u8 {
        self.num_entries
    }

    pub fn gsi_base(&self) -> u32 {
        self.gsi_base
    }

    pub fn gsi_end(&self) -> u32 {
        self.gsi_base + (self.num_entries as u32) - 1
    }

    pub fn handles_gsi(&self, gsi: u32) -> bool {
        gsi >= self.gsi_base && gsi <= self.gsi_end()
    }

    pub fn read_entry(&self, irq_index: u8) -> RedirectionEntry {
        assert!(
            irq_index < self.num_entries,
            "IOAPIC: irq_index {} >= num_entries {}",
            irq_index,
            self.num_entries,
        );

        let reg_low = IOAPIC_REDTBL_BASE + 2 * (irq_index as u32);
        let lo = self.read_reg(reg_low) as u64;
        let hi = self.read_reg(reg_low + 1) as u64;
        RedirectionEntry::from_raw(lo | (hi << 32))
    }

    pub fn write_entry(&mut self, irq_index: u8, entry: RedirectionEntry) {
        assert!(
            irq_index < self.num_entries,
            "IOAPIC: irq_index {} >= num_entries {}",
            irq_index,
            self.num_entries,
        );

        let raw = entry.raw();
        let reg_low = IOAPIC_REDTBL_BASE + 2 * (irq_index as u32);

        self.write_reg(reg_low + 1, (raw >> 32) as u32);
        self.write_reg(reg_low, raw as u32);
    }

    pub fn mask_irq(&mut self, irq_index: u8) {
        let entry = self.read_entry(irq_index).masked(true);
        self.write_entry(irq_index, entry);
    }

    pub fn unmask_irq(&mut self, irq_index: u8) {
        let entry = self.read_entry(irq_index).masked(false);
        self.write_entry(irq_index, entry);
    }

    pub fn mask_all(&mut self) {
        for i in 0..self.num_entries {
            let reg_low = IOAPIC_REDTBL_BASE + 2 * (i as u32);
            let lo = self.read_reg(reg_low);
            self.write_reg(reg_low, lo | MASK_BIT as u32);
        }
    }

    pub fn route_irq(
        &mut self,
        irq_index: u8,
        vector: u8,
        dest_apic_id: u8,
    ) {
        let entry = RedirectionEntry::new()
            .vector(vector)
            .delivery(DeliveryMode::Fixed)
            .destination_mode(DestinationMode::Physical)
            .polarity(Polarity::ActiveHigh)
            .trigger(TriggerMode::Edge)
            .masked(false)
            .destination(dest_apic_id);

        self.write_entry(irq_index, entry);
    }

    pub fn route_gsi(
        &mut self,
        gsi: u32,
        vector: u8,
        dest_apic_id: u8,
        polarity: Polarity,
        trigger: TriggerMode,
    ) {
        assert!(
            self.handles_gsi(gsi),
            "IOAPIC (gsi_base={}) does not handle GSI {}",
            self.gsi_base,
            gsi,
        );

        let irq_index = (gsi - self.gsi_base) as u8;

        let entry = RedirectionEntry::new()
            .vector(vector)
            .delivery(DeliveryMode::Fixed)
            .destination_mode(DestinationMode::Physical)
            .polarity(polarity)
            .trigger(trigger)
            .masked(false)
            .destination(dest_apic_id);

        self.write_entry(irq_index, entry);
    }
}

#[inline]
fn read_indirect(mmio: &IOAPICMmio, index: u32) -> u32 {
    mmio.ioregsel().write(index);
    mmio.iowin().read()
}

#[inline]
fn write_indirect(mmio: &IOAPICMmio, index: u32, value: u32) {
    mmio.ioregsel().write(index);
    mmio.iowin().write(value);
}