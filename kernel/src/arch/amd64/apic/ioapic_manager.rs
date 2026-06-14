use alloc::vec::Vec;
use spin::{Mutex, Once};
use x2apic::ioapic::{IrqFlags, IrqMode};
use crate::arch::amd64::{
    acpi::{get_acpi_tables, madt::MadTable},
    apic::ioapic::IOApic,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryMode {
    Fixed = 0b000,
    LowestPriority = 0b001,
    Smi = 0b010,
    Nmi = 0b100,
    Init = 0b101,
    ExtInt = 0b111,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Polarity {
    ActiveHigh,
    ActiveLow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TriggerMode {
    Edge,
    Level,
}

#[derive(Clone, Copy, Debug)]
pub struct IsoEntry {
    pub legacy_irq: u8,
    pub gsi: u32,
    pub polarity: Polarity,
    pub trigger: TriggerMode,
}

#[derive(Debug)]
pub enum IrqError {
    GsiNotHandled(u32),
    NoFreeVectors,
    AlreadyConfigured(u32),
    PinOutOfRange { pin: u8, max: u32 },
    VectorNotConfigured(u8),
}

const IRQ_VECTOR_BASE: u8 = 0x30;
const IRQ_VECTOR_END: u8 = 0xFE;

#[derive(Clone, Copy, Debug)]
struct GsiMapping {
    gsi: u32,
    vector: u8,
    pin: u8,
    ioapic_idx: usize,
}

struct VectorAllocator {
    next: u8,
}

impl VectorAllocator {
    const fn new() -> Self {
        Self { next: IRQ_VECTOR_BASE }
    }

    fn alloc(&mut self) -> Option<u8> {
        if self.next > IRQ_VECTOR_END {
            return None;
        }
        let v = self.next;
        self.next += 1;
        Some(v)
    }

    fn release(&mut self, _vector: u8) {
        // TODO: bitmap для переиспользования
    }
}

pub struct IoapicManager {
    ioapics: Vec<IOApic>,
    isos: Vec<IsoEntry>,
    mappings: Mutex<Vec<GsiMapping>>,
    allocator: Mutex<VectorAllocator>,
}

impl IoapicManager {
    pub fn initialize() -> Self {
        let acpi = get_acpi_tables().read();
        let madt = acpi.get_table::<MadTable>().expect("No MADT");

        let ioapics = madt.ioapics.iter()
            .map(|def| IOApic::new(def.id, def.gsi_base, def.address))
            .collect();

        let isos = madt.iso.iter()
            .map(|ovr| {
                let (polarity, trigger) = parse_mps_inti_flags(ovr.flags);
                IsoEntry {
                    legacy_irq: ovr.irq,
                    gsi: ovr.gsi,
                    polarity,
                    trigger,
                }
            })
            .collect();

        Self {
            ioapics,
            isos,
            mappings: Mutex::new(Vec::new()),
            allocator: Mutex::new(VectorAllocator::new()),
        }
    }

    pub fn route_gsi(
        &self,
        gsi: u32,
        dest: u8,
        mode: IrqMode,
        flags: IrqFlags,
    ) -> Result<u8, IrqError> {
        {
            let mappings = self.mappings.lock();
            if mappings.iter().any(|m| m.gsi == gsi) {
                return Err(IrqError::AlreadyConfigured(gsi));
            }
        }

        let (ioapic_idx, ioapic, pin) = self.find_ioapic_for_gsi(gsi)?;

        let vector = self.allocator.lock().alloc()
            .ok_or(IrqError::NoFreeVectors)?;

        ioapic.setup_irq(pin, vector, mode, flags, dest);

        self.mappings.lock().push(GsiMapping {
            gsi,
            vector,
            pin,
            ioapic_idx,
        });

        Ok(vector)
    }

    pub fn route_legacy_irq(&self, irq: u8, dest: u8) -> Result<u8, IrqError> {
        let (gsi, trigger, polarity) = match self.isos.iter()
            .find(|iso| iso.legacy_irq == irq)
        {
            Some(iso) => (iso.gsi, iso.trigger, iso.polarity),
            None => (irq as u32, TriggerMode::Edge, Polarity::ActiveHigh),
        };

        let flags = to_irq_flags(trigger, polarity) | IrqFlags::MASKED;
        self.route_gsi(gsi, dest, IrqMode::Fixed, flags)
    }

    pub fn enable_gsi(&self, gsi: u32) -> Result<(), IrqError> {
        let (_, ioapic, pin) = self.find_ioapic_for_gsi(gsi)?;
        ioapic.enable_irq(pin);
        Ok(())
    }

    pub fn disable_gsi(&self, gsi: u32) -> Result<(), IrqError> {
        let (_, ioapic, pin) = self.find_ioapic_for_gsi(gsi)?;
        ioapic.disable_irq(pin);
        Ok(())
    }

    pub fn mask_by_vector(&self, vector: u8) -> Result<(), IrqError> {
        let gsi = self.gsi_for_vector(vector)
            .ok_or(IrqError::VectorNotConfigured(vector))?;
        self.disable_gsi(gsi)
    }

    pub fn unmask_by_vector(&self, vector: u8) -> Result<(), IrqError> {
        let gsi = self.gsi_for_vector(vector)
            .ok_or(IrqError::VectorNotConfigured(vector))?;
        self.enable_gsi(gsi)
    }

    pub fn gsi_for_vector(&self, vector: u8) -> Option<u32> {
        self.mappings.lock().iter()
            .find(|m| m.vector == vector)
            .map(|m| m.gsi)
    }

    pub fn vector_for_gsi(&self, gsi: u32) -> Option<u8> {
        self.mappings.lock().iter()
            .find(|m| m.gsi == gsi)
            .map(|m| m.vector)
    }

    fn find_ioapic_for_gsi(&self, gsi: u32) -> Result<(usize, &IOApic, u8), IrqError> {
        for (idx, ioapic) in self.ioapics.iter().enumerate() {
            if ioapic.handles_gsi(gsi) {
                return Ok((idx, ioapic, ioapic.gsi_to_pin(gsi)));
            }
        }
        Err(IrqError::GsiNotHandled(gsi))
    }
}

fn to_irq_flags(trigger: TriggerMode, polarity: Polarity) -> IrqFlags {
    let mut flags = IrqFlags::empty();
    if let TriggerMode::Level = trigger {
        flags |= IrqFlags::LEVEL_TRIGGERED;
    }
    if let Polarity::ActiveLow = polarity {
        flags |= IrqFlags::LOW_ACTIVE;
    }
    flags
}

fn parse_mps_inti_flags(flags: u16) -> (Polarity, TriggerMode) {
    let polarity = match flags & 0b11 {
        0b01 => Polarity::ActiveHigh,
        0b11 => Polarity::ActiveLow,
        _    => Polarity::ActiveHigh,  
    };
    let trigger = match (flags >> 2) & 0b11 {
        0b01 => TriggerMode::Edge,
        0b11 => TriggerMode::Level,
        _    => TriggerMode::Edge,    
    };
    (polarity, trigger)
}

static MANAGER: Once<IoapicManager> = Once::new();

pub fn ioapic_manager_init() {
    MANAGER.call_once(|| IoapicManager::initialize());
}

pub fn ioapic_manager() -> &'static IoapicManager {
    MANAGER.get().expect("IOAPIC manager not initialized")
}