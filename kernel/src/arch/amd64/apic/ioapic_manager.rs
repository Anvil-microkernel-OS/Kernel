use alloc::{collections::btree_map::BTreeMap, vec::Vec};
use spin::{Mutex, Once};

use crate::{arch::amd64::{acpi::{get_acpi_tables, madt::MadTable}, apic::ioapic::{IOAPIC_REDIRECTION_TABLE_REGISTER_OFFSET, IOAPICRedirectionTableRegister, IOApic}}, early_println};

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
pub struct IrqRouting {
    pub vector: u8,
    pub dest_apic_id: u8,
    pub delivery_mode: DeliveryMode,
    pub polarity: Polarity,
    pub trigger: TriggerMode,
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
    VectorNotConfigured(u8)
}

const IRQ_VECTOR_BASE: u8 = 0x30;
const IRQ_VECTOR_END: u8 = 0xFE;

pub struct IoapicManager {
    ioapics: Vec<Mutex<IOApic>>,

    isos: Vec<IsoEntry>,

    routes: Mutex<alloc::collections::BTreeMap<u32, IrqRouting>>,
    
    vectors: Mutex<VectorAllocator>,

    vector_to_gsi: Mutex<[Option<u32>; 256]>,
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

    }
}

impl IoapicManager {
    pub fn initialize() -> Self {
        let acpi = get_acpi_tables().read();
        let madt = acpi.get_table::<MadTable>().expect("No MADT");

        let ioapics = madt.ioapics.iter()
            .map(|def| Mutex::new(IOApic::new(def.id, def.gsi_base, def.address)))
            .collect();

        let isos = madt.iso.iter()
            .map(|iso| {
                IsoEntry {
                    legacy_irq: iso.irq,
                    gsi: iso.gsi,
                    polarity: parse_polarity(iso.flags, iso.irq),
                    trigger:  parse_trigger(iso.flags, iso.irq),
                }
            })
            .collect();

        let manager = Self {
            ioapics,
            isos,
            routes: Mutex::new(alloc::collections::BTreeMap::new()),
            vectors: Mutex::new(VectorAllocator::new()),
            vector_to_gsi: Mutex::new([None; 256])
        };

        manager.reset_all_entries();

        manager
    }

    fn locate(&self, gsi: u32) -> Result<(spin::MutexGuard<'_, IOApic>, u8), IrqError> {
        for ioapic in &self.ioapics {
            let guard = ioapic.lock();
            if let Some(pin) = guard.gsi_to_pin(gsi) {
                return Ok((guard, pin));
            }
        }
        Err(IrqError::GsiNotHandled(gsi))
    }

    pub fn configure_irq(&self, gsi: u32, routing: IrqRouting) -> Result<(), IrqError> {
        {
            let routes = self.routes.lock();
            if routes.contains_key(&gsi) {
                return Err(IrqError::AlreadyConfigured(gsi));
            }
        }

        let (ioapic, pin) = self.locate(gsi)?;

        let entry = IOAPICRedirectionTableRegister::new()
            .with_interrupt_vector(routing.vector)
            .with_delivery_mode(routing.delivery_mode as u8)
            .with_destination_mode(false) // physical
            .with_interrupt_input_pin_polarity(matches!(routing.polarity, Polarity::ActiveLow))
            .with_trigger_mode(matches!(routing.trigger, TriggerMode::Level))
            .with_interrupt_mask(true)
            .with_destination_field(routing.dest_apic_id);

        ioapic.write_ioredtbl(pin, entry);
        drop(ioapic); 

        self.routes.lock().insert(gsi, routing);
        self.vector_to_gsi.lock()[routing.vector as usize] = Some(gsi);
        Ok(())
    }

    pub fn unconfigure_irq(&self, gsi: u32) -> Result<(), IrqError> {
        let (ioapic, pin) = self.locate(gsi)?;
        ioapic.mask_pin(pin);
        let zero_entry = IOAPICRedirectionTableRegister::new()
            .with_interrupt_mask(true);
        ioapic.write_ioredtbl(pin, zero_entry);
        drop(ioapic);

        let removed = self.routes.lock().remove(&gsi);
        if let Some(routing) = removed {
            self.vector_to_gsi.lock()[routing.vector as usize] = None;
            self.vectors.lock().release(routing.vector);
        }
        Ok(())
    }

    pub fn gsi_to_vector(&self, gsi: u32) -> Option<u8> {
        self.routes.lock().get(&gsi).map(|r| r.vector)
    }

    pub fn vector_to_gsi(&self, vector: u8) -> Option<u32> {
        self.vector_to_gsi.lock()[vector as usize]
    }
    
    pub fn mask_by_vector(&self, vector: u8) -> Result<(), IrqError> {
        let gsi = self.vector_to_gsi(vector)
            .ok_or(IrqError::VectorNotConfigured(vector))?;
        self.mask_irq(gsi)
    }

    pub fn mask_irq(&self, gsi: u32) -> Result<(), IrqError> {
        let (ioapic, pin) = self.locate(gsi)?;
        ioapic.mask_pin(pin);
        Ok(())
    }

    pub fn unmask_irq(&self, gsi: u32) -> Result<(), IrqError> {
        let (ioapic, pin) = self.locate(gsi)?;
        ioapic.unmask_pin(pin);
        Ok(())
    }

    pub fn set_affinity(&self, gsi: u32, dest_apic_id: u8) -> Result<(), IrqError> {
        let (ioapic, pin) = self.locate(gsi)?;
        let reg_index = IOAPIC_REDIRECTION_TABLE_REGISTER_OFFSET + pin * 2;
        let raw = ioapic.read_64b_from_reg(reg_index);
        let mut entry = IOAPICRedirectionTableRegister::from(raw);
        entry.set_destination_field(dest_apic_id);
        ioapic.write_ioredtbl(pin, entry);
        drop(ioapic);

        if let Some(routing) = self.routes.lock().get_mut(&gsi) {
            routing.dest_apic_id = dest_apic_id;
        }
        Ok(())
    }

    pub fn configure_legacy_irq(
        &self,
        legacy_irq: u8,
        vector: u8,
        dest_apic_id: u8,
    ) -> Result<u32, IrqError> {
        let iso = self.lookup_iso(legacy_irq);
        let gsi = iso.map(|i| i.gsi).unwrap_or(legacy_irq as u32);
        let polarity = iso.map(|i| i.polarity).unwrap_or(Polarity::ActiveHigh);
        let trigger  = iso.map(|i| i.trigger ).unwrap_or(TriggerMode::Edge);

        self.configure_irq(gsi, IrqRouting {
            vector,
            dest_apic_id,
            delivery_mode: DeliveryMode::Fixed,
            polarity,
            trigger,
        })?;

        Ok(gsi)
    }

    pub fn configure_irq_alloc_vector(
        &self,
        gsi: u32,
        dest_apic_id: u8,
        delivery_mode: DeliveryMode,
        polarity: Polarity,
        trigger: TriggerMode,
    ) -> Result<u8, IrqError> {
        let vector = self.vectors.lock().alloc().ok_or(IrqError::NoFreeVectors)?;
        match self.configure_irq(gsi, IrqRouting {
            vector,
            dest_apic_id,
            delivery_mode,
            polarity,
            trigger,
        }) {
            Ok(()) => Ok(vector),
            Err(e) => {
                self.vectors.lock().release(vector);
                Err(e)
            }
        }
    }

    fn reset_all_entries(&self) {
        for ioapic in &self.ioapics {
            let g = ioapic.lock();
            let n = g.num_redir_entries();
            for pin in 0..n {
                let zero = IOAPICRedirectionTableRegister::new()
                    .with_interrupt_mask(true);  // explicit
                g.write_ioredtbl(pin as u8, zero);
            }
        }
    }

    fn lookup_iso(&self, legacy_irq: u8) -> Option<&IsoEntry> {
        self.isos.iter().find(|i| i.legacy_irq == legacy_irq)
    }
}

fn parse_polarity(flags: u16, source: u8) -> Polarity {
    match flags & 0b11 {
        0b00 => bus_default_polarity(source),
        0b01 => Polarity::ActiveHigh,
        0b11 => Polarity::ActiveLow,
        _    => Polarity::ActiveHigh, 
    }
}

fn parse_trigger(flags: u16, source: u8) -> TriggerMode {
    match (flags >> 2) & 0b11 {
        0b00 => bus_default_trigger(source),
        0b01 => TriggerMode::Edge,
        0b11 => TriggerMode::Level,
        _    => TriggerMode::Edge,
    }
}

fn bus_default_polarity(_source: u8) -> Polarity { Polarity::ActiveHigh }
fn bus_default_trigger(_source: u8) -> TriggerMode { TriggerMode::Edge }


static MANAGER: Once<IoapicManager> = Once::new();

pub fn ioapic_manager_init() {
    MANAGER.call_once(|| IoapicManager::initialize());
}

pub fn ioapic_manager() -> &'static IoapicManager {
    MANAGER.get().expect("IOAPIC manager not initialized")
}