use alloc::vec::Vec;
use spin::Once;

use crate::{bootinfo::BootInfo, memory::misc::primitives::PhysAddr};

#[cfg(target_arch = "x86_64")]
mod cpuid_info;

#[cfg(platform_acpi)]
mod acpi;

#[cfg(platform_acpi)]
use self::acpi::{init_device_info, DeviceDescrCfg};

#[cfg(platform_device_tree)]
mod device_tree;

#[cfg(platform_device_tree)]
pub use self::device_tree::*;


#[derive(Debug, Clone, Copy)]
pub struct CpuCoreInfo {
    pub id: usize,
    pub boot_capable: bool,
}

#[derive(Debug, Clone)]
pub struct InterruptControllerInfo {
    pub base_address: PhysAddr,

    #[cfg(target_arch = "x86_64")]
    pub kind: IoapicInfo,

    #[cfg(target_arch = "aarch64")]
    pub kind: GicInfo,

    #[cfg(target_arch = "riscv64")]
    pub kind: PlicInfo,
}

#[derive(Debug, Clone)]
pub struct LocalInterruptControllerInfo {
    pub physical_addr: PhysAddr,

    #[cfg(target_arch = "x86_64")]
    pub kind: LapicInfo
}

#[cfg(target_arch = "x86_64")]
#[derive(Debug, Clone)]
pub struct LapicInfo {
    pub support_x2_init: bool,
}

#[cfg(target_arch = "x86_64")]
#[derive(Debug, Clone)]
pub struct IoapicInfo {
    pub id: u8,
    pub gsi_base: u32,
}

#[cfg(target_arch = "aarch64")]
#[derive(Debug, Clone)]
pub struct GicInfo {
    pub distributor_addr: PhysAddr,
    pub redistributor_addr: PhysAddr,
    pub version: u8,
}

#[cfg(target_arch = "riscv64")]
#[derive(Debug, Clone)]
pub struct PlicInfo {
    pub nr_irqs: u32,
    pub nr_contexts: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct IrqOverride {
    pub source_irq: u8,
    pub global_irq: u32,
    pub flags: u16,
}

#[derive(Debug, Clone)]
pub struct IrqSubsystemInfo {
    pub local_controller: LocalInterruptControllerInfo,
    pub controllers: Vec<InterruptControllerInfo>,
    pub overrides: Vec<IrqOverride>,
}

#[derive(Debug, Clone)]
pub struct TimerInfo {
    pub base_address: PhysAddr,
    pub frequency_hz: u64,

    #[cfg(target_arch = "x86_64")]
    pub kind: HpetInfo,

    #[cfg(target_arch = "riscv64")]
    pub kind: ClintTimerInfo,

    #[cfg(target_arch = "aarch64")]
    pub kind: ArmGenericTimerInfo,
}

#[cfg(target_arch = "x86_64")]
#[derive(Debug, Clone)]
pub struct HpetInfo {
    pub clock_period_fs: u32, 
    pub hpet_number: u8,
    pub page_protection: u8,
}

#[cfg(target_arch = "riscv64")]
#[derive(Debug, Clone)]
pub struct ClintTimerInfo {
    pub mtime_offset: usize,
    pub mtimecmp_offset: usize,
}

#[cfg(target_arch = "aarch64")]
#[derive(Debug, Clone)]
pub struct ArmGenericTimerInfo {
    pub el1_phys_irq: u32,
    pub el1_virt_irq: u32,
}

#[derive(Debug, Clone)]
pub enum EarlyConsole {
    #[cfg(target_arch = "x86_64")]
    IoPort(u16),               

    Mmio {
        base: PhysAddr,
        width: u8,             
        clock_hz: u32,
        baud: u32,
    },
}

#[derive(Debug, Clone)]
pub struct BoardInfo {
    pub cpu_cores: Vec<CpuCoreInfo>,
    pub irq: IrqSubsystemInfo,
    pub timer: TimerInfo,
    pub early_console: Option<EarlyConsole>,
}

pub static BASIC_BOARD_INFO: Once<BoardInfo> = Once::new();

#[inline(always)]
pub fn get_basic_board_info<'a>() -> &'a BoardInfo {
    BASIC_BOARD_INFO.get().expect("Board info is not initialized yet")
}

pub fn initialize_board_info() {
    #[cfg(platform_acpi)]
    {
        let device_cfg = DeviceDescrCfg {
            rsdrp_addr: BootInfo::get().rsdp_addr().unwrap(),
            memmap: BootInfo::get().memmap_entries().unwrap()
        };
        init_device_info(device_cfg);
    }
    
    #[cfg(not(platform_acpi))]
    {
        panic!("Unsupported board info parse method!");
    }
}