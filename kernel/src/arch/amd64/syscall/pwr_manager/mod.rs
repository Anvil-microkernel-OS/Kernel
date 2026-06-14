use crate::{arch::amd64::{acpi::{fadt::FadtTable, get_acpi_tables}, syscall::{SyscallArguments, SyscallError}}, define_syscall_group};

define_syscall_group! {
    pub enum PwrManagerSyscalls {
        PowerCtl = 75
    }
}

fn handle_powerctl(power_cmd: u64) -> Result<u64, SyscallError> {
    match power_cmd {
        0 => get_acpi_tables().read().get_table::<FadtTable>().unwrap().reboot(),
        1 => get_acpi_tables().read().get_table::<FadtTable>().unwrap().shutdown(),
        _ => return Err(SyscallError::InvalidArgument)
    }
}

pub(crate) fn dispatch_pwr_manager_syscall_group(syscall: PwrManagerSyscalls, args: &SyscallArguments) -> Result<u64, SyscallError> {
    match syscall {
        PwrManagerSyscalls::PowerCtl => handle_powerctl(args.arg1),
    }
}