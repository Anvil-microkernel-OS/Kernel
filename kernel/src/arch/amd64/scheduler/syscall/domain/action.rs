use alloc::string::String;

use crate::{arch::amd64::{capability_sys::{cap_resolver::resolve_domain, capability::{CapType, Capability, Rights}, cnode::CapIdx}, memory::u_k_boundary::uaccsess::copy_slice_from_user, scheduler::syscall::{SyscallArguments, SyscallError, get_curr_exec_ctx}}, define_syscall_group, isolation::domain::{Domain, DomainPolicy}};

define_syscall_group! {
    pub enum DomainActionSyscalls {
        CreateDomain = 70,
        DestroyDomain = 71
    }
}

fn handle_create_domain(domain_cap: CapIdx, name_ptr: u64, name_len: u64) -> Result<u64, SyscallError> {
    if name_len == 0 {
        return Err(SyscallError::BufferTooSmall)
    }

    let mut name = String::with_capacity(name_len as usize);
    if !copy_slice_from_user(name_ptr as usize, unsafe { name.as_bytes_mut() }) {
        return Err(SyscallError::Fault);
    }

    let ctx = get_curr_exec_ctx();

    let domain = resolve_domain(&ctx.1.cnode, domain_cap, Rights::MANAGE).map_err(|_| SyscallError::PermissionDenied)?;

    let app_policy = DomainPolicy::unrestricted();
    let new_child = Domain::new_child(&domain.0, 1, name, app_policy);

    let slot = ctx.1.cnode.alloc(Capability::new(CapType::Domain(new_child), Rights::MANAGE));

    Ok(slot as u64)
}

fn handle_destroy_domain() -> Result<u64, SyscallError> {
    todo!();
}

pub fn dispatch_domain_actions_syscall_group(syscall: DomainActionSyscalls, args: &SyscallArguments) -> Result<u64, SyscallError> {
    match syscall {
        DomainActionSyscalls::CreateDomain => handle_create_domain(args.arg1 as CapIdx, args.arg2, args.arg3),
        DomainActionSyscalls::DestroyDomain => handle_destroy_domain()
    }
}