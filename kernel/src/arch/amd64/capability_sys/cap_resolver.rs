use alloc::sync::Arc;
use spin::Mutex;

use crate::arch::amd64::{capability_sys::{capability::{CapType, Rights}, cnode::{CNode, CapIdx}}, ipc::{channel::ChannelHandle, port::Port}, memory::vmo::Vmo, scheduler::{syscall::SyscallError, task::{Process, Thread}}};

pub enum ResolverError {
    InvalidCapabilityIdx,
    PermissionDenied,
    WrongLocalType
}

impl ResolverError {
    pub fn to_syscall_error(&self) -> SyscallError {
        match self {
            ResolverError::InvalidCapabilityIdx => SyscallError::InvalidArgument,
            ResolverError::PermissionDenied => SyscallError::PermissionDenied,
            ResolverError::WrongLocalType => SyscallError::InvalidArgument
        }
    }
}

pub fn resolve_vspace(
    cnode: &CNode,
    cap_idx: CapIdx,
    required_rights: Rights,
) -> Result<(Arc<Process>, Rights), ResolverError> {
    let cap = cnode.get(cap_idx).ok_or(ResolverError::InvalidCapabilityIdx)?;
    
    if !cap.rights.contains(required_rights) {
        return Err(ResolverError::PermissionDenied);
    }
    
    match &cap._type {
        CapType::VSpace(proc) => Ok((Arc::clone(proc), cap.rights)),
        _ => Err(ResolverError::WrongLocalType),
    }
}

pub fn resolve_process(
    cnode: &CNode,
    cap_idx: CapIdx,
    required_rights: Rights,
) -> Result<(Arc<Process>, Rights), ResolverError> {
    let cap = cnode.get(cap_idx).ok_or(ResolverError::InvalidCapabilityIdx)?;
    
    if !cap.rights.contains(required_rights) {
        return Err(ResolverError::PermissionDenied);
    }
    
    match &cap._type {
        CapType::Process(proc) => Ok((Arc::clone(proc), cap.rights)),
        _ => Err(ResolverError::WrongLocalType),
    }
}

pub fn resolve_cnode(
    cnode: &CNode,
    cap_idx: CapIdx,
    required_rights: Rights,
) -> Result<(Arc<Process>, Rights), ResolverError> {
    let cap = cnode.get(cap_idx).ok_or(ResolverError::InvalidCapabilityIdx)?;
    
    if !cap.rights.contains(required_rights) {
        return Err(ResolverError::PermissionDenied);
    }
    
    match &cap._type {
        CapType::CNode(proc) => Ok((Arc::clone(proc), cap.rights)),
        _ => Err(ResolverError::WrongLocalType),
    }
}

pub fn resolve_thread(
    cnode: &CNode,
    cap_idx: CapIdx,
    required_rights: Rights,
) -> Result<(Arc<Thread>, Rights), ResolverError> {
    let cap = cnode.get(cap_idx).ok_or(ResolverError::InvalidCapabilityIdx)?;
    
    if !cap.rights.contains(required_rights) {
        return Err(ResolverError::PermissionDenied);
    }
    
    match &cap._type {
        CapType::Thread(thread) => Ok((Arc::clone(thread), cap.rights)),
        _ => Err(ResolverError::WrongLocalType),
    }
}

pub fn resolve_vmo(
    cnode: &CNode,
    cap_idx: CapIdx,
    required_rights: Rights,
) -> Result<(Arc<Mutex<Vmo>>, Rights), ResolverError> {
    let cap = cnode.get(cap_idx).ok_or(ResolverError::InvalidCapabilityIdx)?;
    
    if !cap.rights.contains(required_rights) {
        return Err(ResolverError::PermissionDenied);
    }
    
    match &cap._type {
        CapType::Vmo(vmo) => Ok((Arc::clone(vmo), cap.rights)),
        _ => Err(ResolverError::WrongLocalType),
    }
}

pub fn resolve_channel(
    cnode: &CNode,
    cap_idx: CapIdx,
    required_rights: Rights,
) -> Result<(ChannelHandle, Rights), ResolverError> {
    let cap = cnode.get(cap_idx).ok_or(ResolverError::InvalidCapabilityIdx)?;
    
    if !cap.rights.contains(required_rights) {
        return Err(ResolverError::PermissionDenied);
    }
    
    match &cap._type {
        CapType::Channel(ch) => Ok((ch.clone(), cap.rights)),
        _ => Err(ResolverError::WrongLocalType),
    }
}

pub fn resolve_port(
    cnode: &CNode,
    cap_idx: CapIdx,
    required_rights: Rights,
) -> Result<(Arc<Port>, Rights), ResolverError> {
    let cap = cnode.get(cap_idx).ok_or(ResolverError::InvalidCapabilityIdx)?;
    
    if !cap.rights.contains(required_rights) {
        return Err(ResolverError::PermissionDenied);
    }
    
    match &cap._type {
        CapType::Port(port) => Ok((Arc::clone(port), cap.rights)),
        _ => Err(ResolverError::WrongLocalType),
    }
}