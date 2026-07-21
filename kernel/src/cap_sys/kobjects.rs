use crate::{cap_sys::capability::{CapInner, Capability, Rights}, scheduling::primitives::{process::Process, thread::Thread}};

/* 
pub enum KernelObjRef<'a> {
    VSpace(&'a VSpaceRoot),
    Process(&'a Process),
    Thread(&'a Thread),
    CNode(&'a CNode),
    Vmo(&'a Vmo),
    Channel(&'a Channel),
    Port(&'a Port),
    Domain(&'a Domain),
}
 
pub enum KernelObjRefMut<'a> {
    VSpace(&'a mut VSpaceRoot),
    Process(&'a mut Process),
    Thread(&'a mut Thread),
    CNode(&'a mut CNode),
    Vmo(&'a mut Vmo),
    Channel(&'a mut Channel),
    Port(&'a mut Port),
    Domain(&'a mut Domain),
}
 
 
 
impl KernelObjects {
    pub fn resolve_thread(&self, cap: &Capability, required: Rights) -> Option<&Thread> {
        if !cap.check_rights(required) { return None; }
        match cap.inner.as_ref()? {
            CapInner::Thread(k) => self.threads.get(*k),
            _ => None,
        }
    }
 
    pub fn resolve_process(&self, cap: &Capability, required: Rights) -> Option<&Process> {
        if !cap.check_rights(required) { return None; }
        match cap.inner.as_ref()? {
            CapInner::Process(k) => self.processes.get(*k),
            _ => None,
        }
    }
 
    pub fn resolve_vmo(&self, cap: &Capability, required: Rights) -> Option<&Vmo> {
        if !cap.check_rights(required) { return None; }
        match cap.inner.as_ref()? {
            CapInner::Vmo(k) => self.vmos.get(*k),
            _ => None,
        }
    }
 
    pub fn resolve_channel(&self, cap: &Capability, required: Rights) -> Option<&Channel> {
        if !cap.check_rights(required) { return None; }
        match cap.inner.as_ref()? {
            CapInner::Channel(k) => self.channels.get(*k),
            _ => None,
        }
    }
 
    pub fn resolve_vspace(&self, cap: &Capability, required: Rights) -> Option<&VSpaceRoot> {
        if !cap.check_rights(required) { return None; }
        match cap.inner.as_ref()? {
            CapInner::VSpace(k) => self.vspaces.get(*k),
            _ => None,
        }
    }
 
    pub fn resolve_cnode(&self, cap: &Capability, required: Rights) -> Option<&CNode> {
        if !cap.check_rights(required) { return None; }
        match cap.inner.as_ref()? {
            CapInner::CNode(k) => self.cnodes.get(*k),
            _ => None,
        }
    }
 
    pub fn resolve_port(&self, cap: &Capability, required: Rights) -> Option<&Port> {
        if !cap.check_rights(required) { return None; }
        match cap.inner.as_ref()? {
            CapInner::Port(k) => self.ports.get(*k),
            _ => None,
        }
    }
 
    pub fn resolve_domain(&self, cap: &Capability, required: Rights) -> Option<&Domain> {
        if !cap.check_rights(required) { return None; }
        match cap.inner.as_ref()? {
            CapInner::Domain(k) => self.domains.get(*k),
            _ => None,
        }
    }
}
*/