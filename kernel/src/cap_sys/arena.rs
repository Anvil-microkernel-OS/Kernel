use slotmap::{SlotMap, new_key_type};
use spin::Mutex;

use crate::{cap_sys::capability::{CapInner, Capability, Rights}, scheduling::primitives::{process::Process, thread::Thread}};

new_key_type! {
    pub struct ThreadKey;
    pub struct ProcessKey;
    pub struct VmoKey;
    pub struct ChannelKey;
    pub struct PortKey;
    pub struct DomainKey;
    pub struct VSpaceKey;
    pub struct CNodeKey;
}

/*pub struct KernelObjects {
    pub threads:   SlotMap<ThreadKey, Thread>,
    pub processes: SlotMap<ProcessKey, Process>,
   // pub vmos:      SlotMap<VmoKey, Vmo>,
   // pub channels:  SlotMap<ChannelKey, Channel>,
   // pub ports:     SlotMap<PortKey, Port>,
   // pub domains:   SlotMap<DomainKey, Domain>,
   // pub vspaces:   SlotMap<VSpaceKey, VSpaceRoot>,
    //pub cnodes:    SlotMap<CNodeKey, CNode>,
}

pub static KOBJECTS: Mutex<KernelObjects> = Mutex::new(KernelObjects::new());

impl KernelObjects {
    pub const fn new() -> Self {
        Self {
            threads:   SlotMap::with_key(),
            processes: SlotMap::with_key(),
            /*vmos:      SlotMap::with_key(),
            channels:  SlotMap::with_key(),
            ports:     SlotMap::with_key(),
            domains:   SlotMap::with_key(),
            vspaces:   SlotMap::with_key(),
            cnodes:    SlotMap::with_key(),*/
        }
    }
 
    #[inline]
    pub fn insert_thread(&mut self, t: Thread) -> ThreadKey {
        self.threads.insert(t)
    }
 
    #[inline]
    pub fn insert_process(&mut self, p: Process) -> ProcessKey {
        self.processes.insert(p)
    }
 
    /*#[inline]
    pub fn insert_vmo(&mut self, v: Vmo) -> VmoKey {
        self.vmos.insert(v)
    }
 
    #[inline]
    pub fn insert_channel(&mut self, c: Channel) -> ChannelKey {
        self.channels.insert(c)
    }
 
    #[inline]
    pub fn insert_port(&mut self, p: Port) -> PortKey {
        self.ports.insert(p)
    }
 
    #[inline]
    pub fn insert_domain(&mut self, d: Domain) -> DomainKey {
        self.domains.insert(d)
    }
 
    #[inline]
    pub fn insert_vspace(&mut self, v: VSpaceRoot) -> VSpaceKey {
        self.vspaces.insert(v)
    }
 
    #[inline]
    pub fn insert_cnode(&mut self, c: CNode) -> CNodeKey {
        self.cnodes.insert(c)
    }*/
 
    pub fn resolve(&self, cap: &Capability) -> Option<KernelObjRef<'_>> {
        let inner = cap.inner.as_ref()?;
        if cap.rights == Rights::NONE {
            return None;
        }
        match inner {
            CapInner::Thread(k)  => self.threads.get(*k).map(KernelObjRef::Thread),
            CapInner::Process(k) => self.processes.get(*k).map(KernelObjRef::Process),
            /*CapInner::Vmo(k)     => self.vmos.get(*k).map(KernelObjRef::Vmo),
            CapInner::Channel(k) => self.channels.get(*k).map(KernelObjRef::Channel),
            CapInner::Port(k)    => self.ports.get(*k).map(KernelObjRef::Port),
            CapInner::Domain(k)  => self.domains.get(*k).map(KernelObjRef::Domain),
            CapInner::VSpace(k)  => self.vspaces.get(*k).map(KernelObjRef::VSpace),
            CapInner::CNode(k)   => self.cnodes.get(*k).map(KernelObjRef::CNode),*/
        }
    }
 
    pub fn resolve_mut(&mut self, cap: &Capability) -> Option<KernelObjRefMut<'_>> {
        let inner = cap.inner.as_ref()?;
        if cap.rights == Rights::NONE {
            return None;
        }
        match inner {
            CapInner::Thread(k)  => self.threads.get_mut(*k).map(KernelObjRefMut::Thread),
            CapInner::Process(k) => self.processes.get_mut(*k).map(KernelObjRefMut::Process),
            /*CapInner::Vmo(k)     => self.vmos.get_mut(*k).map(KernelObjRefMut::Vmo),
            CapInner::Channel(k) => self.channels.get_mut(*k).map(KernelObjRefMut::Channel),
            CapInner::Port(k)    => self.ports.get_mut(*k).map(KernelObjRefMut::Port),
            CapInner::Domain(k)  => self.domains.get_mut(*k).map(KernelObjRefMut::Domain),
            CapInner::VSpace(k)  => self.vspaces.get_mut(*k).map(KernelObjRefMut::VSpace),
            CapInner::CNode(k)   => self.cnodes.get_mut(*k).map(KernelObjRefMut::CNode),*/
        }
    }
 
    pub fn revoke_thread(&mut self, k: ThreadKey) -> Option<Thread> {
        self.threads.remove(k)
    }
 
    pub fn revoke_process(&mut self, k: ProcessKey) -> Option<Process> {
        self.processes.remove(k)
    }
 
    /*pub fn revoke_vmo(&mut self, k: VmoKey) -> Option<Vmo> {
        self.vmos.remove(k)
    }
 
    pub fn revoke_channel(&mut self, k: ChannelKey) -> Option<Channel> {
        self.channels.remove(k)
    }
 
    pub fn revoke_port(&mut self, k: PortKey) -> Option<Port> {
        self.ports.remove(k)
    }
 
    pub fn revoke_domain(&mut self, k: DomainKey) -> Option<Domain> {
        self.domains.remove(k)
    }
 
    pub fn revoke_vspace(&mut self, k: VSpaceKey) -> Option<VSpaceRoot> {
        self.vspaces.remove(k)
    }
 
    pub fn revoke_cnode(&mut self, k: CNodeKey) -> Option<CNode> {
        self.cnodes.remove(k)
    }*/
 
    pub fn revoke_cap(&mut self, cap: &Capability) -> bool {
        let Some(inner) = &cap.inner else { return false };
        match inner {
            CapInner::Thread(k)  => self.threads.remove(*k).is_some(),
            CapInner::Process(k) => self.processes.remove(*k).is_some(),
            /*CapInner::Vmo(k)     => self.vmos.remove(*k).is_some(),
            CapInner::Channel(k) => self.channels.remove(*k).is_some(),
            CapInner::Port(k)    => self.ports.remove(*k).is_some(),
            CapInner::Domain(k)  => self.domains.remove(*k).is_some(),
            CapInner::VSpace(k)  => self.vspaces.remove(*k).is_some(),
            CapInner::CNode(k)   => self.cnodes.remove(*k).is_some(),*/
        }
    }
 
    pub fn is_valid(&self, cap: &Capability) -> bool {
        let Some(inner) = &cap.inner else { return false };
        match inner {
            CapInner::Thread(k)  => self.threads.contains_key(*k),
            CapInner::Process(k) => self.processes.contains_key(*k),
            /*CapInner::Vmo(k)     => self.vmos.contains_key(*k),
            CapInner::Channel(k) => self.channels.contains_key(*k),
            CapInner::Port(k)    => self.ports.contains_key(*k),
            CapInner::Domain(k)  => self.domains.contains_key(*k),
            CapInner::VSpace(k)  => self.vspaces.contains_key(*k),
            CapInner::CNode(k)   => self.cnodes.contains_key(*k),*/
        }
    }
}
 
*/