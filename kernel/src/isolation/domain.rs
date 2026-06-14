use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use alloc::{string::String, sync::Arc, vec::Vec};
use spin::Mutex;
use intrusive_collections::{LinkedList, LinkedListLink, UnsafeRef, intrusive_adapter};
use crate::arch::amd64::{capability_sys::capability::{CapType, Capability, Rights}, scheduler::{kill_all_processes_in_domain, task::{Pid, Tid}}};

pub type Koid = u32;
type DomainRef = Arc<Domain>;

#[derive(Clone)]
pub struct CapTypePolicy {
    pub max_rights: Rights,
    pub allowed: bool,
}

impl CapTypePolicy {
    pub const fn allow(max_rights: Rights) -> Self {
        Self { max_rights, allowed: true }
    }

    pub const fn deny() -> Self {
        Self { max_rights: Rights::empty(), allowed: false }
    }
}

#[derive(Clone)]
pub struct DomainPolicy {
    pub cnode:   CapTypePolicy,
    pub channel: CapTypePolicy,
    pub port:    CapTypePolicy,
    pub process: CapTypePolicy,
    pub thread:  CapTypePolicy,
    pub vspace:  CapTypePolicy,
    pub vmo:     CapTypePolicy,
    pub domain:  CapTypePolicy,

    pub max_processes: Option<usize>,
    pub max_threads:   Option<usize>,
    pub max_vmos:      Option<usize>,
    //todo - ram & cpu time
}

impl DomainPolicy {
    pub fn unrestricted() -> Self {
        Self {
            cnode:   CapTypePolicy::allow(Rights::all()),
            channel: CapTypePolicy::allow(Rights::all()),
            port:    CapTypePolicy::allow(Rights::all()),
            process: CapTypePolicy::allow(Rights::all()),
            thread:  CapTypePolicy::allow(Rights::all()),
            vspace:  CapTypePolicy::allow(Rights::all()),
            vmo:     CapTypePolicy::allow(Rights::all()),
            domain:  CapTypePolicy::allow(Rights::all()),
            max_processes: None,
            max_threads:   None,
            max_vmos:      None,
        }
    }

    pub fn policy_for(&self, cap_type: &CapType) -> &CapTypePolicy {
        match cap_type {
            CapType::CNode(..)   => &self.cnode,
            CapType::Channel(..) => &self.channel,
            CapType::Port(..)    => &self.port,
            CapType::Process(..) => &self.process,
            CapType::Thread(..)  => &self.thread,
            CapType::VSpace(..)  => &self.vspace,
            CapType::Vmo(..)     => &self.vmo,
            CapType::Domain(..)  => &self.domain,
            CapType::Null        => panic!("no policy for Null cap"),
        }
    }

    pub fn intersect(&self, parent: &DomainPolicy) -> DomainPolicy {
        DomainPolicy {
            cnode:   intersect_policy(&self.cnode,   &parent.cnode),
            channel: intersect_policy(&self.channel, &parent.channel),
            port:    intersect_policy(&self.port,    &parent.port),
            process: intersect_policy(&self.process, &parent.process),
            thread:  intersect_policy(&self.thread,  &parent.thread),
            vspace:  intersect_policy(&self.vspace,  &parent.vspace),
            vmo:     intersect_policy(&self.vmo,     &parent.vmo),
            domain:  intersect_policy(&self.domain,  &parent.domain),
            max_processes: stricter_limit(self.max_processes, parent.max_processes),
            max_threads:   stricter_limit(self.max_threads,   parent.max_threads),
            max_vmos:      stricter_limit(self.max_vmos,      parent.max_vmos),
        }
    }
}

fn intersect_policy(child: &CapTypePolicy, parent: &CapTypePolicy) -> CapTypePolicy {
    CapTypePolicy {
        allowed:    child.allowed && parent.allowed,
        max_rights: child.max_rights & parent.max_rights,
    }
}

fn stricter_limit(a: Option<usize>, b: Option<usize>) -> Option<usize> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (Some(x), None)    => Some(x),
        (None,    Some(y)) => Some(y),
        (None,    None)    => None,
    }
}

pub struct Domain {
    pub koid:   Koid,
    pub name:   String,
    pub parent: Option<DomainRef>,
    pub sibling_link: LinkedListLink,
    pub global_link:  LinkedListLink,
    pub children: Mutex<LinkedList<DomainSiblingAdapter>>,
    pub policy:   DomainPolicy,
    pub process_count: AtomicUsize,
    pub thread_count:  AtomicUsize,
    pub vmo_count:     AtomicUsize,
    pub is_critical: bool,
    pub critical_procs: Option<Vec<Pid>>
}

unsafe impl Sync for Domain {}

intrusive_adapter!(
    pub DomainSiblingAdapter = UnsafeRef<Domain>:
        Domain { sibling_link => LinkedListLink }
);
intrusive_adapter!(
    pub DomainGlobalAdapter = UnsafeRef<Domain>:
        Domain { global_link => LinkedListLink }
);

#[derive(Debug)]
pub enum DomainError {
    PolicyDenied,          
    RightsExceedPolicy,    
    LimitExceeded,       
    NullCapability,       
}

pub enum CollapseAction {
    KillDomain,
    KernelPanic,
}

impl Domain {
    pub fn new_root(koid: Koid, name: impl Into<String>, is_critical: bool, critical_procs: Option<Vec<Pid>>) -> DomainRef {
        Arc::new(Self {
            koid,
            name: name.into(),
            parent: None,
            sibling_link: LinkedListLink::new(),
            global_link:  LinkedListLink::new(),
            children:      Mutex::new(LinkedList::new(DomainSiblingAdapter::NEW)),
            policy:        DomainPolicy::unrestricted(),
            process_count: AtomicUsize::new(0),
            thread_count:  AtomicUsize::new(0),
            vmo_count:     AtomicUsize::new(0),
            is_critical,
            critical_procs
        })
    }

    pub fn new_child(
        parent: &DomainRef,
        koid: Koid,
        name: impl Into<String>,
        requested_policy: DomainPolicy,
        is_critical: bool,
        critical_procs: Option<Vec<Pid>>
    ) -> DomainRef {
        let effective_policy = requested_policy.intersect(&parent.policy);

        Arc::new(Self {
            koid,
            name: name.into(),
            parent: Some(Arc::clone(parent)),
            sibling_link: LinkedListLink::new(),
            global_link:  LinkedListLink::new(),
            children:      Mutex::new(LinkedList::new(DomainSiblingAdapter::NEW)),
            policy:        effective_policy,
            process_count: AtomicUsize::new(0),
            thread_count:  AtomicUsize::new(0),
            vmo_count:     AtomicUsize::new(0),
            is_critical, 
            critical_procs
        })
    }

    pub fn mint(
        &self,
        source: &Capability,
        requested_rights: Rights,
    ) -> Result<Capability, DomainError> {
        if matches!(source._type, CapType::Null) {
            return Err(DomainError::NullCapability);
        }

        let policy = self.policy.policy_for(&source._type);

        if !policy.allowed {
            return Err(DomainError::PolicyDenied);
        }

        let effective_rights = source.rights & requested_rights & policy.max_rights;

        if effective_rights != requested_rights & source.rights {
            return Err(DomainError::RightsExceedPolicy);
        }

        Ok(Capability {
            rights: effective_rights,
            _type:  source._type.clone(),
        })
    }

    pub fn check_process_limit(&self) -> Result<(), DomainError> {
        if let Some(max) = self.policy.max_processes {
            if self.process_count.load(Ordering::Relaxed) >= max {
                return Err(DomainError::LimitExceeded);
            }
        }
        Ok(())
    }

    pub fn check_thread_limit(&self) -> Result<(), DomainError> {
        if let Some(max) = self.policy.max_threads {
            if self.thread_count.load(Ordering::Relaxed) >= max {
                return Err(DomainError::LimitExceeded);
            }
        }
        Ok(())
    }

    pub fn check_vmo_limit(&self) -> Result<(), DomainError> {
        if let Some(max) = self.policy.max_vmos {
            if self.vmo_count.load(Ordering::Relaxed) >= max {
                return Err(DomainError::LimitExceeded);
            }
        }
        Ok(())
    }

    pub fn on_process_created(&self) {
        self.process_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn on_process_destroyed(&self) {
        self.process_count.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn notify_proc_exit(&self, pid: Pid, exit_code: i64) -> Option<CollapseAction> {
        self.on_process_destroyed();

        let is_critical = match &self.critical_procs {
            Some(procs) => procs.contains(&pid),
            None => false,
        };

        if !is_critical {
            return None;
        }

        Some(self.collapse())
    }

    pub fn collapse(&self) -> CollapseAction {
        let children = self.children.lock();
        for child in children.iter() {
            child.collapse();
        }
        drop(children);

        //kill_all_processes_in_domain(self.koid);

        match &self.parent {
            Some(parent) if self.is_critical => parent.collapse(),
            Some(_) => CollapseAction::KillDomain,
            None => {
                CollapseAction::KernelPanic
            }
        }
    }

    pub fn on_thread_created(&self) { self.thread_count.fetch_add(1, Ordering::Relaxed); }
    pub fn on_thread_destroyed(&self) { self.thread_count.fetch_sub(1, Ordering::Relaxed); }
    pub fn on_vmo_created(&self) { self.vmo_count.fetch_add(1, Ordering::Relaxed); }
    pub fn on_vmo_destroyed(&self) { self.vmo_count.fetch_sub(1, Ordering::Relaxed); }

    pub fn is_descendant_of(&self, ancestor_koid: Koid) -> bool {
        if self.koid == ancestor_koid {
            return true;
        }
        let mut current = self.parent.clone();
        while let Some(p) = current {
            if p.koid == ancestor_koid {
                return true;
            }
            current = p.parent.clone();
        }
        false
    }
}