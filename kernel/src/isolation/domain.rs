use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize};

use alloc::{string::String, sync::Arc};
use atomic_enum::atomic_enum;
use intrusive_collections::{LinkedList, LinkedListLink, UnsafeRef, intrusive_adapter};

use crate::arch::amd64::capability_sys::capability::CapType;

type Koid = u32;
type DomainRef = Arc<Domain>;

#[atomic_enum]
pub enum DomainState {
    Active,
    Killing,
    Dead
}

#[repr(u8)]
#[derive(Copy, Clone)]
pub enum PolicyAction {
    Allow = 0,
    Deny = 1,
    Kill = 2,
    AllowException = 3,   
    DenyException = 4,    
}

pub struct Filter {
    name: String,
    rule: FilterRule,
}

pub enum FilterRule {
    DenySyscall { syscall: u16, action: PolicyAction },

    LimitObjectCreation { object_type: CapType, action: PolicyAction },
    
    //Dynamic(DynamicRule),
}

pub struct CompiledFilterChain {
    syscall_deny_mask: [u64; 4],     
    syscall_kill_mask: [u64; 4],
    
    object_creation: ObjectCreationPolicy,
    
    //dynamic_rules: Option<Box<DynamicRules>>,
}

pub struct ObjectCreationPolicy {
    new_process: PolicyAction,
    new_thread: PolicyAction,
    new_vmo: PolicyAction,
    new_channel: PolicyAction,
    new_domain: PolicyAction,
    new_timer: PolicyAction,
    bad_handle: PolicyAction,
}

pub struct DomainPolicy {
    parent_epoch_seen: AtomicU64,
    epoch: AtomicU64,
    timer_slack: AtomicU64,
}

#[repr(align(64))] 
pub struct DomainAccounting {
    pages_committed: AtomicU64,
    _pad1: [u8; 56],
    pub pages_locked: AtomicU64,
    _pad2: [u8; 56],
    pub handles_count: AtomicU32,
    pub threads_count: AtomicU32,
    pub processes_count: AtomicU32,
    pub cpu_time_ns: AtomicU64,
    pub limits: DomainLimits,
}

pub struct DomainLimits {
    pub max_pages: u64,
    pub max_locked_pages: u64,
    pub max_handles: u32,
    pub max_threads: u32,
    pub max_processes: u32,
    pub max_child_domains: u32,
}

pub struct Domain {
    pub koid: Koid,
    pub name: String,
    pub refcount: AtomicUsize,
    pub parent: Option<DomainRef>,

    pub sibling_link: LinkedListLink,
    pub global_link: LinkedListLink,

    pub children: LinkedList<DomainSiblingAdapter>,

    policy: DomainPolicy,
    accounting: DomainAccounting,
    state: AtomicDomainState,
}

intrusive_adapter!(pub DomainSiblingAdapter = UnsafeRef<Domain>: Domain { sibling_link => LinkedListLink });
intrusive_adapter!(pub DomainGlobalAdapter = UnsafeRef<Domain>: Domain { global_link => LinkedListLink });