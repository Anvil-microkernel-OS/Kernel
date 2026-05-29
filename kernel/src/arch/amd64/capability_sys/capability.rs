use core::ops::BitAnd;

use alloc::sync::Arc;
use spin::Mutex;

use crate::{arch::amd64::{ipc::{channel::ChannelHandle, port::Port}, memory::vmo::Vmo, scheduler::task::{Process, Thread}}, isolation::domain::Domain};

#[derive(Clone)]
pub enum CapType {
    Null,
    VSpace(Arc<Process>),
    Process(Arc<Process>),
    Thread(Arc<Thread>),
    CNode(Arc<Process>),
    Vmo(Arc<Mutex<Vmo>>),
    Channel(ChannelHandle),
    Port(Arc<Port>),
    Domain(Arc<Domain>)
}

pub struct Capability {
    pub rights: Rights,
    pub _type: CapType
}

impl Capability {
    pub fn new(_type: CapType, rights: Rights) -> Self {
        Self {
            _type,
            rights
        }
    }
    
    pub fn null() -> Self {
        Capability {
            rights: Rights::NONE,
            _type: CapType::Null,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self._type, CapType::Null)
    }

    pub fn rights(&self) -> Rights {
        self.rights
    }

    pub fn with_rights(&self, new_rights: Rights) -> Self {
        Capability {
            rights: new_rights,
            _type: self._type.clone(),
        }
    }
}

impl Clone for Capability {
    fn clone(&self) -> Self {
        Capability {
            rights: self.rights,
            _type: self._type.clone(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Rights(u64);

impl Rights {
    pub const NONE:  Rights = Rights(0);
    pub const READ:  Rights = Rights(1 << 0);
    pub const WRITE: Rights = Rights(1 << 1);
    pub const EXEC:  Rights = Rights(1 << 2);
    pub const GRANT: Rights = Rights(1 << 3); 
    pub const DESTROY: Rights = Rights(1 << 4);
    pub const MANAGE: Rights = Rights(1 << 5); 
    pub const ALL:   Rights = Rights(0xFFF);

    pub fn contains(self, other: Rights) -> bool {
        (self.0 & other.0) == other.0
    }

    pub const fn empty() -> Self {
        Rights(0)
    }

    pub const fn all() -> Self {
        Rights(0xFFF)
    }
}

impl BitAnd for Rights {
    type Output = Rights;

    fn bitand(self, rhs: Self) -> Self::Output {
        Rights(self.0 & rhs.0)
    }
}

