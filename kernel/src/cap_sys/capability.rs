use core::ops::{BitAnd, BitOr};

use crate::cap_sys::arena::{CNodeKey, ChannelKey, DomainKey, PortKey, ProcessKey, ThreadKey, VSpaceKey, VmoKey};

#[derive(Clone)]
pub enum CapInner {
    VSpace(VSpaceKey),
    Process(ProcessKey),
    Thread(ThreadKey),
    CNode(CNodeKey),
    Vmo(VmoKey),
    Channel(ChannelKey),
    Port(PortKey),
    Domain(DomainKey),
}

pub struct Capability {
    pub inner: Option<CapInner>,
    pub rights: Rights
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct Rights(u16);

impl Rights {
    pub const NONE:    Rights = Rights(0);
    pub const READ:    Rights = Rights(1 << 0);
    pub const WRITE:   Rights = Rights(1 << 1);
    pub const EXEC:    Rights = Rights(1 << 2);
    pub const GRANT:   Rights = Rights(1 << 3);
    pub const DESTROY: Rights = Rights(1 << 4);
    pub const MANAGE:  Rights = Rights(1 << 5);
    pub const ALL:     Rights = Rights(0x3F);

    /// MANAGE → WRITE|READ, WRITE → READ, EXEC → READ
    #[inline(always)]
    const fn expand(bits: u16) -> u16 {
        let mut b = bits;
        // MANAGE need WRITE + READ + DESTROY
        if b & (1 << 5) != 0 { b |= (1 << 1) | (1 << 0) | (1 << 4); }
        // WRITE need READ
        if b & (1 << 1) != 0 { b |= 1 << 0; }
        // EXEC need READ
        if b & (1 << 2) != 0 { b |= 1 << 0; }
        b
    }

    #[inline(always)]
    pub const fn new(bits: u16) -> Self {
        Rights(Self::expand(bits))
    }

    #[inline(always)]
    pub const fn contains(self, other: Rights) -> bool {
        let expanded = Self::expand(self.0);
        (expanded & other.0) == other.0
    }

    #[inline(always)]
    pub const fn attenuate(self, mask: Rights) -> Rights {
        Rights(self.0 & mask.0)
    }

    #[inline(always)]
    pub const fn can_derive(self, subset: Rights) -> bool {
        self.contains(subset)
    }

    pub const fn empty() -> Self { Rights(0) }
    pub const fn bits(self) -> u16 { self.0 }
}

impl BitAnd for Rights {
    type Output = Rights;
    #[inline(always)]
    fn bitand(self, rhs: Self) -> Self { Rights(self.0 & rhs.0) }
}

impl BitOr for Rights {
    type Output = Rights;
    #[inline(always)]
    fn bitor(self, rhs: Self) -> Self { Rights(Self::expand(self.0 | rhs.0)) }
}