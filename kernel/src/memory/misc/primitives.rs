use core::fmt;

use crate::{arch::CurrentMemArchSpec, memory::misc::arch_specific::Arch};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TableKind {
    User,
    Kernel,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct PhysAddr(pub usize);

impl PhysAddr {
    pub const fn new(addr: usize) -> Self {
        Self(addr)
    }

    pub const fn as_usize(self) -> usize {
        self.0
    }

    pub const fn pfn(self) -> Pfn {
        Pfn(self.0 >> CurrentMemArchSpec::PAGE_SHIFT)
    }

    pub const fn is_page_aligned(self) -> bool {
        self.0 & (CurrentMemArchSpec::PAGE_SIZE - 1) == 0
    }

    pub const fn page_offset(self) -> usize {
        self.0 & (CurrentMemArchSpec::PAGE_SIZE - 1)
    }

    pub const fn page_align_down(self) -> Self {
        Self(self.0 & !(CurrentMemArchSpec::PAGE_SIZE - 1))
    }

    pub const fn page_align_up(self) -> Self {
        Self((self.0 + CurrentMemArchSpec::PAGE_SIZE - 1) & !(CurrentMemArchSpec::PAGE_SIZE - 1))
    }
}

impl core::ops::Add<usize> for PhysAddr {
    type Output = Self;
    fn add(self, rhs: usize) -> Self {
        Self(self.0 + rhs)
    }
}

impl core::ops::Sub<PhysAddr> for PhysAddr {
    type Output = usize;
    fn sub(self, rhs: PhysAddr) -> usize {
        self.0 - rhs.0
    }
}

impl fmt::Debug for PhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PhysAddr({:#x})", self.0)
    }
}

impl fmt::Display for PhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Pfn(pub usize);

impl Pfn {
    pub const fn new(pfn: usize) -> Self {
        Self(pfn)
    }

    pub const fn to_phys(self) -> PhysAddr {
        PhysAddr(self.0 << CurrentMemArchSpec::PAGE_SHIFT)
    }

    pub const fn as_usize(self) -> usize {
        self.0
    }
}

impl fmt::Debug for Pfn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pfn({})", self.0)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct VirtAddr(pub usize);

impl VirtAddr {
    pub const fn new(addr: usize) -> Self {
        Self(addr)
    }

    pub const fn as_usize(self) -> usize {
        self.0
    }

    pub const fn as_ptr<T>(self) -> *const T {
        self.0 as *const T
    }

    pub const fn as_mut_ptr<T>(self) -> *mut T {
        self.0 as *mut T
    }

    pub const fn is_page_aligned(self) -> bool {
        self.0 & (CurrentMemArchSpec::PAGE_SIZE - 1) == 0
    }

    pub const fn page_align_down(self) -> Self {
        Self(self.0 & !(CurrentMemArchSpec::PAGE_SIZE - 1))
    }

    pub const fn page_align_up(self) -> Self {
        Self((self.0 + CurrentMemArchSpec::PAGE_SIZE - 1) & !(CurrentMemArchSpec::PAGE_SIZE - 1))
    }

    pub const fn page_offset(self) -> usize {
        self.0 & (CurrentMemArchSpec::PAGE_SIZE - 1)
    }

    #[inline(always)]
    pub fn kind(&self) -> TableKind {
        if (self.0 as isize) < 0 {
            TableKind::Kernel
        } else {
            TableKind::User
        }
    }
}

impl core::ops::Add<usize> for VirtAddr {
    type Output = Self;
    fn add(self, rhs: usize) -> Self { Self(self.0 + rhs) }
}

impl core::ops::Sub<usize> for VirtAddr {
    type Output = Self;
    fn sub(self, rhs: usize) -> Self { Self(self.0 - rhs) }
}

impl core::ops::Sub<VirtAddr> for VirtAddr {
    type Output = usize;
    fn sub(self, rhs: VirtAddr) -> usize { self.0 - rhs.0 }
}

impl fmt::Debug for VirtAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VirtAddr({:#x})", self.0)
    }
}

impl fmt::Display for VirtAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}