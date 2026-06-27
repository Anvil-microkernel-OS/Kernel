use core::marker::PhantomData;

use crate::memory::{misc::{arch_specific::Arch, primitives::PhysAddr}, vmm::pflags::PFlags};

#[derive(Clone, Copy, Debug)]
pub struct VPage<A> {
    data_ptr: usize,
    _phantom: PhantomData<A>
}

impl<A: Arch> VPage<A> {
    #[inline(always)]
    pub fn new(address: usize, flags: usize) -> Self {
        let data = (((address >> A::PAGE_SHIFT) & A::ENTRY_ADDRESS_MASK) << A::ENTRY_ADDRESS_SHIFT)
            | flags;
        Self::from_data(data)
    }

    #[inline(always)]
    pub fn from_data(data: usize) -> Self {
        Self {
            data_ptr: data,
            _phantom: PhantomData,
        }
    }

    #[inline(always)]
    pub fn data(&self) -> usize {
        self.data_ptr
    }

    #[inline(always)]
    pub fn address(&self) -> Result<PhysAddr, PhysAddr> {
        let addr = PhysAddr::new(
            ((self.data_ptr >> A::ENTRY_ADDRESS_SHIFT) & A::ENTRY_ADDRESS_MASK) << A::PAGE_SHIFT,
        );

        if self.present() {
            Ok(addr)
        } else {
            Err(addr)
        }
    }

    #[inline(always)]
    pub fn flags(&self) -> PFlags<A> {
        unsafe { PFlags::from_data(self.data_ptr & A::ENTRY_FLAGS_MASK) }
    }
    #[inline(always)]
    pub fn set_flags(&mut self, flags: PFlags<A>) {
        self.data_ptr &= !A::ENTRY_FLAGS_MASK;
        self.data_ptr |= flags.data();
    }

    #[inline(always)]
    pub fn present(&self) -> bool {
        self.data_ptr & A::ENTRY_FLAG_PRESENT != 0
    }
}