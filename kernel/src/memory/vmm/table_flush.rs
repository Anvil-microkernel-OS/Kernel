use core::{marker::PhantomData, mem};

use crate::memory::misc::{arch_specific::Arch, primitives::VirtAddr};

pub trait Flusher<A> {
    fn consume(&mut self, flush: PageFlush<A>);
}

pub struct PageFlush<A> {
    virt: VirtAddr,
    _phantom: PhantomData<A>,
}

impl<A: Arch> PageFlush<A> {
    pub fn new(virt: VirtAddr) -> Self {
        Self {
            virt,
            _phantom: PhantomData,
        }
    }

    pub fn flush(self) {
        A::invalidate(self.virt);
    }

    #[expect(clippy::forget_non_drop)]
    pub unsafe fn ignore(self) {
        mem::forget(self);
    }
}

pub struct PageFlushAll<A: Arch> {
    phantom: PhantomData<fn() -> A>,
}

impl<A: Arch> PageFlushAll<A> {
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }

    pub fn flush(self) {}

    pub unsafe fn ignore(self) {
        mem::forget(self);
    }
}
impl<A: Arch> Drop for PageFlushAll<A> {
    fn drop(&mut self) {
        A::invalidate_all();
    }
}
impl<A: Arch> Flusher<A> for PageFlushAll<A> {
    fn consume(&mut self, flush: PageFlush<A>) {
        unsafe {
            flush.ignore();
        }
    }
}
impl<A: Arch, T: Flusher<A> + ?Sized> Flusher<A> for &mut T {
    fn consume(&mut self, flush: PageFlush<A>) {
        <T as Flusher<A>>::consume(self, flush)
    }
}
impl<A: Arch> Flusher<A> for () {
    fn consume(&mut self, _: PageFlush<A>) {}
}