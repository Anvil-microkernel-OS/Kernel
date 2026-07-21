use crate::{arch::CurrentMemArchSpec, memory::{misc::{arch_specific::Arch, primitives::VirtAddr}, vmm::pflags::PFlags}};

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug)]
    pub struct MapFlags: u32 {
        const READ    = 1 << 0;
        const WRITE   = 1 << 1;
        const EXEC    = 1 << 2;
        const USER    = 1 << 3;
        const NOCACHE = 1 << 4;
    }
}

