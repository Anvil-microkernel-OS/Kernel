use crate::memory::pmm::hhdm_offset;

pub mod primitives;
pub mod arch_specific;

pub const KILOBYTE: usize = 1024;
pub const MEGABYTE: usize = KILOBYTE * 1024;
pub const GIGABYTE: usize = MEGABYTE * 1024;
pub const TERABYTE: usize = GIGABYTE * 1024;

#[inline]
pub fn virt_to_phys(virt: usize) -> usize {
    return virt - hhdm_offset();
}

#[inline]
pub fn phys_to_virt(phys: usize) -> usize {
    return phys + hhdm_offset();
}

#[inline]
pub const fn align_up(x: usize, a: usize) -> usize {
    (x + a - 1) & !(a - 1)
}

#[inline]
pub const fn align_down(x: usize, a: usize) -> usize {
    x & !(a - 1)
}

#[inline]
pub fn floor_log2(x: usize) -> usize {
    usize::BITS as usize - 1 - x.leading_zeros() as usize
}

#[inline]
pub fn pages_to_order(pages: usize) -> usize {
    assert!(pages > 0);
    let mut order = 0;
    let mut n = 1usize;
    while n < pages {
        n <<= 1;
        order += 1;
    }
    order
}

pub struct HumanSize {
    pub value: usize,
    pub unit: SizeUnit,
}

#[derive(Clone, Copy, Debug)]
pub enum SizeUnit {
    Bytes,
    KiB,
    MiB,
    GiB,
    TiB,
}

impl SizeUnit {
    pub const fn as_str(self) -> &'static str {
        match self {
            SizeUnit::Bytes => "B",
            SizeUnit::KiB   => "KiB",
            SizeUnit::MiB   => "MiB",
            SizeUnit::GiB   => "GiB",
            SizeUnit::TiB   => "TiB",
        }
    }
}

pub fn human_readable_size(bytes: usize) -> HumanSize {
    if bytes >= TERABYTE {
        HumanSize {
            value: bytes / TERABYTE,
            unit: SizeUnit::TiB,
        }
    } else if bytes >= GIGABYTE {
        HumanSize {
            value: bytes / GIGABYTE,
            unit: SizeUnit::GiB,
        }
    } else if bytes >= MEGABYTE {
        HumanSize {
            value: bytes / MEGABYTE,
            unit: SizeUnit::MiB,
        }
    } else if bytes >= KILOBYTE {
        HumanSize {
            value: bytes / MEGABYTE,
            unit: SizeUnit::KiB,
        }
    } else {
        HumanSize {
            value: bytes,
            unit: SizeUnit::Bytes,
        }
    }
}