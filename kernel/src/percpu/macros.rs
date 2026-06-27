use crate::{arch::get_arch_specific_percpu_rg_ptr, percpu::preempt::PreemptGuard};

#[inline(always)]
pub fn percpu_ptr<T>(sym: *const T) -> *mut T {
    let gs = get_arch_specific_percpu_rg_ptr();
    let vma = sym as u64;
    (gs.wrapping_add(vma)) as *mut T
}

#[macro_export]
macro_rules! __raw_define_per_cpu {
    (
        section = $section:literal,
        $(#[$attr:meta])*
        $vis:vis $name:ident : $ty:ty,
        atomic_type = $atomic_ty:ty
    ) => {
        #[unsafe(link_section = $section)]
        $(#[$attr])*
        $vis static $name: core::mem::MaybeUninit<$atomic_ty> =
            core::mem::MaybeUninit::zeroed();

        ::paste::paste! {
            #[inline(always)]
            $vis fn [<get_per_cpu_no_guard_ $name>]() -> $ty {
                let sym = core::ptr::addr_of!($name) as *const $atomic_ty;
                let ptr = $crate::percpu::macros::percpu_ptr(sym);
                unsafe { (&*ptr).load(core::sync::atomic::Ordering::Relaxed) }
            }
        }

        ::paste::paste! {
            #[inline(always)]
            $vis fn [<set_per_cpu_ $name>](v: $ty) {
                let sym = core::ptr::addr_of!($name) as *const $atomic_ty;
                let ptr = $crate::percpu::macros::percpu_ptr(sym);
                unsafe { (&*ptr).store(v, core::sync::atomic::Ordering::Relaxed) }
            }
        }

        ::paste::paste! {
            #[inline(always)]
            $vis fn [<inc_per_cpu_ $name>]() {
                let sym = core::ptr::addr_of!($name) as *const $atomic_ty;
                let ptr = $crate::percpu::macros::percpu_ptr(sym);
                unsafe { 
                    let atomic = &*ptr;
                    let _ = atomic.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                }
            }
        }

        ::paste::paste! {
            #[inline(always)]
            $vis fn [<dec_per_cpu_ $name>]() {
                let sym = core::ptr::addr_of!($name) as *const $atomic_ty;
                let ptr = $crate::percpu::macros::percpu_ptr(sym);
                unsafe { 
                    let atomic = &*ptr;
                    let _ = atomic.fetch_sub(1, core::sync::atomic::Ordering::Relaxed);
                }
            }
        }
    };
}

#[macro_export]
macro_rules! define_per_cpu_u16 {
    ($(#[$attr:meta])* $vis:vis $name:ident) => {
        #[allow(non_snake_case)]
        $crate::__raw_define_per_cpu!(
            section = ".percpu.bss",
            $(#[$attr])*
            $vis $name : u16,
            atomic_type = core::sync::atomic::AtomicU16
        );
    };
}

#[macro_export]
macro_rules! define_per_cpu_u32 {
    ($(#[$attr:meta])* $vis:vis $name:ident) => {
        #[allow(non_snake_case)]
        $crate::__raw_define_per_cpu!(
            section = ".percpu.bss",
            $(#[$attr])*
            $vis $name : u32,
            atomic_type = core::sync::atomic::AtomicU32
        );
    };
}

#[macro_export]
macro_rules! define_per_cpu_u64 {
    ($(#[$attr:meta])* $vis:vis $name:ident) => {
        #[allow(non_snake_case)]
        $crate::__raw_define_per_cpu!(
            section = ".percpu.bss",
            $(#[$attr])*
            $vis $name : u64,
            atomic_type = core::sync::atomic::AtomicU64
        );
    };
}

#[macro_export]
macro_rules! define_per_cpu_struct {
    (
        $(#[$attr:meta])*
        $vis:vis struct $name:ident {
            $(
                $field_vis:vis $field:ident : $ty:ty
            ),* $(,)?
        }
    ) => {
        #[repr(C, align(64))]
        $(#[$attr])*
        $vis struct $name {
            $( $field_vis $field : $ty ),*
        }

        #[unsafe(link_section = ".percpu.bss")]
        static $name: core::mem::MaybeUninit<$name> =
            core::mem::MaybeUninit::zeroed();

        impl $name {
            #[inline(always)]
            fn __gs_base_u64() -> u64 {
                $crate::arch::get_arch_specific_percpu_rg_ptr()
            }

            #[inline(always)]
            fn __sym_vma_u64() -> u64 {
                core::ptr::addr_of!($name) as u64
            }

            #[inline(always)]
            pub fn get() -> &'static Self {
                unsafe {
                    let ptr_u64 = Self::__gs_base_u64().wrapping_add(Self::__sym_vma_u64());
                    &*(ptr_u64 as *const $name)
                }
            }

            #[inline(always)]
            pub fn get_mut() -> &'static mut Self {
                let ptr_u64 = Self::__gs_base_u64().wrapping_add(Self::__sym_vma_u64());
                unsafe { &mut *(ptr_u64 as *mut $name) }
            }

            #[inline(always)]
            pub fn with_guard<R>(f: impl FnOnce(&mut Self) -> R) -> R {
                let _guard =
                    $crate::percpu::preempt::PreemptGuard::new(());
                f(Self::get_mut())
            }
        }
    };
}
