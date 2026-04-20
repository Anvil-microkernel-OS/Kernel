pub fn copy_from_user<T>(ptr: usize) -> Option<T>
where T: Copy
{
    if !validate_user_ptr(ptr, core::mem::size_of::<T>()) {
        return None;
    }
    
    unsafe {
        let val: T;
        core::arch::asm!(
            "stac",
            options(nostack, preserves_flags)
        );
        val = (ptr as *const T).read();
        core::arch::asm!(
            "clac",
            options(nostack, preserves_flags)
        );
        Some(val)
    }
}

pub fn copy_to_user<T>(ptr: usize, val: T) -> bool
where T: Copy
{
    if !validate_user_ptr(ptr, core::mem::size_of::<T>()) {
        return false;
    }

    unsafe {
        core::arch::asm!(
            "stac",
            options(nostack, preserves_flags)
        );
        (ptr as *mut T).write(val);
        core::arch::asm!(
            "clac",
            options(nostack, preserves_flags)
        );
    }
    true
}

fn validate_user_ptr(ptr: usize, size: usize) -> bool {
    if ptr == 0
        || ptr % core::mem::align_of::<u8>() != 0 
        || ptr > 0x0000_7FFF_FFFF_FFFF
        || ptr.saturating_add(size) > 0x0000_7FFF_FFFF_FFFF
    {
        return false;
    }
    true
}

pub fn enable_smep() -> bool {
    let cpuid =  core::arch::x86_64::__cpuid_count(7, 0);
    
    let has_smep = cpuid.ebx & (1 << 7)  != 0;

    unsafe {
        let mut cr4: u64;
        core::arch::asm!("mov {}, cr4", out(reg) cr4);
        
        if has_smep {
            cr4 |= 1 << 20; // SMEP bit
        }
        
        core::arch::asm!("mov cr4, {}", in(reg) cr4);
    }

    return has_smep;
}