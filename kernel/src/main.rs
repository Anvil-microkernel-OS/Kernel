#![no_std]
#![no_main]

use core::fmt::Write;
use crate::arch::early_startup;
use crate::arch::interrupt::halt;
use crate::bootinfo::BootInfo;
use crate::early_print::fb_printer::{RENDERER, ScrollingFbTextRenderer};
use crate::framebuffer::Framebuffer;
use crate::scheduling::core::{init_scheduler_percpu, initialize_cpu_descr_storages};
extern crate alloc;

mod arch;
mod serial;
pub mod framebuffer;
mod early_print;
mod bootinfo;
mod panic;
pub mod interrupt;
mod memory;
pub mod platform_description;
pub mod io_ops;
pub mod percpu;
pub mod smp;
pub mod timer;
pub mod misc;
pub mod scheduling;
pub mod cap_sys;

include!(concat!(env!("OUT_DIR"), "/kernel_version.rs"));

static FONT: &[u8] = include_bytes!("../external/cp850-8x16.psf");

pub fn print_hello_banner() {
    let mut renderer = RENDERER.get().unwrap().lock();
    renderer.set_color(0xFFFFFF, 0x000000);
    
    write!(renderer, "\n").unwrap();
    write!(renderer, "========================================================\n").unwrap();
    write!(renderer, "  {} - Experimental microkernel operating system\n", KERNEL_NAME).unwrap();
    write!(renderer, "========================================================\n").unwrap();
    write!(renderer, "  Version:   {}\n", KERNEL_VERSION_FULL).unwrap();
    write!(renderer, "--------------------------------------------------------\n").unwrap();
    write!(renderer, "  Version:   {}\n", KERNEL_VERSION_FULL).unwrap();
    write!(renderer, "  Git:       {} ({})\n", GIT_HASH, GIT_BRANCH).unwrap();
    write!(renderer, "  Built:     unix {}\n", BUILD_UNIX_TIME).unwrap();
    write!(renderer, "  Toolchain: {}\n", RUSTC_VERSION).unwrap();
    write!(renderer, "  Target:    {}\n", TARGET_TRIPLE).unwrap();
    write!(renderer, "========================================================\n").unwrap();
    write!(renderer, "\n").unwrap();

    write!(renderer, "Booting...\n").unwrap();
}

#[unsafe(no_mangle)]
unsafe extern "C" fn kmain() -> ! {
    BootInfo::init(); 
    assert!(BootInfo::get().bootloader_supported());

    serial_print!("kmain started!\n");

    Framebuffer::init(
        BootInfo::get().framebuffer().unwrap().addr(), 
        BootInfo::get().framebuffer().unwrap().width() as usize, 
        BootInfo::get().framebuffer().unwrap().height() as usize, 
        BootInfo::get().framebuffer().unwrap().pitch() as usize,
        BootInfo::get().framebuffer().unwrap().bpp() as usize
    );

    ScrollingFbTextRenderer::init(
        FONT,
        Framebuffer::get_global()
    );

    print_hello_banner();

    early_startup();

    initialize_cpu_descr_storages(1);
    init_scheduler_percpu();

    loop {
        halt();
    }
}

#[panic_handler]
fn rust_panic(_info: &core::panic::PanicInfo) -> ! {
    serial_print!("Kernel panic at: {:?}\nMessage:{:?}\n", _info.location(), _info.message());
    //let message = format!("Kernel Panic at: {:?}\nMessage: {:?}\n", _info.location(), _info.message());
    //panic_screen(message.as_str(), true);

    loop {
        halt();
    }
}
