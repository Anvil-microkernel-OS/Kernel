#![no_std]
#![no_main]
#![feature(cell_leak)]
#![feature(abi_x86_interrupt)]

use alloc::format;
use core::fmt::Write;
use crate::arch::amd64::scheduler::exec_loader::make_init_task;
use crate::arch::amd64::scheduler::task_storage::{register_process, register_thread, spawn_thread};
use crate::arch::{early_arch_init, final_arch_init};
use crate::bootinfo::BootInfo;
use crate::cpio_parser::cpio_find;
use crate::early_print::fb_printer::{RENDERER, ScrollingFbTextRenderer};
use crate::framebuffer::Framebuffer;
use crate::isolation::init_root_domain;
use crate::panic::panic_screen;
extern crate alloc;

mod arch;
mod serial;
mod selftest;
mod cmd_args;
pub mod framebuffer;
mod early_print;
mod bootinfo;
mod misc;
mod cpio_parser;
mod core_messaging;
mod panic;
mod isolation;

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

    early_arch_init();

    early_println!("Detecting CPIO...");

    let init_srvs = BootInfo::get_init_srvs().expect("No init pack of services found!");

    early_println!("Detected CPIO!");

    early_println!("Detecting init service...");

    if let Some(data) = cpio_find(init_srvs, "init.bin") {
        let init = make_init_task(data, 1, 0, "init", init_srvs).unwrap();
        register_process(init.0);
        register_thread(&init.1);
        spawn_thread(init.1);
        early_println!("Init service detected & pushed to exec!");
    } else {
        panic!("No init service found!");
    }

    early_println!("Post init arch...");

    final_arch_init()
}

#[panic_handler]
fn rust_panic(_info: &core::panic::PanicInfo) -> ! {
    let message = format!("Kernel Panic at: {:?}\nMessage: {:?}\n", _info.location(), _info.message());
    panic_screen(message.as_str(), true);
}
