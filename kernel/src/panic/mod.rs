use crate::{early_print::fb_printer::RENDERER, serial_print};

pub fn panic_screen(message: &str, kernel_reason: bool) -> ! {
    serial_print!("{}\n", message);
    
    let mut renderer = RENDERER.get().unwrap().lock();
    renderer.set_color(0xFFFFFF, 0x0000AA);
    
    let (cols, rows) = renderer.grid_dims();
    
    let title = if kernel_reason { 
        "ANVIL OS - KERNEL PANIC" 
    } else { 
        "ANVIL OS - MACHINE PANIC" 
    };

    renderer.panic_print_centered(5, title);
    
    let separator = "═".repeat(cols.min(60));
    renderer.panic_print_centered(7, &separator);
    
    let max_msg_width = (cols * 3) / 4;  
    renderer.panic_print_wrapped_centered(
        9,                       
        message,
        max_msg_width
    );
    
    let bottom_message = "The system has stopped. Please contact the developers and send a screenshot of this error.\nGitHub: https://github.com/Anvil-microkernel-OS";

    renderer.panic_print_wrapped_centered(
        rows - 6,
        bottom_message,
        cols - 4  
    );
    
    loop {

    }
}