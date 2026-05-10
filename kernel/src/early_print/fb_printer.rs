use spin::{Mutex, Once};

use crate::framebuffer::Framebuffer;

pub static RENDERER: Once<Mutex<ScrollingFbTextRenderer>> = Once::new();

#[repr(C, packed)]
struct PSF1Header {
    magic: [u8; 2],
    mode: u8,
    charsize: u8,
}

#[repr(C, packed)]
struct PSF2Header {
    magic: [u8; 4],
    version: u32,
    headersize: u32,
    flags: u32,
    numglyph: u32,
    bytesperglyph: u32,
    height: u32,
    width: u32,
}

pub struct ScrollingFbTextRenderer {
    x: usize,                        
    y: usize,
    font_data: &'static [u8],
    char_width: usize,
    char_height: usize,
    bytes_per_glyph: usize,
    fg_color: u32,                   
    bg_color: u32,                   
    fb: &'static Mutex<Framebuffer>,
}

impl ScrollingFbTextRenderer {
    pub fn init(
        font_data: &'static [u8],
        fb: &'static Mutex<Framebuffer>
    ) {
        let (char_width, char_height, bytes_per_glyph) = Self::parse_psf(font_data);
        
        RENDERER.call_once(|| Mutex::new(Self {
            x: 0,
            y: 0,
            font_data,
            char_width,
            char_height,
            bytes_per_glyph,
            fg_color: 0xFFFFFF,           
            bg_color: 0x000000,           
            fb
        }));
    }

    fn parse_psf(data: &[u8]) -> (usize, usize, usize) {
        if data.len() >= 32 && &data[0..4] == b"\x72\xb5\x4a\x86" {
            let header = unsafe { &*(data.as_ptr() as *const PSF2Header) };
            return (
                header.width as usize,
                header.height as usize,
                header.bytesperglyph as usize,
            );
        }
        
        if data.len() >= 4 && &data[0..2] == b"\x36\x04" {
            let header = unsafe { &*(data.as_ptr() as *const PSF1Header) };
            let height = header.charsize as usize;
            let width = 8;
            let bytes_per_glyph = height;
            return (width, height, bytes_per_glyph);
        }
        
        (8, 16, 16)
    }

    fn header_size(&self) -> usize {
        if self.font_data.len() >= 32 && &self.font_data[0..4] == b"\x72\xb5\x4a\x86" {
            let header = unsafe { &*(self.font_data.as_ptr() as *const PSF2Header) };
            header.headersize as usize
        } else {
            4
        }
    }

    fn get_glyph_offset(&self, ch: char) -> usize {
        let idx = ch as usize;
        let max_glyphs = (self.font_data.len() - self.header_size()) / self.bytes_per_glyph;
        
        let glyph_idx = if idx < max_glyphs { idx } else { 0 };
        self.header_size() + glyph_idx * self.bytes_per_glyph
    }

    fn draw_char_at(
        &self,
        ch: char,
        px: usize,
        py: usize,
        fg: u32,
        bg: u32,
        fb: &mut Framebuffer,
    ) {
        let glyph_offset = self.get_glyph_offset(ch);
        let glyph_data = &self.font_data[glyph_offset..glyph_offset + self.bytes_per_glyph];

        let bytes_per_line = (self.char_width + 7) / 8;

        for row in 0..self.char_height {
            let line_offset = row * bytes_per_line;

            for col in 0..self.char_width {
                let byte_idx = line_offset + (col / 8);
                let bit_idx = 7 - (col % 8);

                if byte_idx < glyph_data.len() {
                    let bit = (glyph_data[byte_idx] >> bit_idx) & 1;
                    let color = if bit == 1 { fg } else { bg };
                    fb.draw_pixel(px + col, py + row, color);
                }
            }
        }
    }

    pub fn set_color(&mut self, fg: u32, bg: u32) {
        self.fg_color = fg;
        self.bg_color = bg;

        let mut locked_fb = self.fb.lock();
        locked_fb.set_color(fg, bg);
        locked_fb.clear_with_color();
    }


    pub fn grid_dims(&self) -> (usize, usize) {
        let fb = self.fb.lock();
        let cols = fb.get_width() / self.char_width;
        let rows = fb.get_height() / self.char_height;
        (cols, rows)
    }

    pub fn clear_row(&mut self, row: usize) {
        let mut fb = self.fb.lock();
        let fb_width = fb.get_width();
        let fb_height = fb.get_height();

        let py = row * self.char_height;
        if py + self.char_height > fb_height { return; }

        for x in 0..fb_width {
            for y in py..py + self.char_height {
                fb.draw_pixel(x, y, self.bg_color);
            }
        }
    }

    pub fn set_cursor(&mut self, col: usize, row: usize) {
        self.x = col * self.char_width;
        self.y = row * self.char_height;
    }

    pub fn get_cursor(&self) -> (usize, usize) {
        (self.x / self.char_width, self.y / self.char_height)
    }

    fn newline(&mut self, fb: &mut Framebuffer) {
        self.x = 0;
        self.y += self.char_height;

        let fb_height = fb.get_height();

        if self.y + self.char_height > fb_height {
            fb.scroll(self.char_height);
            self.y -= self.char_height;
        }
    }

    pub fn write_char(&mut self, ch: char) {
        let mut fb_guard = self.fb.lock();
        let fb_width = fb_guard.get_width();

        match ch {
            '\n' => {
                self.newline(&mut fb_guard);
            }
            '\r' => {
                self.x = 0;
            }
            '\t' => {
                let tab_width = self.char_width * 4;
                self.x = ((self.x + tab_width) / tab_width) * tab_width;

                if self.x >= fb_width {
                    self.newline(&mut fb_guard);
                }
            }
            _ => {
                if self.x + self.char_width > fb_width {
                    self.newline(&mut fb_guard);
                }

                self.draw_char_at(ch, self.x, self.y, self.fg_color, self.bg_color, &mut fb_guard);
                self.x += self.char_width;
            }
        }
    }

    pub fn write_str(&mut self, s: &str) {
        for ch in s.chars() {
            self.write_char(ch);
        }
    }

    pub fn panic_print_centered(&mut self, start_row: usize, text: &str) -> usize {
        let lines = self.split_into_lines(text);
        let (cols, _) = self.grid_dims();
        
        let mut current_row = start_row;
        for line in &lines {
            let line_len = self.visible_length(line);
            
            let display_len = line_len.min(cols);
            
            let col = if display_len < cols {
                (cols - display_len) / 2
            } else {
                0
            };
            
            self.panic_draw_line_at(col, current_row, line);
            current_row += 1;
            
            let (_, total_rows) = self.grid_dims();
            if current_row >= total_rows {
                break;
            }
        }
        
        lines.len()
    }

    pub fn panic_print_at(&mut self, col: usize, row: usize, text: &str) -> usize {
        let lines = self.split_into_lines(text);
        let mut current_row = row;
        
        for line in &lines {
            self.panic_draw_line_at(col, current_row, line);
            current_row += 1;
            
            let (_, total_rows) = self.grid_dims();
            if current_row >= total_rows {
                break;
            }
        }
        
        lines.len()
    }

    fn split_into_lines<'a>(&self, text: &'a str) -> alloc::vec::Vec<alloc::string::String> {
        use alloc::string::String;
        use alloc::vec::Vec;
        
        let mut lines = Vec::new();
        let mut current_line = String::new();
        
        for ch in text.chars() {
            match ch {
                '\n' => {
                    lines.push(current_line.clone());
                    current_line.clear();
                }
                '\r' => {
                    current_line.clear();
                }
                '\t' => {
                    let target = ((current_line.len() / 4) + 1) * 4;
                    while current_line.len() < target {
                        current_line.push(' ');
                    }
                }
                _ => {
                    current_line.push(ch);
                }
            }
        }
        
        if !current_line.is_empty() {
            lines.push(current_line);
        }
        
        lines
    }

    fn visible_length(&self, s: &str) -> usize {
        s.chars().count()
    }

    fn panic_draw_line_at(&mut self, col: usize, row: usize, line: &str) {
        let mut fb = self.fb.lock();
        let fb_width = fb.get_width();
        let fb_height = fb.get_height();
        
        let mut cur_x = col * self.char_width;
        let cur_y = row * self.char_height;
        
        if cur_y + self.char_height > fb_height {
            return;
        }
        
        for ch in line.chars() {
            if cur_x + self.char_width > fb_width {
                break;
            }
            
            self.draw_char_at(ch, cur_x, cur_y, self.fg_color, self.bg_color, &mut fb);
            cur_x += self.char_width;
        }
    }

    pub fn panic_print_wrapped(&mut self, col: usize, row: usize, text: &str, max_width: usize) -> usize {
        use alloc::vec::Vec;
        
        let lines = self.split_into_lines(text);
        let mut current_row = row;
        let (_, total_rows) = self.grid_dims();
        
        for line in &lines {
            // Разбить строку на куски по max_width
            let chunks = self.wrap_line(line, max_width);
            for chunk in chunks {
                if current_row >= total_rows {
                    return current_row - row;
                }
                self.panic_draw_line_at(col, current_row, &chunk);
                current_row += 1;
            }
        }
        
        current_row - row
    }

    fn wrap_line(&self, line: &str, max_width: usize) -> alloc::vec::Vec<alloc::string::String> {
        use alloc::string::String;
        use alloc::vec::Vec;
        
        let mut chunks = Vec::new();
        let mut current = String::new();
        
        for word in line.split(' ') {
            if current.is_empty() {
                current.push_str(word);
            } else if current.len() + 1 + word.len() <= max_width {
                current.push(' ');
                current.push_str(word);
            } else {
                chunks.push(current.clone());
                current = String::from(word);
            }
        }
        
        if !current.is_empty() {
            chunks.push(current);
        }
        
        chunks
    }

    pub fn panic_print_wrapped_centered(&mut self, row: usize, text: &str, max_width: usize) -> usize {
        use alloc::vec::Vec;
        
        let (cols, total_rows) = self.grid_dims();
        let actual_width = max_width.min(cols);
        let lines = self.split_into_lines(text);
        let mut current_row = row;
        
        for line in &lines {
            let chunks = self.wrap_line(line, actual_width);
            for chunk in chunks {
                if current_row >= total_rows {
                    return current_row - row;
                }
                
                let chunk_len = chunk.chars().count();
                let col = if chunk_len < cols {
                    (cols - chunk_len) / 2
                } else {
                    0
                };
                
                self.panic_draw_line_at(col, current_row, &chunk);
                current_row += 1;
            }
        }
        
        current_row - row
    }
}

impl core::fmt::Write for ScrollingFbTextRenderer {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        Self::write_str(self, s);
        Ok(())
    }
}