pub trait IoOperations {
    fn read8(addr: usize) -> u8;
    fn write8(addr: usize, val: u8);
    fn read16(addr: usize) -> u16;
    fn write16(addr: usize, val: u16);
    fn read32(addr: usize) -> u32;
    fn write32(addr: usize, val: u32);
}

