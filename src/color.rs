use bytemuck::{Pod, Zeroable};

use std::fmt;

#[derive(Debug, Copy, Clone, Zeroable, Pod)]
#[repr(C)]
pub struct Color {
    pub red: u8,
    pub green: u8,
    pub blue: u8,
    pub alpha: u8,
}

impl Color {
    #[inline]
    pub const fn from_array([red, green, blue, alpha]: [u8; 4]) -> Self {
        Self {
            red,
            green,
            blue,
            alpha,
        }
    }
}

impl fmt::Display for Color {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{:02x}{:02x}{:02x}", self.red, self.green, self.blue)?;
        if self.alpha != 255 {
            write!(f, "{:02x}", self.alpha)?;
        }
        Ok(())
    }
}
