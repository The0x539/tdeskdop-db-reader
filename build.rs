use heck::SnekCase;
use indexmap::IndexMap;

use std::fs::File;
use std::io::{BufRead, BufReader, Write};

#[derive(Debug, Copy, Clone)]
struct Color {
    red: u8,
    green: u8,
    blue: u8,
    alpha: u8,
}

enum PaletteEntry<'a> {
    Rgb(u8, u8, u8),
    Rgba(u8, u8, u8, u8),
    Name(&'a str),
    Or(Box<Self>, Box<Self>),
}

impl<'a> PaletteEntry<'a> {
    fn from_str(s: &'a str) -> Option<Self> {
        if let Some((l, r)) = s.split_once('|') {
            let left = Self::from_str(l)?;
            let right = Self::from_str(r)?;
            return Some(Self::Or(Box::new(left), Box::new(right)));
        }

        let s = s.trim();
        if s == "" {
            None
        } else if s.starts_with('#') {
            let s = &s[1..];
            if s.len() != 6 && s.len() != 8 {
                return None;
            }
            // TODO: this doesn't handle non-ASCII very well
            let red = u8::from_str_radix(&s[0..2], 16).ok()?;
            let green = u8::from_str_radix(&s[2..4], 16).ok()?;
            let blue = u8::from_str_radix(&s[4..6], 16).ok()?;
            if s.len() == 8 {
                let alpha = u8::from_str_radix(&s[6..8], 16).ok()?;
                Some(Self::Rgba(red, green, blue, alpha))
            } else {
                Some(Self::Rgb(red, green, blue))
            }
        } else {
            Some(Self::Name(s))
        }
    }

    fn resolve(&self, palette: &IndexMap<String, Color>) -> Option<Color> {
        match *self {
            Self::Rgba(red, green, blue, alpha) => Some(Color {
                red,
                green,
                blue,
                alpha,
            }),
            Self::Rgb(red, green, blue) => Some(Color {
                red,
                green,
                blue,
                alpha: 255,
            }),
            Self::Name(name) => palette.get(name).copied(),
            Self::Or(ref l, ref r) => l.resolve(palette).or_else(|| r.resolve(palette)),
        }
    }
}

type Palette = IndexMap<String, Color>;

const PALETTE_DEFINITION_PATH: &str = "colors.palette";

fn load_palette_definition() -> std::io::Result<Palette> {
    let palette_file = BufReader::new(File::open(PALETTE_DEFINITION_PATH)?);

    let mut palette = IndexMap::new();
    palette.insert(
        "transparent".to_owned(),
        Color {
            red: 255,
            green: 255,
            blue: 255,
            alpha: 0,
        },
    );

    for line in palette_file.lines() {
        let line = line?;
        let trimmed = match line.find("//") {
            Some(i) => line[..i].trim(),
            None => line.trim(),
        };
        if trimmed.is_empty() {
            continue;
        }

        let colon = line.find(':').expect("no colon");
        let semicolon = line.find(';').expect("no semicolon");

        let name = line[..colon].trim();
        let value = line[colon + 1..semicolon].trim();

        let color = PaletteEntry::from_str(value)
            .expect("color parse fail")
            .resolve(&palette)
            .expect("no entry");

        palette.insert(name.to_owned(), color);
    }

    Ok(palette)
}

const PALETTE_MODULE_PATH: &str = "src/palette.rs";

fn main() -> std::io::Result<()> {
    let palette = load_palette_definition()?;
    let mut checksum_string = Vec::new();
    for (name, color) in &palette {
        write!(
            checksum_string,
            "&{}:{{ {}, {}, {}, {} }}",
            name, color.red, color.green, color.blue, color.alpha,
        )?;
    }
    let checksum = crczoo::crc32(&checksum_string);

    let n_colors = palette.len();
    let n_bytes = n_colors * 4;

    let mut palette_module = File::create(PALETTE_MODULE_PATH)?;

    macro_rules! w {
        ($($x:tt)*) => {
            writeln!(palette_module, $($x)*)?
        }
    }

    w!("use crate::color::Color;");
    w!("use bytemuck::{{Zeroable, Pod}};");
    w!("use std::fmt;");

    w!("#[derive(Debug, Copy, Clone, Zeroable, Pod)]");
    w!("#[repr(C)]");
    w!("pub struct Palette {{");
    for name in palette.keys() {
        w!("    pub {}: Color,", name.to_snek_case());
    }
    w!("}}");

    w!("impl Palette {{");
    w!("    pub const CHECKSUM: u32 = {};", checksum);
    w!(
        "    pub fn load_from_cache(cached: Box<[u8; {}]>) -> Box<Self> {{",
        n_bytes,
    );
    w!("        bytemuck::allocation::cast_box(cached)");
    w!("    }}");
    w!("}}");

    w!("impl fmt::Display for Palette {{");
    w!("    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {{");
    for name in palette.keys() {
        // TODO: skip if equal to default value?
        w!(
            "        writeln!(f, \"{}: {{}};\", self.{})?;",
            name,
            name.to_snek_case(),
        );
    }
    w!("        Ok(())");
    w!("    }}");
    w!("}}");

    Ok(())
}
