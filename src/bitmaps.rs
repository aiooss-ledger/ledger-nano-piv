#![allow(unused)]
use crate::screen_util::draw;

#[derive(Copy, Clone)]
pub struct Glyph<const S: usize> {
    pub bitmap: [u8; S],
    pub width: u32,
    pub height: u32,
    pub inverted: bool,
}

impl<const S: usize> Glyph<S> {
    pub const fn new(bitmap: [u8; S], width: u32, height: u32) -> Glyph<S> {
        Glyph {
            bitmap,
            width,
            height,
            inverted: false,
        }
    }
    pub const fn from_include(packed: ([u8; S], u32, u32)) -> Glyph<S> {
        Glyph {
            bitmap: packed.0,
            width: packed.1,
            height: packed.2,
            inverted: false,
        }
    }
    pub const fn invert(self) -> Glyph<S> {
        Glyph {
            inverted: true,
            ..self
        }
    }
    pub fn erase(&self, x: i32, y: i32) {
        draw(x, y, self.width, self.height, false, &BLANK[..S]);
    }
    pub fn draw(&self, x: i32, y: i32) {
        draw(x, y, self.width, self.height, self.inverted, &self.bitmap);
    }
}

use crate::layout::*;

impl<const S: usize> Displayable for Glyph<S> {
    fn display_pad(&self, line: Line, layout: Layout, padding: i32) {
        let x = match layout {
            Layout::LeftAligned => 2,
            Layout::RightAligned => 126 - self.width,
            Layout::Centered => 64 - self.width / 2,
        } as i32;
        draw(
            x,
            line as i32 - self.height as i32,
            self.width as u32,
            self.height,
            self.inverted,
            &self.bitmap,
        );
    }
}

impl<const S: usize> Displayable for [Glyph<S>] {
    fn display_pad(&self, line: Line, layout: Layout, padding: i32) {
        let total_width = self.len() * (self[0].width as usize + padding as usize); // width is the same for all elements, due to the type
        let mut cur_x = match layout {
            Layout::LeftAligned => 2,
            Layout::RightAligned => 126 - total_width,
            Layout::Centered => 64 - total_width / 2,
        } as i32;
        for bmp in self.iter() {
            draw(
                cur_x,
                line as i32 - bmp.height as i32,
                bmp.width as u32,
                bmp.height,
                bmp.inverted,
                &bmp.bitmap,
            );
            cur_x += bmp.width as i32 + padding;
        }
    }
}

pub const BLANK: [u8; 128 * 8] = [0u8; 128 * 8];
pub const PADLOCK: Glyph<25> = Glyph::new(
    [
        0x00, 0x00, 0x78, 0x00, 0x3f, 0xc0, 0x0c, 0x30, 0x03, 0xff, 0xc3, 0xff, 0x30, 0x30, 0x0c,
        0x0c, 0x03, 0xc3, 0xc0, 0xf0, 0x3f, 0xfc, 0x0f, 0x00, 0x00,
    ],
    14,
    14,
);
