mod opensans;

pub struct CharArray([&'static [u8]; 96]);

struct Font {
    chars: CharArray,
    dims: [u8; 96],
    height: u8,
}

impl Font {
    const fn new(chars: CharArray, dims: [u8; 96], height: u8) -> Font {
        Font {
            chars,
            dims,
            height,
        }
    }
}

use nanos_sdk::pic_rs;
// use core::ops::Index;
// impl Index<usize> for CharArray {
//     type Output = &'static [u8];
//     fn index(&self, index: usize) -> &Self::Output {
//         nanos_sdk::debug_print("yolo");
//         pic_rs(&self.0[index])
//     }
// }

const OPEN_SANS_REGULAR_11PX: Font = Font::new(
    opensans::OPEN_SANS_REGULAR_11PX_CHARS,
    opensans::OPEN_SANS_REGULAR_11PX_DIMS,
    12,
);
const OPEN_SANS_EXTRABOLD_11PX: Font = Font::new(
    opensans::OPEN_SANS_EXTRABOLD_11PX_CHARS,
    opensans::OPEN_SANS_EXTRABOLD_11PX_DIMS,
    12,
);

// use nanos_sdk::pic;
use crate::screen_util::draw;
use core::ffi::c_void;
extern "C" {
    fn pic(link_address: *mut c_void) -> *mut c_void;
}
// pub fn picrs<T>(x: &T) -> &T {
//     let ptr = unsafe { pic(x as *const T as *mut c_void) as *const T };
//     unsafe { &*ptr }
// }

use crate::layout::*;

const OPEN_SANS: [Font; 2] = [OPEN_SANS_REGULAR_11PX, OPEN_SANS_EXTRABOLD_11PX];

impl Displayable for &str {
    fn display_pad(&self, y: Line, layout: Layout, padding: i32) {
        let mut font_choice = 0;
        let total_width = self
            .as_bytes()
            .iter()
            .map(pic_rs)
            .fold(0u8, |acc, c| match *c {
                b'*' => {
                    font_choice ^= 1;
                    acc
                }
                _ => acc + OPEN_SANS[font_choice].dims[*c as usize - 0x20] + padding as u8,
            });

        let mut cur_x = match layout {
            Layout::LeftAligned => 2,
            Layout::RightAligned => 126 - total_width,
            Layout::Centered => 64 - total_width / 2,
        } as i32;

        for c in self.as_bytes().iter().map(pic_rs) {
            if *c == b'*' {
                font_choice ^= 1;
                continue;
            }

            let offset_c = *c as usize - 0x20;
            // let character = picrs(&OPEN_SANS[font_choice].chars.0[offset_c]);
            let character = unsafe {
                let tmp = pic(OPEN_SANS[font_choice].chars.0[offset_c].as_ptr() as *mut c_void)
                    as *const u8;
                core::slice::from_raw_parts(tmp, OPEN_SANS[font_choice].chars.0[offset_c].len())
            };
            let c_width = OPEN_SANS[font_choice].dims[offset_c];
            let c_height = OPEN_SANS[font_choice].height;
            draw(
                cur_x,
                y as i32 - (3 * c_height / 2) as i32,
                c_width as u32,
                c_height as u32,
                false,
                character,
            );
            cur_x += c_width as i32 + padding;
        }
    }
}
