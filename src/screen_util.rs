#![allow(dead_code)]

use nanos_sdk::screen;

pub fn draw(x_pos: i32, y_pos: i32, w: u32, h: u32, inv: bool, bmp: &[u8]) {
    screen::sdk_bagl_hal_draw_bitmap_within_rect(x_pos, y_pos, w, h, inv, bmp);
    screen::sdk_screen_update();
}

pub fn fulldraw(x_pos: i32, y_pos: i32, bmp: &[u8]) {
    draw(x_pos, y_pos, 128, 64, false, bmp);
}

#[cfg(not(feature = "speculos"))]
pub fn seph_setup_ticker(interval_ms: u16) {
    let ms = interval_ms.to_be_bytes();
    nanos_sdk::seph::seph_send(&[0x4e, 0, 2, ms[0], ms[1]]);
}
