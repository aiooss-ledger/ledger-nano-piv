#![no_std]
#![no_main]

use nanos_sdk::bindings::os_serial;
use nanos_sdk::buttons::ButtonEvent;
use nanos_sdk::io;

mod bitmaps;
mod fonts;
mod layout;
mod screen_util;

use layout::*;

nanos_sdk::set_panic!(nanos_sdk::exiting_panic);

/// Status Words as specified in table 6 of Interfaces for Personal Identity
/// Verification specification.
#[derive(Copy, Clone)]
#[repr(u16)]
enum StatusWords {
    // VerificationFailed = 0x6300,
    // SecureMessagingNotSupported = 0x6882,
    // SecurityStatusNotSatisfied = 0x6982,
    // AuthMethodBlocked = 0x6983,
    // MissingSecureMessagingData = 0x6987,
    // IncorrectSecureMessagingData = 0x6988,
    WrongData = 0x6A80,
    FuncNotSupported = 0x6A81,
    // FileNotFound = 0x6A82,
    // FileFull = 0x6A84,
    IncorrectP1P2 = 0x6A86,
    // RefDataNotFound = 0x6A88,
}

impl From<StatusWords> for io::Reply {
    fn from(sw: StatusWords) -> io::Reply {
        io::Reply(sw as u16)
    }
}

const PIV_APP_AID: [u8; 5] = [0xa0, 0x00, 0x00, 0x03, 0x08];

/// Select card command
fn process_select_card(comm: &mut io::Comm) {
    if comm.get_p1() != 0x04 || comm.get_p2() != 0x00 {
        return comm.reply(StatusWords::IncorrectP1P2);
    }
    if let Ok(d) = comm.get_data() {
        if d != PIV_APP_AID {
            return comm.reply(StatusWords::WrongData);
        }
    }

    comm.append(&[
        0x61, 0x11, 0x4f, 0x06, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x79, 0x07, 0x4f, 0x05,
    ]);
    comm.append(&PIV_APP_AID);
    comm.reply_ok();
}

/// General Authenticate card command
fn process_general_auth(comm: &mut io::Comm) {
    // TODO
    comm.reply_ok();
}

/// Ask the card to continue to answer
fn continue_response(comm: &mut io::Comm) {
    if comm.get_p1() != 0x00 || comm.get_p2() != 0x00 {
        return comm.reply(StatusWords::IncorrectP1P2);
    }

    // TODO
    comm.reply_ok();
}

/// Get data from card
fn process_get_data(comm: &mut io::Comm) {
    if comm.get_p1() != 0x3F || comm.get_p2() != 0xFF {
        return comm.reply(StatusWords::IncorrectP1P2);
    }

    // TODO
    comm.reply_ok();
}

/// Get ledger serial
const LEDGER_SERIAL_SIZE: usize = 7;

fn get_ledger_serial() -> [u8; LEDGER_SERIAL_SIZE] {
    let mut serial = [0_u8; LEDGER_SERIAL_SIZE];

    unsafe {
        os_serial(serial.as_mut_ptr(), LEDGER_SERIAL_SIZE as u32);
    }

    serial
}

/// Get card serial
fn process_get_serial(comm: &mut io::Comm) {
    if comm.get_p1() != 0x00 || comm.get_p2() != 0x00 {
        return comm.reply(StatusWords::IncorrectP1P2);
    }

    let ldg_serial = get_ledger_serial();
    let age_serial = [ldg_serial[0], ldg_serial[2], ldg_serial[4], ldg_serial[6]];

    comm.append(&age_serial);
    comm.reply_ok();
}

/// Get card version
fn process_get_version(comm: &mut io::Comm) {
    if comm.get_p1() != 0x00 || comm.get_p2() != 0x00 {
        return comm.reply(StatusWords::IncorrectP1P2);
    }

    // Same answer as Yubikey 5.4 firmware
    comm.append(&[5, 4, 0]);
    comm.reply_ok();
}

#[no_mangle]
extern "C" fn sample_main() {
    let mut comm = io::Comm::new();

    // erase screen
    screen_util::fulldraw(0, 0, &bitmaps::BLANK);
    bitmaps::PADLOCK.draw(64 - (bitmaps::PADLOCK.width as i32) / 2, 4);
    "*PIV* app".display(Line::Second, Layout::Centered);
    loop {
        match comm.next_event() {
            io::Event::Button(ButtonEvent::BothButtonsRelease) => nanos_sdk::exit_app(0),
            io::Event::Button(_) => {}

            // Standard PIV commands
            // See https://csrc.nist.gov/publications/detail/sp/800-73/4/final
            io::Event::Command(0xA4) => process_select_card(&mut comm),
            io::Event::Command(0x87) => process_general_auth(&mut comm),
            io::Event::Command(0xC0) => continue_response(&mut comm),
            io::Event::Command(0xCB) => process_get_data(&mut comm),

            // YubicoPIV extensions
            // See https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html
            io::Event::Command(0xf8) => process_get_serial(&mut comm),
            io::Event::Command(0xfd) => process_get_version(&mut comm),

            io::Event::Command(_) => comm.reply(StatusWords::FuncNotSupported),

            io::Event::Ticker => {}
        }
    }
}
