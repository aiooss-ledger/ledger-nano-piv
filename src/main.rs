#![no_std]
#![no_main]

use nanos_sdk::buttons::ButtonEvent;
use nanos_sdk::io;
use nanos_sdk::bindings::{os_serial};

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
    // WrongData = 0x6A80,
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

/// Verify card command
fn process_verify(comm: &mut io::Comm) {
    if comm.get_p1() != 0x00 && comm.get_p1() != 0xFF {
        return comm.reply(StatusWords::IncorrectP1P2);
    }

    // TODO
    comm.reply_ok();
}

/// Generate Asymmetric Key Pair card command
fn process_gen_asym(comm: &mut io::Comm) {
    if comm.get_p1() != 0x00 {
        return comm.reply(StatusWords::IncorrectP1P2);
    }

    // TODO
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

/// Put data on card
fn process_put_data(comm: &mut io::Comm) {
    if comm.get_p1() != 0x3F || comm.get_p2() != 0xFF {
        return comm.reply(StatusWords::IncorrectP1P2);
    }

    // TODO
    comm.reply_ok();
}

/// Get card metadata
fn process_get_metadata(comm: &mut io::Comm) {
    // TODO
    comm.reply_ok();
}

/// Get ledger serial

const LEDGER_SERIAL_SIZE: usize = 7;
const SERIAL_SIZE_AGE: usize = 4;

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


    let serial = get_ledger_serial();
    comm.append(&serial[0..SERIAL_SIZE_AGE]);
    comm.reply_ok();
}

/// Reset card content
///
/// Clear all slots, all tags and regenerate guid, card id and serial.
fn process_reset(comm: &mut io::Comm) {
    if comm.get_p1() != 0x00 || comm.get_p2() != 0x00 {
        return comm.reply(StatusWords::IncorrectP1P2);
    }

    // TODO
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

/// Import asymetric private key
fn process_import_asym(comm: &mut io::Comm) {
    // TODO
    comm.reply_ok();
}

#[no_mangle]
extern "C" fn sample_main() {
    let mut comm = io::Comm::new();
    loop {
        match comm.next_event() {
            io::Event::Button(ButtonEvent::BothButtonsRelease) => nanos_sdk::exit_app(0),
            io::Event::Button(_) => {},

            // Standard PIV commands
            // See https://csrc.nist.gov/publications/detail/sp/800-73/4/final
            io::Event::Command(0x20) => process_verify(&mut comm),
            io::Event::Command(0x47) => process_gen_asym(&mut comm),
            io::Event::Command(0x87) => process_general_auth(&mut comm),
            io::Event::Command(0xC0) => continue_response(&mut comm),
            io::Event::Command(0xCB) => process_get_data(&mut comm),
            io::Event::Command(0xDB) => process_put_data(&mut comm),

            // YubicoPIV extensions
            // See https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html
            io::Event::Command(0xf7) => process_get_metadata(&mut comm),
            io::Event::Command(0xf8) => process_get_serial(&mut comm),
            io::Event::Command(0xfb) => process_reset(&mut comm),
            io::Event::Command(0xfd) => process_get_version(&mut comm),
            io::Event::Command(0xfe) => process_import_asym(&mut comm),

            io::Event::Command(_) => comm.reply(StatusWords::FuncNotSupported),

            io::Event::Ticker => {}
        }
    }
}
