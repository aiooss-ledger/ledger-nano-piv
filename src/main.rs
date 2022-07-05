#![no_std]
#![no_main]

use nanos_sdk::bindings::os_serial;
use nanos_sdk::buttons::ButtonEvent;
use nanos_sdk::io;
use nanos_sdk::bindings::cx_ecdh_no_throw;
use nanos_sdk::io::SyscallError;
use nanos_sdk::bindings::{CX_ECDH_POINT, CX_OK};
use nanos_sdk::bindings::cx_ecfp_private_key_t;
use nanos_sdk::ecc::CurvesId;

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
    WrongLength = 0x6700,
    // SecureMessagingNotSupported = 0x6882,
    // SecurityStatusNotSatisfied = 0x6982,
    // AuthMethodBlocked = 0x6983,
    // MissingSecureMessagingData = 0x6987,
    // IncorrectSecureMessagingData = 0x6988,
    WrongData = 0x6A80,
    FuncNotSupported = 0x6A81,
    FileNotFound = 0x6A82,
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
const BIP32_PATH: [u32; 5] = nanos_sdk::ecc::make_bip32_path(b"m/5261654'/0'/0'/130'");

/// Helper function that derives the seed over Secp256r1
fn bip32_derive_secp256r1(path: &[u32]) -> Result<[u8; 32], SyscallError> {
    let mut raw_key = [0u8; 32];
    nanos_sdk::ecc::bip32_derive(CurvesId::Secp256r1, path, &mut raw_key)?;
    Ok(raw_key)
}

fn ecdh(
    pvkey: &cx_ecfp_private_key_t,
    mode: u32,
    p: &[u8],
    p_len: u32,
) -> Option<([u8; 0x20])> {

    let mut secret = [0u8; 0x20];
    //let secret_len = &mut (secret.len() as u32);
    let len = unsafe {
        cx_ecdh_no_throw(
            pvkey,
            mode,
            p.as_ptr(),
            p_len,
            secret.as_mut_ptr(),
            0x20
        )
    };
    if len != CX_OK {
        None
    } else {
        Some(secret)
    }
}

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
    let alg = comm.get_p1();
    let key = comm.get_p2();

    // Right now, we only support Secp256r1
    if alg != 0x11 {
        return comm.reply(StatusWords::FuncNotSupported);
    }

    // Right now, we only support retired slots
    if !(0x82 <= key && key <= 0x8C) {
        return comm.reply(StatusWords::FuncNotSupported);
    }

    let d = match comm.get_data() {
        Ok(d) => d,
        Err(_) => {
            return comm.reply(StatusWords::WrongData);
        }
    };

    // Outer layer
    if d[0] != 0x7c {
        return comm.reply(StatusWords::WrongData);
    }

    let length = d[1] as usize;
    let d = &d[2..2+length];

    // Empty tlv (???)
    if d[0] != 0x82 || d[1] != 0 {
        return comm.reply(StatusWords::WrongData);
    }
    let d = &d[2..];

    // Diffie-Hellman packet
    if d[0] != 0x85 {
        return comm.reply(StatusWords::WrongData);
    }
    let length = d[1] as usize;

    if length != 0x41 {
        return comm.reply(StatusWords::WrongData);
    }

    let d = &d[2..];
    // EC point
    if d[0] != 0x04 {
        return comm.reply(StatusWords::WrongData);
    }

    let raw_key = bip32_derive_secp256r1(&BIP32_PATH).unwrap();
    let pk = nanos_sdk::ecc::ec_init_key(CurvesId::Secp256r1, &raw_key).unwrap();

    let secret = ecdh(&pk, CX_ECDH_POINT, d, 0x41).unwrap();

    comm.append(&[0x7c, 0x22, 0x82, 0x20]);
    comm.append(&secret);

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

// Process get data
fn process_get_data(comm: &mut io::Comm) {
    if comm.get_p1() != 0x3F || comm.get_p2() != 0xFF {
        return comm.reply(StatusWords::IncorrectP1P2);
    }

    let data = match comm.get_data() {
        Ok(d) => d,
        Err(e) => {
            return comm.reply(e);
        }
    };

    let tag = data[0];
    let len = data[1];

    // Check tag
    if tag != 0x5C {
        return comm.reply(StatusWords::WrongData);
    }

    // Check length
    if len as usize != data.len() - 2 {
        return comm.reply(StatusWords::WrongLength);
    }

    // Extract slot number
    if data[2] != 0x5F {
        return comm.reply(StatusWords::FileNotFound);
    }

    if data[3] != 0xC1 {
        // Todo: handle yk files
        // https://github.com/arekinath/PivApplet/blob/60fc61ac21fda3caf6cbd4c96f7a7e2db07f2a32/src/net/cooperi/pivapplet/PivApplet.java#L2849
        return comm.reply(StatusWords::FileNotFound);
    }

    if data[4] != 0x0D {
        // Todo: handle multiple slots
        return comm.reply(StatusWords::FileNotFound);
    }

    // Todo: replay data
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
    "*PIV* ready".display(Line::Second, Layout::Centered);
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
