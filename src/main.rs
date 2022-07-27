#![no_std]
#![no_main]

use nanos_sdk::bindings::cx_ecdh_no_throw;
use nanos_sdk::bindings::cx_ecfp_private_key_t;
use nanos_sdk::bindings::{os_global_pin_is_validated, os_serial};
use nanos_sdk::bindings::{CX_ECDH_POINT, CX_OK};
use nanos_sdk::buttons::ButtonEvent;
use nanos_sdk::ecc::CurvesId;
use nanos_sdk::io;
use nanos_sdk::io::SyscallError;

mod bitmaps;
mod data_object;
mod data_response;
mod fonts;
mod layout;
mod screen_util;
mod status;
mod utils;

use data_object::*;
use data_response::*;
use layout::*;
use status::*;

nanos_sdk::set_panic!(nanos_sdk::exiting_panic);

// PIV Application ID
// (https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-73-4.pdf, 2.2)
// Right truncated version
const PIV_AID: [u8; 9] = [0xa0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00];

// BIP32 Path for PIV
// m/5261654'/<account>'/<usage>'/<key reference>'
// 5261654 corresponds to "PIV" encoded in big-endian ASCII.
const BIP32_PATH: [u32; 5] = nanos_sdk::ecc::make_bip32_path(b"m/5261654'/0'/0'/130'");

/// Helper function that derives the seed over Secp256r1
fn bip32_derive_secp256r1(path: &[u32]) -> Result<[u8; 32], SyscallError> {
    let mut raw_key = [0u8; 32];
    nanos_sdk::ecc::bip32_derive(CurvesId::Secp256r1, path, &mut raw_key)?;
    Ok(raw_key)
}

fn ecdh(pvkey: &cx_ecfp_private_key_t, mode: u32, p: &[u8], p_len: u32) -> Option<([u8; 0x20])> {
    let mut secret = [0u8; 0x20];
    //let secret_len = &mut (secret.len() as u32);
    let len =
        unsafe { cx_ecdh_no_throw(pvkey, mode, p.as_ptr(), p_len, secret.as_mut_ptr(), 0x20) };
    if len != CX_OK {
        None
    } else {
        Some(secret)
    }
}

/// Select card command
fn process_select_card(comm: &mut io::Comm) {
    if comm.get_p1() != 0x04 || comm.get_p2() != 0x00 {
        return comm.reply(StatusWord::IncorrectP1P2);
    }
    if let Ok(d) = comm.get_data() {
        if d != PIV_AID {
            return comm.reply(StatusWord::WrongData);
        }
    }

    comm.append(&[
        0x61, 0x11, 0x4f, 0x06, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x79, 0x07, 0x4f, 0x05,
    ]);
    comm.append(&PIV_AID);
    comm.reply_ok();
}

/// General Authenticate card command
fn process_general_auth(comm: &mut io::Comm) {
    let alg = comm.get_p1();
    let key = comm.get_p2();

    // Right now, we only support Secp256r1
    if alg != 0x11 {
        return comm.reply(StatusWord::FuncNotSupported);
    }

    // Right now, we only support retired slots
    if !(0x82..=0x8C).contains(&key) {
        return comm.reply(StatusWord::FuncNotSupported);
    }

    let d = match comm.get_data() {
        Ok(d) => d,
        Err(_) => {
            return comm.reply(StatusWord::WrongData);
        }
    };

    // Outer layer
    if d[0] != 0x7c {
        return comm.reply(StatusWord::WrongData);
    }

    let length = d[1] as usize;
    let d = &d[2..2 + length];

    // Empty tlv (???)
    if d[0] != 0x82 || d[1] != 0 {
        return comm.reply(StatusWord::WrongData);
    }
    let d = &d[2..];

    // Diffie-Hellman packet
    if d[0] != 0x85 {
        return comm.reply(StatusWord::WrongData);
    }
    let length = d[1] as usize;

    if length != 0x41 {
        return comm.reply(StatusWord::WrongData);
    }

    let d = &d[2..];
    // EC point
    if d[0] != 0x04 {
        return comm.reply(StatusWord::WrongData);
    }

    let raw_key = bip32_derive_secp256r1(&BIP32_PATH).unwrap();
    let pk = nanos_sdk::ecc::ec_init_key(CurvesId::Secp256r1, &raw_key).unwrap();

    let secret = ecdh(&pk, CX_ECDH_POINT, d, 0x41).unwrap();

    comm.append(&[0x7c, 0x22, 0x82, 0x20]);
    comm.append(&secret);

    comm.reply_ok();
}

/// Ask the card to continue to answer
fn process_continue_response(comm: &mut io::Comm, response_buffer: &mut DataResponseBuffer) {
    if comm.get_p1() != 0x00 || comm.get_p2() != 0x00 {
        return comm.reply(StatusWord::IncorrectP1P2);
    }

    response_buffer.send(comm);
}

/// Check 'get data' command parameters
fn check_get_data_params(data: &[u8]) -> Result<(), StatusWord> {
    let tag = data[0];
    let len = data[1];

    // Check tag
    if tag != 0x5C {
        return Err(StatusWord::WrongData);
    }

    // Check length
    if len as usize != data.len() - 2 {
        return Err(StatusWord::WrongLength);
    }

    Ok(())
}

fn process_get_data(comm: &mut io::Comm, response_buffer: &mut DataResponseBuffer) {
    if comm.get_p1() != 0x3F || comm.get_p2() != 0xFF {
        return comm.reply(StatusWord::IncorrectP1P2);
    }

    let data = match comm.get_data() {
        Ok(d) => d,
        Err(e) => {
            return comm.reply(e);
        }
    };

    // Check params
    if let Err(status) = check_get_data_params(data) {
        return comm.reply(status);
    }

    match DataObjectIdentifier::from(&data[2..]).handle(response_buffer) {
        Ok(()) => response_buffer.send(comm),
        Err(s) => comm.reply(s),
    }
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
        return comm.reply(StatusWord::IncorrectP1P2);
    }

    let ldg_serial = get_ledger_serial();
    let age_serial = [ldg_serial[0], ldg_serial[2], ldg_serial[4], ldg_serial[6]];

    comm.append(&age_serial);
    comm.reply_ok();
}

/// Get card version
fn process_get_version(comm: &mut io::Comm) {
    if comm.get_p1() != 0x00 || comm.get_p2() != 0x00 {
        return comm.reply(StatusWord::IncorrectP1P2);
    }

    // Same answer as Yubikey 5.4 firmware
    comm.append(&[5, 4, 0]);
    comm.reply_ok();
}

/// Verify PIV Card Application PIN
fn process_verify(comm: &mut io::Comm) {
    if comm.get_p1() != 0x00 || comm.get_p2() != 0x80 {
        return comm.reply(StatusWord::IncorrectP1P2);
    }

    if unsafe { os_global_pin_is_validated() } != 0 {
        comm.reply_ok();
    } else {
        comm.reply(StatusWord::VerificationFailed);
    }
}

#[no_mangle]
extern "C" fn sample_main() {
    let mut comm = io::Comm::new();

    // Erase screen and show message
    screen_util::fulldraw(0, 0, &bitmaps::BLANK);
    bitmaps::PADLOCK.draw(64 - (bitmaps::PADLOCK.width as i32) / 2, 4);
    "*PIV* ready".display(Line::Second, Layout::Centered);

    // When response is split across multiple APDU packets, remaining length to
    // read is sent to the host in the status word. The host ask the card to
    // continue the response with 0xC0 instruction.
    let mut response_buffer = DataResponseBuffer::new();

    loop {
        match comm.next_event() {
            io::Event::Button(ButtonEvent::BothButtonsRelease) => nanos_sdk::exit_app(0),
            io::Event::Button(_) => {}

            // Standard PIV commands
            // See https://csrc.nist.gov/publications/detail/sp/800-73/4/final
            io::Event::Command(0x20) => process_verify(&mut comm),
            io::Event::Command(0xA4) => process_select_card(&mut comm),
            io::Event::Command(0x87) => process_general_auth(&mut comm),
            io::Event::Command(0xC0) => process_continue_response(&mut comm, &mut response_buffer),
            io::Event::Command(0xCB) => process_get_data(&mut comm, &mut response_buffer),

            // YubicoPIV extensions
            // See https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html
            io::Event::Command(0xf8) => process_get_serial(&mut comm),
            io::Event::Command(0xfd) => process_get_version(&mut comm),

            io::Event::Command(_) => comm.reply(StatusWord::FuncNotSupported),

            io::Event::Ticker => {}
        }
    }
}
