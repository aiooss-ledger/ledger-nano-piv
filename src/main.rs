#![no_std]
#![no_main]

use nanos_sdk::bindings::cx_ecdh_no_throw;
use nanos_sdk::bindings::cx_ecfp_private_key_t;
use nanos_sdk::bindings::os_serial;
use nanos_sdk::bindings::{CX_ECDH_POINT, CX_OK};
use nanos_sdk::buttons::ButtonEvent;
use nanos_sdk::ecc::CurvesId;
use nanos_sdk::io;
use nanos_sdk::io::SyscallError;

mod bitmaps;
mod fonts;
mod layout;
mod screen_util;

use layout::*;

use heapless::Vec;

nanos_sdk::set_panic!(nanos_sdk::exiting_panic);

/// Status Words as specified in table 6 of Interfaces for Personal Identity
/// Verification specification.
#[derive(Copy, Clone)]
enum StatusWords {
    MoreDataAvailable(u8),
    WrongLength,
    WrongData,
    FuncNotSupported,
    FileNotFound,
    IncorrectP1P2,
    // VerificationFailed = 0x6300,
    // SecureMessagingNotSupported = 0x6882,
    // SecurityStatusNotSatisfied = 0x6982,
    // AuthMethodBlocked = 0x6983,
    // MissingSecureMessagingData = 0x6987,
    // IncorrectSecureMessagingData = 0x6988,
    // FileFull = 0x6A84,
    // RefDataNotFound = 0x6A88,
}

impl From<StatusWords> for u16 {
    fn from(val: StatusWords) -> Self {
        match val {
            StatusWords::MoreDataAvailable(size) => 0x6100 + (size as u16),
            StatusWords::WrongLength => 0x6700,
            StatusWords::WrongData => 0x6A80,
            StatusWords::FuncNotSupported => 0x6A81,
            StatusWords::FileNotFound => 0x6A82,
            StatusWords::IncorrectP1P2 => 0x6A86,
        }
    }
}

impl From<StatusWords> for io::Reply {
    fn from(sw: StatusWords) -> io::Reply {
        io::Reply(sw.into())
    }
}

const PIV_APP_AID: [u8; 9] = [0xa0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00];
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

const APDU_MAX_CHUNK_SIZE: usize = 255;
const DATA_RESP_BUFFER_SIZE: usize = 512;

struct DataResponseBuffer {
    data: Vec<u8, DATA_RESP_BUFFER_SIZE>,
    read_cnt: usize,
}

impl DataResponseBuffer {
    fn new() -> Self {
        Self {
            data: Vec::new(),
            read_cnt: 0,
        }
    }

    fn remaining_length(&self) -> usize {
        self.data.len() - self.read_cnt
    }

    fn set(&mut self, data: &[u8]) {
        // Ensure buffer is not overflowed
        let copied_length = data.len().min(DATA_RESP_BUFFER_SIZE);

        // Copy data content
        self.data.clear();
        self.data
            .extend_from_slice(&data[0..copied_length])
            .unwrap();

        // Init read counter
        self.read_cnt = 0;
    }

    fn get_next_chunk_size(&self) -> usize {
        APDU_MAX_CHUNK_SIZE.min(self.remaining_length())
    }

    fn read_next_chunk(&mut self) -> &[u8] {
        let read_length = self.get_next_chunk_size();
        let begin = self.read_cnt;
        let end = self.read_cnt + read_length;
        self.read_cnt += read_length;
        &self.data[begin..end]
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
    if !(0x82..=0x8C).contains(&key) {
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
    let d = &d[2..2 + length];

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

fn compute_continue_response(comm: &mut io::Comm, response_buffer: &mut DataResponseBuffer) {
    if response_buffer.get_next_chunk_size() == 0 {
        // No data to respond
        comm.reply_ok();
        return;
    }

    // Read data
    comm.append(response_buffer.read_next_chunk());

    // Reply status
    let next_size = response_buffer.get_next_chunk_size();
    if next_size > 0 {
        comm.reply(StatusWords::MoreDataAvailable(next_size as u8));
    } else {
        comm.reply_ok();
    }
}

/// Ask the card to continue to answer
fn process_continue_response(comm: &mut io::Comm, response_buffer: &mut DataResponseBuffer) {
    if comm.get_p1() != 0x00 || comm.get_p2() != 0x00 {
        return comm.reply(StatusWords::IncorrectP1P2);
    }

    compute_continue_response(comm, response_buffer);
}

/// Check 'get data' command parameters
fn check_get_data_params(data: &[u8]) -> Option<StatusWords> {
    let tag = data[0];
    let len = data[1];

    // Check tag
    if tag != 0x5C {
        return Some(StatusWords::WrongData);
    }

    // Check length
    if len as usize != data.len() - 2 {
        return Some(StatusWords::WrongLength);
    }

    // Extract slot number
    if data[2] != 0x5F {
        return Some(StatusWords::FileNotFound);
    }

    if data[3] != 0xC1 {
        // Todo: handle yk files
        // https://github.com/arekinath/PivApplet/blob/60fc61ac21fda3caf6cbd4c96f7a7e2db07f2a32/src/net/cooperi/pivapplet/PivApplet.java#L2849
        return Some(StatusWords::FileNotFound);
    }

    if data[4] != 0x0D {
        // Todo: handle multiple slots
        return Some(StatusWords::FileNotFound);
    }

    None
}

fn compute_get_data_content(response_buffer: &mut DataResponseBuffer) {
    // Compute data buffer: todo
    let hardcoded = [
        0x53, 0x82, 0x01, 0xbf, 0x70, 0x82, 0x01, 0xb6, 0x30, 0x82, 0x01, 0xb2, 0x30, 0x82, 0x01,
        0x59, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x15, 0x00, 0x8d, 0x95, 0xd0, 0xad, 0x81, 0x07,
        0x54, 0x1c, 0x1f, 0x97, 0x37, 0x99, 0x8d, 0x4e, 0x00, 0x3e, 0x99, 0xc3, 0x77, 0x0c, 0x30,
        0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x4d, 0x31, 0x1b,
        0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x12, 0x61, 0x67, 0x65, 0x2d, 0x70, 0x6c,
        0x75, 0x67, 0x69, 0x6e, 0x2d, 0x79, 0x75, 0x62, 0x69, 0x6b, 0x65, 0x79, 0x31, 0x0e, 0x30,
        0x0c, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x05, 0x30, 0x2e, 0x33, 0x2e, 0x30, 0x31, 0x1e,
        0x30, 0x1c, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x15, 0x61, 0x67, 0x65, 0x20, 0x69, 0x64,
        0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x20, 0x39, 0x39, 0x35, 0x30, 0x65, 0x63, 0x65, 0x33,
        0x30, 0x20, 0x17, 0x0d, 0x32, 0x32, 0x30, 0x37, 0x30, 0x34, 0x31, 0x34, 0x32, 0x33, 0x33,
        0x34, 0x5a, 0x18, 0x0f, 0x39, 0x39, 0x39, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35,
        0x39, 0x35, 0x39, 0x5a, 0x30, 0x4d, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x0a,
        0x0c, 0x12, 0x61, 0x67, 0x65, 0x2d, 0x70, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x2d, 0x79, 0x75,
        0x62, 0x69, 0x6b, 0x65, 0x79, 0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c,
        0x05, 0x30, 0x2e, 0x33, 0x2e, 0x30, 0x31, 0x1e, 0x30, 0x1c, 0x06, 0x03, 0x55, 0x04, 0x03,
        0x0c, 0x15, 0x61, 0x67, 0x65, 0x20, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x20,
        0x39, 0x39, 0x35, 0x30, 0x65, 0x63, 0x65, 0x33, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a,
        0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01,
        0x07, 0x03, 0x42, 0x00, 0x04, 0x90, 0xf0, 0x3d, 0x92, 0xb3, 0xa9, 0xf7, 0x0d, 0x2c, 0x1e,
        0x01, 0x96, 0x26, 0x68, 0x99, 0x1f, 0x33, 0xa8, 0x22, 0x9f, 0x46, 0x3d, 0xb1, 0x9a, 0xb7,
        0x92, 0xca, 0x0e, 0x5d, 0x2a, 0x4e, 0x59, 0x13, 0x31, 0x75, 0x3b, 0x33, 0x02, 0x3d, 0x40,
        0xa2, 0x9d, 0x2c, 0x4f, 0x6a, 0x4a, 0x8d, 0x81, 0x82, 0xae, 0x69, 0xd1, 0xe7, 0x07, 0x0d,
        0xae, 0xcd, 0xdb, 0xc8, 0xd2, 0x86, 0x93, 0x1f, 0x4c, 0xa3, 0x14, 0x30, 0x12, 0x30, 0x10,
        0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xc4, 0x0a, 0x03, 0x08, 0x04, 0x02, 0x01,
        0x02, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x47,
        0x00, 0x30, 0x44, 0x02, 0x20, 0x43, 0x9a, 0xf5, 0x07, 0x33, 0x4b, 0xfe, 0x58, 0xb0, 0x8c,
        0xb0, 0xd4, 0xca, 0x38, 0x54, 0x22, 0x90, 0x47, 0xdc, 0x1e, 0x2c, 0x8d, 0xf4, 0x7a, 0x0d,
        0x98, 0xe0, 0x67, 0x64, 0x17, 0x92, 0xcc, 0x02, 0x20, 0x5e, 0x37, 0x06, 0x01, 0x61, 0xb2,
        0x14, 0xef, 0x47, 0x32, 0x7c, 0x6c, 0x8c, 0x74, 0x1c, 0xad, 0x7f, 0xd5, 0xc4, 0xfe, 0xd6,
        0x57, 0xb4, 0x75, 0xdc, 0x9a, 0x46, 0x79, 0x0d, 0x37, 0x7a, 0x51, 0x71, 0x01, 0x00, 0xfe,
        0x00,
    ];

    // Set data response buffer
    response_buffer.set(&hardcoded);
}

fn process_get_data(comm: &mut io::Comm, response_buffer: &mut DataResponseBuffer) {
    if comm.get_p1() != 0x3F || comm.get_p2() != 0xFF {
        return comm.reply(StatusWords::IncorrectP1P2);
    }

    let data = match comm.get_data() {
        Ok(d) => d,
        Err(e) => {
            return comm.reply(e);
        }
    };

    // Check params
    if let Some(status) = check_get_data_params(data) {
        return comm.reply(status);
    }

    // Compute get data content
    compute_get_data_content(response_buffer);

    // Response
    compute_continue_response(comm, response_buffer);
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
            io::Event::Command(0xA4) => process_select_card(&mut comm),
            io::Event::Command(0x87) => process_general_auth(&mut comm),
            io::Event::Command(0xC0) => process_continue_response(&mut comm, &mut response_buffer),
            io::Event::Command(0xCB) => process_get_data(&mut comm, &mut response_buffer),

            // YubicoPIV extensions
            // See https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html
            io::Event::Command(0xf8) => process_get_serial(&mut comm),
            io::Event::Command(0xfd) => process_get_version(&mut comm),

            io::Event::Command(_) => comm.reply(StatusWords::FuncNotSupported),

            io::Event::Ticker => {}
        }
    }
}
