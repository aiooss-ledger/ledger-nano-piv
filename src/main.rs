#![no_std]
#![no_main]

extern crate num;
#[macro_use]
extern crate num_derive;

use nanos_sdk::bindings::{CX_ECDH_POINT, CX_OK};
use nanos_sdk::bindings::cx_ecdh_no_throw;
use nanos_sdk::bindings::cx_ecfp_private_key_t;
use nanos_sdk::bindings::os_serial;
use nanos_sdk::buttons::ButtonEvent;
use nanos_sdk::ecc::CurvesId;
use nanos_sdk::io::{Comm, Event};
use nanos_sdk::io::SyscallError;
use num::FromPrimitive;

use layout::*;

use crate::comm::{CommExt, IntoReply, PIVReply};
use crate::error::PIVError;

mod bitmaps;
mod fonts;
mod layout;
mod screen_util;

mod error;
mod comm;
#[macro_use]
mod logging;

use heapless::Vec;

nanos_sdk::set_panic!(nanos_sdk::exiting_panic);

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
            0x20,
        )
    };
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
        self.data.extend_from_slice(&data[0..copied_length]).unwrap();

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
fn process_select_card(comm: &mut Comm) -> Result<PIVReply, PIVError> {
    comm.expect_parameters(0x04, 0x00)?;
    comm.expect_data(&PIV_APP_AID)?;

    comm.append(&[
        0x61, 0x11, 0x4f, 0x06, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x79, 0x07, 0x4f, 0x05,
    ]);
    comm.append(&PIV_APP_AID);
    Ok(PIVReply::Ok)
}

/// General Authenticate card command
fn process_general_auth(comm: &mut Comm) -> Result<PIVReply, PIVError> {
    let (alg, key) = comm.parameters();

    // Right now, we only support Secp256r1
    if alg != 0x11 {
        return Err(PIVError::FuncNotSupported);
    }

    // Right now, we only support retired slots
    if !(0x82 <= key && key <= 0x8C) {
        return Err(PIVError::FuncNotSupported);
    }

    let d = match comm.get_data() {
        Ok(d) => d,
        Err(_) => {
            return Err(PIVError::WrongData);
        }
    };

    // Outer layer
    if d[0] != 0x7c {
        return Err(PIVError::WrongData);
    }

    let length = d[1] as usize;
    let d = &d[2..2 + length];

    // Empty tlv (???)
    if d[0] != 0x82 || d[1] != 0 {
        return Err(PIVError::WrongData);
    }
    let d = &d[2..];

    // Diffie-Hellman packet
    if d[0] != 0x85 {
        return Err(PIVError::WrongData);
    }
    let length = d[1] as usize;

    if length != 0x41 {
        return Err(PIVError::WrongData);
    }

    let d = &d[2..];
    // EC point
    if d[0] != 0x04 {
        return Err(PIVError::WrongData);
    }

    let raw_key = bip32_derive_secp256r1(&BIP32_PATH).unwrap();
    let pk = nanos_sdk::ecc::ec_init_key(CurvesId::Secp256r1, &raw_key).unwrap();

    let secret = ecdh(&pk, CX_ECDH_POINT, d, 0x41).unwrap();

    comm.append(&[0x7c, 0x22, 0x82, 0x20]);
    comm.append(&secret);

    Ok(PIVReply::Ok)
}

fn compute_continue_response(comm: &mut Comm, data_response_buffer: &mut DataResponseBuffer) -> Result<PIVReply, PIVError> {
    if data_response_buffer.get_next_chunk_size() == 0 {
        // No data to respond
        return Ok(PIVReply::Ok);
    }

    // Read data
    comm.append(data_response_buffer.read_next_chunk());

    // Reply status
    let next_size = data_response_buffer.get_next_chunk_size();
    return if next_size > 0 {
        Ok(PIVReply::MoreDataAvailable(next_size as u8))
    } else {
        Ok(PIVReply::Ok)
    };
}

/// Ask the card to continue to answer
fn process_continue_response(comm: &mut Comm, data_response_buffer: &mut DataResponseBuffer) -> Result<PIVReply, PIVError> {
    comm.expect_parameters(0x00, 0x00)?;

    compute_continue_response(comm, data_response_buffer)
}

/// Check 'get data' command parameters
fn check_get_data_params(data: &[u8]) -> Result<(), PIVError> {
    let tag = data[0];
    let len = data[1];

    // Check tag
    if tag != 0x5C {
        return Err(PIVError::WrongData);
    }

    // Check length
    if len as usize != data.len() - 2 {
        return Err(PIVError::WrongLength { expected: len as usize, actual: data.len() - 2 });
    }

    // Extract slot number
    if data[2] != 0x5F {
        return Err(PIVError::FileNotFound);
    }

    if data[3] != 0xC1 {
        // Todo: handle yk files
        // https://github.com/arekinath/PivApplet/blob/60fc61ac21fda3caf6cbd4c96f7a7e2db07f2a32/src/net/cooperi/pivapplet/PivApplet.java#L2849
        return Err(PIVError::FileNotFound);
    }

    if data[4] != 0x0D {
        // Todo: handle multiple slots
        return Err(PIVError::FileNotFound);
    }

    Ok(())
}

fn compute_get_data_content(data_response_buffer: &mut DataResponseBuffer) {
    // Compute data buffer: todo
    let hardcoded = [
        0x53, 0x82, 0x01, 0xbf, 0x70, 0x82, 0x01, 0xb6, 0x30, 0x82, 0x01, 0xb2, 0x30, 0x82, 0x01, 0x59,
        0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x15, 0x00, 0x8d, 0x95, 0xd0, 0xad, 0x81, 0x07, 0x54, 0x1c,
        0x1f, 0x97, 0x37, 0x99, 0x8d, 0x4e, 0x00, 0x3e, 0x99, 0xc3, 0x77, 0x0c, 0x30, 0x0a, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x4d, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03,
        0x55, 0x04, 0x0a, 0x0c, 0x12, 0x61, 0x67, 0x65, 0x2d, 0x70, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x2d,
        0x79, 0x75, 0x62, 0x69, 0x6b, 0x65, 0x79, 0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04, 0x0b,
        0x0c, 0x05, 0x30, 0x2e, 0x33, 0x2e, 0x30, 0x31, 0x1e, 0x30, 0x1c, 0x06, 0x03, 0x55, 0x04, 0x03,
        0x0c, 0x15, 0x61, 0x67, 0x65, 0x20, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x20, 0x39,
        0x39, 0x35, 0x30, 0x65, 0x63, 0x65, 0x33, 0x30, 0x20, 0x17, 0x0d, 0x32, 0x32, 0x30, 0x37, 0x30,
        0x34, 0x31, 0x34, 0x32, 0x33, 0x33, 0x34, 0x5a, 0x18, 0x0f, 0x39, 0x39, 0x39, 0x39, 0x31, 0x32,
        0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a, 0x30, 0x4d, 0x31, 0x1b, 0x30, 0x19, 0x06,
        0x03, 0x55, 0x04, 0x0a, 0x0c, 0x12, 0x61, 0x67, 0x65, 0x2d, 0x70, 0x6c, 0x75, 0x67, 0x69, 0x6e,
        0x2d, 0x79, 0x75, 0x62, 0x69, 0x6b, 0x65, 0x79, 0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04,
        0x0b, 0x0c, 0x05, 0x30, 0x2e, 0x33, 0x2e, 0x30, 0x31, 0x1e, 0x30, 0x1c, 0x06, 0x03, 0x55, 0x04,
        0x03, 0x0c, 0x15, 0x61, 0x67, 0x65, 0x20, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x20,
        0x39, 0x39, 0x35, 0x30, 0x65, 0x63, 0x65, 0x33, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
        0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
        0x42, 0x00, 0x04, 0x90, 0xf0, 0x3d, 0x92, 0xb3, 0xa9, 0xf7, 0x0d, 0x2c, 0x1e, 0x01, 0x96, 0x26,
        0x68, 0x99, 0x1f, 0x33, 0xa8, 0x22, 0x9f, 0x46, 0x3d, 0xb1, 0x9a, 0xb7, 0x92, 0xca, 0x0e, 0x5d,
        0x2a, 0x4e, 0x59, 0x13, 0x31, 0x75, 0x3b, 0x33, 0x02, 0x3d, 0x40, 0xa2, 0x9d, 0x2c, 0x4f, 0x6a,
        0x4a, 0x8d, 0x81, 0x82, 0xae, 0x69, 0xd1, 0xe7, 0x07, 0x0d, 0xae, 0xcd, 0xdb, 0xc8, 0xd2, 0x86,
        0x93, 0x1f, 0x4c, 0xa3, 0x14, 0x30, 0x12, 0x30, 0x10, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01,
        0x82, 0xc4, 0x0a, 0x03, 0x08, 0x04, 0x02, 0x01, 0x02, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x47, 0x00, 0x30, 0x44, 0x02, 0x20, 0x43, 0x9a, 0xf5, 0x07,
        0x33, 0x4b, 0xfe, 0x58, 0xb0, 0x8c, 0xb0, 0xd4, 0xca, 0x38, 0x54, 0x22, 0x90, 0x47, 0xdc, 0x1e,
        0x2c, 0x8d, 0xf4, 0x7a, 0x0d, 0x98, 0xe0, 0x67, 0x64, 0x17, 0x92, 0xcc, 0x02, 0x20, 0x5e, 0x37,
        0x06, 0x01, 0x61, 0xb2, 0x14, 0xef, 0x47, 0x32, 0x7c, 0x6c, 0x8c, 0x74, 0x1c, 0xad, 0x7f, 0xd5,
        0xc4, 0xfe, 0xd6, 0x57, 0xb4, 0x75, 0xdc, 0x9a, 0x46, 0x79, 0x0d, 0x37, 0x7a, 0x51, 0x71, 0x01,
        0x00, 0xfe, 0x00,
    ];

    // Set data response buffer
    data_response_buffer.set(&hardcoded);
}

fn process_get_data(comm: &mut Comm, data_response_buffer: &mut DataResponseBuffer) -> Result<PIVReply, PIVError> {
    comm.expect_parameters(0x3F, 0xFF)?;

    let data = comm.data()?;

    // Check params
    check_get_data_params(data)?;

    // Compute get data content
    compute_get_data_content(data_response_buffer);

    // Response
    compute_continue_response(comm, data_response_buffer)
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
fn process_get_serial(comm: &mut Comm) -> Result<PIVReply, PIVError> {
    comm.expect_parameters(0x00, 0x00)?;

    let ldg_serial = get_ledger_serial();
    let age_serial = [ldg_serial[0], ldg_serial[2], ldg_serial[4], ldg_serial[6]];

    comm.append(&age_serial);
    Ok(PIVReply::Ok)
}

/// Get card version
fn process_get_version(comm: &mut Comm) -> Result<PIVReply, PIVError> {
    comm.expect_parameters(0x00, 0x00)?;

    // Same answer as Yubikey 5.4 firmware
    comm.append(&[5, 4, 0]);
    Ok(PIVReply::Ok)
}

#[derive(FromPrimitive, Debug)]
enum PIVCommand {
    // Standard PIV commands
    // See https://csrc.nist.gov/publications/detail/sp/800-73/4/final
    SelectCard = 0xA4,
    GeneralAuth = 0x87,
    ContinueResponse = 0xC0,
    GetData = 0xCB,

    // YubicoPIV extensions
    // See https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html
    GetSerial = 0xf8,
    GetVersion = 0xfd,
}

#[no_mangle]
extern "C" fn sample_main() {
    let mut comm = Comm::new();

    info!("PIV {} starting", env!("CARGO_PKG_VERSION"));

    // erase screen
    screen_util::fulldraw(0, 0, &bitmaps::BLANK);
    bitmaps::PADLOCK.draw(64 - (bitmaps::PADLOCK.width as i32) / 2, 4);
    "*PIV* ready".display(Line::Second, Layout::Centered);
    env!("CARGO_PKG_VERSION").display(Line::Third, Layout::Centered);

    let mut data_response_buffer = DataResponseBuffer::new();

    loop {
        match comm.next_event() {
            Event::Button(ButtonEvent::BothButtonsRelease) => nanos_sdk::exit_app(0),
            Event::Button(_) | Event::Ticker => {}
            Event::Command(command) => {
                let res = match PIVCommand::from_u8(command) {
                    None => Err(PIVError::FuncNotSupported),
                    Some(command) => {
                        trace!("processing command {:?}", command);
                        match command {
                            PIVCommand::SelectCard => process_select_card(&mut comm),
                            PIVCommand::GeneralAuth => process_general_auth(&mut comm),
                            PIVCommand::ContinueResponse => process_continue_response(&mut comm, &mut data_response_buffer),
                            PIVCommand::GetData => process_get_data(&mut comm, &mut data_response_buffer),
                            PIVCommand::GetSerial => process_get_serial(&mut comm),
                            PIVCommand::GetVersion => process_get_version(&mut comm),
                        }
                    }
                };
                comm.reply(res.into_reply())
            }
        }
    }
}
