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
    data: [u8; DATA_RESP_BUFFER_SIZE],
    read_cnt: usize,
}

impl DataResponseBuffer {
    fn new() -> Self {
        Self {
            data: [0; DATA_RESP_BUFFER_SIZE],
            read_cnt: 0,
        }
    }

    fn remaining_length(&self) -> usize {
        DATA_RESP_BUFFER_SIZE - self.read_cnt
    }

    fn set(&mut self, data: &[u8]) {
        let copied_length = data.len().min(DATA_RESP_BUFFER_SIZE);
        self.data.copy_from_slice(&data[0..copied_length]);
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
    let hardcoded = [0xA5; 512];

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
