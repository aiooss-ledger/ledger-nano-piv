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
// #[repr(u16)]
enum StatusWords {
    MoreDataAvailable(u8),
    // VerificationFailed = 0x6300,
    WrongLength,
    // SecureMessagingNotSupported = 0x6882,
    // SecurityStatusNotSatisfied = 0x6982,
    // AuthMethodBlocked = 0x6983,
    // MissingSecureMessagingData = 0x6987,
    // IncorrectSecureMessagingData = 0x6988,
    WrongData,
    FuncNotSupported,
    FileNotFound,
    // FileFull = 0x6A84,
    IncorrectP1P2,
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

const PIV_APP_AID: [u8; 5] = [0xa0, 0x00, 0x00, 0x03, 0x08];

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

fn compute_continue_response(comm: &mut io::Comm, data_response_buffer: &mut DataResponseBuffer) {
    if data_response_buffer.get_next_chunk_size() == 0 {
        // No data to respond
        comm.reply_ok();
        return;
    }

    // Read data
    comm.append(data_response_buffer.read_next_chunk());

    // Reply status
    let next_size = data_response_buffer.get_next_chunk_size();
    if next_size > 0 {
        comm.reply(StatusWords::MoreDataAvailable(next_size as u8));
    } else {
        comm.reply_ok();
    }
}

/// Ask the card to continue to answer
fn process_continue_response(comm: &mut io::Comm, data_response_buffer: &mut DataResponseBuffer) {
    if comm.get_p1() != 0x00 || comm.get_p2() != 0x00 {
        return comm.reply(StatusWords::IncorrectP1P2);
    }

    compute_continue_response(comm, data_response_buffer);
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

fn compute_get_data_content(data_response_buffer: &mut DataResponseBuffer) {
    // Compute data buffer: todo
    let hardcoded = [0xA5; 512];

    // Set data response buffer
    data_response_buffer.set(&hardcoded);
}

fn process_get_data(comm: &mut io::Comm, data_response_buffer: &mut DataResponseBuffer) {
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
    compute_get_data_content(data_response_buffer);

    // Response
    compute_continue_response(comm, data_response_buffer);
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

    let mut data_response_buffer = DataResponseBuffer::new();

    loop {
        match comm.next_event() {
            io::Event::Button(ButtonEvent::BothButtonsRelease) => nanos_sdk::exit_app(0),
            io::Event::Button(_) => {}

            // Standard PIV commands
            // See https://csrc.nist.gov/publications/detail/sp/800-73/4/final
            io::Event::Command(0xA4) => process_select_card(&mut comm),
            io::Event::Command(0x87) => process_general_auth(&mut comm),
            io::Event::Command(0xC0) => {
                process_continue_response(&mut comm, &mut data_response_buffer)
            }
            io::Event::Command(0xCB) => process_get_data(&mut comm, &mut data_response_buffer),

            // YubicoPIV extensions
            // See https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html
            io::Event::Command(0xf8) => process_get_serial(&mut comm),
            io::Event::Command(0xfd) => process_get_version(&mut comm),

            io::Event::Command(_) => comm.reply(StatusWords::FuncNotSupported),

            io::Event::Ticker => {}
        }
    }
}
