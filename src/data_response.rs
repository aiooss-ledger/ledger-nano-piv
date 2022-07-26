use crate::status::*;
use nanos_sdk::io;
use tinyvec::ArrayVec;

const APDU_MAX_CHUNK_SIZE: usize = 255;
const DATA_RESP_BUFFER_SIZE: usize = 512;

// When response is split across multiple APDU packets, remaining length to
// read is sent to the host in the status word. The host ask the card to
// continue the response with 0xC0 instruction.
pub struct DataResponseBuffer {
    data: ArrayVec<[u8; DATA_RESP_BUFFER_SIZE]>,
    read_cnt: usize,
}

impl DataResponseBuffer {
    pub fn new() -> DataResponseBuffer {
        Self {
            data: ArrayVec::new(),
            read_cnt: 0,
        }
    }

    fn remaining_length(&self) -> usize {
        self.data.len() - self.read_cnt
    }

    pub fn set(&mut self, data: &[u8]) {
        // Ensure buffer is not overflowed
        let copied_length = data.len().min(DATA_RESP_BUFFER_SIZE);

        // Copy data content
        self.data.clear();
        self.data.extend_from_slice(&data[0..copied_length]);

        // Init read counter
        self.read_cnt = 0;
    }

    pub fn extend(&mut self, data: &[u8]) {
        let copied_length = data.len().min(DATA_RESP_BUFFER_SIZE - self.data.len());

        self.data.extend_from_slice(&data[0..copied_length]);
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

    pub fn send(&mut self, comm: &mut io::Comm) {
        if self.get_next_chunk_size() == 0 {
            // No data to respond
            comm.reply_ok();
            return;
        }

        // Read data
        comm.append(self.read_next_chunk());

        // Reply status
        let next_size = self.get_next_chunk_size();
        if next_size > 0 {
            comm.reply(StatusWord::MoreDataAvailable(next_size as u8));
        } else {
            comm.reply_ok();
        }
    }
}
