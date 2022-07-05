use nanos_sdk::io::{Comm, Reply, StatusWords};

use crate::error::PIVError;

pub trait CommExt {
    fn parameters(&self) -> (u8, u8);
    fn expect_parameters(&self, p1: u8, p2: u8) -> Result<(), PIVError>;

    fn data(&self) -> Result<&[u8], PIVError>;
    fn expect_data(&self, data: &[u8]) -> Result<(), PIVError>;
}


impl CommExt for Comm {
    fn parameters(&self) -> (u8, u8) {
        (self.get_p1(), self.get_p2())
    }

    fn expect_parameters(&self, p1: u8, p2: u8) -> Result<(), PIVError> {
        match self.parameters() {
            (actual_p1, _) if actual_p1 != p1 => Err(PIVError::IncorrectP1 { expected: p1, actual: actual_p1 }),
            (_, actual_p2) if actual_p2 != p2 => Err(PIVError::IncorrectP2 { expected: p2, actual: actual_p2 }),
            _ => Ok(()),
        }
    }

    fn data(&self) -> Result<&[u8], PIVError> {
        self.get_data().map_err(|status| PIVError::DataError { status })
    }

    fn expect_data(&self, expected_data: &[u8]) -> Result<(), PIVError> {
        self.data()
            .and_then(|actual_data| match actual_data == expected_data {
                true => Ok(()),
                false => Err(PIVError::WrongData)
            })
    }
}

pub trait IntoReply {
    fn into_reply(self) -> Reply;
}

impl IntoReply for Result<PIVReply, PIVError> {
    fn into_reply(self) -> Reply {
        match self {
            Ok(reply) => reply.into(),
            Err(error) => error.into()
        }
    }
}

pub enum PIVReply {
    Ok,
    MoreDataAvailable(u8),
}

impl Into<Reply> for PIVReply {
    fn into(self) -> Reply {
        Reply(match self {
            PIVReply::Ok => StatusWords::Ok as u16,
            PIVReply::MoreDataAvailable(size) => 0x6100 + (size as u16)
        })
    }
}
